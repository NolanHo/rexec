use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use russh::ChannelMsg;
use ssh2_config::{ParseRule, SshConfig};

mod diagnostics;
mod history;
mod protocol;
mod remote;
mod ssh;

use protocol::{FrameReader, FrameType};

/// Global quiet flag. When set, all progress/status output (Remote PID,
/// exit, sync, reconnect, host-key prompts) is suppressed so stdout/stderr
/// carry only the remote command's own output.
pub(crate) static QUIET: AtomicBool = AtomicBool::new(false);

/// `--json` was requested. The deploy decision is only ever *reported* by the
/// JSON summary, so the extra read-only probe behind it (see
/// `probe_remote_worker_version`) runs only when someone reads the field — the
/// traced deploy call records its decision in the trace either way.
pub(crate) static JSON_SUMMARY: AtomicBool = AtomicBool::new(false);

/// Exit code of the remote command, set while streaming frames. Propagated as
/// rexec's own exit status (like ssh does), so `rexec … && next` and agents
/// that check `$?` cannot mistake a failed remote run for a success.
/// 0 = nothing to propagate; negative (signal-killed child) → 255.
pub(crate) static REMOTE_EXIT: AtomicI32 = AtomicI32::new(0);

/// `--reveal-secrets` was requested. Secret VALUES (env vars) are recorded
/// verbatim in the owner-only history tree, but every OUTPUT surface masks them
/// by default so a key cannot land in terminal scrollback, CI logs or an agent
/// transcript just because rexec ran.
pub(crate) static REVEAL_SECRETS: AtomicBool = AtomicBool::new(false);

/// SOCKS5 proxy for this invocation (`--socks5 HOST:PORT` or `REXEC_SOCKS5`).
///
/// Applies to the *first* TCP leg of the route — the target itself for a direct
/// connection, the outermost jump host for a `ProxyJump` chain. It overrides an
/// ssh-config `ProxyCommand`; without it, a `ProxyCommand` that is one of the
/// recognizable SOCKS5 shapes is used instead of only being warned about.
static SOCKS5_PROXY: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// The explicit SOCKS5 proxy for this invocation, if any.
pub(crate) fn socks5_proxy() -> Option<&'static str> {
    SOCKS5_PROXY.get().map(String::as_str)
}

/// [`socks5_proxy`] as an owned value, for storing on a resolved hop.
fn explicit_socks5() -> Option<String> {
    socks5_proxy().map(str::to_string)
}

/// True when the user opted into seeing secret values in output.
pub(crate) fn reveal_secrets() -> bool {
    REVEAL_SECRETS.load(Ordering::Relaxed)
}

/// An env value as it may appear in OUTPUT (never in the stored record).
///
/// Masked unless the user asked with `--reveal-secrets`; an empty value carries
/// no secret and stays empty so `KEY=` still reads as "set but empty".
fn mask_env_value(value: &str, reveal: bool) -> String {
    if reveal || value.is_empty() {
        value.to_string()
    } else {
        "***".to_string()
    }
}

/// Map a remote exit code onto a local process exit status: negatives (the
/// worker could not obtain a real code, e.g. the child died of a signal)
/// become 255, like ssh's own error status.
pub(crate) fn remote_exit_status(code: i32) -> i32 {
    if code < 0 { 255 } else { code }
}

/// How much of the worker's own stderr is kept for the "worker died before it
/// started" error. Bounded so a chatty worker cannot balloon memory; the tail
/// is what explains the failure.
const WORKER_STDERR_KEEP: usize = 8 * 1024;

/// True when the last byte written to local stderr was not a newline (the
/// command's stderr frames can end mid-line: `printf 'x' >&2`).
///
/// Local diagnostics must start on a fresh line — otherwise the one-line
/// `--json` summary would be glued to the command's output and stop being
/// parseable. Tracked by the frame writers, cleared on read.
static STDERR_TAIL_UNTERMINATED: AtomicBool = AtomicBool::new(false);

/// Record what the frame writers just put on stderr.
fn note_stderr_write(bytes: &[u8]) {
    if let Some(last) = bytes.last() {
        STDERR_TAIL_UNTERMINATED.store(*last != b'\n', Ordering::Relaxed);
    }
}

/// Start a fresh stderr line if the previous write left one dangling.
fn ensure_stderr_line_start() {
    if STDERR_TAIL_UNTERMINATED.swap(false, Ordering::Relaxed) {
        eprintln!();
    }
}

/// Print a progress/status line to stderr unless --quiet is set.
#[macro_export]
macro_rules! status {
    ($($t:tt)*) => {{
        if !$crate::QUIET.load(std::sync::atomic::Ordering::Relaxed) {
            $crate::ensure_stderr_line_start();
            eprintln!($($t)*);
        }
    }};
}

/// Print a progress line only in verbose mode.
///
/// Success is silent by default: in normal mode stdout/stderr carry the
/// command's own output and nothing else. The same facts (remote PID, exit
/// status, sync/reconnect progress) are one flag away under `-v`, and the
/// decision trace always accompanies a failure.
#[macro_export]
macro_rules! progress {
    ($($t:tt)*) => {{
        if $crate::diagnostics::mode().progress_lines() {
            $crate::status!($($t)*);
        }
    }};
}

#[derive(Parser)]
#[command(
    name = "rexec",
    version,
    about = "Remote code execution + folder sync over SSH"
)]
struct Cli {
    /// SSH host alias (resolved via ~/.ssh/config) or user@host:port
    host: Option<String>,

    /// SSH port (overrides host:port and ssh-config Port)
    #[arg(short = 'p', long = "port", value_name = "PORT", global = true)]
    port: Option<u16>,

    /// Suppress progress/status output (Remote PID, exit, sync, reconnect)
    #[arg(short = 'q', long = "quiet", global = true)]
    quiet: bool,

    /// Print the decision trace (resolution, auth, deploy) even on success;
    /// errors always carry it
    #[arg(short = 'v', long = "verbose", global = true)]
    verbose: bool,

    /// Emit a single-line machine-readable result summary on stderr
    #[arg(long = "json", global = true)]
    json: bool,

    /// Do not record this run in the local execution history (same as
    /// REXEC_HISTORY=0; reading `rexec history …` still works)
    #[arg(long = "no-history", global = true)]
    no_history: bool,

    /// Show secret values (env vars) in output. They are recorded locally
    /// either way; without this flag every printed surface masks them
    #[arg(long = "reveal-secrets", global = true)]
    reveal_secrets: bool,

    /// Route the first hop through this SOCKS5 proxy (`HOST:PORT`). Overrides
    /// ssh-config `ProxyCommand`; also settable via the `REXEC_SOCKS5` env var
    #[arg(long = "socks5", value_name = "HOST:PORT", global = true)]
    socks5: Option<String>,

    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Check remote dependencies (rsync, sh) and install if missing
    Init,

    /// Execute a command on the remote host
    Run {
        /// Set an environment variable on the remote command (KEY=VALUE). Repeatable.
        #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,

        /// Read environment variables from a local file (KEY=VALUE per line). Repeatable.
        #[arg(long = "env-file", value_name = "PATH")]
        env_file: Vec<PathBuf>,

        /// Sync a local file or folder to the remote host before executing (LOCAL:REMOTE)
        #[arg(long, value_name = "LOCAL:REMOTE")]
        sync: Option<String>,

        /// Command to execute on the remote host
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Sync a local script to the remote and run it (interpreter auto-detected)
    Script {
        /// Set an environment variable on the remote command (KEY=VALUE). Repeatable.
        #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,

        /// Read environment variables from a local file (KEY=VALUE per line). Repeatable.
        #[arg(long = "env-file", value_name = "PATH")]
        env_file: Vec<PathBuf>,

        /// Remote directory to sync the script into (default ~/.rexec/scripts)
        #[arg(long = "sync-to", value_name = "REMOTE_DIR")]
        sync_to: Option<String>,

        /// Interpreter to run the script with (default: shebang or extension)
        #[arg(long = "interpreter", value_name = "CMD")]
        interpreter: Option<String>,

        /// Local script file to sync and run
        script: PathBuf,

        /// Arguments passed to the script (use -- to separate options)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// List SSH hosts configured in ~/.ssh/config
    List {
        /// Optional: show resolved details (user, port, identity, description)
        /// for a single alias
        alias: Option<String>,

        /// Also show the detail columns (user, identity); the default table
        /// already carries `host:port`, which is part of which machine this is
        #[arg(short = 'l', long = "long")]
        long: bool,

        /// Keep hosts whose alias/host:port/user/description matches PATTERN
        /// (case-insensitive substring; `*`/`?` make it a glob over
        /// alias+hostname+host:port). Repeatable — every pattern must match
        #[arg(short = 'f', long = "filter", value_name = "PATTERN")]
        filter: Vec<String>,

        /// Keep hosts whose resolved user equals NAME (case-insensitive)
        #[arg(long = "user", value_name = "NAME")]
        user: Option<String>,

        /// Keep hosts whose resolved port equals PORT
        #[arg(long = "port", value_name = "PORT")]
        port: Option<u16>,
    },

    /// Show what a run WOULD do — resolution, deploy decision, launch command —
    /// without executing the command or deploying anything
    Plan {
        /// Command the plan is for (shown, never executed)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// [internal] Run as worker on the remote host (reads command from stdin)
    Worker,

    /// [internal] Attach to a running worker's log
    Attach {
        #[arg(long)]
        pid: u32,

        #[arg(long)]
        offset: u64,
    },

    /// Inspect the local execution history (~/.rexec/history)
    History {
        #[command(subcommand)]
        cmd: HistoryCmd,
    },
}

/// `rexec history …` subcommands — all read the local index except `prune`
/// (which deletes runs) and `fetch` (which reads one file on the remote).
#[derive(Subcommand)]
enum HistoryCmd {
    /// List recent recorded runs, newest first (pure data on stdout)
    List {
        /// Maximum number of runs to print
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: usize,

        /// Only runs whose host (as typed) or resolved target contains this
        #[arg(long)]
        host: Option<String>,

        /// Only runs that failed: non-zero exit, or no exit observed at all
        #[arg(long)]
        failed: bool,
    },

    /// Show one run: a human summary, or one raw artifact with a selector
    Show {
        /// Run id, as printed by `rexec history list`
        id: String,

        /// Write the captured stdout bytes and nothing else (pipe-friendly)
        #[arg(long)]
        stdout: bool,

        /// Write the captured stderr bytes and nothing else (pipe-friendly)
        #[arg(long)]
        stderr: bool,

        /// Print the recorded decision trace, one line per entry
        #[arg(long)]
        trace: bool,

        /// Print the raw stored JSON record line
        #[arg(long)]
        meta: bool,
    },

    /// Case-insensitive substring search over commands and env values
    Grep {
        /// Plain substring (no regex); matched against command + env values
        pattern: String,

        /// Maximum number of matching runs to print
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: usize,

        /// Only runs whose host (as typed) or resolved target contains this
        #[arg(long)]
        host: Option<String>,

        /// Only runs that failed: non-zero exit, or no exit observed at all
        #[arg(long)]
        failed: bool,

        /// Also search the captured stdout/stderr of each matching run
        #[arg(long)]
        output: bool,
    },

    /// Aggregate statistics over the recorded runs
    Stats {
        /// Only runs whose host (as typed) or resolved target contains this
        #[arg(long)]
        host: Option<String>,
    },

    /// Print the history root directory (the tree itself appears on first write)
    Path,

    /// Delete old runs and enforce a size cap
    Prune {
        /// Remove runs started more than this many days ago
        #[arg(long, default_value_t = 30)]
        keep_days: u64,

        /// Then remove the oldest runs while the tree is larger than this
        #[arg(long)]
        max_mb: Option<u64>,
    },

    /// Pull the FULL worker log of a recorded run from the remote (read-only)
    Fetch {
        /// Run id, as printed by `rexec history list`
        id: String,

        /// Write to this file instead of stdout
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Clone, Debug)]
pub struct RemoteHost {
    pub hostname: String,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub identity_file: Option<PathBuf>,
    /// Resolved `ProxyJump` chain: the hosts to tunnel through, outermost hop
    /// first, so `jump.last()` is the hop that opens the connection to us.
    ///
    /// Empty means a direct TCP connection. Chains are flattened during
    /// resolution (`ProxyJump a,b` and a jump host that itself jumps both come
    /// out in connection order), so each hop's own `jump` is empty.
    pub jump: Vec<RemoteHost>,
    /// The original `ProxyJump` spec strings, in the same order as `jump`.
    ///
    /// Kept for tools that resolve hosts themselves — `rsync` spawns a real
    /// `ssh`, and `-J js4` lets that ssh apply the hop's config block, while
    /// `-J zengqixin@192.168.4.70:42200` would match no block and pick up the
    /// wrong identity from `Host *`.
    pub jump_specs: Vec<String>,
    /// The ssh-config alias this target was resolved from, when it was one.
    ///
    /// `rsync` gets the alias rather than the resolved address so the ssh it
    /// spawns applies that host's own config block (IdentityFile list, Port,
    /// ProxyJump). `ssh` matches `Host` blocks by the hostname it is given, so a
    /// resolved `user@<HostName>` may match no block at all (or only `Host *`)
    /// and end up offering a key that host does not accept — that is exactly how
    /// rsync to `10.30.40.4` failed while rexec's own path succeeded.
    pub alias: Option<String>,
    /// SOCKS5 proxy (`HOST:PORT`) to reach this hop's TCP address through.
    ///
    /// Set on the *first* TCP leg only: the explicit `--socks5`/`REXEC_SOCKS5`,
    /// or the host's own `ProxyCommand` when it is one of the recognizable
    /// SOCKS5 shapes (`nc -x`, `ncat --proxy … --proxy-type socks5`, …). Later
    /// jump hops are reached through `direct-tcpip` and need no proxy.
    pub socks5: Option<String>,
}

/// True when `s` starts with a Windows drive prefix (`^[A-Za-z]:`), e.g. `C:\proj`.
///
/// Checked on every platform, not just Windows: it can only match input that
/// carries such a prefix. Needed because `--sync` splits on the first ':',
/// which would turn `C:\proj:/home/you/proj` into LOCAL="C" and
/// REMOTE="\proj:/home/you/proj" — handing rsync a host named "C". POSIX paths
/// cannot start with `X:`, and MSYS2/WSL-style paths (`/c/proj`) parse fine.
fn has_windows_drive_prefix(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

fn parse_sync_arg(arg: &str) -> Result<(PathBuf, String)> {
    if has_windows_drive_prefix(arg) {
        return Err(anyhow!(
            "--sync LOCAL looks like a Windows drive path ('{}'), which rsync \
             cannot use; pass an MSYS2-style path instead, e.g. /c/proj:/remote/dir",
            arg
        ));
    }
    let (local, remote) = arg
        .split_once(':')
        .ok_or_else(|| anyhow!("--sync must be LOCAL:REMOTE, got '{}'", arg))?;
    if local.is_empty() || remote.is_empty() {
        return Err(anyhow!("--sync LOCAL and REMOTE must both be non-empty"));
    }
    Ok((PathBuf::from(local), remote.to_string()))
}

/// Parse a local env file into (KEY, VALUE) pairs.
///
/// One `KEY=VALUE` per line. Blank lines and `#` comments are skipped, a
/// leading `export ` is stripped, and one layer of surrounding quotes on the
/// value is removed. Lines without `=` are skipped with a warning.
fn parse_env_file(path: &Path) -> Result<Vec<(String, String)>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading env file {}", path.display()))?;
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((k, mut v)) = line.split_once('=') else {
            // Never echo the line: a malformed env-file line is exactly where a
            // stray secret lives (a key pasted without its name, a wrapped
            // line), and this warning would otherwise put it on stderr.
            if reveal_secrets() {
                eprintln!("⚠ env file: skipping malformed line (no '='): {:?}", line);
            } else {
                eprintln!(
                    "⚠ env file: skipping malformed line (no '=', {} bytes) — --reveal-secrets prints it",
                    line.len()
                );
            }
            continue;
        };
        let k = k.trim();
        if k.is_empty() {
            continue;
        }
        v = v.trim();
        // Strip one layer of matching surrounding quotes.
        if v.len() >= 2 {
            let (first, last) = (v.as_bytes()[0] as char, v.as_bytes()[v.len() - 1] as char);
            if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
                v = &v[1..v.len() - 1];
            }
        }
        out.push((k.to_string(), v.to_string()));
    }
    Ok(out)
}

/// Load an SSH config with `Include` directives fully expanded.
///
/// The ssh2-config crate resolves relative Include paths with a glob against
/// the process CWD, while OpenSSH anchors every relative Include path at the
/// directory of the *top-level* user config (~/.ssh), regardless of nesting.
/// Without this expansion, aliases defined in e.g. `~/.ssh/config.d/*.conf`
/// silently vanish. We expand Includes ourselves — tilde, glob (skipping
/// directories and dotfiles), anchored at the top-level config dir, cycle
/// guard, depth limit — and hand the parser plain text with no Include lines
/// left. `%token`/`${VAR}` expansion (OpenSSH 9.9+) and `Match` conditionals
/// (unsupported by the crate) are not expanded.
fn load_ssh_config_text(path: &Path) -> Result<String> {
    // Every relative Include path anchors at the top-level config's dir.
    let root_dir = path.parent().unwrap_or(Path::new("."));
    let mut out = String::new();
    let mut stack: Vec<PathBuf> = Vec::new();
    let mut state = ExpansionState::default();
    expand_config_file(
        path,
        root_dir,
        &mut out,
        &mut stack,
        Scope::Global,
        &mut state,
    )?;
    if state.saw_match {
        // Warnings are not suppressed by `-q`: a Match block we cannot evaluate
        // changes which host ssh would use, and dropping it silently would be
        // the exact opacity this tool exists to remove.
        eprintln!(
            "⚠ ssh config: `Match` blocks are not implemented; directives inside them are ignored"
        );
    }
    Ok(out)
}

/// The parse scope a line belongs to. OpenSSH tracks this as the `active`
/// boolean inherited down the Include chain (readconf.c `*activep`); the
/// textual equivalent here is the enclosing `Host` line — or a `Host *` line
/// for the global scope.
#[derive(Clone)]
enum Scope {
    Global,
    Host(String), // verbatim `Host` line
}

impl Scope {
    /// The line to re-emit after an Include to restore this scope.
    fn restore_line(&self) -> &str {
        match self {
            // Global directives must apply to every host: `Host *` makes the
            // crate attach them to the wildcard block (first-wins, so more
            // specific blocks defined earlier keep their values).
            Scope::Global => "Host *",
            Scope::Host(line) => line,
        }
    }
}

/// Expansion state that OpenSSH keeps globally and the crate does not.
///
/// 1. **First-obtained-wins for the routing directives.** The crate stores
///    `ProxyJump`/`ProxyCommand` in `unsupported_fields`, a map that *overwrites*,
///    so two lines in one block would leave the last value — OpenSSH keeps the
///    first. Keyed by `(scope line, keyword)` so an Include's own blocks and the
///    enclosing block do not interfere.
/// 2. **`Match` blocks.** `Match` is unknown to the crate, so its directives would
///    leak into the preceding `Host` block and be applied unconditionally. We drop
///    the block and warn instead of silently changing the route.
#[derive(Default)]
struct ExpansionState {
    seen: std::collections::HashSet<(String, String)>,
    saw_match: bool,
}

impl ExpansionState {
    /// The scope key first-wins is tracked under (the verbatim block line).
    fn key(scope: &Scope) -> String {
        scope.restore_line().to_string()
    }
}

/// The directive keyword of a config line, lowercased, or `None` for a blank
/// line or comment. OpenSSH accepts `Key value` and `Key=value` alike.
fn directive_keyword(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let kw_end = trimmed
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(trimmed.len());
    Some(trimmed[..kw_end].to_ascii_lowercase())
}

/// Directives whose duplicate in one block must keep the FIRST value, because
/// the crate's unsupported-field map would otherwise keep the last.
fn first_wins_keyword(line: &str) -> Option<String> {
    match directive_keyword(line)?.as_str() {
        kw @ ("proxyjump" | "proxycommand") => Some(kw.to_string()),
        _ => None,
    }
}

/// Append the contents of `path` to `out`, replacing `Include` lines with the
/// expanded contents of the referenced files. `root_dir` is the directory of
/// the top-level config (~/.ssh): every relative Include path anchors there,
/// at any nesting depth, matching OpenSSH user-config behavior. `inherited`
/// is the scope active where this file was Included from — child files start
/// in that scope and restore it after their own Includes, mirroring
/// readconf.c's `oactive`/`*activep = oactive` save/restore.
fn expand_config_file(
    path: &Path,
    root_dir: &Path,
    out: &mut String,
    stack: &mut Vec<PathBuf>,
    inherited: Scope,
    state: &mut ExpansionState,
) -> Result<()> {
    const MAX_INCLUDE_DEPTH: usize = 16;
    // OpenSSH fatals when include depth EXCEEDS 16 (readconf.c), i.e. 16
    // nested include levels are allowed; stack.len() counts open ancestors.
    if stack.len() > MAX_INCLUDE_DEPTH {
        return Err(anyhow!(
            "ssh config include depth exceeds {} at {}",
            MAX_INCLUDE_DEPTH,
            path.display()
        ));
    }
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    // Cycle guard: only the *ancestor chain* is deduplicated, so a file
    // included from two sibling blocks (diamond) is still expanded twice,
    // matching OpenSSH (which guards depth only).
    if stack.contains(&canonical) {
        return Ok(());
    }
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        // OpenSSH tolerates a file vanishing between glob and open (ENOENT).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        // Non-UTF8 configs can't be parsed by the crate; OpenSSH reads bytes.
        // An included file is skipped with a warning rather than failing
        // every alias — but the top-level config itself stays a hard error
        // (silently ignoring ~/.ssh/config would turn every alias into a raw
        // hostname). At this point the top level has an empty stack.
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData && !stack.is_empty() => {
            eprintln!("⚠ ssh config: skipping non-UTF8 include {}", path.display());
            return Ok(());
        }
        Err(e) => {
            return Err(anyhow::Error::new(e).context(format!("reading {}", path.display())));
        }
    };
    stack.push(canonical);
    let mut current_scope = inherited;
    // Inside a dropped `Match` block; a `Host` line ends it (OpenSSH's state
    // machine treats `Match` like `Host` in that respect).
    let mut skipping_match = false;
    for line in text.lines() {
        if skipping_match {
            if is_host_line(line) {
                skipping_match = false;
            } else {
                continue;
            }
        }
        if let Some(args) = include_args(line) {
            for arg in args {
                let expanded = expand_tilde_path(&arg);
                let target = if expanded.is_absolute() {
                    expanded
                } else {
                    root_dir.join(expanded)
                };
                // Each matched file is emitted as its own block, preceded by
                // the current scope line (see expand_include_target): the
                // crate is last-wins WITHIN a block but first-wins ACROSS
                // blocks, and OpenSSH is first-obtained-wins AND restores the
                // scope after every single matched file — so an include must
                // neither override enclosing pre-include values nor let one
                // included file's trailing `Host` block capture the next
                // file's global directives.
                if let Err(e) = expand_include_target(
                    &target,
                    root_dir,
                    out,
                    stack,
                    current_scope.clone(),
                    state,
                ) {
                    stack.pop(); // keep the ancestor chain balanced on error paths
                    return Err(e);
                }
            }
            // OpenSSH restores the enclosing block's state after an include
            // (readconf.c: `*activep = oactive`) — including the state
            // inherited from a parent include. Directives after the Include
            // keep applying to the enclosing host (or globally).
            out.push_str(current_scope.restore_line());
            out.push('\n');
        } else {
            // A `Match` block cannot be evaluated here; dropping it is the only
            // honest option (leaking its directives into the previous `Host`
            // block would apply them unconditionally — a silent route change).
            if directive_keyword(line).as_deref() == Some("match") {
                state.saw_match = true;
                skipping_match = true;
                continue;
            }
            if is_host_line(line) {
                current_scope = Scope::Host(line.to_string());
            }
            if let Some(kw) = first_wins_keyword(line) {
                let key = (ExpansionState::key(&current_scope), kw.clone());
                if !state.seen.insert(key) {
                    out.push_str(&format!(
                        "# rexec: duplicate {kw} ignored (ssh keeps the first value)\n"
                    ));
                    continue;
                }
            }
            out.push_str(line);
            out.push('\n');
        }
    }
    stack.pop();
    Ok(())
}

/// Expand one Include argument (already tilde-expanded and anchored): glob it,
/// skip directories and dotfiles (OpenSSH's glob(3) does not match leading
/// dots), recurse into each matched file. A glob with no match is a silent
/// no-op (OpenSSH behavior).
fn expand_include_target(
    target: &Path,
    root_dir: &Path,
    out: &mut String,
    stack: &mut Vec<PathBuf>,
    scope: Scope,
    state: &mut ExpansionState,
) -> Result<()> {
    let pattern = target.to_string_lossy();
    let options = glob::MatchOptions {
        require_literal_leading_dot: true,
        ..Default::default()
    };
    let paths = match glob::glob_with(pattern.as_ref(), options) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("⚠ ssh config: invalid Include pattern {pattern}: {e}");
            return Ok(());
        }
    };
    for entry in paths.flatten() {
        // Directories matched by the glob are skipped, not fatal (OpenSSH
        // reads them as empty configs). This also skips dangling symlinks
        // (metadata follows the link, ENOENT → not a file).
        let is_file = std::fs::metadata(&entry)
            .map(|m| m.is_file())
            .unwrap_or(false);
        if !is_file {
            continue;
        }
        // OpenSSH restores the active scope after EVERY matched file
        // (readconf.c: "don't let Match in includes clobber the containing
        // file's Match state"). Textually: start each file's block with the
        // enclosing scope line, so a file ending inside its own `Host` block
        // cannot capture the next file's global directives.
        out.push_str(scope.restore_line());
        out.push('\n');
        expand_config_file(&entry, root_dir, out, stack, scope.clone(), state)?;
    }
    Ok(())
}

/// True if `line` opens a `Host` block (case-insensitive keyword, whitespace
/// or `=` after it).
fn is_host_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    let kw_end = trimmed
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(trimmed.len());
    trimmed[..kw_end].eq_ignore_ascii_case("host")
}

/// If `line` is an `Include` directive (`Include paths...`, fully
/// case-insensitive keyword, `=` with optional surrounding whitespace
/// allowed, args may be single- or double-quoted to carry spaces), return
/// the parsed path arguments.
fn include_args(line: &str) -> Option<Vec<String>> {
    let trimmed = line.trim();
    let kw_end = trimmed
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(trimmed.len());
    if !trimmed[..kw_end].eq_ignore_ascii_case("include") {
        return None; // any other keyword — including lookalikes (IncludeX)
    }
    let rest = trimmed[kw_end..].trim_start();
    let rest = rest
        .strip_prefix('=')
        .map(|r| r.trim_start())
        .unwrap_or(rest);
    // Tokenize like OpenSSH's argv_split (misc.c): quotes carry spaces and
    // ADJACENT quoted/unquoted fragments join into one token
    // (`"dir/"*.conf` is a single arg); an unquoted `#` starting a token ends
    // the argument list (comment). Returns Some(vec![]) for a bare/malformed
    // keyword line: the line is consumed (dropped) rather than passed through
    // to the crate's own CWD-relative Include handling.
    let mut args: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut started = false; // current token has content (possibly just quotes)
    'chars: for ch in rest.chars() {
        match quote {
            Some(q) if ch == q => quote = None, // fragment continues; do not split
            Some(_) => {
                cur.push(ch);
                started = true;
            }
            None => match ch {
                '\'' | '"' => {
                    quote = Some(ch);
                    started = true;
                }
                '#' if !started => break 'chars, // comment: stop parsing args
                c if c.is_whitespace() => {
                    if started {
                        args.push(std::mem::take(&mut cur));
                        started = false;
                    }
                }
                _ => {
                    cur.push(ch);
                    started = true;
                }
            },
        }
    }
    if started {
        args.push(cur);
    }
    Some(args)
}

/// Expand a leading `~` or `~/` to the user's home directory.
fn expand_tilde_path(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    } else if p == "~"
        && let Some(home) = dirs::home_dir()
    {
        return home;
    }
    PathBuf::from(p)
}

/// Path to the local OpenSSH user config.
fn ssh_config_path() -> Result<PathBuf> {
    Ok(dirs::home_dir()
        .context("cannot determine home directory")?
        .join(".ssh/config"))
}

/// Parse `~/.ssh/config` with `Include` directives expanded.
///
/// Shared by `list_hosts` (whose output is unchanged) and by alias resolution,
/// so both see exactly the same set of hosts.
fn load_user_ssh_config() -> Result<(PathBuf, SshConfig)> {
    let path = ssh_config_path()?;
    if !path.exists() {
        return Err(anyhow!("~/.ssh/config not found at {}", path.display()));
    }
    let config_str = load_ssh_config_text(&path)?;
    let mut reader = BufReader::new(config_str.as_bytes());
    // ALLOW_UNSUPPORTED_FIELDS is what keeps `ProxyJump`/`ProxyCommand` visible:
    // the crate eats `UnsupportedField` errors silently unless this rule is set
    // (parser.rs), and those two directives decide which socket ssh would open.
    let config = SshConfig::default()
        .parse(
            &mut reader,
            ParseRule::ALLOW_UNKNOWN_FIELDS | ParseRule::ALLOW_UNSUPPORTED_FIELDS,
        )
        .context("parsing ssh config (after Include expansion)")?;
    Ok((path, config))
}

/// ssh-config directives that would change *which socket* ssh opens, but that
/// this client does not implement.
///
/// `ssh2_config` records them in `HostParams::unsupported_fields` and then drops
/// them. `ProxyJump` is now implemented (see `resolve_jump_chain`); what remains
/// here is `ProxyCommand` — a shell command we cannot honestly emulate, so the
/// run must at least say that it is connecting directly instead.
///
/// Returned as sorted `directive=value` strings for a stable trace/warning.
fn unimplemented_routing(params: &ssh2_config::HostParams) -> Vec<String> {
    const ROUTING: [&str; 1] = ["proxycommand"];
    // A `ProxyCommand` we can actually honor (one of the SOCKS5 shapes) is not
    // unimplemented, so it must not be warned about.
    let socks5_honored = proxy_command_socks5(params).is_some();
    let mut hits: Vec<String> = params
        .unsupported_fields
        .iter()
        .filter(|(k, _)| ROUTING.contains(&k.to_ascii_lowercase().as_str()))
        .filter(|(k, _)| !(socks5_honored && k.eq_ignore_ascii_case("proxycommand")))
        .map(|(k, v)| format!("{k}={}", v.join(" ")))
        .collect();
    hits.sort();
    hits
}

/// Warn (trace + stderr) about every unimplemented routing directive, naming the
/// address we are about to connect to instead. Warnings are not suppressed by
/// `-q`: a wrong destination is not a progress detail.
///
/// `route` is `directly` or the `ProxyJump` label, so the warning never claims a
/// direct connection while a jump chain is actually in use.
fn warn_unimplemented_routing(
    params: &ssh2_config::HostParams,
    shown_host: &str,
    target: &str,
    route: &str,
    trace: &mut diagnostics::Trace,
) {
    for hit in unimplemented_routing(params) {
        trace.add(format!("resolve: {hit} not implemented → via {route}"));
        // The most common unsupported ProxyCommand is a jump host in disguise
        // (`ssh -W %h:%p hop`). Point at the directive that *is* implemented
        // instead of leaving the reader to translate it.
        let hint = if hit.starts_with("proxycommand=ssh") && hit.contains(" -W ") {
            " — that looks like a jump host: `ProxyJump <hop>` in the config is implemented"
        } else {
            ""
        };
        eprintln!(
            "⚠ ssh config: {hit} for {shown_host} is not implemented; connecting {route} to {target}{hint}"
        );
    }
}

/// A host may set both `ProxyJump` and a SOCKS5 `ProxyCommand`. OpenSSH uses
/// whichever line comes FIRST in the file (verified against `ssh -G`/`ssh -v`);
/// rexec cannot see that order — the config parser hands over a map — so it uses
/// ProxyJump, and says so once instead of quietly picking one.
fn warn_both_routing_directives(shown_host: &str, trace: &mut diagnostics::Trace) {
    trace.add(format!(
        "resolve: {shown_host} sets both ProxyJump and a SOCKS5 ProxyCommand; using ProxyJump"
    ));
    eprintln!(
        "⚠ ssh config: {shown_host} sets both ProxyJump and a SOCKS5 ProxyCommand; rexec uses \
         ProxyJump (ssh uses whichever line comes first) — pass --socks5 to force the proxy"
    );
}

/// `directly` for a direct connection, otherwise the route label — the phrase
/// used in routing warnings. A SOCKS5 proxy counts as routing: the connection
/// does not leave this process straight for the target.
fn route_phrase(remote: &RemoteHost) -> String {
    if remote.jump.is_empty() && remote.socks5.is_none() {
        "directly".to_string()
    } else {
        jump_chain_label(remote)
    }
}

/// The SOCKS5 proxy an ssh-config `ProxyCommand` points at, when it is one of
/// the shapes that unambiguously mean "dial this SOCKS5 proxy and CONNECT
/// through it".
///
/// Only a strict allowlist is accepted — anything else keeps the
/// "not implemented" warning instead of guessing at shell semantics:
///
/// ```text
/// nc -X 5 -x HOST[:PORT] %h %p      nc -x HOST[:PORT] %h %p
/// netcat -X 5 -x HOST[:PORT] %h %p  ncat --proxy HOST[:PORT] --proxy-type socks5 %h %p
/// connect [-5] -S HOST[:PORT] %h %p
/// ```
///
/// The port defaults to 1080 where the tool does. Rejected on purpose:
/// `-X 4`/SOCKS4, `-X connect`/`-H`/`--proxy` without `--proxy-type socks5`
/// (HTTP CONNECT), `ssh -W %h:%p jump` (that is a jump host — `ProxyJump`
/// covers it), and `socat` (its SOCKS5 address grammar differs between versions
/// and sources, so a wrong guess would silently dial the wrong endpoint).
fn proxy_command_socks5(params: &ssh2_config::HostParams) -> Option<String> {
    let args: Vec<String> = params
        .unsupported_fields
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("proxycommand"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    socks5_from_proxy_command(&args)
}

/// The pure form of [`proxy_command_socks5`]: recognize a tokenized
/// `ProxyCommand` (the crate hands over argv-split tokens, quotes already
/// resolved).
fn socks5_from_proxy_command(args: &[String]) -> Option<String> {
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let (cmd, rest) = argv.split_first()?;
    // `ProxyCommand /usr/bin/nc …` is just as common as a bare `nc`.
    let cmd = cmd.rsplit('/').next().unwrap_or(cmd);
    // `nc -x`/`connect -S` default to the conventional SOCKS port when the
    // config leaves it out (verified against OpenBSD nc: `-x 127.0.0.1` dials
    // 127.0.0.1:1080).
    let normalize = |s: &str| -> Option<String> {
        let parsed = parse_user_host_port(s).ok()?;
        if parsed.hostname.is_empty() {
            return None;
        }
        // Keep IPv6 literals bracketed: `fe80::1:1080` would otherwise parse
        // back as an address with no port at all.
        let host = if parsed.hostname.contains(':') {
            format!("[{}]", parsed.hostname)
        } else {
            parsed.hostname.clone()
        };
        Some(format!("{host}:{}", parsed.port.unwrap_or(1080)))
    };

    // Every other supported shape ends with the destination placeholders.
    let (tail_host, tail_port) = (rest.get(rest.len().checked_sub(2)?)?, rest.last()?);
    if *tail_host != "%h" || *tail_port != "%p" {
        return None;
    }
    let flags = &rest[..rest.len() - 2];

    match cmd {
        "nc" | "netcat" | "ncat" => {
            let mut proxy: Option<&str> = None;
            let mut socks = false;
            let mut i = 0;
            while i < flags.len() {
                match flags[i] {
                    // `-x HOST:PORT` (both nc and ncat).
                    "-x" => {
                        proxy = Some(*flags.get(i + 1)?);
                        i += 2;
                    }
                    // `-X 5` = SOCKS5; `-X 4`/`connect` are not supported.
                    "-X" => {
                        if *flags.get(i + 1)? != "5" {
                            return None;
                        }
                        socks = true;
                        i += 2;
                    }
                    // ncat uses long options.
                    "--proxy" => {
                        proxy = Some(*flags.get(i + 1)?);
                        i += 2;
                    }
                    "--proxy-type" => {
                        if !flags.get(i + 1)?.eq_ignore_ascii_case("socks5") {
                            return None;
                        }
                        socks = true;
                        i += 2;
                    }
                    // Benign flags that take no value.
                    "-q" | "-v" | "-n" => i += 1,
                    // `-w N` takes a value; skip both tokens.
                    "-w" => i += 2,
                    _ => return None,
                }
            }
            let proxy = proxy?;
            // `nc -x` defaults to SOCKS5, `ncat --proxy` needs the explicit type
            // (ncat's default is an HTTP proxy).
            if cmd == "ncat" && !socks {
                return None;
            }
            normalize(proxy)
        }
        "connect" | "connect-proxy" => {
            // `connect [-5] -S HOST[:PORT] %h %p` (-S = SOCKS, default SOCKS5).
            // `-H` is an HTTP proxy there, so it must not match.
            let mut proxy: Option<&str> = None;
            let mut i = 0;
            while i < flags.len() {
                match flags[i] {
                    "-S" => {
                        proxy = Some(*flags.get(i + 1)?);
                        i += 2;
                    }
                    "-5" => i += 1,
                    "-q" | "-v" => i += 1,
                    _ => return None,
                }
            }
            normalize(proxy?)
        }
        _ => None,
    }
}

/// How deep a `ProxyJump` chain may nest before we call it a cycle.
const MAX_JUMP_DEPTH: usize = 16;

/// The `ProxyJump` chain a host asks for, in connection order.
///
/// OpenSSH takes one value that may itself be a comma-separated chain, each
/// element a bare alias/host, `user@host`, `host:port` or `[v6]:port`. A value
/// that is exactly `none` disables jumping; inside a list, `none` is an ordinary
/// host name (`ssh -J none,js4` chains through a host literally called `none`).
/// Note that a later `ProxyJump none` never overrides an earlier block's jump:
/// like `ssh`, first-obtained-wins applies across blocks.
fn proxy_jump_specs(params: &ssh2_config::HostParams) -> Vec<String> {
    let value = params
        .unsupported_fields
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("proxyjump"))
        .map(|(_, v)| v.join(" "))
        .unwrap_or_default();
    let parts: Vec<String> = value
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect();
    if parts.len() == 1 && parts[0].eq_ignore_ascii_case("none") {
        return Vec::new();
    }
    parts
}

/// Split one `ProxyJump` element into `(user, host, port)`.
///
/// `ssh -J` accepts `[user@]host[:port]`, and a name that matches a config alias
/// still gets that alias's block for everything the spec does not state. The
/// host part alone is what decides whether the element is an alias.
fn split_jump_spec(spec: &str) -> (Option<String>, String, Option<u16>) {
    let (user, rest) = match spec.split_once('@') {
        Some((u, r)) => (Some(u.to_string()), r),
        None => (None, spec),
    };
    match parse_user_host_port(rest) {
        Ok(h) => (user, h.hostname, h.port),
        // Unparseable tail (e.g. a stray '['): keep it verbatim so the failure
        // names what the user actually wrote.
        Err(_) => (user, rest.to_string(), None),
    }
}

/// Resolve a `ProxyJump` chain into concrete hops, outermost first (the order
/// they must be connected in), together with the **original spec strings** in the
/// same order.
///
/// A jump host that is a config alias is resolved through the config — including
/// its own `ProxyJump`, hence the recursion — while anything else is taken as a
/// literal `[user@]host[:port]`, which is what `ssh -J` does with a name that
/// has no config entry. An explicit `user@`/`:port` in the spec overrides the
/// alias's own block, exactly like `ssh -J user@alias:port`.
///
/// The depth cap turns a config cycle (`A` jumps to `B`, `B` jumps back to `A`)
/// into an error instead of a hang.
///
/// The specs are kept because `rsync` shells out to a real `ssh`: handing it the
/// alias lets that ssh apply the hop's own config block (User/Port/IdentityFile),
/// which a resolved `user@<HostName>` may not match (few configs key a block on
/// the address behind the alias).
fn resolve_jump_chain(
    params: &ssh2_config::HostParams,
    config: &SshConfig,
    depth: usize,
) -> Result<(Vec<RemoteHost>, Vec<String>)> {
    let specs = proxy_jump_specs(params);
    if specs.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    if depth >= MAX_JUMP_DEPTH {
        return Err(anyhow!(
            "ssh config ProxyJump chain is deeper than {MAX_JUMP_DEPTH} hops (cycle?)"
        ));
    }
    let mut chain = Vec::new();
    let mut chain_specs = Vec::new();
    for (idx, spec) in specs.into_iter().enumerate() {
        let (spec_user, spec_host, spec_port) = split_jump_spec(&spec);
        // Always merge the matching config — including a bare `Host *` block and
        // a block keyed by the literal address, which is what `ssh -J host`
        // reads too. Inline parts of the spec win over the block.
        let hop_params = config.query(&spec_host);
        let hop = RemoteHost {
            hostname: hop_params
                .host_name
                .clone()
                .unwrap_or_else(|| spec_host.clone()),
            port: spec_port.or(hop_params.port),
            user: spec_user.clone().or_else(|| hop_params.user.clone()),
            identity_file: hop_params
                .identity_file
                .as_ref()
                .and_then(|v| v.first().cloned()),
            jump: Vec::new(),
            jump_specs: Vec::new(),
            alias: is_defined_alias(config, &spec_host).then(|| spec_host.clone()),
            // Only the first TCP leg can go through a SOCKS5 proxy: every later
            // hop rides a direct-tcpip channel opened on the previous session.
            socks5: if idx == 0 {
                explicit_socks5().or_else(|| proxy_command_socks5(&hop_params))
            } else {
                None
            },
        };
        // A hop may itself route somewhere we cannot go (`ProxyCommand`); say so
        // per hop — a bare timeout on hop 2 would name the wrong culprit
        // otherwise. No trace object here: these warnings always print, and the
        // run's trace is written by the caller.
        for hit in unimplemented_routing(&hop_params) {
            eprintln!(
                "⚠ ssh config: {hit} for jump host {spec_host} is not implemented; \
                 connecting directly to {}:{}",
                hop.hostname,
                hop.port.unwrap_or(22)
            );
        }
        // A hop that is itself an alias may chain further (nebula99 → lyg2004 →
        // js4); a literal hop has no further config to follow.
        if is_defined_alias(config, &spec_host) {
            let (nested, nested_specs) = resolve_jump_chain(&hop_params, config, depth + 1)?;
            chain.extend(nested);
            chain_specs.extend(nested_specs);
        }
        chain.push(hop);
        chain_specs.push(spec);
    }
    Ok((chain, chain_specs))
}

/// The `-J` argument for a real `ssh`: the original jump specs, in order.
///
/// Falls back to the resolved hops when no specs were recorded (a `RemoteHost`
/// built by hand, as tests do), so the argument is never silently dropped.
fn jump_j_arg(remote: &RemoteHost) -> Option<String> {
    if remote.jump.is_empty() {
        return None;
    }
    let specs: Vec<String> = if remote.jump_specs.len() == remote.jump.len() {
        remote.jump_specs.clone()
    } else {
        remote
            .jump
            .iter()
            .map(|h| {
                let addr = match h.port {
                    Some(p) => format!("{}:{p}", h.hostname),
                    None => h.hostname.clone(),
                };
                match &h.user {
                    Some(u) => format!("{u}@{addr}"),
                    None => addr,
                }
            })
            .collect()
    };
    // rsync splits `-e` on whitespace, so a spec that contains any would push
    // extra tokens into the ssh it spawns (the token after `-J a` would become
    // ssh's destination). Refuse the argument instead of building it wrong.
    if let Some(bad) = specs
        .iter()
        .find(|s| s.chars().any(char::is_whitespace))
        .cloned()
    {
        eprintln!(
            "⚠ ssh config: ProxyJump entry {bad:?} contains whitespace; \
             not passing a -J chain to rsync (sync will not use the jump host)"
        );
        return None;
    }
    Some(specs.join(","))
}

/// `a → b → c` label for a jump chain, or `direct` when there is none.
fn jump_chain_label(remote: &RemoteHost) -> String {
    // A SOCKS5 proxy is part of the route, not a detail: "direct" would be a
    // lie and a warning that said "connecting directly" would send the reader
    // looking for a firewall problem.
    let proxy = if remote.jump.is_empty() {
        remote.socks5.clone()
    } else {
        remote.jump[0].socks5.clone()
    };
    let mut legs: Vec<String> = Vec::new();
    if let Some(p) = proxy {
        legs.push(format!("socks5 {p}"));
    }
    legs.extend(remote.jump.iter().map(|h| {
        let port = h.port.unwrap_or(22);
        format!("{}:{port}", h.hostname)
    }));
    if legs.is_empty() {
        return "direct".to_string();
    }
    format!("via {}", legs.join(" → "))
}

/// Local user name, used the way `ssh` and `list` do when no `User` is
/// configured for the host.
fn default_user() -> String {
    std::env::var("USER").unwrap_or_else(|_| "root".to_string())
}

/// `user@host:port` as the decision trace and the `--json` summary report it.
fn resolved_label(remote: &RemoteHost) -> String {
    format!(
        "{}@{}:{}",
        remote.user.clone().unwrap_or_else(default_user),
        remote.hostname,
        remote.port.unwrap_or(22)
    )
}

/// True when `name` can only be a literal target, never an ssh-config alias.
///
/// Literal shapes: `user@host[:port]` (explicit user), `[IPv6][:port]`, and
/// IP/FQDN shapes — a leading digit (`10.0.0.5`) or a dot
/// (`host.example.com`). Anything else must resolve in ~/.ssh/config: the old
/// silent fallback (treat the name as a raw hostname) turned every alias typo
/// into a DNS failure or a connect timeout against a host that does not exist.
fn is_literal_host(name: &str) -> bool {
    name.contains('@')
        || name.starts_with('[')
        || name.starts_with(|c: char| c.is_ascii_digit())
        || name.contains('.')
}

/// True when a concrete (`Host` line) clause in the config matches `name` —
/// either a defined alias or a name covered by a wildcard block (`Host web*`).
fn is_defined_alias(config: &SshConfig, name: &str) -> bool {
    config.get_hosts().iter().any(|host| {
        host.pattern
            .iter()
            .any(|c| !c.negated && c.pattern != "*" && c.intersects(name))
    })
}

/// Concrete aliases defined in the config — wildcards, negations and the
/// global `Host *` block excluded, deduplicated. This is the inventory the
/// alias-miss error suggests from.
fn defined_aliases(config: &SshConfig) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for host in config.get_hosts() {
        for clause in &host.pattern {
            if clause.negated || clause.pattern == "*" {
                continue;
            }
            out.push(clause.pattern.clone());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Up to `max` configured aliases closest to `name`: prefix matches (either
/// direction) rank above substring matches, then alphabetically. Deliberately
/// simple — this is a nudge after a typo, not fuzzy matching.
fn suggest_aliases(name: &str, aliases: &[String], max: usize) -> Vec<String> {
    let needle = name.to_ascii_lowercase();
    if needle.is_empty() {
        return Vec::new();
    }
    let mut scored: Vec<(u8, &String)> = Vec::new();
    for alias in aliases {
        let lower = alias.to_ascii_lowercase();
        // Wildcard blocks are not something the user can retype as a target.
        if lower.is_empty() || lower.contains('*') || lower.contains('?') || lower.starts_with('!')
        {
            continue;
        }
        let score = if lower.starts_with(&needle) || needle.starts_with(&lower) {
            0
        } else if lower.contains(&needle) || needle.contains(&lower) {
            1
        } else {
            continue;
        };
        scored.push((score, alias));
    }
    scored.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
    scored
        .into_iter()
        .take(max)
        .map(|(_, alias)| alias.clone())
        .collect()
}

/// Error for a name that neither looks like a literal host nor resolves in
/// `~/.ssh/config`.
fn alias_miss_error(name: &str, aliases: &[String], config: &Path) -> anyhow::Error {
    let mut msg = format!("host '{}' is not defined in {}", name, config.display());
    let suggestions = suggest_aliases(name, aliases, 3);
    if !suggestions.is_empty() {
        msg.push_str(&format!("\n  did you mean: {}", suggestions.join(", ")));
    }
    msg.push_str(
        "\n  hint: use user@host for a literal host (e.g. root@10.0.0.5), or -p PORT \
         to override the port (alias:port is not supported); `rexec list` shows configured aliases",
    );
    anyhow!(msg)
}

/// Resolve a host argument to a concrete target, recording every decision in
/// `trace`.
///
/// Literal shapes are parsed as-is; every other name MUST resolve in
/// `~/.ssh/config` (Include-expanded). An unknown name is an error — never the
/// old silent fallback to a raw hostname.
fn resolve_host(
    host: &str,
    port_override: Option<u16>,
    trace: &mut diagnostics::Trace,
) -> Result<RemoteHost> {
    // A bare IPv6 literal (`fe80::1`) must be parsed by the std parser: the
    // generic `host:port` split would read `fe80:` + port 1.
    let bare_v6 = (!host.contains('@') && !host.contains('['))
        .then(|| host.parse::<std::net::Ipv6Addr>().ok())
        .flatten();
    let literal = bare_v6.is_some() || is_literal_host(host);
    // Where the port came from, for the `-p` trace line: an inline `host:port`
    // must be distinguishable from a port inherited out of ssh-config (a
    // literal target can inherit one from a `Host *` block).
    let mut port_from_input = false;
    let mut remote = if literal {
        let mut parsed = match bare_v6 {
            Some(v6) => RemoteHost {
                hostname: v6.to_string(),
                port: None,
                user: None,
                identity_file: None,
                jump: Vec::new(),
                jump_specs: Vec::new(),
                alias: None,
                socks5: None,
            },
            None => parse_user_host_port(host)?,
        };
        port_from_input = parsed.port.is_some();
        // A literal target still inherits config params — the global `Host *`
        // block (Port/User/IdentityFile) and any block matching the literal
        // (`Host *.example.com`, `Host prod.example.com`). This is what `ssh`
        // does and what the pre-transparency resolution did for every bare
        // name; dropping it silently changed which port/user/key a raw target
        // used. Inline parts of the input (an explicit `user@host`, a
        // `host:port` port) win over config, and `user@host` never consulted
        // config before, so it still does not. Config problems are ignored on
        // this path: a literal target must keep working without one.
        if !host.contains('@')
            && let Ok((_, config)) = load_user_ssh_config()
        {
            let params = config.query(&parsed.hostname);
            parsed.hostname = params
                .host_name
                .clone()
                .unwrap_or_else(|| parsed.hostname.clone());
            if parsed.user.is_none() {
                parsed.user = params.user.clone();
            }
            if parsed.port.is_none() {
                parsed.port = params.port;
            }
            parsed.identity_file = params
                .identity_file
                .as_ref()
                .and_then(|v| v.first().cloned());
            // A literal target inherits `ProxyJump` from a matching block the
            // same way `ssh 10.0.0.5` does (e.g. `Host *.example.com` with a
            // jump host). A config problem must not break the literal path.
            match resolve_jump_chain(&params, &config, 0) {
                Ok((jump, jump_specs)) => {
                    parsed.jump = jump;
                    parsed.jump_specs = jump_specs;
                    // Without a jump chain this host *is* the first TCP leg, so
                    // the proxy (explicit, else its own ProxyCommand) applies
                    // here. With a chain, hop 1 already carries it — ssh gives
                    // ProxyJump precedence over the target's ProxyCommand.
                    parsed.socks5 = if parsed.jump.is_empty() {
                        explicit_socks5().or_else(|| proxy_command_socks5(&params))
                    } else {
                        if proxy_command_socks5(&params).is_some() {
                            warn_both_routing_directives(&parsed.hostname, trace);
                        }
                        None
                    };
                }
                // A config problem must not break a literal target, but it must
                // not disappear either: a broken `ProxyJump` silently turning
                // into a direct connection is exactly the failure mode this
                // whole path exists to end.
                Err(e) => {
                    trace.add(format!(
                        "resolve: ProxyJump for {} ignored: {e:#}",
                        parsed.hostname
                    ));
                    eprintln!(
                        "⚠ ssh config: ProxyJump for {} could not be resolved ({e}); \
                         connecting directly",
                        parsed.hostname
                    );
                }
            }
            warn_unimplemented_routing(
                &params,
                &parsed.hostname,
                &resolved_label(&parsed),
                &route_phrase(&parsed),
                trace,
            );
        }
        trace.add(format!("resolve: literal {}", resolved_label(&parsed)));
        parsed
    } else {
        let path = ssh_config_path()?;
        if !path.exists() {
            return Err(alias_miss_error(host, &[], &path));
        }
        let config = load_user_ssh_config()?.1;
        if !is_defined_alias(&config, host) {
            return Err(alias_miss_error(host, &defined_aliases(&config), &path));
        }
        let host_config = config.query(host);
        let (jump, jump_specs) = resolve_jump_chain(&host_config, &config, 0)?;
        let target_socks5 = if jump.is_empty() {
            explicit_socks5().or_else(|| proxy_command_socks5(&host_config))
        } else {
            if proxy_command_socks5(&host_config).is_some() {
                warn_both_routing_directives(host, trace);
            }
            None
        };
        let resolved = RemoteHost {
            hostname: host_config
                .host_name
                .clone()
                .unwrap_or_else(|| host.to_string()),
            port: host_config.port,
            user: host_config.user.clone(),
            identity_file: host_config
                .identity_file
                .as_ref()
                .and_then(|v| v.first().cloned()),
            jump,
            jump_specs,
            alias: Some(host.to_string()),
            socks5: target_socks5,
        };
        let key = resolved
            .identity_file
            .as_ref()
            .map(|p| format!(" (key {})", p.display()))
            .unwrap_or_default();
        warn_unimplemented_routing(
            &host_config,
            host,
            &resolved_label(&resolved),
            &route_phrase(&resolved),
            trace,
        );
        trace.add(format!(
            "resolve: alias {} → {}{}",
            host,
            resolved_label(&resolved),
            key
        ));
        resolved
    };

    // --port overrides host:port and ssh-config Port — record which value it
    // replaced, so a surprising -p is visible in the trace. The source is
    // decided by provenance, not by shape: a literal target can inherit its
    // port from ssh-config (`Host * Port`), which must not be reported as an
    // inline `host:port`.
    if let Some(p) = port_override {
        let source = match (remote.port, port_from_input) {
            (Some(old), true) => format!("from host:port {old}"),
            (Some(old), false) => format!("from ssh-config {old}"),
            (None, _) => "no port configured (default 22)".to_string(),
        };
        remote.port = Some(p);
        trace.add(format!("-p override: {p} ({source})"));
    }
    Ok(remote)
}

fn parse_user_host_port(s: &str) -> Result<RemoteHost> {
    let (user, rest) = if let Some((u, r)) = s.split_once('@') {
        (Some(u.to_string()), r)
    } else {
        (None, s)
    };

    // Three shapes, in order: `[v6]` / `[v6]:port` (brackets are REQUIRED around
    // a literal v6 that carries a port), a bare v6 address (no port syntax is
    // possible), then the classic `host[:port]`. Splitting on the last ':' for
    // everything would read `fe80::1` as host `fe80:` + port 1 and would leave
    // the brackets of `[fe80::1]` inside the hostname.
    let (hostname, port) = if let Some(inner) = rest.strip_prefix('[') {
        let (host, tail) = inner
            .split_once(']')
            .ok_or_else(|| anyhow!("unclosed '[' in host {rest:?} — write [addr]:port"))?;
        let port = match tail {
            "" => None,
            _ => Some(
                tail.strip_prefix(':')
                    .ok_or_else(|| anyhow!("unexpected {tail:?} after ']' in host {rest:?}"))?
                    .parse::<u16>()?,
            ),
        };
        (host.to_string(), port)
    } else if let Ok(v6) = rest.parse::<std::net::Ipv6Addr>() {
        (v6.to_string(), None)
    } else if let Some((h, p)) = rest.rsplit_once(':') {
        (h.to_string(), Some(p.parse::<u16>()?))
    } else {
        (rest.to_string(), None)
    };

    Ok(RemoteHost {
        hostname,
        port,
        user,
        identity_file: None,
        jump: Vec::new(),
        jump_specs: Vec::new(),
        alias: None,
        socks5: None,
    })
}

/// Build the user-facing error for a failed rsync spawn.
///
/// Windows has no bundled rsync, so `--sync` depends on a separately installed
/// MSYS2 or WSL one; a bare "program not found" leaves the user with no way
/// forward. Only that case gets an install hint — every other failure (and
/// every unix failure) keeps the original `failed to spawn rsync` context.
fn rsync_spawn_error(e: std::io::Error) -> anyhow::Error {
    #[cfg(windows)]
    if e.kind() == std::io::ErrorKind::NotFound {
        return anyhow!(
            "rsync not found — install it via MSYS2 (pacman -S rsync) or use WSL; \
             --sync is unavailable without it"
        );
    }
    anyhow::Error::new(e).context("failed to spawn rsync")
}

/// What `rsync` is told about the destination: `(host argument, extra ssh flags)`.
///
/// rsync spawns a real `ssh`, and that ssh must apply the *host's* config — its
/// IdentityFile list, Port and ProxyJump. So a config alias is handed over
/// as-is; only a literal target needs the resolved address plus an explicit `-J`
/// chain. (ssh matches `Host` blocks by the hostname it is given: a resolved
/// `user@<HostName>` matches no block keyed on the alias — at best `Host *` —
/// which is how rsync got the wrong key before this.)
fn rsync_endpoint(remote: &RemoteHost) -> (String, String) {
    match &remote.alias {
        Some(alias) => (alias.clone(), String::new()),
        None => {
            let host = match &remote.user {
                Some(u) => format!("{}@{}", u, remote.hostname),
                None => remote.hostname.clone(),
            };
            let jump = match jump_j_arg(remote) {
                Some(specs) => format!(" -J {specs}"),
                None => String::new(),
            };
            (host, jump)
        }
    }
}

/// The `ssh` command rsync runs (`-e`): the port of the resolved target plus,
/// for a literal target, the explicit `-J` chain from `rsync_endpoint`.
fn sync_ssh_e(remote: &RemoteHost) -> String {
    const SSH_OPTS: &str = "-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=5 -o ServerAliveCountMax=3";
    let (_, jump_arg) = rsync_endpoint(remote);
    match remote.port {
        Some(p) => format!("ssh -p {p} {SSH_OPTS}{jump_arg}"),
        None => format!("ssh {SSH_OPTS}{jump_arg}"),
    }
}

async fn do_sync(local: &Path, remote_path: &str, remote: &RemoteHost) -> Result<()> {
    let (rsync_host, _) = rsync_endpoint(remote);
    let ssh_e = sync_ssh_e(remote);

    // Single file: rsync the file directly (no --delete, no trailing-slash
    // rewriting). If `remote` ends with '/', rsync drops the file into that
    // remote directory; otherwise it writes to the given file path.
    if local.is_file() {
        let remote_target = format!("{}:{}", rsync_host, remote_path);
        let mut child = tokio::process::Command::new("rsync")
            .args([
                "-az",
                "-e",
                ssh_e.as_str(),
                &local.to_string_lossy(),
                &remote_target,
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .map_err(rsync_spawn_error)?;
        return wait_rsync(&mut child, local, &rsync_host, remote, remote_path).await;
    }

    if !local.is_dir() {
        return Err(anyhow!(
            "local sync path '{}' does not exist (expected a file or directory)",
            local.display()
        ));
    }

    // Directory: sync contents (trailing slash on both sides) with --delete.
    let local_str = local.to_string_lossy();
    let local_arg = if local_str.ends_with('/') {
        local_str.into_owned()
    } else {
        format!("{}/", local_str)
    };
    let remote_arg = if remote_path.ends_with('/') {
        remote_path.to_string()
    } else {
        format!("{}/", remote_path)
    };

    let mut child = tokio::process::Command::new("rsync")
        .args([
            "-az",
            "--delete",
            "-e",
            ssh_e.as_str(),
            &local_arg,
            &format!("{}:{}", rsync_host, remote_arg),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(rsync_spawn_error)?;

    wait_rsync(&mut child, local, &rsync_host, remote, &remote_arg).await
}

/// Wait for an rsync child process with a timeout, surfacing a manual-recovery
/// hint on timeout. `remote_path` is the remote-side path (no host prefix).
async fn wait_rsync(
    child: &mut tokio::process::Child,
    local: &Path,
    rsync_host: &str,
    remote: &RemoteHost,
    remote_path: &str,
) -> Result<()> {
    let timeout = Duration::from_secs(300);
    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => {
            if !status.success() {
                return Err(anyhow!("rsync failed with status {}", status));
            }
        }
        Ok(Err(e)) => {
            return Err(anyhow!("failed to wait for rsync: {}", e));
        }
        Err(_) => {
            let _ = child.kill().await;
            let port_hint = remote
                .port
                .map(|p| format!(" -p {}", p))
                .unwrap_or_default();
            return Err(anyhow!(
                "rsync timed out after {} seconds. \
                 Use `rsync -az -e 'ssh{}' {}:{}` manually to diagnose.",
                timeout.as_secs(),
                port_hint,
                rsync_host,
                remote_path
            ));
        }
    }
    progress!(
        "✓ Synced {} -> {}:{}",
        local.display(),
        rsync_host,
        remote_path
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `sh -c shell_quote(input)` reproduces the original input.
    /// This tests the full quoting round-trip through a real shell.
    /// Unix-only: spawns a local `sh`, which does not exist on Windows.
    #[cfg(unix)]
    fn assert_shell_roundtrip(input: &str) {
        let quoted = shell_quote(input).unwrap();
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("printf %s {}", quoted))
            .output()
            .expect("failed to run sh");
        let result = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            result, input,
            "shell_quote roundtrip failed for {:?}",
            input
        );
    }

    #[test]
    fn test_shell_quote_simple() {
        assert_eq!(shell_quote("hello").unwrap(), "'hello'");
    }

    #[test]
    fn test_shell_quote_empty() {
        assert_eq!(shell_quote("").unwrap(), "''");
    }

    #[test]
    #[cfg(unix)] // uses assert_shell_roundtrip (spawns sh)
    fn test_shell_quote_with_double_quotes() {
        // Double quotes inside single quotes are literal
        let quoted = shell_quote(r#"echo "hello world""#).unwrap();
        assert_eq!(quoted, r#"'echo "hello world"'"#);
        assert_shell_roundtrip(r#"echo "hello world""#);
    }

    #[test]
    #[cfg(unix)] // uses assert_shell_roundtrip (spawns sh)
    fn test_shell_quote_with_single_quotes() {
        // Single quotes must be escaped with the '"'"' trick
        let quoted = shell_quote("echo 'hello'").unwrap();
        assert_eq!(quoted, "'echo '\"'\"'hello'\"'\"''");
        assert_shell_roundtrip("echo 'hello'");
    }

    #[test]
    #[cfg(unix)] // uses assert_shell_roundtrip (spawns sh)
    fn test_shell_quote_with_special_chars() {
        // $, backticks, \, !, etc. should all be literal inside single quotes
        assert_shell_roundtrip("echo $HOME");
        assert_shell_roundtrip("echo `whoami`");
        assert_shell_roundtrip("echo $((1+2))");
        assert_shell_roundtrip("echo a; echo b");
        assert_shell_roundtrip("echo a | grep b");
        assert_shell_roundtrip("echo a && echo b");
        assert_shell_roundtrip("echo a > /tmp/test");
    }

    #[test]
    #[cfg(unix)] // uses assert_shell_roundtrip (spawns sh)
    fn test_shell_quote_mixed_quotes() {
        assert_shell_roundtrip(r#"echo "it's $HOME""#);
        assert_shell_roundtrip("echo 'single' && echo \"double\"");
    }

    #[test]
    #[cfg(unix)] // uses assert_shell_roundtrip (spawns sh)
    fn test_shell_quote_newline() {
        assert_shell_roundtrip("echo hello\necho world");
    }

    #[test]
    fn test_shell_quote_rejects_null_byte() {
        let result = shell_quote("echo hello\0; rm -rf /");
        assert!(result.is_err());
    }

    #[test]
    fn test_run_env_and_command_parsing() {
        // -e/--env flags parse before the trailing command; --env-file accepts a path.
        let cli = Cli::parse_from([
            "rexec", "h", "run", "-e", "A=b", "--env", "C=d", "--", "echo", "hi",
        ]);
        match cli.action {
            Action::Run {
                env,
                env_file,
                command,
                ..
            } => {
                assert_eq!(
                    env,
                    vec!["A=b".to_string(), "C=d".to_string()],
                    "env: {:?}",
                    env
                );
                assert!(env_file.is_empty());
                assert_eq!(
                    command,
                    vec!["echo".to_string(), "hi".to_string()],
                    "cmd: {:?}",
                    command
                );
            }
            _ => panic!("not Run"),
        }
    }

    /// Test the full quoting chain: command → shell_quote → sh -c → result.
    /// This simulates what happens when rexec passes a command to the remote worker.
    #[test]
    #[cfg(unix)] // spawns a local `sh`
    fn test_full_quoting_chain() {
        // The command the user types (after local shell processing)
        let commands = vec![
            "echo hello",
            "echo 'hello world'",
            r#"echo "hello world""#,
            "echo $HOME",
            "python -c 'print(42)'",
            "cd /tmp && ls -la",
            "echo 'it'\''s a test'",
        ];

        for cmd in commands {
            // Step 1: shell_quote the command (as done in run_command)
            let quoted = shell_quote(cmd).unwrap();

            // Step 2: simulate the remote `sh` parsing a quoted fragment.
            // Today the command travels over stdin (__REXEC_CMD__), but
            // script paths and args are still embedded quoted (run_script),
            // so the quote → remote-sh round-trip must be lossless.
            let worker_output = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("printf %s {}", quoted))
                .output()
                .expect("failed to run sh");
            let received = String::from_utf8(worker_output.stdout).unwrap();

            // Step 3: the remote shell must see the exact original fragment
            assert_eq!(
                received, cmd,
                "command corrupted through quoting chain: {:?} → {:?} → {:?}",
                cmd, quoted, received
            );
        }
    }

    #[test]
    fn test_ssh_config_include_expansion() {
        // Layout (root-anchored: every relative Include path resolves against
        // the TOP-LEVEL config dir, matching OpenSSH — not the including
        // file's dir, not the CWD; the test CWD is the crate root):
        //   tmp/ssh/config            → Host main + Include config.d/*.conf
        //   tmp/ssh/config.d/a.conf   → Host alias-a (Port 27001)
        //   tmp/ssh/config.d/b.conf   → nested iNcLuDe = extra.conf
        //   tmp/ssh/extra.conf        → Host alias-b
        // Plus a directory and a dotfile in config.d/ that the glob must not
        // blow up on (dirs are skipped, dotfiles are not matched).
        let base = std::env::temp_dir().join(format!("rexec-test-inc-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(ssh.join("config.d/subdir")).unwrap();
        std::fs::write(
            ssh.join("config"),
            "Host main\n  HostName 1.2.3.4\nInclude config.d/*.conf\n",
        )
        .unwrap();
        std::fs::write(
            ssh.join("config.d/a.conf"),
            "Host alias-a\n  HostName 5.6.7.8\n  Port 27001\n",
        )
        .unwrap();
        std::fs::write(ssh.join("config.d/b.conf"), "iNcLuDe = extra.conf\n").unwrap();
        std::fs::write(ssh.join("extra.conf"), "Host alias-b\n  HostName 9.9.9.9\n").unwrap();
        std::fs::write(
            ssh.join("config.d/.hidden.conf"),
            "Host hidden\n  HostName 3.3.3.3\n",
        )
        .unwrap();

        let text = load_ssh_config_text(&ssh.join("config")).unwrap();
        assert!(
            !text.lines().any(|l| include_args(l).is_some()),
            "Include lines must be expanded away: {text}"
        );
        assert!(
            text.contains("Host alias-a"),
            "included host missing: {text}"
        );
        assert!(text.contains("Port 27001"));
        assert!(
            text.contains("Host alias-b"),
            "nested include missing: {text}"
        );
        assert!(
            text.contains("Host main"),
            "including file content must survive"
        );
        assert!(!text.contains("hidden"), "dotfiles must not be globbed");

        // The expanded text must actually parse and resolve the included alias.
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
            .unwrap();
        assert_eq!(config.query("alias-a").port.unwrap(), 27001);
        assert_eq!(config.query("alias-a").host_name.unwrap(), "5.6.7.8");

        std::fs::remove_dir_all(&base).unwrap();
    }

    /// `ProxyJump` is implemented now, so it must NOT be reported as an
    /// unimplemented routing directive — but it must still be visible through
    /// `proxy_jump_specs`, which relies on the same crate field.
    #[test]
    fn test_proxy_jump_is_parsed_not_warned() {
        let text = "Host behind-jump\n  HostName 10.30.40.4\n  ProxyJump js4\n";

        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(
                &mut reader,
                ParseRule::ALLOW_UNKNOWN_FIELDS | ParseRule::ALLOW_UNSUPPORTED_FIELDS,
            )
            .unwrap();
        let params = config.query("behind-jump");
        assert_eq!(proxy_jump_specs(&params), vec!["js4".to_string()]);
        assert!(
            unimplemented_routing(&params).is_empty(),
            "ProxyJump is implemented; only ProxyCommand still warns"
        );

        // Without ALLOW_UNSUPPORTED_FIELDS the directive disappears entirely —
        // this is the silent-ignore trap both helpers exist to avoid.
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
            .unwrap();
        assert!(proxy_jump_specs(&config.query("behind-jump")).is_empty());
    }

    #[test]
    fn test_proxy_jump_specs_forms() {
        let parse = |text: &str, alias: &str| {
            let mut reader = std::io::BufReader::new(text.as_bytes());
            let config = SshConfig::default()
                .parse(
                    &mut reader,
                    ParseRule::ALLOW_UNKNOWN_FIELDS | ParseRule::ALLOW_UNSUPPORTED_FIELDS,
                )
                .unwrap();
            proxy_jump_specs(&config.query(alias))
        };
        // Comma chain, and each element keeps its own shape.
        assert_eq!(
            parse("Host a\n  ProxyJump one,two\n", "a"),
            vec!["one".to_string(), "two".to_string()]
        );
        assert_eq!(
            parse("Host a\n  ProxyJump root@jump.example:2222\n", "a"),
            vec!["root@jump.example:2222".to_string()]
        );
        // `none` disables jumping only as the whole value; inside a list it is an
        // ordinary host name, like `ssh -J none,js4`.
        assert!(parse("Host a\n  ProxyJump none\n", "a").is_empty());
        assert!(parse("Host a\n  ProxyJump NONE\n", "a").is_empty());
        assert_eq!(
            parse("Host a\n  ProxyJump none,js4\n", "a"),
            vec!["none".to_string(), "js4".to_string()]
        );
        assert!(parse("Host a\n  HostName 1.2.3.4\n", "a").is_empty());

        // A later `ProxyJump none` does NOT cancel an earlier block's jump:
        // first-obtained-wins, exactly like ssh.
        let mut reader = std::io::BufReader::new(
            "Host *\n  ProxyJump js4\nHost internal\n  ProxyJump none\n".as_bytes(),
        );
        let config = SshConfig::default()
            .parse(
                &mut reader,
                ParseRule::ALLOW_UNKNOWN_FIELDS | ParseRule::ALLOW_UNSUPPORTED_FIELDS,
            )
            .unwrap();
        assert_eq!(
            proxy_jump_specs(&config.query("internal")),
            vec!["js4".to_string()]
        );
    }

    /// `[user@]host[:port]` elements keep their config block, exactly like
    /// `ssh -J ops@alias:port`; a literal hop still inherits `Host *`.
    #[test]
    fn test_resolve_jump_chain_merges_spec_forms() {
        let text = "\
Host *\n  User deploy\n  Port 2222\n\
Host js4\n  HostName 192.168.4.70\n  Port 42200\n  User zengqixin\n  IdentityFile ~/.ssh/js4_key\n\
Host prod\n  ProxyJump ops@js4\n\
Host lit\n  ProxyJump 192.168.4.70\n\
Host dotted\n  ProxyJump jump.example.com:2222\n";
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(
                &mut reader,
                ParseRule::ALLOW_UNKNOWN_FIELDS | ParseRule::ALLOW_UNSUPPORTED_FIELDS,
            )
            .unwrap();

        // Inline `user@` wins over the block's User; the block supplies the
        // rest. Port stays `Host *`'s 2222 because `Host *` is parsed first and
        // OpenSSH is first-obtained-wins — verified against
        // `ssh -G -F <cfg> ops@js4` (user ops, hostname 192.168.4.70, port 2222,
        // identityfile .../js4_key).
        let (chain, _) = resolve_jump_chain(&config.query("prod"), &config, 0).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].hostname, "192.168.4.70");
        assert_eq!(chain[0].port, Some(2222));
        assert_eq!(
            chain[0].user.as_deref(),
            Some("ops"),
            "inline user@ wins over the block"
        );
        assert!(
            chain[0]
                .identity_file
                .as_deref()
                .is_some_and(|p| p.ends_with("js4_key")),
            "hop inherited the block's IdentityFile: {:?}",
            chain[0].identity_file
        );
        assert_eq!(chain[0].alias.as_deref(), Some("js4"));

        // A literal hop still gets `Host *` defaults (User/Port), so rexec and
        // the rsync hand-off connect the same way.
        let (chain, specs) = resolve_jump_chain(&config.query("lit"), &config, 0).unwrap();
        assert_eq!(chain[0].hostname, "192.168.4.70");
        assert_eq!(chain[0].port, Some(2222));
        assert_eq!(chain[0].user.as_deref(), Some("deploy"));
        assert_eq!(chain[0].alias, None);
        assert_eq!(specs, vec!["192.168.4.70".to_string()]);

        // A literal hop still gets `Host *` defaults; the inline port stays inline.
        let (chain, _) = resolve_jump_chain(&config.query("dotted"), &config, 0).unwrap();
        assert_eq!(chain[0].hostname, "jump.example.com");
        assert_eq!(chain[0].port, Some(2222));
        assert_eq!(chain[0].user.as_deref(), Some("deploy"));
        assert_eq!(chain[0].alias, None);

        assert_eq!(
            split_jump_spec("ops@[fe80::1]:2222"),
            (Some("ops".to_string()), "fe80::1".to_string(), Some(2222))
        );
    }

    /// `route_phrase` is what routing warnings print: it must never claim a
    /// direct connection while a jump chain is in use.
    #[test]
    fn test_route_phrase_never_claims_direct() {
        let mut remote = RemoteHost {
            hostname: "10.0.0.1".to_string(),
            port: Some(22),
            user: None,
            identity_file: None,
            jump: Vec::new(),
            jump_specs: Vec::new(),
            alias: None,
            socks5: None,
        };
        assert_eq!(route_phrase(&remote), "directly");
        remote.jump = vec![RemoteHost {
            hostname: "192.168.4.70".to_string(),
            port: Some(42200),
            user: None,
            identity_file: None,
            jump: Vec::new(),
            jump_specs: Vec::new(),
            alias: Some("js4".to_string()),
            socks5: None,
        }];
        assert_eq!(route_phrase(&remote), "via 192.168.4.70:42200");
    }

    /// Recognition of the `ProxyCommand` shapes that mean "SOCKS5 proxy here".
    /// Anything ambiguous must stay unrecognized (and keep its warning).
    #[test]
    fn test_socks5_from_proxy_command_shapes() {
        let args = |s: &str| s.split_whitespace().map(str::to_string).collect::<Vec<_>>();
        let yes = |s: &str| socks5_from_proxy_command(&args(s));
        let no = |s: &str| assert_eq!(socks5_from_proxy_command(&args(s)), None, "accepted: {s}");

        // Accepted, all spelling out the proxy address.
        assert_eq!(
            yes("nc -X 5 -x 127.0.0.1:1080 %h %p").as_deref(),
            Some("127.0.0.1:1080")
        );
        assert_eq!(
            yes("nc -x 127.0.0.1:1080 %h %p").as_deref(),
            Some("127.0.0.1:1080")
        );
        assert_eq!(
            yes("/usr/bin/nc -w 5 -x 127.0.0.1:1080 %h %p").as_deref(),
            Some("127.0.0.1:1080")
        );
        assert_eq!(
            yes("ncat --proxy 127.0.0.1:1080 --proxy-type socks5 %h %p").as_deref(),
            Some("127.0.0.1:1080")
        );
        assert_eq!(
            yes("connect -S 127.0.0.1:1080 %h %p").as_deref(),
            Some("127.0.0.1:1080")
        );
        // The conventional SOCKS port is assumed when the config omits it.
        assert_eq!(
            yes("nc -X 5 -x 127.0.0.1 %h %p").as_deref(),
            Some("127.0.0.1:1080")
        );
        assert_eq!(
            yes("ncat --proxy 127.0.0.1 --proxy-type socks5 %h %p").as_deref(),
            Some("127.0.0.1:1080")
        );
        assert_eq!(
            yes("connect -5 -S 127.0.0.1 %h %p").as_deref(),
            Some("127.0.0.1:1080")
        );
        assert_eq!(
            yes("nc -x [fe80::1]:1080 %h %p").as_deref(),
            Some("[fe80::1]:1080"),
            "IPv6 proxy addresses keep their brackets on the wire"
        );

        // Rejected: a jump host (ProxyJump covers it), SOCKS4/HTTP, wrong
        // arity, unknown flags, a proxy without a port.
        no("ssh -W %h:%p jump");
        no("nc -X 4 -x 127.0.0.1:1080 %h %p");
        no("nc -X connect -x 127.0.0.1:1080 %h %p");
        no("connect -4 -S 127.0.0.1:1080 %h %p");
        no("socat - SOCKS5:127.0.0.1:1080:%h:%p");
        no("nc -x 127.0.0.1:1080 %h");
        no("nc -x 127.0.0.1:1080");
        no("nc -x 127.0.0.1:1080 --weird %h %p");
        no("ncat --proxy 127.0.0.1:1080 %h %p");
        no("ncat --proxy 127.0.0.1:1080 --proxy-type http %h %p");
        no("socat - SOCKS4:127.0.0.1:1080:%h:%p");
        no("connect -H 127.0.0.1:8080 %h %p");
    }

    /// A config whose `ProxyCommand` is a SOCKS5 shape must be honored, not
    /// warned about; other shapes keep the warning.
    #[test]
    fn test_proxy_command_socks5_suppresses_the_warning() {
        let parse = |line: &str| {
            let text = format!("Host a\n  HostName 10.173.91.2\n  {line}\n");
            let mut reader = std::io::BufReader::new(text.as_bytes());
            let config = SshConfig::default()
                .parse(
                    &mut reader,
                    ParseRule::ALLOW_UNKNOWN_FIELDS | ParseRule::ALLOW_UNSUPPORTED_FIELDS,
                )
                .unwrap();
            config.query("a")
        };

        let honored = parse("ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p");
        assert_eq!(
            proxy_command_socks5(&honored).as_deref(),
            Some("127.0.0.1:1080")
        );
        assert!(
            unimplemented_routing(&honored).is_empty(),
            "an honored ProxyCommand is not unimplemented"
        );

        let ignored = parse("ProxyCommand ssh -W %h:%p jump");
        assert_eq!(proxy_command_socks5(&ignored), None);
        assert_eq!(
            unimplemented_routing(&ignored),
            vec!["proxycommand=ssh -W %h:%p jump".to_string()]
        );
    }

    /// The route label must mention a SOCKS5 proxy, so warnings never claim a
    /// direct connection when one is in use.
    #[test]
    fn test_route_labels_include_socks5() {
        let mut remote = RemoteHost {
            hostname: "10.173.91.2".to_string(),
            port: Some(22),
            user: None,
            identity_file: None,
            jump: Vec::new(),
            jump_specs: Vec::new(),
            alias: None,
            socks5: Some("127.0.0.1:1080".to_string()),
        };
        assert_eq!(jump_chain_label(&remote), "via socks5 127.0.0.1:1080");
        assert_eq!(route_phrase(&remote), "via socks5 127.0.0.1:1080");

        // With a jump chain the proxy belongs to the first leg, which the label
        // takes from the first hop when the target itself carries none.
        remote.socks5 = None;
        remote.jump = vec![RemoteHost {
            hostname: "192.168.4.70".to_string(),
            port: Some(42200),
            user: None,
            identity_file: None,
            jump: Vec::new(),
            jump_specs: Vec::new(),
            alias: Some("js4".to_string()),
            socks5: Some("127.0.0.1:1080".to_string()),
        }];
        assert_eq!(
            jump_chain_label(&remote),
            "via socks5 127.0.0.1:1080 → 192.168.4.70:42200"
        );
    }

    /// The `-e` string rsync gets: port of the resolved target, and `-J` only
    /// when the target is a literal (an alias carries its own ProxyJump).
    #[test]
    fn test_sync_ssh_e_composition() {
        let mut remote = RemoteHost {
            hostname: "10.30.40.4".to_string(),
            port: Some(22),
            user: Some("zengqixin".to_string()),
            identity_file: None,
            jump: vec![RemoteHost {
                hostname: "192.168.4.70".to_string(),
                port: Some(42200),
                user: Some("zengqixin".to_string()),
                identity_file: None,
                jump: Vec::new(),
                jump_specs: Vec::new(),
                alias: Some("js4".to_string()),
                socks5: None,
            }],
            jump_specs: vec!["js4".to_string()],
            alias: None,
            socks5: None,
        };
        let e = sync_ssh_e(&remote);
        assert!(e.starts_with("ssh -p 22 -o BatchMode=yes"), "{e}");
        assert!(e.ends_with(" -J js4"), "{e}");

        remote.alias = Some("lyg2004".to_string());
        let e = sync_ssh_e(&remote);
        assert!(!e.contains("-J"), "an alias carries its own ProxyJump: {e}");

        remote.port = None;
        let e = sync_ssh_e(&remote);
        assert!(e.starts_with("ssh -o BatchMode=yes"), "{e}");
    }

    /// Duplicate routing directives inside one block keep the FIRST value
    /// (OpenSSH semantics); the crate's unsupported-field map would keep the last.
    #[test]
    fn test_expansion_keeps_first_proxy_jump() {
        let base = std::env::temp_dir().join(format!("rexec-firstwins-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let cfg = base.join("config");
        std::fs::write(
            &cfg,
            "Host a\n  ProxyJump first\n  ProxyJump second\nHost b\n  ProxyCommand nc %h %p\n  ProxyCommand nc -x 127.0.0.1 %h %p\n",
        )
        .unwrap();
        let text = load_ssh_config_text(&cfg).unwrap();
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(
                &mut reader,
                ParseRule::ALLOW_UNKNOWN_FIELDS | ParseRule::ALLOW_UNSUPPORTED_FIELDS,
            )
            .unwrap();
        assert_eq!(
            proxy_jump_specs(&config.query("a")),
            vec!["first".to_string()],
            "the first ProxyJump in a block wins"
        );
        assert_eq!(
            unimplemented_routing(&config.query("b")),
            vec!["proxycommand=nc %h %p".to_string()],
            "the first ProxyCommand in a block wins"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// `Match` blocks cannot be evaluated: they are dropped (not leaked into the
    /// previous `Host` block, which would apply them unconditionally).
    #[test]
    fn test_expansion_drops_match_blocks() {
        let base = std::env::temp_dir().join(format!("rexec-match-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let cfg = base.join("config");
        std::fs::write(
            &cfg,
            "Host target\n  HostName 127.0.0.1\n  Port 9\nMatch host other\n  ProxyJump evil\n",
        )
        .unwrap();
        let text = load_ssh_config_text(&cfg).unwrap();
        assert!(
            !text.to_ascii_lowercase().contains("match"),
            "the Match line must not reach the parser: {text}"
        );
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(
                &mut reader,
                ParseRule::ALLOW_UNKNOWN_FIELDS | ParseRule::ALLOW_UNSUPPORTED_FIELDS,
            )
            .unwrap();
        assert!(
            proxy_jump_specs(&config.query("target")).is_empty(),
            "a Match-block ProxyJump must not attach to the previous Host block"
        );
        assert_eq!(config.query("target").port, Some(9));
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// A jump chain flattens into connection order, and a jump host that itself
    /// jumps contributes its own chain first (nebula99 → lyg2004 → js4 shape).
    #[test]
    fn test_resolve_jump_chain_flattens_recursively() {
        let text = "\
Host nebula99\n  HostName 154.57.56.2\n  Port 8122\n  ProxyJump lyg2004\n\
Host lyg2004\n  HostName 10.30.40.4\n  ProxyJump js4\n\
Host js4\n  HostName 192.168.4.70\n  Port 42200\n  User zengqixin\n";
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(
                &mut reader,
                ParseRule::ALLOW_UNKNOWN_FIELDS | ParseRule::ALLOW_UNSUPPORTED_FIELDS,
            )
            .unwrap();

        let (chain, specs) = resolve_jump_chain(&config.query("nebula99"), &config, 0).unwrap();
        let hops: Vec<(String, u16, Option<String>)> = chain
            .iter()
            .map(|h| (h.hostname.clone(), h.port.unwrap_or(22), h.user.clone()))
            .collect();
        assert_eq!(
            hops,
            vec![
                (
                    "192.168.4.70".to_string(),
                    42200,
                    Some("zengqixin".to_string())
                ),
                ("10.30.40.4".to_string(), 22, None),
            ],
            "outermost hop first: js4, then lyg2004"
        );
        assert!(chain.iter().all(|h| h.jump.is_empty()), "chains are flat");
        // The raw specs are what `rsync -e ssh -J …` must receive: aliases, so
        // that ssh applies each hop's own config block.
        assert_eq!(specs, vec!["js4".to_string(), "lyg2004".to_string()]);

        // A literal jump target needs no config entry (`ssh -J user@host:port`).
        let text = "Host a\n  ProxyJump ops@jump.example:2222\n";
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(
                &mut reader,
                ParseRule::ALLOW_UNKNOWN_FIELDS | ParseRule::ALLOW_UNSUPPORTED_FIELDS,
            )
            .unwrap();
        let (chain, specs) = resolve_jump_chain(&config.query("a"), &config, 0).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].hostname, "jump.example");
        assert_eq!(chain[0].port, Some(2222));
        assert_eq!(chain[0].user.as_deref(), Some("ops"));
        assert_eq!(specs, vec!["ops@jump.example:2222".to_string()]);

        // `-J` argument: specs when recorded, resolved hops otherwise.
        let mut target = RemoteHost {
            hostname: "154.57.56.2".to_string(),
            port: Some(8122),
            user: None,
            identity_file: None,
            jump: chain.clone(),
            jump_specs: specs,
            alias: None,
            socks5: None,
        };
        assert_eq!(
            jump_j_arg(&target).as_deref(),
            Some("ops@jump.example:2222")
        );
        target.jump_specs.clear();
        assert_eq!(
            jump_j_arg(&target).as_deref(),
            Some("ops@jump.example:2222")
        );
        assert_eq!(
            jump_j_arg(&RemoteHost {
                jump: Vec::new(),
                ..target.clone()
            }),
            None,
            "a direct host has no -J argument"
        );
    }

    /// The rsync hand-off must give the ssh rsync spawns everything it needs:
    /// the alias for a config host (so that host's own block applies — keys,
    /// port and ProxyJump), and the resolved address plus `-J` only for a
    /// literal target.
    #[test]
    fn test_rsync_endpoint_hands_over_alias_or_j_chain() {
        let js4 = RemoteHost {
            hostname: "192.168.4.70".to_string(),
            port: Some(42200),
            user: Some("zengqixin".to_string()),
            identity_file: None,
            jump: Vec::new(),
            jump_specs: Vec::new(),
            alias: Some("js4".to_string()),
            socks5: None,
        };
        let alias_target = RemoteHost {
            hostname: "10.30.40.4".to_string(),
            port: Some(22),
            user: Some("zengqixin".to_string()),
            identity_file: None,
            jump: vec![js4],
            jump_specs: vec!["js4".to_string()],
            alias: Some("lyg2004".to_string()),
            socks5: None,
        };
        assert_eq!(
            rsync_endpoint(&alias_target),
            ("lyg2004".to_string(), String::new()),
            "an alias goes to rsync as-is; ssh applies its config and ProxyJump"
        );

        let literal = RemoteHost {
            alias: None,
            socks5: None,
            ..alias_target.clone()
        };
        assert_eq!(
            rsync_endpoint(&literal),
            ("zengqixin@10.30.40.4".to_string(), " -J js4".to_string())
        );

        let direct = RemoteHost {
            jump: Vec::new(),
            jump_specs: Vec::new(),
            ..literal.clone()
        };
        assert_eq!(
            rsync_endpoint(&direct),
            ("zengqixin@10.30.40.4".to_string(), String::new())
        );
    }

    /// A config cycle must fail loudly instead of recursing forever.
    #[test]
    fn test_resolve_jump_chain_depth_limit() {
        let text = "Host a\n  ProxyJump b\nHost b\n  ProxyJump a\n";
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(
                &mut reader,
                ParseRule::ALLOW_UNKNOWN_FIELDS | ParseRule::ALLOW_UNSUPPORTED_FIELDS,
            )
            .unwrap();
        let err = resolve_jump_chain(&config.query("a"), &config, 0).unwrap_err();
        assert!(
            err.to_string().contains("ProxyJump chain"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_jump_chain_label() {
        let mut target = RemoteHost {
            hostname: "154.57.56.2".to_string(),
            port: Some(8122),
            user: None,
            identity_file: None,
            jump: Vec::new(),
            jump_specs: Vec::new(),
            alias: None,
            socks5: None,
        };
        assert_eq!(jump_chain_label(&target), "direct");
        target.jump = vec![
            RemoteHost {
                hostname: "192.168.4.70".to_string(),
                port: Some(42200),
                user: None,
                identity_file: None,
                jump: Vec::new(),
                jump_specs: Vec::new(),
                alias: None,
                socks5: None,
            },
            RemoteHost {
                hostname: "10.30.40.4".to_string(),
                port: None,
                user: None,
                identity_file: None,
                jump: Vec::new(),
                jump_specs: Vec::new(),
                alias: None,
                socks5: None,
            },
        ];
        assert_eq!(
            jump_chain_label(&target),
            "via 192.168.4.70:42200 → 10.30.40.4:22"
        );
    }

    #[test]
    fn test_unimplemented_routing_reports_proxycommand() {
        let text = "Host tunnelled\n  ProxyCommand nc -X connect -x 127.0.0.1:7890 %h %p\n";
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(
                &mut reader,
                ParseRule::ALLOW_UNKNOWN_FIELDS | ParseRule::ALLOW_UNSUPPORTED_FIELDS,
            )
            .unwrap();
        assert_eq!(
            unimplemented_routing(&config.query("tunnelled")),
            vec!["proxycommand=nc -X connect -x 127.0.0.1:7890 %h %p".to_string()]
        );
    }

    /// Unsupported fields that do not redirect the socket must stay silent:
    /// `StrictHostKeyChecking` and `SendEnv` are recorded by the crate too, and
    /// warning about them would make every ordinary config noisy.
    #[test]
    fn test_unimplemented_routing_ignores_benign_fields() {
        let text =
            "Host plain\n  HostName 10.0.0.5\n  StrictHostKeyChecking accept-new\n  SendEnv LANG\n";
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(
                &mut reader,
                ParseRule::ALLOW_UNKNOWN_FIELDS | ParseRule::ALLOW_UNSUPPORTED_FIELDS,
            )
            .unwrap();
        assert!(unimplemented_routing(&config.query("plain")).is_empty());
    }

    #[test]
    fn test_ssh_config_include_restores_host_scope() {
        // OpenSSH: after an Include inside a Host block, the enclosing host's
        // state is restored — `Port 27001` below belongs to prod, and the
        // included `Host net` gets its own block without leaking.
        let base = std::env::temp_dir().join(format!("rexec-test-scope-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(ssh.join("prod.d")).unwrap();
        std::fs::write(
            ssh.join("config"),
            "Host prod\n  Include prod.d/net.conf\n  Port 27001\n",
        )
        .unwrap();
        std::fs::write(
            ssh.join("prod.d/net.conf"),
            "Host net\n  HostName 10.0.0.9\n",
        )
        .unwrap();

        let text = load_ssh_config_text(&ssh.join("config")).unwrap();
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
            .unwrap();
        assert_eq!(
            config.query("prod").port.unwrap(),
            27001,
            "prod keeps its port after the include"
        );
        assert_eq!(config.query("net").host_name.unwrap(), "10.0.0.9");
        assert!(
            config.query("net").port.is_none(),
            "net must not inherit prod's port"
        );

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_include_restores_inherited_host_scope() {
        // The scope INHERITED from a parent include must be restored after a
        // nested Include (readconf.c's oactive is inherited down the chain):
        // prod.conf is included inside `Host prod` and itself includes
        // extra.conf; after that nested include, prod.conf's directives must
        // keep applying to prod — not leak into extra.conf's `Host other`.
        let base = std::env::temp_dir().join(format!("rexec-test-inh-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(ssh.join("conf.d")).unwrap();
        std::fs::write(
            ssh.join("config"),
            "Host prod\n  Include conf.d/prod.conf\n",
        )
        .unwrap();
        std::fs::write(
            ssh.join("conf.d/prod.conf"),
            "Include conf.d/extra.conf\nHostName 10.0.0.1\nPort 27001\n",
        )
        .unwrap();
        std::fs::write(
            ssh.join("conf.d/extra.conf"),
            "Host other\n  HostName 1.1.1.1\n",
        )
        .unwrap();

        let text = load_ssh_config_text(&ssh.join("config")).unwrap();
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
            .unwrap();
        assert_eq!(
            config.query("prod").host_name.unwrap(),
            "10.0.0.1",
            "prod must keep its directives after the nested include"
        );
        assert_eq!(config.query("prod").port.unwrap(), 27001);
        assert_eq!(config.query("other").host_name.unwrap(), "1.1.1.1");
        assert!(
            config.query("other").port.is_none(),
            "other must not inherit prod's port"
        );

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_top_include_then_global_directive() {
        // A global directive after a top-level Include applies to every host
        // (OpenSSH seeds active=1 at file scope); without a scope restore it
        // would be absorbed into the last included Host block.
        let base = std::env::temp_dir().join(format!("rexec-test-glob-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(ssh.join("inc")).unwrap();
        std::fs::write(ssh.join("config"), "Include inc/a.conf\nPort 2222\n").unwrap();
        std::fs::write(ssh.join("inc/a.conf"), "Host alpha\n  HostName 5.5.5.5\n").unwrap();

        let text = load_ssh_config_text(&ssh.join("config")).unwrap();
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
            .unwrap();
        assert_eq!(config.query("alpha").port.unwrap(), 2222);
        assert_eq!(
            config.query("unrelated").port.unwrap(),
            2222,
            "global directive must apply to hosts other than the included ones"
        );
        assert_eq!(config.query("alpha").host_name.unwrap(), "5.5.5.5");

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_include_dir_matched_by_glob_is_skipped() {
        // A directory matched by the include glob must be skipped, not fatal
        // (a git-managed ~/.ssh has .git dirs; `config.d/*` matches subdirs).
        let base = std::env::temp_dir().join(format!("rexec-test-dirg-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(ssh.join("config.d/adir")).unwrap();
        std::fs::write(ssh.join("config"), "Include config.d/*\nHost top\n").unwrap();
        std::fs::write(ssh.join("config.d/adir/inner.conf"), "Host inner\n").unwrap();
        std::fs::write(ssh.join("config.d/real.conf"), "Host real\n").unwrap();

        let text = load_ssh_config_text(&ssh.join("config")).unwrap();
        assert!(text.contains("Host top"));
        assert!(text.contains("Host real"), "regular files load: {text}");
        assert!(
            !text.contains("inner"),
            "a directory hit by the glob must not be read"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_include_depth_boundary() {
        // OpenSSH allows 16 nested include levels and fatals beyond.
        let base = std::env::temp_dir().join(format!("rexec-test-depb-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let make_chain = |n: usize| {
            for i in 0..n {
                let next = if i + 1 < n {
                    format!("Include c{}.conf\n", i + 1)
                } else {
                    "Host deepest\n".to_string()
                };
                std::fs::write(ssh.join(format!("c{i}.conf")), next).unwrap();
            }
        };
        // chain(n) = n files = n-1 include levels; OpenSSH allows 16 levels.
        make_chain(17);
        let ok = load_ssh_config_text(&ssh.join("c0.conf")).unwrap();
        assert!(
            ok.contains("Host deepest"),
            "16 include levels must be allowed"
        );

        make_chain(18);
        assert!(
            load_ssh_config_text(&ssh.join("c0.conf")).is_err(),
            "17 include levels must fail"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_include_no_override_of_enclosing_values() {
        // OpenSSH is first-obtained-wins: an include without Host lines must
        // NOT override a value the enclosing host set before the Include,
        // even though the crate is last-wins within a single block. The
        // pre-include scope re-emit splits the blocks so first-wins applies.
        let base = std::env::temp_dir().join(format!("rexec-test-ovr-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::write(ssh.join("inc.conf"), "Port 9999\nUser included\n").unwrap();
        std::fs::write(
            ssh.join("config"),
            "Host prod\n  Port 2202\n  Include inc.conf\n",
        )
        .unwrap();

        let text = load_ssh_config_text(&ssh.join("config")).unwrap();
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
            .unwrap();
        assert_eq!(
            config.query("prod").port.unwrap(),
            2202,
            "the enclosing host's pre-include value must win (OpenSSH first-obtained)"
        );
        assert_eq!(
            config.query("prod").user.unwrap(),
            "included",
            "non-conflicting include values must still apply to the enclosing host"
        );

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_glob_files_do_not_capture_each_other() {
        // OpenSSH restores the scope after EVERY matched file: a defaults
        // file that sorts after an alias file must still contribute global
        // directives — not be captured into the alias file's trailing
        // `Host` block. This is the realistic config.d/*.conf shape.
        let base = std::env::temp_dir().join(format!("rexec-test-cap-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(ssh.join("inc")).unwrap();
        std::fs::write(ssh.join("config"), "Include inc/*.conf\nHost marker\n").unwrap();
        std::fs::write(
            ssh.join("inc/a-alias.conf"),
            "Host alpha\n  HostName 5.5.5.5\n",
        )
        .unwrap();
        std::fs::write(ssh.join("inc/b-defaults.conf"), "Port 8888\nUser gu\n").unwrap();

        let text = load_ssh_config_text(&ssh.join("config")).unwrap();
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
            .unwrap();
        assert_eq!(config.query("alpha").host_name.unwrap(), "5.5.5.5");
        assert_eq!(
            config.query("beta").port.unwrap(),
            8888,
            "global directives from a later file must apply to unrelated hosts"
        );
        assert_eq!(config.query("beta").user.unwrap(), "gu");
        assert_eq!(config.query("alpha").port.unwrap(), 8888);
        assert_eq!(config.query("marker").port.unwrap(), 8888);

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_two_include_args_in_host_block() {
        // `Include A B` inside a Host block: OpenSSH restores the scope after
        // each arg; values from B (which has no Host lines) must reach the
        // enclosing host even though A ended inside its own Host block.
        let base = std::env::temp_dir().join(format!("rexec-test-2arg-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::write(ssh.join("a.conf"), "Host inner\n  HostName 7.7.7.7\n").unwrap();
        std::fs::write(ssh.join("b.conf"), "Port 8888\nUser gu\n").unwrap();
        std::fs::write(
            ssh.join("config"),
            "Host prod\n  Include a.conf b.conf\n  Port 2202\n",
        )
        .unwrap();

        let text = load_ssh_config_text(&ssh.join("config")).unwrap();
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
            .unwrap();
        assert_eq!(
            config.query("prod").port.unwrap(),
            8888,
            "values from the second include arg must reach prod (first-obtained)"
        );
        assert_eq!(config.query("prod").user.unwrap(), "gu");
        assert_eq!(config.query("inner").host_name.unwrap(), "7.7.7.7");

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_diamond_include() {
        // The same file included from two Host blocks must be expanded twice
        // (OpenSSH re-includes; only the ancestor chain is deduplicated).
        let base = std::env::temp_dir().join(format!("rexec-test-dia-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::write(ssh.join("shared.conf"), "Port 2999\n").unwrap();
        std::fs::write(
            ssh.join("config"),
            "Host a\n  Include shared.conf\nHost b\n  Include shared.conf\n",
        )
        .unwrap();
        let text = load_ssh_config_text(&ssh.join("config")).unwrap();
        let mut reader = std::io::BufReader::new(text.as_bytes());
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
            .unwrap();
        assert_eq!(config.query("a").port.unwrap(), 2999);
        assert_eq!(config.query("b").port.unwrap(), 2999);

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_include_quoted_and_spaces() {
        let base = std::env::temp_dir().join(format!("rexec-test-q-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(ssh.join("dir with space")).unwrap();
        std::fs::write(
            ssh.join("config"),
            "Include \"dir with space/x.conf\"\nInclude 'y.conf'\n",
        )
        .unwrap();
        std::fs::write(ssh.join("dir with space/x.conf"), "Host qx\n").unwrap();
        std::fs::write(ssh.join("y.conf"), "Host qy\n").unwrap();
        let text = load_ssh_config_text(&ssh.join("config")).unwrap();
        assert!(text.contains("Host qx"), "quoted path with space: {text}");
        assert!(text.contains("Host qy"), "single-quoted path: {text}");
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_include_depth_limit() {
        let base = std::env::temp_dir().join(format!("rexec-test-dep-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        for i in 0..20 {
            std::fs::write(
                ssh.join(format!("c{i}.conf")),
                format!("Include c{}.conf\n", i + 1),
            )
            .unwrap();
        }
        let result = load_ssh_config_text(&ssh.join("c0.conf"));
        assert!(
            result.is_err(),
            "chain of 20 includes must hit the depth limit"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn test_ssh_config_include_cycle_and_missing_glob() {
        let base = std::env::temp_dir().join(format!("rexec-test-inc2-{}", std::process::id()));
        let ssh = base.join("ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        // a includes a missing glob and b; b includes a back (cycle).
        std::fs::write(
            ssh.join("a.conf"),
            "Include missing-dir/*.conf b.conf\nHost ha\n",
        )
        .unwrap();
        std::fs::write(ssh.join("b.conf"), "Include a.conf\nHost hb\n").unwrap();
        let text = load_ssh_config_text(&ssh.join("a.conf")).unwrap();
        assert!(text.contains("Host ha"));
        assert!(text.contains("Host hb"));
        assert!(
            !text.lines().any(|l| include_args(l).is_some()),
            "no Include lines may survive: {text}"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    fn host_entry(alias: &str, hostname: &str, user: &str, desc: Option<&str>) -> HostEntry {
        HostEntry {
            alias: alias.to_string(),
            hostname: hostname.to_string(),
            port: 22,
            user: user.to_string(),
            identity: None,
            description: desc.map(str::to_string),
        }
    }

    #[test]
    fn test_glob_match() {
        assert!(glob_match("web*", "web1"));
        assert!(glob_match("web*", "WEB-prod"));
        assert!(glob_match("*prod*", "a-prod-b"));
        assert!(glob_match("h?st", "host"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("h?st", "hoost"));
        assert!(!glob_match("web*", "app1"));
        assert!(!glob_match("a*b*c", "a-b")); // trailing literal missing
        assert!(glob_match("a*b*c", "a1b2c"));
    }

    #[test]
    fn test_host_matches_filters() {
        let e = host_entry("mint-dev", "192.168.4.70", "root", Some("H20 training box"));
        let no = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // plain patterns: substring over alias, hostname, user and description
        assert!(host_matches(&e, &no(&["mint"]), None, None));
        assert!(host_matches(&e, &no(&["168.4"]), None, None), "hostname");
        assert!(
            host_matches(&e, &no(&["ROOT"]), None, None),
            "user, case-folded"
        );
        assert!(
            host_matches(&e, &no(&["training"]), None, None),
            "description"
        );
        assert!(!host_matches(&e, &no(&["web"]), None, None));
        // globs match alias/hostname/host:port only
        assert!(host_matches(&e, &no(&["mint-*"]), None, None));
        assert!(host_matches(&e, &no(&["192.168.*"]), None, None));
        assert!(
            !host_matches(&e, &no(&["*raining*"]), None, None),
            "no glob over description"
        );
        // several patterns must all match
        assert!(host_matches(&e, &no(&["mint", "70"]), None, None));
        assert!(!host_matches(&e, &no(&["mint", "web"]), None, None));
        // exact field filters
        assert!(host_matches(&e, &[], Some("root"), Some(22)));
        assert!(!host_matches(&e, &[], Some("nolan"), None));
        assert!(!host_matches(&e, &[], None, Some(2222)));
    }

    #[test]
    fn test_host_entry_address_and_port_filtering() {
        let mut e = host_entry("mint-glm52-l20x-1", "47.94.214.197", "root", None);
        e.port = 26001;
        assert_eq!(e.address(), "47.94.214.197:26001");

        // IPv6 literals are bracketed so the port stays readable.
        let mut v6 = host_entry("v6-box", "fe80::1", "root", None);
        v6.port = 2222;
        assert_eq!(v6.address(), "[fe80::1]:2222");

        // A config that already writes brackets (`HostName [fe80::1]`) must not
        // come out doubled — brackets are syntax, not part of the host.
        let mut v6b = host_entry("v6-bracketed", "[fe80::1]", "root", None);
        v6b.port = 2222;
        assert_eq!(v6b.address(), "[fe80::1]:2222");

        let no = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // The port is visible in the table, so it must be searchable: as a
        // substring (`-f 26001`) and as a glob over the address (`*:26001` —
        // `47.94.*` would also match the plain hostname and pin nothing).
        assert!(
            host_matches(&e, &no(&["26001"]), None, None),
            "address port"
        );
        assert!(
            host_matches(&e, &no(&["*:26001"]), None, None),
            "glob over address"
        );
        assert!(host_matches(&e, &no(&["47.94.214.197:26001"]), None, None));
        assert!(!host_matches(&e, &no(&["*:26002"]), None, None));
        assert!(!host_matches(&e, &no(&["26002"]), None, None));
    }

    #[test]
    fn test_descriptions_from_config_text_and_sidecar() {
        // The annotation attaches to the Host line that follows it, survives a
        // blank line, and covers every concrete pattern on that line.
        let text = "# rexec: fleet head node\n\nHost fleet-0 fleet-head\n  HostName 1.2.3.4\n# rexec: training box\nHost train-1\n  Port 2222\nHost *\n  User root\n";
        let map = descriptions_from_config_text(text);
        assert_eq!(
            map.get("fleet-0").map(String::as_str),
            Some("fleet head node")
        );
        assert_eq!(
            map.get("fleet-head").map(String::as_str),
            Some("fleet head node")
        );
        assert_eq!(map.get("train-1").map(String::as_str), Some("training box"));
        assert!(!map.contains_key("*"), "wildcards get no annotation");

        // A directive between comment and Host detaches the annotation.
        let detached = "# rexec: stale\nUser root\nHost later\n";
        assert!(descriptions_from_config_text(detached).is_empty());

        // Sidecar: `alias = description`, comments/blanks ignored, last wins.
        let dir = std::env::temp_dir().join(format!("rexec-sidecar-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let side = dir.join("hosts.conf");
        std::fs::write(
            &side,
            "# comment\nalpha = first\nalpha = second\n\nbeta = only\n= noname\nemptydesc =\n",
        )
        .unwrap();
        let side_map = descriptions_from_sidecar(&side);
        assert_eq!(side_map.get("alpha").map(String::as_str), Some("second"));
        assert_eq!(side_map.get("beta").map(String::as_str), Some("only"));
        assert_eq!(side_map.len(), 2, "nameless/valueless lines are skipped");
        assert!(descriptions_from_sidecar(&dir.join("missing.conf")).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_mask_env_value() {
        // Values are the secret: masked unless explicitly revealed; an empty
        // value stays empty (nothing to hide, and `KEY=` should read as unset).
        assert_eq!(mask_env_value("sk-live-abcdef", false), "***");
        assert_eq!(mask_env_value("sk-live-abcdef", true), "sk-live-abcdef");
        assert_eq!(mask_env_value("", false), "");
        assert_eq!(mask_env_value("", true), "");
    }

    #[test]
    fn test_mask_index_line_env_keeps_the_rest_of_the_record() {
        let line =
            r#"{"id":"x","env":[["API_KEY","sk-live"],["EMPTY",""]],"note":"keep","future":7}"#;
        let masked = mask_index_line_env(line);
        let v: serde_json::Value = serde_json::from_str(&masked).unwrap();
        assert_eq!(v["env"][0][0], "API_KEY", "the key name is not a secret");
        assert_eq!(v["env"][0][1], "***", "the value is masked");
        assert_eq!(v["env"][1][1], "", "an empty value stays empty");
        // Everything else — including keys this build does not know — survives,
        // which is why the JSON object is edited instead of re-typed.
        assert_eq!(v["id"], "x");
        assert_eq!(v["note"], "keep");
        assert_eq!(v["future"], 7);

        // A line that is not valid JSON is returned untouched (callers only
        // pass lines they just parsed for the id).
        assert_eq!(mask_index_line_env("not json"), "not json");
    }

    #[test]
    fn test_parse_user_host_port_ipv6_and_legacy_forms() {
        let p = |s: &str| parse_user_host_port(s).unwrap();
        // Bracketed literals: the brackets are syntax, never part of the host.
        let v6 = p("[fe80::1]:2222");
        assert_eq!(v6.hostname, "fe80::1");
        assert_eq!(v6.port, Some(2222));
        let v6_no_port = p("[fe80::1]");
        assert_eq!(v6_no_port.hostname, "fe80::1");
        assert_eq!(v6_no_port.port, None);
        // Bare v6 addresses carry no port syntax at all (the colons are not a
        // separator): this used to parse as host `fe80:` + port 1.
        let bare = p("fe80::1");
        assert_eq!(bare.hostname, "fe80::1");
        assert_eq!(bare.port, None);
        // ... including after an explicit user.
        let user_v6 = p("root@fe80::1");
        assert_eq!(user_v6.user.as_deref(), Some("root"));
        assert_eq!(user_v6.hostname, "fe80::1");
        assert_eq!(user_v6.port, None);
        let user_v6_port = p("root@[fd00::1]:2222");
        assert_eq!(user_v6_port.hostname, "fd00::1");
        assert_eq!(user_v6_port.port, Some(2222));
        // Legacy shapes are unchanged.
        let legacy = p("root@example.com:2222");
        assert_eq!(legacy.user.as_deref(), Some("root"));
        assert_eq!(legacy.hostname, "example.com");
        assert_eq!(legacy.port, Some(2222));
        assert_eq!(p("example.com").port, None);
        assert_eq!(p("10.0.0.5:22").port, Some(22));
        // Malformed brackets fail loudly instead of silently mangling the host.
        assert!(
            parse_user_host_port("[fe80::1").is_err(),
            "unclosed bracket"
        );
        assert!(
            parse_user_host_port("[fe80::1]x").is_err(),
            "garbage after bracket"
        );
    }

    #[test]
    fn test_include_args_forms() {
        assert_eq!(
            include_args("Include config.d/x.conf"),
            Some(vec!["config.d/x.conf".to_string()])
        );
        assert_eq!(
            include_args("include=z.conf"),
            Some(vec!["z.conf".to_string()])
        );
        assert_eq!(
            include_args("iNcLuDe = a.conf b.conf"),
            Some(vec!["a.conf".to_string(), "b.conf".to_string()])
        );
        assert_eq!(
            include_args("INCLUDE \"a b.conf\" c.conf"),
            Some(vec!["a b.conf".to_string(), "c.conf".to_string()])
        );
        assert_eq!(
            include_args("Include \"dir/\"*.conf"),
            Some(vec!["dir/*.conf".to_string()]),
            "adjacent quoted/unquoted fragments must join"
        );
        assert_eq!(
            include_args("Include a.conf # trailing comment"),
            Some(vec!["a.conf".to_string()]),
            "unquoted # starting a token ends the arg list"
        );
        assert_eq!(
            include_args("Include a#b.conf"),
            Some(vec!["a#b.conf".to_string()]),
            "# inside a token is literal"
        );
        assert_eq!(
            include_args("Include"),
            Some(vec![]),
            "bare keyword: consumed (dropped), not passed through"
        );
        assert_eq!(include_args("Host foo"), None, "other keyword");
        assert_eq!(
            include_args("  IncludeX y"),
            None,
            "IncludeX is not Include"
        );
        assert_eq!(
            include_args("hostname 1.2.3.4"),
            None,
            "hostname is not include"
        );
        assert!(is_host_line("Host prod"));
        assert!(is_host_line("  host = x"));
        assert!(!is_host_line("HostName 1.2.3.4"));
        assert!(!is_host_line("HostKeyAlias k"));
    }

    #[test]
    fn test_detect_runner_shebang() {
        let dir = std::env::temp_dir();
        let p = dir.join("rexec_test_shebang.sh");
        std::fs::write(&p, "#!/bin/bash\necho hi\n").unwrap();
        assert_eq!(detect_runner(&p).unwrap(), None);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn test_detect_runner_by_extension() {
        let dir = std::env::temp_dir();
        let py = dir.join("rexec_test_detect.py");
        std::fs::write(&py, "print(1)\n").unwrap();
        assert_eq!(detect_runner(&py).unwrap(), Some("python3".to_string()));
        let sh = dir.join("rexec_test_detect.sh");
        std::fs::write(&sh, "echo hi\n").unwrap();
        assert_eq!(detect_runner(&sh).unwrap(), Some("sh".to_string()));
        let _ = std::fs::remove_file(&py);
        let _ = std::fs::remove_file(&sh);
    }

    #[test]
    fn test_collect_env_flags() {
        let env = vec!["A=b".to_string(), "C=d".to_string()];
        assert_eq!(
            collect_env(&env, &[]).unwrap(),
            vec![
                ("A".to_string(), "b".to_string()),
                ("C".to_string(), "d".to_string())
            ]
        );
        // missing '='
        assert!(collect_env(&["noequal".to_string()], &[]).is_err());
        // empty key
        assert!(collect_env(&["=nokey".to_string()], &[]).is_err());
    }

    #[test]
    fn test_sync_arg_windows_drive_letter_guard() {
        // `C:\proj` would otherwise parse as host "C" + remote "\proj".
        assert!(has_windows_drive_prefix(r"C:\proj"));
        assert!(has_windows_drive_prefix("c:/proj"));
        assert!(has_windows_drive_prefix("Z:"));
        assert!(!has_windows_drive_prefix("/home/user/proj"));
        assert!(!has_windows_drive_prefix("./proj"));
        assert!(!has_windows_drive_prefix("C"));
        assert!(!has_windows_drive_prefix("C1:/proj"));

        let err = parse_sync_arg(r"C:\proj:/home/user/proj")
            .unwrap_err()
            .to_string();
        assert!(err.contains("/c/proj"), "unhelpful error: {}", err);

        // MSYS2-style and POSIX paths still parse as before.
        let (local, remote) = parse_sync_arg("/c/proj:/home/user/proj").unwrap();
        assert_eq!(local, PathBuf::from("/c/proj"));
        assert_eq!(remote, "/home/user/proj");
        let (local, remote) = parse_sync_arg("./project:/srv/app").unwrap();
        assert_eq!(local, PathBuf::from("./project"));
        assert_eq!(remote, "/srv/app");
    }

    #[test]
    fn test_is_literal_host() {
        // Literal shapes: an explicit user, a bracketed IPv6, an IP, an FQDN.
        for literal in [
            "root@10.0.0.5",
            "root@web1",
            "user@host:2222",
            "[2001:db8::1]:22",
            "10.0.0.5",
            "192.168.1.7:2222",
            "host.example.com",
            "web1.internal",
            "1web",
        ] {
            assert!(is_literal_host(literal), "{literal:?} should be literal");
        }
        // Everything else MUST resolve as an ssh-config alias (the old code
        // silently treated these as raw hostnames).
        for alias in ["web1", "prod", "my-server", "web1:2222", "prod-01"] {
            assert!(!is_literal_host(alias), "{alias:?} should need config");
        }
    }

    #[test]
    fn test_suggest_aliases_ranks_prefix_over_substring() {
        let aliases: Vec<String> = [
            "prod-web-2",
            "staging",
            "web1",
            "web2",
            "prod-db",
            "*.internal",
            "!blocked",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        // Prefix matches ("web*") before substring matches ("prod-web-*").
        assert_eq!(
            suggest_aliases("web", &aliases, 3),
            vec![
                "web1".to_string(),
                "web2".to_string(),
                "prod-web-2".to_string()
            ]
        );
        // Wildcards and negations are never suggested.
        let suggestions = suggest_aliases("web", &aliases, 10);
        assert!(
            !suggestions
                .iter()
                .any(|s| s.contains('*') || s.contains('!'))
        );
        // No relation → no suggestion (the error just omits the line).
        assert!(suggest_aliases("database", &aliases, 3).is_empty());
        // `max` is honoured.
        assert_eq!(
            suggest_aliases("web", &aliases, 1),
            vec!["web1".to_string()]
        );
        // Case-insensitive.
        assert_eq!(
            suggest_aliases("WEB1", &aliases, 1),
            vec!["web1".to_string()]
        );
        assert!(suggest_aliases("", &aliases, 3).is_empty());
    }

    #[test]
    fn test_alias_miss_error_lists_suggestions_and_hint() {
        let aliases: Vec<String> = ["web1", "web2", "db1"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let msg = alias_miss_error("web", &aliases, Path::new("/home/u/.ssh/config")).to_string();
        assert!(msg.contains("host 'web' is not defined"), "{msg}");
        assert!(msg.contains("did you mean: web1, web2"), "{msg}");
        assert!(msg.contains("use user@host for a literal host"), "{msg}");
        // A name with no relation still gets the hint, just no suggestions.
        let msg = alias_miss_error("nope", &aliases, Path::new("/home/u/.ssh/config")).to_string();
        assert!(!msg.contains("did you mean"), "{msg}");
        assert!(msg.contains("use user@host for a literal host"), "{msg}");
    }

    #[test]
    fn test_plan_remote_asset_mapping() {
        assert_eq!(
            plan_remote_asset("Linux x86_64").as_deref(),
            Some("linux-amd64")
        );
        assert_eq!(
            plan_remote_asset("Linux aarch64").as_deref(),
            Some("linux-arm64")
        );
        assert_eq!(
            plan_remote_asset("Darwin arm64").as_deref(),
            Some("macos-arm64")
        );
        assert_eq!(
            plan_remote_asset("Windows_NT AMD64").as_deref(),
            Some("windows-amd64")
        );
        assert_eq!(
            plan_remote_asset("Windows_NT ARM64").as_deref(),
            Some("windows-arm64")
        );
        // Unmapped probes (Git-Bash uname, missing binary) → no guess.
        assert_eq!(plan_remote_asset("MINGW64_NT-10.0-19045"), None);
        assert_eq!(plan_remote_asset(""), None);
        assert_eq!(plan_remote_asset("Windows_NT X86"), None);
    }

    /// Structural check: braces/brackets/strings balance and every `"` inside a
    /// string is escaped — enough to prove the hand-written serializer emits
    /// ONE parseable JSON value without pulling in `serde_json`.
    fn assert_json_balanced(line: &str) {
        let mut depth = 0i32;
        let mut in_string = false;
        let mut escaped = false;
        for c in line.chars() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_string = false;
                }
                continue;
            }
            match c {
                '"' => in_string = true,
                '{' | '[' => depth += 1,
                '}' | ']' => depth -= 1,
                _ => {}
            }
            assert!(depth >= 0, "unbalanced JSON: {line}");
        }
        assert!(!in_string, "unterminated string: {line}");
        assert_eq!(depth, 0, "unbalanced JSON: {line}");
    }

    #[test]
    fn test_summary_json_line_field_order_and_values() {
        let summary = diagnostics::RunSummary {
            host: "web1".to_string(),
            resolved: "root@10.0.0.5:2222".to_string(),
            pid: Some(4242),
            exit_code: Some(1),
            duration_ms: Some(812),
            deployed: true,
            stdout_bytes: 12,
            stderr_bytes: 3,
            log_path: None,
            error: Some("boom".to_string()),
        };
        let line = summary_json_line(&summary);
        assert_eq!(
            line,
            r#"{"host":"web1","resolved":"root@10.0.0.5:2222","pid":4242,"exit_code":1,"duration_ms":812,"deployed":true,"stdout_bytes":12,"stderr_bytes":3,"log_path":null,"error":"boom"}"#
        );
        assert_json_balanced(&line);
        assert!(!line.contains('\n'), "must be exactly one line");
    }

    #[test]
    fn test_summary_json_line_success_omits_error_and_nulls_options() {
        let summary = diagnostics::RunSummary {
            host: "prod".to_string(),
            resolved: "root@example.com:22".to_string(),
            pid: None,
            exit_code: None,
            duration_ms: Some(5),
            deployed: false,
            stdout_bytes: 0,
            stderr_bytes: 0,
            log_path: None,
            error: None,
        };
        let line = summary_json_line(&summary);
        assert_eq!(
            line,
            r#"{"host":"prod","resolved":"root@example.com:22","pid":null,"exit_code":null,"duration_ms":5,"deployed":false,"stdout_bytes":0,"stderr_bytes":0,"log_path":null}"#
        );
        assert!(!line.contains("\"error\""), "{line}");
        assert_json_balanced(&line);
    }

    #[test]
    fn test_summary_json_line_escapes_control_characters() {
        let summary = diagnostics::RunSummary {
            host: "we\"b\\1".to_string(),
            resolved: String::new(),
            pid: None,
            exit_code: None,
            duration_ms: None,
            deployed: false,
            stdout_bytes: 0,
            stderr_bytes: 0,
            log_path: Some("/tmp/a\tb.log".to_string()),
            error: Some("line1\nline2\r\u{7}\u{1b}[0m".to_string()),
        };
        let line = summary_json_line(&summary);
        assert!(line.contains(r#""host":"we\"b\\1""#), "{line}");
        assert!(line.contains(r#""log_path":"/tmp/a\tb.log""#), "{line}");
        assert!(
            line.contains(r#""error":"line1\nline2\r\u0007\u001b[0m""#),
            "{line}"
        );
        // No raw control characters survive into the line.
        assert!(!line.chars().any(|c| (c as u32) < 0x20), "{line}");
        assert_json_balanced(&line);
    }

    #[test]
    fn test_worker_start_failure_carries_stderr_and_launch_command() {
        let err = worker_start_failure(
            b"worker requires a command over stdin\n",
            "~/.rexec/rexec worker",
            "web1",
        )
        .to_string();
        assert!(
            err.starts_with("connection lost before worker started"),
            "{err}"
        );
        assert!(
            err.contains("worker requires a command over stdin"),
            "{err}"
        );
        assert!(
            err.contains("launch command: ~/.rexec/rexec worker"),
            "{err}"
        );
        assert!(err.contains("rexec web1 init"), "{err}");

        // A worker that dies silently still names the launch command.
        let err = worker_start_failure(b"", "~/.rexec/rexec worker", "web1").to_string();
        assert!(err.contains("worker stderr: (none)"), "{err}");
        assert!(
            err.contains("launch command: ~/.rexec/rexec worker"),
            "{err}"
        );
    }

    #[test]
    fn test_attach_trace_appends_only_when_recorded() {
        let mut trace = diagnostics::Trace::default();
        let err = attach_trace(anyhow!("plain failure"), &trace);
        assert_eq!(err.to_string(), "plain failure");

        trace.add("resolve: literal root@10.0.0.5:22");
        let err = attach_trace(anyhow!("with context"), &trace);
        let text = err.to_string();
        assert!(text.starts_with("with context\n"), "{text}");
        assert!(text.contains("decision trace:"), "{text}");
        assert!(
            text.contains("→ resolve: literal root@10.0.0.5:22"),
            "{text}"
        );
    }

    // ── history helpers ──

    fn sample_record(id: &str, host: &str, exit: Option<i32>) -> history::RunRecord {
        history::RunRecord {
            id: id.to_string(),
            ts_start: "2026-09-22T04:15:33Z".to_string(),
            duration_ms: 1200,
            host: host.to_string(),
            resolved: format!("root@{host}:22"),
            command: "echo hi".to_string(),
            env: vec![("FOO".to_string(), "Bar".to_string())],
            exit_code: exit,
            pid: Some(42),
            deployed: false,
            stdout_bytes: 3,
            stderr_bytes: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            rexec_version: "0.3.1".to_string(),
            trace: vec!["resolve: literal root@host:22".to_string()],
            error: None,
        }
    }

    #[test]
    fn test_single_line_escapes_control_characters() {
        assert_eq!(single_line("echo hi", 60), "echo hi");
        assert_eq!(single_line("echo a\necho b", 60), "echo a\\necho b");
        assert_eq!(single_line("a\tb\rc", 60), "a\\tb\\rc");
        assert_eq!(single_line("bell\u{7}", 60), "bell\\u0007");
        // A rendered newline must never survive into a table row.
        assert!(!single_line("a\nb", 60).contains('\n'));
    }

    #[test]
    fn test_single_line_truncates_on_char_boundaries() {
        // Exactly `max` fits: no marker.
        assert_eq!(single_line(&"x".repeat(60), 60), "x".repeat(60));
        // Over budget: `max - 1` characters plus the marker = exactly `max`.
        let cut = single_line(&"x".repeat(100), 60);
        assert_eq!(cut.chars().count(), 60);
        assert_eq!(cut, format!("{}…", "x".repeat(59)));
        // Multibyte input is cut on a char boundary, never mid-codepoint.
        let cut = single_line(&"é".repeat(100), 10);
        assert_eq!(cut.chars().count(), 10);
        assert_eq!(cut, format!("{}…", "é".repeat(9)));
        assert_eq!(single_line("anything", 0), "");
    }

    #[test]
    fn test_percentile_nearest_rank() {
        assert_eq!(percentile(&[], 50), None);
        assert_eq!(percentile(&[5], 95), Some(5));
        assert_eq!(percentile(&[1, 2, 3, 4], 50), Some(2));
        assert_eq!(percentile(&[1, 2, 3, 4], 95), Some(4));
        assert_eq!(percentile(&[10, 20, 30], 50), Some(20));
        // p0 is the minimum, never an out-of-bounds index.
        assert_eq!(percentile(&[7, 8, 9], 0), Some(7));
        // p95 of 10 items is the maximum (nearest rank, no interpolation).
        assert_eq!(percentile(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 95), Some(10));
    }

    #[test]
    fn test_record_matches_host_and_failed_filters() {
        let ok = sample_record("20260922T041533Z-1", "prod-1", Some(0));
        let bad = sample_record("20260922T041534Z-2", "dev", Some(1));
        let unknown = sample_record("20260922T041535Z-3", "dev", None);

        assert!(record_matches(&ok, None, false));
        assert!(record_matches(&bad, None, false));
        // `failed` keeps non-zero AND never-observed exits, drops clean runs.
        assert!(!record_matches(&ok, None, true));
        assert!(record_matches(&bad, None, true));
        assert!(record_matches(&unknown, None, true));
        // Host matches the alias as typed or the resolved target, as a
        // case-insensitive substring.
        assert!(record_matches(&ok, Some("prod"), false));
        assert!(record_matches(&ok, Some("PROD-1"), false));
        assert!(record_matches(&ok, Some("root@prod-1"), false));
        assert!(!record_matches(&ok, Some("dev"), false));
        assert!(record_matches(&ok, Some(""), false));
    }

    #[test]
    fn test_match_context_window_and_case_folding() {
        // 3 chars of context each side of "hello" in "echo hello world".
        assert_eq!(
            match_context("echo hello world", "hello", 3, 3).as_deref(),
            Some("…ho hello wo…")
        );
        // ASCII case-insensitive, offsets preserved.
        assert_eq!(
            match_context("ECHO Hello World", "hello", 0, 0).as_deref(),
            Some("…Hello…")
        );
        assert_eq!(match_context("nothing here", "absent", 40, 40), None);
        assert_eq!(match_context("anything", "", 40, 40), None);
        // The whole text when the context covers it: no clipping markers.
        assert_eq!(
            match_context("echo hello world", "hello", 40, 40).as_deref(),
            Some("echo hello world")
        );
        // Newlines in the matched region are escaped, not printed raw.
        let fragment = match_context("a\nb MATCH c\nd", "match", 40, 40).unwrap();
        assert!(fragment.contains("\\n"), "{fragment}");
        assert!(!fragment.contains('\n'), "{fragment}");
    }

    #[test]
    fn test_json_string_field_reads_the_id() {
        assert_eq!(
            json_string_field(r#"{"id":"abc-1","host":"h"}"#, "id").as_deref(),
            Some("abc-1")
        );
        // Spacing from a pretty-printed line.
        assert_eq!(
            json_string_field(r#"{"id": "abc-2"}"#, "id").as_deref(),
            Some("abc-2")
        );
        // The key text also appearing inside another value must not fool it.
        assert_eq!(
            json_string_field(r#"{"host":"id","id":"abc-3"}"#, "id").as_deref(),
            Some("abc-3")
        );
        assert_eq!(
            json_string_field(r#"{"id":"a\"b"}"#, "id").as_deref(),
            Some("a\"b")
        );
        assert_eq!(json_string_field(r#"{"noid":"x"}"#, "id"), None);
        // A non-string value under the key is not an id.
        assert_eq!(json_string_field(r#"{"id":123}"#, "id"), None);
    }

    #[test]
    fn test_history_enabled_flag_beats_env() {
        assert!(history_enabled(false, None));
        assert!(history_enabled(false, Some("1")));
        assert!(history_enabled(false, Some("")));
        // Only the exact "0" disables via the environment.
        assert!(!history_enabled(false, Some("0")));
        // --no-history wins over everything.
        assert!(!history_enabled(true, None));
        assert!(!history_enabled(true, Some("1")));
    }

    #[test]
    fn test_rfc3339_utc_known_timestamps() {
        let at =
            |secs: u64| rfc3339_utc(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs));
        assert_eq!(at(0), "1970-01-01T00:00:00Z");
        assert_eq!(at(946_684_800), "2000-01-01T00:00:00Z");
        assert_eq!(at(1_700_000_000), "2023-11-14T22:13:20Z");
        // Leap day in a leap year (Hinnant's civil_from_days).
        assert_eq!(at(1_709_208_000), "2024-02-29T12:00:00Z");
    }

    #[test]
    fn test_history_specific_helpers() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(1024 * 1024), "1.0 MiB");

        assert_eq!(prune_max_bytes(Some(10)), 10 * 1024 * 1024);
        assert_eq!(prune_max_bytes(Some(0)), 0);
        // "No cap" must saturate, not overflow (debug builds would panic).
        assert_eq!(prune_max_bytes(None), u64::MAX);

        assert!(!remote_is_windows("Linux x86_64", Some("linux-amd64")));
        assert!(!remote_is_windows("Darwin arm64", Some("macos-arm64")));
        assert!(remote_is_windows("Windows_NT AMD64", Some("windows-amd64")));
        // Git-Bash/MSYS `uname` is not mapped to a release asset: the raw text
        // must still be recognized as Windows.
        assert!(remote_is_windows("MINGW64_NT-10.0-19045", None));
        assert!(!remote_is_windows("", None));
    }

    #[test]
    fn test_history_cli_surface_parses() {
        // `history` must reach the subcommand parser, not be eaten by the
        // optional `host` positional.
        let cli = Cli::parse_from([
            "rexec", "history", "list", "-n", "5", "--failed", "--host", "prod",
        ]);
        assert!(!cli.no_history);
        assert!(cli.host.is_none());
        match cli.action {
            Action::History {
                cmd:
                    HistoryCmd::List {
                        limit,
                        host,
                        failed,
                    },
            } => {
                assert_eq!(limit, 5);
                assert_eq!(host.as_deref(), Some("prod"));
                assert!(failed);
            }
            _ => panic!("expected `history list`"),
        }

        let cli = Cli::parse_from(["rexec", "--no-history", "history", "show", "x-1", "--meta"]);
        assert!(cli.no_history);
        match cli.action {
            Action::History {
                cmd:
                    HistoryCmd::Show {
                        id,
                        stdout,
                        stderr,
                        trace,
                        meta,
                    },
            } => {
                assert_eq!(id, "x-1");
                assert!(meta && !stdout && !stderr && !trace);
            }
            _ => panic!("expected `history show`"),
        }

        let cli = Cli::parse_from([
            "rexec", "history", "grep", "API_KEY", "--output", "--failed", "-n", "3",
        ]);
        match cli.action {
            Action::History {
                cmd:
                    HistoryCmd::Grep {
                        pattern,
                        limit,
                        host,
                        failed,
                        output,
                    },
            } => {
                assert_eq!(pattern, "API_KEY");
                assert_eq!(limit, 3);
                assert!(host.is_none() && failed && output);
            }
            _ => panic!("expected `history grep`"),
        }

        let cli = Cli::parse_from([
            "rexec",
            "history",
            "prune",
            "--keep-days",
            "7",
            "--max-mb",
            "50",
        ]);
        match cli.action {
            Action::History {
                cmd: HistoryCmd::Prune { keep_days, max_mb },
            } => {
                assert_eq!(keep_days, 7);
                assert_eq!(max_mb, Some(50));
            }
            _ => panic!("expected `history prune`"),
        }

        // Defaults: `list` limit 20, `fetch` without --out.
        let cli = Cli::parse_from(["rexec", "history", "list"]);
        match cli.action {
            Action::History {
                cmd: HistoryCmd::List { limit, .. },
            } => assert_eq!(limit, 20),
            _ => panic!("expected `history list`"),
        }
        let cli = Cli::parse_from(["rexec", "history", "fetch", "x-1"]);
        match cli.action {
            Action::History {
                cmd: HistoryCmd::Fetch { id, out },
            } => {
                assert_eq!(id, "x-1");
                assert!(out.is_none());
            }
            _ => panic!("expected `history fetch`"),
        }
        // `host` plus `history` is rejected at dispatch, not parsed as a run.
        let cli = Cli::parse_from(["rexec", "myhost", "history", "path"]);
        assert_eq!(cli.host.as_deref(), Some("myhost"));
        assert!(matches!(
            cli.action,
            Action::History {
                cmd: HistoryCmd::Path
            }
        ));
    }

    #[test]
    fn test_history_show_rejects_multiple_selectors() {
        let err = history_show("20260922T041533Z-1", true, true, false, false).unwrap_err();
        assert!(err.to_string().contains("at most one"), "{err}");
    }

    #[test]
    fn test_build_record_maps_summary_capture_and_trace() {
        let mut cap = RunCapture::new("echo hi", &[("K".to_string(), "V".to_string())]);
        cap.stdout.push(b"hello");
        cap.stderr.push(b"oops");
        let summary = diagnostics::RunSummary {
            host: "prod".to_string(),
            resolved: "root@10.0.0.5:22".to_string(),
            pid: Some(7),
            exit_code: Some(1),
            duration_ms: Some(1234),
            deployed: true,
            stdout_bytes: 5,
            stderr_bytes: 4,
            log_path: None,
            error: None,
        };
        let mut trace = diagnostics::Trace::default();
        trace.add("resolve: alias prod → root@10.0.0.5:22");

        let rec = build_record(&cap, &summary, &trace);
        assert_eq!(rec.id, cap.id);
        assert!(
            rec.id.ends_with(&format!("-{}", std::process::id())),
            "{}",
            rec.id
        );
        assert_eq!(rec.ts_start, cap.ts_start);
        assert!(
            rec.ts_start.ends_with('Z') && rec.ts_start.len() == 20,
            "{}",
            rec.ts_start
        );
        assert_eq!(rec.duration_ms, 1234);
        assert_eq!(rec.host, "prod");
        assert_eq!(rec.resolved, "root@10.0.0.5:22");
        assert_eq!(rec.command, "echo hi");
        assert_eq!(rec.env, vec![("K".to_string(), "V".to_string())]);
        assert_eq!(rec.exit_code, Some(1));
        assert_eq!(rec.pid, Some(7));
        assert!(rec.deployed);
        assert_eq!((rec.stdout_bytes, rec.stderr_bytes), (5, 4));
        assert!(!rec.stdout_truncated && !rec.stderr_truncated);
        assert_eq!(rec.rexec_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(
            rec.trace,
            vec!["resolve: alias prod → root@10.0.0.5:22".to_string()]
        );

        // A duration that was never measured (the run died before the boundary
        // could time it) records as 0 rather than panicking.
        let untimed = diagnostics::RunSummary {
            duration_ms: None,
            exit_code: None,
            ..summary
        };
        let rec = build_record(&cap, &untimed, &trace);
        assert_eq!(rec.duration_ms, 0);
        assert_eq!(rec.exit_code, None);
    }

    #[test]
    fn test_run_capture_marks_truncation_at_the_cap() {
        let mut cap = RunCapture::new("cat big", &[]);
        assert!(!cap.stdout.truncated());
        cap.stdout.push(&vec![b'x'; history::CAPTURE_LIMIT + 1]);
        assert!(cap.stdout.truncated());
        assert_eq!(cap.stdout.total(), history::CAPTURE_LIMIT as u64 + 1);
        // The untouched stream stays untruncated and empty.
        assert!(!cap.stderr.truncated());
        assert!(cap.stderr.captured().is_empty());
    }
}

/// Simple shell quoting for a single argument.
/// Rejects null bytes to prevent command injection via C-string truncation.
fn shell_quote(s: &str) -> Result<String> {
    if s.contains('\0') {
        return Err(anyhow!("command contains null byte — rejected for safety"));
    }
    Ok(format!("'{}'", s.replace('\'', "'\"'\"'")))
}

/// `rexec <CARGO_PKG_VERSION>` — the version string a remote worker must
/// answer to count as up to date (same comparison `ssh.rs` makes).
fn local_worker_version() -> String {
    format!("rexec {}", env!("CARGO_PKG_VERSION"))
}

/// Remote worker version, read as `--version` output (`rexec x.y.z`), or
/// `None` when nothing readable answers. Never deploys.
///
/// `cmd /c` is probed first because it is harmless on a POSIX remote
/// (`cmd: command not found`), while the POSIX probe must NOT run on a Windows
/// remote: `2>/dev/null` is not a cmd redirect and would create a stray
/// `<drive>:\dev\null` (see `ssh::detect_remote_asset`). `%USERPROFILE%` is
/// expanded by the nested `cmd`.
async fn probe_remote_worker_version(
    session: &russh::client::Handle<ssh::ClientHandler>,
) -> Option<String> {
    let windows = ssh::exec_remote(
        session,
        r#"cmd /c ""%USERPROFILE%\.rexec\rexec.exe" --version""#,
    )
    .await
    .unwrap_or_default();
    let output = if windows.trim().is_empty() {
        ssh::exec_remote(session, "~/.rexec/rexec --version 2>/dev/null")
            .await
            .unwrap_or_default()
    } else {
        windows
    };
    let version = output.trim();
    if version.is_empty() {
        None
    } else {
        Some(version.to_string())
    }
}

/// Error for a worker that died before its Started frame.
///
/// The worker's own stderr is the only explanation available for a failure
/// that early (e.g. "worker requires a command over stdin" from an unexpected
/// invocation, or a binary that cannot run on the remote), so the message
/// carries it together with the launch command that was attempted. The
/// decision trace is appended by the CLI boundary to every failure, not
/// duplicated here.
fn worker_start_failure(worker_stderr: &[u8], worker_cmd: &str, host: &str) -> anyhow::Error {
    let text = String::from_utf8_lossy(worker_stderr);
    let text = text.trim();
    let mut msg = String::from("connection lost before worker started");
    msg.push_str("\nworker stderr: ");
    msg.push_str(if text.is_empty() { "(none)" } else { text });
    msg.push_str(&format!("\nlaunch command: {worker_cmd}"));
    msg.push_str(&format!(
        "\nhint: `rexec {host} init` checks the remote deps; a worker that cannot run leaves its \
         error above"
    ));
    anyhow!(msg)
}

/// Where the worker's log for `pid` lives on the remote, as a hint the user
/// can paste into `ssh`. Windows remotes need the literal profile path —
/// cmd.exe does not expand `~`.
fn remote_log_hint(remote_env: &ssh::RemoteEnv, pid: u32) -> String {
    if remote_env.is_windows {
        format!(
            "{}\\.rexec\\logs\\{}.log",
            remote_env.home.trim_end_matches('\\'),
            pid
        )
    } else {
        format!("~/.rexec/logs/{pid}.log")
    }
}

/// Everything the CLI boundary needs to write a history record, filled by
/// `run_command` before it touches the remote so a failure still leaves a
/// record ("why did that fail?" is exactly what history is for).
///
/// Kept out of `diagnostics::RunSummary` on purpose: that struct is the
/// `--json` contract (field order unit-tested), while the history record's
/// extra inputs — command, env, raw captures — are history-only and threaded
/// separately rather than widening the machine-readable summary.
struct RunCapture {
    id: String,
    ts_start: String,
    command: String,
    env: Vec<(String, String)>,
    stdout: history::RingCapture,
    stderr: history::RingCapture,
}

impl RunCapture {
    /// Start capturing a run whose command and env are already known.
    fn new(command: &str, env: &[(String, String)]) -> Self {
        Self {
            id: history::new_id(std::process::id()),
            ts_start: rfc3339_utc(std::time::SystemTime::now()),
            command: command.to_string(),
            env: env.to_vec(),
            stdout: history::RingCapture::new(history::CAPTURE_LIMIT),
            stderr: history::RingCapture::new(history::CAPTURE_LIMIT),
        }
    }
}

/// Assemble the record for a finished run from the summary, the capture and the
/// decision trace. Split out of [`record_history`] so the mapping is
/// unit-testable without writing into the real history tree.
fn build_record(
    cap: &RunCapture,
    summary: &diagnostics::RunSummary,
    trace: &diagnostics::Trace,
) -> history::RunRecord {
    history::RunRecord {
        id: cap.id.clone(),
        ts_start: cap.ts_start.clone(),
        duration_ms: summary.duration_ms.unwrap_or(0),
        host: summary.host.clone(),
        resolved: summary.resolved.clone(),
        command: cap.command.clone(),
        env: cap.env.clone(),
        exit_code: summary.exit_code,
        pid: summary.pid,
        deployed: summary.deployed,
        // The captures' own totals are the authoritative byte counts: they are
        // what the stored logs contain (and where truncation applies), so a
        // record can never disagree with its own artifacts.
        stdout_bytes: cap.stdout.total(),
        stderr_bytes: cap.stderr.total(),
        stdout_truncated: cap.stdout.truncated(),
        stderr_truncated: cap.stderr.truncated(),
        rexec_version: env!("CARGO_PKG_VERSION").to_string(),
        trace: trace.lines().to_vec(),
        // Only rexec-level failures carry an error here; a remote non-zero exit
        // is already visible in `exit_code`.
        error: summary.error.clone(),
    }
}

/// Write the history record for a finished run — success OR failure.
///
/// Best-effort by contract: history must never change a run's outcome or exit
/// status, so a write error is one warning line on stderr and nothing more.
/// `None` means recording is off for this invocation: nothing was captured.
fn record_history(
    capture: Option<&RunCapture>,
    summary: &diagnostics::RunSummary,
    trace: &diagnostics::Trace,
) {
    let Some(cap) = capture else { return };
    let rec = build_record(cap, summary, trace);
    if let Err(e) = history::record(&rec, Some(&cap.stdout), Some(&cap.stderr)) {
        ensure_stderr_line_start();
        eprintln!("⚠ history: {e:#}");
    }
}

/// Core run logic: deploy worker, stream output, reconnect on disconnect.
///
/// Every decision lands in `trace` (printed on failure in any mode, on success
/// only under `-v`) and every measured fact lands in `summary` (`--json`).
///
/// `unused_assignments`: `session = new_session` on reconnect keeps the SSH
/// handle alive (channel holds an implicit ref), but the compiler can't see it.
#[allow(unused_assignments)]
async fn run_command(
    remote: &RemoteHost,
    host: &str,
    command: &str,
    env: &[(String, String)],
    trace: &mut diagnostics::Trace,
    summary: &mut diagnostics::RunSummary,
    capture: &mut Option<RunCapture>,
) -> Result<()> {
    summary.resolved = resolved_label(remote);

    // Record the intent before the first remote touch: the command and its env
    // are already known, so even a failure to connect leaves an analyzable
    // record (the ring captures are only allocated when recording is on).
    // A capture created earlier (pre-flight, in the CLI arm) keeps its id and
    // start time; only the command/env it could not know yet are filled in.
    if history::enabled() {
        match capture {
            Some(cap) => {
                cap.command = command.to_string();
                cap.env = env.to_vec();
            }
            None => *capture = Some(RunCapture::new(command, env)),
        }
    }

    let mut session = ssh::connect_traced(remote, trace).await?;

    let remote_env = ssh::ensure_remote_binary_traced(&mut session, host, trace).await?;
    // `|=`: `script` runs may already have deployed during their pre-flight
    // check, and this call then sees an up-to-date worker (false) — the run
    // still deployed, and the record/JSON must say so.
    summary.deployed |= remote_env.deployed;

    // Start worker on remote. The command itself is NOT passed on argv (so
    // `pkill -f`/`pgrep -f` cannot match the worker by command content); it is
    // sent over stdin as a special env entry, alongside any -e/--env vars.
    // The launch command is platform-correct: POSIX `~` does not expand under
    // cmd.exe/PowerShell on Windows remotes.
    let worker_cmd = remote_env.worker_command();
    trace.add(format!("worker: launching `{worker_cmd}`"));
    let mut channel = session.channel_open_session().await?;
    channel.exec(true, worker_cmd.clone()).await?;

    // Send the command + environment to the worker over the channel's stdin.
    // The worker reads these before spawning the child, so neither the command
    // nor secrets appear in the remote process's argv (ps).
    // Format: `__REXEC_CMD__=<command>\0` first, then `KEY=VALUE\0`..., EOF.
    let mut payload = Vec::new();
    payload.extend_from_slice(b"__REXEC_CMD__=");
    payload.extend_from_slice(command.as_bytes());
    payload.push(0);
    for (k, v) in env {
        payload.extend_from_slice(k.as_bytes());
        payload.push(b'=');
        payload.extend_from_slice(v.as_bytes());
        payload.push(0);
    }
    channel.data(payload.as_slice()).await?;
    // Signal stdin EOF so the worker's read completes.
    channel.eof().await?;

    let mut frame_reader = FrameReader::new();
    let mut offset: u64 = 0;
    // base_offset preserves the total log-file offset across FrameReader resets.
    // After reconnection, frame_reader is reset to 0, so:
    //   offset = base_offset + frame_reader.consumed_bytes()
    let mut base_offset: u64 = 0;
    let mut pid: Option<u32> = None;
    // The worker's OWN stderr (SSH extended data — the command's stderr arrives
    // as protocol frames). Streamed through as it arrives and kept for the
    // "worker died before it started" error, where it is the only explanation
    // available.
    let mut worker_stderr: Vec<u8> = Vec::new();
    // Track whether signal handler is available — if it fails to init,
    // stop polling sig_rx to avoid busy-loop on None.
    let mut signal_available = true;

    // Signal handler: print remote info and exit on Ctrl+C / SIGTERM.
    // Both platforms only ever send `()` on sig_tx, so the select! arms below
    // stay platform-independent.
    let (sig_tx, mut sig_rx) = tokio::sync::mpsc::channel::<()>(1);
    tokio::spawn(async move {
        // unix: SIGINT + SIGTERM. A console process on Windows has no SIGTERM,
        // so ctrl_c() (Ctrl+C / Ctrl+Break) covers the same user intent.
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigint = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => return,
            };
            tokio::select! {
                _ = sigint.recv() => {}
                _ = sigterm.recv() => {}
            }
        }
        #[cfg(windows)]
        {
            // Err means the handler could not be installed: drop the task so the
            // receiver sees None and warns once — same as a failed unix signal().
            if tokio::signal::ctrl_c().await.is_err() {
                return;
            }
        }
        let _ = sig_tx.send(()).await;
    });

    loop {
        tokio::select! {
            // Signal received — print remote info and exit
            sig = async {
                if signal_available { sig_rx.recv().await }
                else { std::future::pending::<Option<()>>().await }
            } => {
                if sig.is_none() {
                    // Signal handler task failed to init — disable polling to avoid busy-loop
                    signal_available = false;
                    status!("⚠ Signal handler unavailable; Ctrl+C will not work");
                    continue;
                }
                if let Some(p) = pid {
                    status!(
                        "⚠ Interrupted by signal. Remote process still running.\n  PID: {}",
                        p
                    );
                }
                return Ok(());
            }
            // Normal channel reading
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { ref data }) => {
                        frame_reader.push(data);
                        while let Some(frame) = frame_reader.next_frame() {
                            // Track offset at frame boundaries, not raw SSH bytes
                            offset = base_offset + frame_reader.consumed_bytes();
                            match frame.frame_type {
                                FrameType::Stdout => {
                                    use std::io::Write;
                                    summary.stdout_bytes += frame.data.len() as u64;
                                    if let Some(cap) = capture.as_mut() {
                                        cap.stdout.push(&frame.data);
                                    }
                                    let stdout = std::io::stdout();
                                    let mut lock = stdout.lock();
                                    lock.write_all(&frame.data)?;
                                    lock.flush()?;
                                }
                                FrameType::Stderr => {
                                    use std::io::Write;
                                    summary.stderr_bytes += frame.data.len() as u64;
                                    if let Some(cap) = capture.as_mut() {
                                        cap.stderr.push(&frame.data);
                                    }
                                    note_stderr_write(&frame.data);
                                    // Interactive stderr gets the remote's error
                                    // output in red; piped/agent use stays
                                    // byte-pure (no escape sequences).
                                    let stderr = std::io::stderr();
                                    let mut lock = stderr.lock();
                                    if diagnostics::stderr_is_tty() {
                                        lock.write_all(
                                            diagnostics::red(&String::from_utf8_lossy(&frame.data))
                                                .as_bytes(),
                                        )?;
                                    } else {
                                        lock.write_all(&frame.data)?;
                                    }
                                    lock.flush()?;
                                }
                                FrameType::Started => {
                                    pid = frame.as_pid();
                                    if let Some(p) = pid {
                                        summary.pid = Some(p);
                                        trace.add(format!("worker: started (pid {p})"));
                                        progress!("Remote PID: {}", p);
                                    }
                                }
                                FrameType::Exited => {
                                    use std::io::Write;
                                    std::io::stdout().flush()?;
                                    let code = frame.as_exit_code().unwrap_or(-1);
                                    summary.exit_code = Some(code);
                                    trace.add(format!("exit: remote code {code}"));
                                    if code == 0 {
                                        // Success is silent by default; only -v
                                        // reports it.
                                        progress!("✓ Remote process exited");
                                    } else {
                                        // A warning, not progress: it prints in
                                        // every mode. The exit code and where
                                        // the full log lives are exactly what
                                        // the caller needs, and staying silent
                                        // here would hide a failed run.
                                        let log = match pid {
                                            Some(p) => remote_log_hint(&remote_env, p),
                                            None => "~/.rexec/logs/<pid>.log".to_string(),
                                        };
                                        ensure_stderr_line_start();
                                        eprintln!("⚠ remote exit {} (log: {})", code, log);
                                        // Propagate as rexec's own status (ssh
                                        // semantics); the boundary reads it.
                                        REMOTE_EXIT.store(code, Ordering::Relaxed);
                                    }
                                    return Ok(());
                                }
                                _ => {}
                            }
                        }
                    }
                    Some(ChannelMsg::ExitStatus { .. }) => {}
                    Some(ChannelMsg::ExtendedData { ref data, ext }) => {
                        // The worker's OWN stderr (SSH extended data, ext 1).
                        // Startup failures ("worker requires a command over
                        // stdin") only ever arrive here — dropping them is why
                        // a worker that died before the Started frame used to
                        // fail with a bare "connection lost".
                        if ext == 1 {
                            use std::io::Write;
                            let stderr = std::io::stderr();
                            let mut lock = stderr.lock();
                            lock.write_all(data)?;
                            lock.flush()?;
                            summary.stderr_bytes += data.len() as u64;
                            if let Some(cap) = capture.as_mut() {
                                cap.stderr.push(data);
                            }
                            note_stderr_write(data);
                            worker_stderr.extend_from_slice(data);
                            if worker_stderr.len() > WORKER_STDERR_KEEP {
                                let excess = worker_stderr.len() - WORKER_STDERR_KEEP;
                                worker_stderr.drain(..excess);
                            }
                        }
                    }
                    Some(ChannelMsg::Eof) | None => {
                        // Channel closed — try to reconnect
                        let pid_val = match pid {
                            Some(p) => p,
                            None => return Err(worker_start_failure(&worker_stderr, &worker_cmd, host)),
                        };

                        progress!(
                            "⚠ Connection lost. Remote process still running.\n  PID: {}",
                            pid_val
                        );
                        trace.add(format!(
                            "reconnect: connection lost at offset {offset} (pid {pid_val})"
                        ));

                        // Reconnect with exponential backoff
                        let mut backoff = Duration::from_secs(1);
                        let max_backoff = Duration::from_secs(30);
                        let max_retries = 10;
                        let mut reconnected = false;

                        for retry in 1..=max_retries {
                            progress!(
                                "  Retry {}/{} in {:?}...",
                                retry, max_retries, backoff
                            );
                            // Allow Ctrl+C during backoff
                            tokio::select! {
                                _ = tokio::time::sleep(backoff) => {}
                                sig = async {
                                    if signal_available { sig_rx.recv().await }
                                    else { std::future::pending::<Option<()>>().await }
                                } => {
                                    if sig.is_none() {
                                        signal_available = false;
                                        status!("⚠ Signal handler unavailable");
                                        continue;
                                    }
                                    if let Some(p) = pid {
                                        status!(
                                            "⚠ Interrupted by signal. Remote process still running.\n  PID: {}",
                                            p
                                        );
                                    }
                                    return Ok(());
                                }
                            }
                            backoff = (backoff * 2).min(max_backoff);

                            match ssh::connect_traced(remote, trace).await {
                                Ok(new_session) => {
                                    let attach_cmd =
                                        remote_env.attach_command(pid_val, offset);
                                    match new_session.channel_open_session().await {
                                        Ok(new_channel) => {
                                            match new_channel.exec(true, attach_cmd.as_str()).await {
                                                Ok(()) => {
                                                    session = new_session;
                                                    channel = new_channel;
                                                    // Preserve total offset across FrameReader reset
                                                    base_offset = offset;
                                                    frame_reader = FrameReader::new();
                                                    progress!("✓ Reconnected. Resuming...");
                                                    trace.add(format!(
                                                        "reconnect: resumed at offset {offset}"
                                                    ));
                                                    reconnected = true;
                                                    break;
                                                }
                                                Err(e) => {
                                                    progress!("  Failed to exec attach: {}", e);
                                                    continue;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            progress!("  Failed to open channel: {}", e);
                                            continue;
                                        }
                                    }
                                }
                                Err(_) => {
                                    continue;
                                }
                            }
                        }

                        if !reconnected {
                            return Err(anyhow!(
                                "connection lost after {} retries. Remote PID: {}. The remote process \
                                 may still be running — re-attach with `ssh {} \"~/.rexec/rexec attach \
                                 --pid {} --offset {}\"`",
                                max_retries,
                                pid_val,
                                host,
                                pid_val,
                                offset
                            ));
                        }
                        // Continue reading from the new (attach) channel
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Collect env vars from `-e/--env` flags first, then `--env-file` contents.
fn collect_env(env: &[String], env_file: &[PathBuf]) -> Result<Vec<(String, String)>> {
    let mut env_vars: Vec<(String, String)> = Vec::new();
    for e in env {
        let Some((k, v)) = e.split_once('=') else {
            // The argument IS the secret in this case (a value pasted without
            // its KEY= prefix), so it is never echoed.
            return Err(if reveal_secrets() {
                anyhow!("--env expects KEY=VALUE, got '{}'", e)
            } else {
                anyhow!(
                    "--env expects KEY=VALUE ({} bytes, not shown — --reveal-secrets prints it)",
                    e.len()
                )
            });
        };
        if k.is_empty() {
            return Err(if reveal_secrets() {
                anyhow!("--env key is empty in '{}'", e)
            } else {
                anyhow!("--env key is empty (value not shown — --reveal-secrets prints it)")
            });
        }
        env_vars.push((k.to_string(), v.to_string()));
    }
    for f in env_file {
        env_vars.extend(parse_env_file(f)?);
    }
    Ok(env_vars)
}

/// Decide how to run a script. Returns `None` to execute it directly (script has
/// a `#!` shebang), or `Some(cmd)` to run it via `cmd <script>`.
fn detect_runner(script: &Path) -> Result<Option<String>> {
    use std::io::Read;
    let mut f = std::fs::File::open(script)
        .with_context(|| format!("opening script {}", script.display()))?;
    let mut buf = [0u8; 2];
    let n = f.read(&mut buf)?;
    if n == 2 && &buf == b"#!" {
        return Ok(None); // shebang → direct exec
    }
    match script.extension().and_then(|e| e.to_str()) {
        Some("py") => Ok(Some("python3".to_string())),
        _ => Ok(Some("sh".to_string())),
    }
}

/// Sync a local script to the remote and run it (the `script` subcommand).
///
/// Ten parameters is the lint threshold, but they are distinct borrows threaded
/// straight from `main()` (the three instrumentation borrows — trace, summary,
/// capture — are shared with `run_command`); grouping them into a struct would
/// only rename the same fields and re-plumb every call site.
#[allow(clippy::too_many_arguments)]
async fn run_script(
    remote: &RemoteHost,
    host: &str,
    script: &Path,
    interpreter: Option<&str>,
    sync_to: Option<&str>,
    args: &[String],
    env_vars: &[(String, String)],
    trace: &mut diagnostics::Trace,
    summary: &mut diagnostics::RunSummary,
    capture: &mut Option<RunCapture>,
) -> Result<()> {
    let basename = script
        .file_name()
        .ok_or_else(|| {
            anyhow!(
                "cannot determine script file name from {}",
                script.display()
            )
        })?
        .to_string_lossy()
        .to_string();

    // Ensure the remote dir exists (single-file rsync does not create parents)
    // and resolve it to an absolute path. Using an absolute path for the
    // runner command avoids relying on shell tilde expansion, which quoting
    // would disable (python3 '$HOME/...' does not expand).
    let remote_script = {
        let mut session = ssh::connect_traced(remote, trace).await?;
        // `script` requires rsync (do_sync below) and a POSIX remote path
        // model — reject Windows remotes up front instead of wasting a full
        // SFTP worker deploy and then failing in the rsync step.
        // The deploy decision flows from `RemoteEnv.deployed` (`|=`: this
        // call may deploy, and the later one in run_command then sees an
        // up-to-date worker).
        let env = ssh::ensure_remote_binary_traced(&mut session, host, trace).await?;
        summary.deployed |= env.deployed;
        if env.is_windows {
            return Err(anyhow!(
                "`script` requires a Linux/macOS remote (rsync + POSIX paths); this host is Windows"
            ));
        }
        let home = ssh::exec_remote(&mut session, "printf %s \"$HOME\"")
            .await?
            .trim()
            .to_string();
        let dir = match sync_to {
            Some(s) if s.starts_with('~') => format!("{}{}", home, &s[1..]),
            Some(s) => s.to_string(),
            None => format!("{}/.rexec/scripts", home),
        };
        ssh::exec_remote(&mut session, &format!("mkdir -p {}", shell_quote(&dir)?)).await?;
        format!("{}/{}", dir, basename)
    };

    do_sync(script, &remote_script, remote).await?;

    let runner = match interpreter {
        Some(i) => Some(i.to_string()),
        None => detect_runner(script)?,
    };
    let mut parts: Vec<String> = Vec::new();
    match &runner {
        Some(r) => {
            parts.push(r.clone());
            parts.push(shell_quote(&remote_script)?);
        }
        None => {
            // shebang: chmod +x then run directly
            let q = shell_quote(&remote_script)?;
            parts.push(format!("chmod +x {} && {}", q, q));
        }
    }
    for a in args {
        parts.push(shell_quote(a)?);
    }
    let command = parts.join(" ");
    trace.add(format!(
        "script: synced {} → {remote_script}",
        script.display()
    ));
    run_command(remote, host, &command, env_vars, trace, summary, capture).await?;
    Ok(())
}

/// Release assets rexec ships, e.g. `linux-amd64` — display only, mirroring
/// `ssh::local_asset` (private there). Used by `plan` to say whether a run
/// would upload itself or download a prebuilt worker; it never decides a real
/// deploy, which always stays in `ssh.rs`.
fn local_release_asset() -> String {
    let arch = if std::env::consts::ARCH == "x86_64" {
        "amd64"
    } else {
        "arm64"
    };
    format!("{}-{arch}", std::env::consts::OS)
}

/// Release-asset suffix for a remote platform probe ("Linux x86_64" →
/// "linux-amd64", "Windows_NT AMD64" → "windows-amd64").
///
/// Display only, for `plan`: mirrors `ssh::uname_asset` (private there). An
/// unmapped probe returns `None`, which the plan reports as "platform
/// unrecognized" instead of guessing.
fn plan_remote_asset(probe: &str) -> Option<String> {
    let tokens: Vec<&str> = probe.split_whitespace().collect();
    if tokens.contains(&"Windows_NT") {
        return if tokens.contains(&"AMD64") {
            Some("windows-amd64".to_string())
        } else if tokens.contains(&"ARM64") {
            Some("windows-arm64".to_string())
        } else {
            None
        };
    }
    match (tokens.first(), tokens.get(1)) {
        (Some(&"Linux"), Some(&"x86_64")) => Some("linux-amd64".to_string()),
        (Some(&"Linux"), Some(&"aarch64")) => Some("linux-arm64".to_string()),
        (Some(&"Darwin"), Some(&"x86_64")) => Some("macos-amd64".to_string()),
        (Some(&"Darwin"), Some(&"arm64")) => Some("macos-arm64".to_string()),
        _ => None,
    }
}

/// GitHub repo hosting prebuilt workers — keep in sync with `ssh::GITHUB_REPO`
/// (private there); used only to render the `plan` download URL.
const WORKER_RELEASE_REPO: &str = "NolanHo/rexec";

/// Release URL a cross-platform deploy would download — display only, mirroring
/// the URL built by `ssh::download_worker`.
fn worker_release_url(asset: &str) -> String {
    format!(
        "https://github.com/{}/releases/download/v{}/rexec-{}",
        WORKER_RELEASE_REPO,
        env!("CARGO_PKG_VERSION"),
        asset
    )
}

/// Read-only platform probe for `plan` ("Linux x86_64"). Mirrors the probe
/// commands of `ssh::detect_remote_asset`, which is private and deploys when it
/// runs; this one only ever reads, so a plan cannot mutate the remote.
async fn probe_remote_platform(
    session: &russh::client::Handle<ssh::ClientHandler>,
) -> (String, Option<String>) {
    let uname = ssh::exec_remote(session, "uname -sm")
        .await
        .unwrap_or_default();
    if let Some(asset) = plan_remote_asset(&uname) {
        return (uname.trim().to_string(), Some(asset));
    }
    // No usable `uname` (Windows remote, or Git-Bash's `MINGW64_NT...`):
    // ask cmd.exe, exactly as ssh.rs does.
    let windows = ssh::exec_remote(
        session,
        r#"cmd /c "echo Windows_NT %PROCESSOR_ARCHITECTURE%""#,
    )
    .await
    .unwrap_or_default();
    let asset = plan_remote_asset(&windows);
    let raw = if windows.trim().is_empty() {
        uname.trim().to_string()
    } else {
        windows.trim().to_string()
    };
    (raw, asset)
}

/// Absolute Windows home, for the launch-command display (cmd.exe cannot
/// expand `~`). Mirrors `ssh::remote_home_windows` (private there).
async fn probe_windows_home(session: &russh::client::Handle<ssh::ClientHandler>) -> String {
    ssh::exec_remote(session, r#"cmd /c "echo %USERPROFILE%""#)
        .await
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// `rexec <host> plan -- <cmd>`: everything up to (but not including) the
/// worker launch.
///
/// Connects, resolves, probes the remote platform and the installed worker,
/// prints what a run WOULD do, and exits 0 — without executing the command and
/// without deploying anything. The deploy decision is recomputed from
/// read-only probes because `ssh::ensure_remote_binary_traced` has no dry-run
/// mode and its helpers are private; nothing here can mutate the remote.
async fn plan_command(
    remote: &RemoteHost,
    host: &str,
    command: &str,
    trace: &mut diagnostics::Trace,
    summary: &mut diagnostics::RunSummary,
) -> Result<()> {
    summary.resolved = resolved_label(remote);

    let session = ssh::connect_traced(remote, trace).await?;

    let (platform, asset) = probe_remote_platform(&session).await;
    let remote_version = probe_remote_worker_version(&session).await;
    let local_version = local_worker_version();

    // Reuse ssh.rs's launch-command shapes through the public `RemoteEnv`
    // fields — the display cannot drift from the real command, and building it
    // deploys nothing.
    let is_windows = asset.as_deref().is_some_and(|a| a.starts_with("windows-"));
    let home = if is_windows {
        probe_windows_home(&session).await
    } else {
        String::new()
    };
    let launch = ssh::RemoteEnv {
        is_windows,
        home,
        deployed: false,
    }
    .worker_command();

    let remote_label = remote_version
        .clone()
        .unwrap_or_else(|| "not installed (or no readable version)".to_string());
    let deploy = match (&remote_version, &asset) {
        (Some(v), _) if *v == local_version => {
            format!("nothing — remote worker {v} is up-to-date")
        }
        (_, Some(a)) if *a == local_release_asset() => {
            format!("upload self — the local {local_version} binary (remote asset {a})")
        }
        (_, Some(a)) => format!("download {a} from {}", worker_release_url(a)),
        (_, None) => format!(
            "worker would be (re)installed — the remote platform is unrecognized, so the source \
             depends on the platform match (local asset {})",
            local_release_asset()
        ),
    };

    let platform_label = match &asset {
        Some(a) => format!("{platform} (asset {a})"),
        None => format!("{platform} (unrecognized)"),
    };

    // The plan body IS the command's purpose (like `list`'s table), so it goes
    // to stdout in every mode; the same decisions are recorded in the trace.
    println!("plan: {host} ({})", resolved_label(remote));
    if !remote.jump.is_empty() {
        println!("  route:    {}", jump_chain_label(remote));
    }
    println!("  platform: {platform_label}");
    println!("  worker:   remote {remote_label}; local {local_version}");
    println!("  deploy:   {deploy}");
    println!("  launch:   {launch}");
    println!(
        "  command:  {}",
        if command.is_empty() {
            "(none given)"
        } else {
            command
        }
    );
    println!(
        "  indirection: the command travels to the worker over stdin (never in any process's \
         argv/ps);"
    );
    println!(
        "               the worker writes it to a private script file and runs `sh <script>` \
         (`cmd /C` on Windows),"
    );
    println!(
        "               deleted on exit — to run a local file, sync it with `rexec {host} script \
         <file>`."
    );
    println!("  note: plan only — connected and probed; nothing was executed or deployed.");

    trace.add(format!("plan: route {}", jump_chain_label(remote)));
    trace.add(format!("plan: platform {platform_label}"));
    trace.add(format!(
        "plan: worker remote {remote_label} vs local {local_version}"
    ));
    trace.add(format!("plan: deploy would be {deploy}"));
    trace.add(format!("plan: launch `{launch}` (not executed)"));
    Ok(())
}

/// List SSH hosts from ~/.ssh/config (the `list` subcommand).
/// One row of `rexec list`: everything the table can show, collected once so
/// filtering, the short/long shapes and `--json` all read the same data.
struct HostEntry {
    alias: String,
    hostname: String,
    port: u16,
    user: String,
    /// Resolved `IdentityFile` (first one configured), shown in `--long`.
    identity: Option<String>,
    description: Option<String>,
}

impl HostEntry {
    /// The endpoint as it will actually be contacted: `host:port`, with an IPv6
    /// literal bracketed so the port stays readable (`[fe80::1]:22`).
    ///
    /// The port belongs to "which machine this is", not to stage-two detail: the
    /// same gateway host carries one forwarded port per container, so an alias
    /// without its port identifies nothing. It is shown in the default table and
    /// `--long` alike, and `--filter` substring/glob matches it.
    fn address(&self) -> String {
        // Brackets are syntax, never part of the host (ssh.rs strips them before
        // connecting): normalize first, or a config that writes `HostName [::1]`
        // would render as `[[::1]]:22`.
        let host = self
            .hostname
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(&self.hostname);
        if host.contains(':') {
            format!("[{host}]:{}", self.port)
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// Descriptions for hosts, from two places (a sidecar entry wins):
///
/// 1. A `# rexec: <text>` comment line directly above a `Host` line in the
///    ssh config — including `Include`d files, because the config is read
///    through the Include-expanding loader. The comment attaches to every
///    concrete pattern on that line (wildcards and negations are skipped).
/// 2. `~/.rexec/hosts.conf`, one `alias = description` per line (`#` comments
///    and blank lines ignored) — for aliases whose config lives somewhere you
///    do not want to edit, or that come from a generator.
fn host_descriptions(config_path: &Path) -> std::collections::HashMap<String, String> {
    let text = load_ssh_config_text(config_path).unwrap_or_default();
    let mut out = descriptions_from_config_text(&text);
    if let Some(home) = dirs::home_dir() {
        // Sidecar entries win: they are the explicit, rexec-owned annotation.
        out.extend(descriptions_from_sidecar(
            &home.join(".rexec").join("hosts.conf"),
        ));
    }
    out
}

/// The `# rexec: <text>` half of [`host_descriptions`], over an already
/// Include-expanded config text.
fn descriptions_from_config_text(text: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let mut pending: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed
            .strip_prefix('#')
            .map(str::trim_start)
            .and_then(|c| {
                c.strip_prefix("rexec:")
                    .or_else(|| c.strip_prefix("REXEC:"))
            })
        {
            let text = rest.trim();
            if !text.is_empty() {
                pending = Some(text.to_string());
            }
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue; // blank/other comments keep the annotation attached
        }
        if is_host_line(line) {
            let patterns = trimmed
                .split_once(|c: char| c.is_whitespace() || c == '=')
                .map(|(_, rest)| rest)
                .unwrap_or("")
                .trim_start_matches('=')
                .split_whitespace();
            if let Some(desc) = &pending {
                for p in patterns {
                    if p != "*" && !p.starts_with('!') {
                        out.entry(p.to_string()).or_insert_with(|| desc.clone());
                    }
                }
            }
            pending = None;
            continue;
        }
        // Any other directive ends the annotation's reach.
        pending = None;
    }

    out
}

/// The `~/.rexec/hosts.conf` half: one `alias = description` per line.
///
/// Read errors (missing file included) yield an empty map — a listing must not
/// fail because an optional annotation file is absent.
fn descriptions_from_sidecar(path: &Path) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let Ok(content) = std::fs::read_to_string(path) else {
        return out;
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((alias, desc)) = line.split_once('=') {
            let (alias, desc) = (alias.trim(), desc.trim());
            if !alias.is_empty() && !desc.is_empty() {
                out.insert(alias.to_string(), desc.to_string());
            }
        }
    }
    out
}

/// Case-insensitive glob over a string: `*` matches any run (including empty),
/// `?` exactly one character. Written out rather than pulled from a glob crate
/// because the target is a name, not a path.
fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (
        pattern.to_ascii_lowercase().chars().collect(),
        text.to_ascii_lowercase().chars().collect(),
    );
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Does a host survive the filters?
///
/// A pattern with `*`/`?` glob-matches the alias, hostname and `host:port`
/// address (a glob over a description is rarely what someone means); a plain
/// pattern is a case-insensitive substring test over alias, address, user and
/// description — so `-f prod`, `-f sk-`, `-f 26001` and `-f "training box"` all
/// do the obvious thing. Matching the address is what makes `-f <port>`
/// work the way the displayed table reads. Several patterns must all match;
/// `--user`/`--port` are exact.
fn host_matches(
    entry: &HostEntry,
    patterns: &[String],
    user: Option<&str>,
    port: Option<u16>,
) -> bool {
    if let Some(u) = user
        && !entry.user.eq_ignore_ascii_case(u)
    {
        return false;
    }
    if let Some(p) = port
        && entry.port != p
    {
        return false;
    }
    let address = entry.address();
    patterns.iter().all(|pat| {
        if pat.contains('*') || pat.contains('?') {
            glob_match(pat, &entry.alias)
                || glob_match(pat, &entry.hostname)
                || glob_match(pat, &address)
        } else {
            let needle = pat.to_ascii_lowercase();
            entry.alias.to_ascii_lowercase().contains(&needle)
                || address.to_ascii_lowercase().contains(&needle)
                || entry.user.to_ascii_lowercase().contains(&needle)
                || entry
                    .description
                    .as_deref()
                    .is_some_and(|d| d.to_ascii_lowercase().contains(&needle))
        }
    })
}

/// `rexec list`: the host inventory.
///
/// Two stages by design: the default table is `ALIAS  HOST:PORT  DESCRIPTION`
/// — the port is part of the identity of a host (one gateway address carries a
/// different forwarded port per machine), so it is shown alongside the hostname;
/// `--long` adds user/identity, and passing an alias prints the resolved details
/// for that one host. stdout carries the table (or the `--json` array) and
/// nothing else.
fn list_hosts(
    alias: Option<&str>,
    long: bool,
    filter: &[String],
    user: Option<&str>,
    port: Option<u16>,
) -> Result<()> {
    let (path, config) = load_user_ssh_config()?;
    let descriptions = host_descriptions(&path);
    let default_user = default_user();

    if let Some(a) = alias {
        let p = config.query(a);
        let host = p.host_name.clone().unwrap_or_else(|| a.to_string());
        let port = p.port.unwrap_or(22);
        let user = p.user.clone().unwrap_or_else(|| default_user);
        println!("{:<24} {}@{}:{}", a, user, host, port);
        if let Some(id) = &p.identity_file
            && let Some(first) = id.first()
        {
            println!("{:<24} identity: {}", "", first.display());
        }
        if let Some(desc) = descriptions.get(a) {
            println!("{:<24} description: {}", "", desc);
        }
        return Ok(());
    }

    // Collect every named host block, then filter.
    let mut entries: Vec<HostEntry> = Vec::new();
    for host in config.get_hosts() {
        let patterns: Vec<String> = host.pattern.iter().map(|c| c.to_string()).collect();
        // Skip pure-wildcard entries (e.g. "Host *") — no useful alias.
        if patterns.iter().all(|p| p == "*") {
            continue;
        }
        let alias = patterns.join(" ");
        // Resolve the way a run does — `config.query` merges every matching
        // block first-obtained-wins, so a `Host *` Port/User/IdentityFile is
        // inherited. Reading the block's own params instead would show a
        // `host:port` (and user/key) that a `rexec <alias> run` does not use,
        // which is exactly the kind of mismatch this column exists to prevent.
        let params = patterns
            .iter()
            .find(|p| !p.starts_with('!') && !p.contains('*') && !p.contains('?'))
            .map(|p| config.query(p))
            .unwrap_or_else(|| host.params.clone());
        let hostname = params
            .host_name
            .clone()
            .unwrap_or_else(|| alias.split_whitespace().next().unwrap_or("").to_string());
        entries.push(HostEntry {
            description: patterns.iter().find_map(|p| descriptions.get(p).cloned()),
            alias,
            hostname,
            port: params.port.unwrap_or(22),
            user: params.user.clone().unwrap_or_else(|| default_user.clone()),
            identity: params
                .identity_file
                .as_ref()
                .and_then(|v| v.first())
                .map(|p| p.display().to_string()),
        });
    }
    let total = entries.len();
    entries.retain(|e| host_matches(e, filter, user, port));

    if JSON_SUMMARY.load(Ordering::Relaxed) {
        let rows: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "alias": e.alias,
                    "hostname": e.hostname,
                    "port": e.port,
                    "user": e.user,
                    "identity": e.identity,
                    "description": e.description,
                })
            })
            .collect();
        println!("{}", serde_json::Value::Array(rows));
        return Ok(());
    }

    if entries.is_empty() {
        eprintln!(
            "no hosts match ({} configured{})",
            total,
            if filter.is_empty() && user.is_none() && port.is_none() {
                ""
            } else {
                " — adjust --filter/--user/--port"
            }
        );
        return Ok(());
    }

    // Host:port is stage one (the port is part of which machine this is);
    // user/identity are stage two.
    if long {
        println!(
            "{:<24} {:<32} {:<12} {:<30} DESCRIPTION",
            "ALIAS", "HOST:PORT", "USER", "IDENTITY"
        );
        for e in &entries {
            println!(
                "{:<24} {:<32} {:<12} {:<30} {}",
                e.alias,
                e.address(),
                e.user,
                e.identity
                    .as_deref()
                    .map(|i| single_line(i, 28))
                    .unwrap_or_else(|| "-".to_string()),
                e.description
                    .as_deref()
                    .map(|d| single_line(d, 60))
                    .unwrap_or_default()
            );
        }
    } else {
        println!("{:<24} {:<32} DESCRIPTION", "ALIAS", "HOST:PORT");
        for e in &entries {
            println!(
                "{:<24} {:<32} {}",
                e.alias,
                e.address(),
                e.description
                    .as_deref()
                    .map(|d| single_line(d, 60))
                    .unwrap_or_default()
            );
        }
    }
    Ok(())
}

// ───────────────────────────── history ─────────────────────────────
//
// `rexec history …` reads the local store written by `record_history` at the
// CLI boundary. Everything here is local and read-only except `prune` (which
// deletes runs) and `fetch` (one read-only `cat` on the remote). stdout carries
// pure data — tables and raw artifacts — so it can be piped; friendly notes and
// warnings go to stderr.

/// The enable decision for one invocation: `--no-history` wins, then
/// `REXEC_HISTORY` (exactly `0` disables; anything else, including unset, keeps
/// recording on). Pure, so the rule is unit-tested without touching the
/// process environment.
fn history_enabled(no_history: bool, rexec_history: Option<&str>) -> bool {
    !no_history && rexec_history != Some("0")
}

/// RFC 3339 UTC timestamp (`2026-09-22T04:15:33Z`) for a `SystemTime`.
///
/// `chrono`/`time` are not dependencies (and `Cargo.toml` belongs to another
/// workstream), so days→civil-date is done here with Howard Hinnant's
/// algorithm. Second precision: that is the run id's precision, and a record
/// never needs sub-second resolution to be read back.
fn rfc3339_utc(t: std::time::SystemTime) -> String {
    // A clock before 1970 is not worth failing a run over; the epoch stands in.
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Shift the epoch to 0000-03-01 so the leap day lands at the end of the
    // 400-year cycle (Hinnant's civil_from_days).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Escaped rendering of one character for a single-line cell.
fn escaped_cell(c: char) -> String {
    match c {
        '\n' => "\\n".to_string(),
        '\r' => "\\r".to_string(),
        '\t' => "\\t".to_string(),
        c if (c as u32) < 0x20 || c == '\u{7f}' => format!("\\u{:04x}", c as u32),
        c => c.to_string(),
    }
}

/// One-line view of arbitrary text: C0 controls escaped, then cut to at most
/// `max` rendered characters (never mid-UTF-8) with a trailing `…` when
/// something was dropped. Table cells and search fragments both need this — a
/// raw newline in a recorded command would otherwise break every row.
fn single_line(text: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    let cells: Vec<String> = text.chars().map(escaped_cell).collect();
    let total: usize = cells.iter().map(|c| c.chars().count()).sum();
    // When it all fits, keep every character; otherwise reserve one cell for
    // the marker so the result is still at most `max` wide.
    let budget = if total <= max { max } else { max - 1 };
    let mut out = String::with_capacity(total.min(max) + 1);
    let mut cost = 0;
    for cell in &cells {
        let n = cell.chars().count();
        if cost + n > budget {
            break;
        }
        out.push_str(cell);
        cost += n;
    }
    if total > max {
        out.push('…');
    }
    out
}

/// Nearest-rank percentile of a SORTED slice (`stats` p50/p95).
///
/// Nearest rank (no interpolation) keeps the reported number an actually
/// observed duration: `index = ceil(percent/100 * n) - 1`. `None` when empty.
fn percentile(sorted: &[u64], percent: u32) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let n = sorted.len();
    let rank = ((percent as usize) * n).div_ceil(100).max(1);
    Some(sorted[(rank - 1).min(n - 1)])
}

/// Byte count in a short human form, for the `stats`/`prune` reports.
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Shared `list`/`grep`/`stats` filters.
///
/// `host` matches the alias as typed or the resolved target, ASCII-case-
/// insensitively and as a substring (`--host prod` also finds `prod-2`);
/// `failed` keeps only runs whose exit was non-zero or was never observed at
/// all — a worker that died is a failure too.
fn record_matches(rec: &history::RunRecord, host: Option<&str>, failed: bool) -> bool {
    if failed && rec.exit_code == Some(0) {
        return false;
    }
    match host {
        Some(h) if !h.is_empty() => {
            let h = h.to_ascii_lowercase();
            rec.host.to_ascii_lowercase().contains(&h)
                || rec.resolved.to_ascii_lowercase().contains(&h)
        }
        _ => true,
    }
}

/// One-line window around the first ASCII-case-insensitive occurrence of
/// `needle_lower` (the caller lowercases it) in `hay`: up to `before` leading
/// and `after` trailing characters of context, controls escaped, `…` marking a
/// clipped edge. `None` when there is no match. Plain substring matching — the
/// `regex` crate is not a dependency.
fn match_context(hay: &str, needle_lower: &str, before: usize, after: usize) -> Option<String> {
    if needle_lower.is_empty() {
        return None;
    }
    // ASCII folding preserves byte offsets, so an index into the folded text is
    // a char boundary in the original (Unicode folding could shift it).
    let folded = hay.to_ascii_lowercase();
    let at = folded.find(needle_lower)?;
    let match_end = at + needle_lower.len();
    let start = if before == 0 {
        at
    } else {
        hay[..at]
            .char_indices()
            .rev()
            .nth(before - 1)
            .map(|(i, _)| i)
            .unwrap_or(0)
    };
    let window_end = if after == 0 {
        match_end
    } else {
        hay[match_end..]
            .char_indices()
            .nth(after)
            .map(|(i, _)| match_end + i)
            .unwrap_or(hay.len())
    };
    let mut out = String::new();
    if start > 0 {
        out.push('…');
    }
    out.push_str(&single_line(&hay[start..window_end], usize::MAX));
    if window_end < hay.len() {
        out.push('…');
    }
    Some(out)
}

/// Value of the first `"key":"…"` string field in one JSON line.
///
/// Hand-rolled for the same reason `summary_json_line` is: `--meta` must print
/// the stored index line verbatim, so the raw text is scanned instead of
/// re-serialized, and no JSON parser is pulled in for one comparison.
fn json_string_field(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let mut rest = line;
    while let Some(at) = rest.find(&needle) {
        // Scan past this occurrence either way: the key text can also appear
        // inside an unrelated string value.
        rest = rest[at + needle.len()..].trim_start();
        if let Some(after) = rest.strip_prefix(':').map(str::trim_start)
            && let Some(body) = after.strip_prefix('"')
        {
            let mut out = String::new();
            let mut escaped = false;
            for c in body.chars() {
                if escaped {
                    out.push(match c {
                        'n' => '\n',
                        't' => '\t',
                        'r' => '\r',
                        other => other,
                    });
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    return Some(out);
                } else {
                    out.push(c);
                }
            }
            return None; // unterminated string: malformed line
        }
    }
    None
}

/// The raw `index.jsonl` line for a run id, printed verbatim by `show --meta`
/// (key order, spacing and unknown future keys stay exactly as stored —
/// re-serializing would silently drop what this build does not know).
fn raw_index_line(id: &str) -> Result<String> {
    let path = history::index_path()?;
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    for line in text.lines() {
        if json_string_field(line, "id").as_deref() == Some(id) {
            // The stored line is the raw record — which holds env values
            // verbatim. Only `--reveal-secrets` prints it byte-for-byte;
            // by default the values are masked in place (unknown keys from a
            // newer rexec survive, because the JSON object is edited, not
            // re-typed from the struct).
            return Ok(if reveal_secrets() {
                line.to_string()
            } else {
                mask_index_line_env(line)
            });
        }
    }
    Err(anyhow!("no such run: {id}"))
}

/// Replace every env value in a stored index line with `***`, leaving the rest
/// of the JSON (including keys this build does not know) untouched.
fn mask_index_line_env(line: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(line) else {
        return line.to_string(); // unreachable for a line the caller could parse
    };
    if let Some(env) = value.get_mut("env").and_then(|e| e.as_array_mut()) {
        for pair in env {
            if let Some(arr) = pair.as_array_mut()
                && arr.len() == 2
                && !arr[1].as_str().is_some_and(|v| v.is_empty())
            {
                arr[1] = serde_json::Value::String("***".to_string());
            }
        }
    }
    serde_json::to_string(&value).unwrap_or_else(|_| line.to_string())
}

/// Index records, with "no history yet" expressed as an empty list.
///
/// The first run on a machine has no index file at all: read-only commands must
/// treat that as "nothing recorded" (friendly note; `list`/`stats` still exit
/// 0) rather than as an IO error.
fn load_index_or_empty() -> Result<Vec<history::RunRecord>> {
    if !history::index_path()?.exists() {
        return Ok(Vec::new());
    }
    history::load_index()
}

/// Friendly note for a missing/empty history — stderr, so stdout stays data.
fn note_empty_history() {
    match history::history_root() {
        Ok(root) => eprintln!("(no runs recorded yet — history: {})", root.display()),
        Err(_) => eprintln!("(no runs recorded yet)"),
    }
    if !history::enabled() {
        eprintln!("(recording is disabled in this invocation: --no-history or REXEC_HISTORY=0)");
    }
}

/// Captured-artifact path, from the documented layout (`runs/<id>/stdout.log`,
/// `stderr.log`). Used only to tell "this stream captured nothing" (a clean run
/// writes no file for it) from a read error; bytes always come back through
/// `history::read_artifact`.
fn artifact_path(id: &str, which: history::Artifact) -> Result<PathBuf> {
    let name = match which {
        history::Artifact::Stdout => "stdout.log",
        history::Artifact::Stderr => "stderr.log",
    };
    Ok(history::history_root()?.join("runs").join(id).join(name))
}

fn artifact_name(which: history::Artifact) -> &'static str {
    match which {
        history::Artifact::Stdout => "stdout",
        history::Artifact::Stderr => "stderr",
    }
}

/// Write one captured stream as RAW bytes to stdout — no added newline, so
/// `show --stdout > f` is byte-identical to the capture.
fn show_artifact(id: &str, which: history::Artifact) -> Result<()> {
    let path = artifact_path(id, which)?;
    if !path.exists() {
        status!("(no {} captured for run {id})", artifact_name(which));
        return Ok(());
    }
    let bytes =
        history::read_artifact(id, which).with_context(|| format!("reading {}", path.display()))?;
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    lock.write_all(&bytes)?;
    lock.flush()?;
    Ok(())
}

/// `history list`: one table row per run, newest first.
fn history_list(limit: usize, host: Option<&str>, failed: bool) -> Result<()> {
    let records = load_index_or_empty()?;
    if records.is_empty() {
        note_empty_history();
        return Ok(());
    }
    println!(
        "{:<24} {:<20} {:<20} {:<5} {:>9}  COMMAND",
        "ID", "STARTED", "HOST", "EXIT", "DURATION_MS"
    );
    for rec in records
        .iter()
        .filter(|r| record_matches(r, host, failed))
        .take(limit)
    {
        println!(
            "{:<24} {:<20} {:<20} {:<5} {:>9}  {}",
            single_line(&rec.id, 24),
            single_line(&rec.ts_start, 20),
            single_line(if rec.host.is_empty() { "-" } else { &rec.host }, 20),
            rec.exit_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".to_string()),
            rec.duration_ms,
            single_line(&rec.command, 60),
        );
    }
    Ok(())
}

/// `history show`: a human summary, or exactly one raw artifact when a selector
/// flag is given (stdout then carries only those bytes).
fn history_show(id: &str, stdout: bool, stderr: bool, trace: bool, meta: bool) -> Result<()> {
    let selectors = [stdout, stderr, trace, meta].iter().filter(|s| **s).count();
    if selectors > 1 {
        return Err(anyhow!(
            "choose at most one of --stdout / --stderr / --trace / --meta"
        ));
    }
    let records = load_index_or_empty()?;
    let Some(rec) = records.iter().find(|r| r.id == id) else {
        if records.is_empty() {
            note_empty_history();
        }
        return Err(anyhow!("no such run: {id} (see `rexec history list`)"));
    };

    if stdout {
        return show_artifact(id, history::Artifact::Stdout);
    }
    if stderr {
        return show_artifact(id, history::Artifact::Stderr);
    }
    if trace {
        for line in &rec.trace {
            println!("{line}");
        }
        return Ok(());
    }
    if meta {
        println!("{}", raw_index_line(id)?);
        return Ok(());
    }

    let run_dir = history::history_root()?.join("runs").join(id);
    let dash = |s: &str| {
        if s.is_empty() {
            "-".to_string()
        } else {
            s.to_string()
        }
    };
    let opt = |v: Option<u32>| v.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string());
    let trunc = |t: bool| {
        if t {
            " (truncated at the capture cap)"
        } else {
            ""
        }
    };
    println!("id:        {}", rec.id);
    println!("start:     {}", rec.ts_start);
    println!("duration:  {} ms", rec.duration_ms);
    println!("version:   {}", rec.rexec_version);
    println!("host:      {}", dash(&rec.host));
    println!("resolved:  {}", dash(&rec.resolved));
    println!(
        "exit:      {}",
        rec.exit_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    println!("pid:       {}", opt(rec.pid));
    println!("deployed:  {}", if rec.deployed { "yes" } else { "no" });
    println!(
        "stdout:    {} B{}",
        rec.stdout_bytes,
        trunc(rec.stdout_truncated)
    );
    println!(
        "stderr:    {} B{}",
        rec.stderr_bytes,
        trunc(rec.stderr_truncated)
    );
    println!("command:   {}", single_line(&rec.command, 200));
    if rec.env.is_empty() {
        println!("env:       (none)");
    } else {
        for (k, v) in &rec.env {
            let shown = mask_env_value(v, reveal_secrets());
            println!(
                "env:       {}={}",
                single_line(k, 60),
                single_line(&shown, 200)
            );
        }
    }
    if let Some(err) = &rec.error {
        println!("error:     {}", single_line(err, 400));
    }
    println!(
        "artifacts: {} (meta.json, stdout.log, stderr.log)",
        run_dir.display()
    );
    if rec.trace.is_empty() {
        println!("trace:     (none)");
    } else {
        println!("trace:");
        for line in &rec.trace {
            println!("  → {line}");
        }
    }
    Ok(())
}

/// `history grep`: plain case-insensitive substring search over every run's
/// command and env values (+ captured output with `--output`), one line per
/// matched source, each prefixed by the run id.
fn history_grep(
    pattern: &str,
    limit: usize,
    host: Option<&str>,
    failed: bool,
    output: bool,
) -> Result<()> {
    let records = load_index_or_empty()?;
    if records.is_empty() {
        note_empty_history();
        return Err(anyhow!("nothing recorded to search for {pattern:?}"));
    }
    let needle = pattern.to_ascii_lowercase();
    if needle.is_empty() {
        return Err(anyhow!("empty search pattern"));
    }
    let mut runs = 0usize;
    for rec in records.iter().filter(|r| record_matches(r, host, failed)) {
        if runs >= limit {
            break;
        }
        let mut lines: Vec<String> = Vec::new();
        if let Some(fragment) = match_context(&rec.command, &needle, 40, 40) {
            lines.push(format!("cmd: {fragment}"));
        }
        for (k, v) in &rec.env {
            if match_context(v, &needle, 40, 40).is_some() {
                // The match itself is the signal; the value is the secret, so
                // only `--reveal-secrets` prints the matching fragment.
                let fragment = if reveal_secrets() {
                    match_context(v, &needle, 40, 40).unwrap_or_default()
                } else {
                    "***".to_string()
                };
                lines.push(format!("env {k}={fragment}"));
            }
        }
        if output {
            for which in [history::Artifact::Stdout, history::Artifact::Stderr] {
                // A stream that captured nothing simply has nothing to match.
                let Ok(bytes) = history::read_artifact(&rec.id, which) else {
                    continue;
                };
                let text = String::from_utf8_lossy(&bytes);
                if let Some(fragment) = match_context(&text, &needle, 40, 40) {
                    lines.push(format!("{}: {fragment}", artifact_name(which)));
                }
            }
        }
        if lines.is_empty() {
            continue;
        }
        for line in lines {
            println!("{} {}", rec.id, line);
        }
        runs += 1;
    }
    if runs == 0 {
        return Err(anyhow!("no recorded run matches {pattern:?}"));
    }
    Ok(())
}

/// `history stats`: totals, failures, p50/p95 duration, captured bytes and the
/// on-disk tree size.
fn history_stats(host: Option<&str>) -> Result<()> {
    let records = load_index_or_empty()?;
    if records.is_empty() {
        note_empty_history();
        return Ok(());
    }
    let matched: Vec<&history::RunRecord> = records
        .iter()
        .filter(|r| record_matches(r, host, false))
        .collect();
    let failures = matched.iter().filter(|r| r.exit_code != Some(0)).count();
    let mut durations: Vec<u64> = matched.iter().map(|r| r.duration_ms).collect();
    durations.sort_unstable();
    let stdout_bytes: u64 = matched.iter().map(|r| r.stdout_bytes).sum();
    let stderr_bytes: u64 = matched.iter().map(|r| r.stderr_bytes).sum();
    let root = history::history_root()?;
    let on_disk = history::tree_size(&root);
    let ms = |v: Option<u64>| match v {
        Some(v) => format!("{v} ms"),
        None => "-".to_string(),
    };
    println!("runs:      {}", matched.len());
    println!("failures:  {failures}");
    println!(
        "duration:  p50 {}, p95 {}",
        ms(percentile(&durations, 50)),
        ms(percentile(&durations, 95))
    );
    println!(
        "captured:  {stdout_bytes} B stdout + {stderr_bytes} B stderr (true bytes seen, before the \
         per-stream cap)"
    );
    println!("on disk:   {on_disk} B ({})", human_bytes(on_disk));
    println!("per host:");
    let mut per_host: std::collections::BTreeMap<&str, (usize, usize)> =
        std::collections::BTreeMap::new();
    for rec in &matched {
        let entry = per_host.entry(rec.host.as_str()).or_insert((0, 0));
        entry.0 += 1;
        if rec.exit_code != Some(0) {
            entry.1 += 1;
        }
    }
    for (name, (total, failed)) in &per_host {
        println!(
            "  {:<24} {} runs, {} failed",
            if name.is_empty() { "-" } else { name },
            total,
            failed
        );
    }
    println!("history:   {}", root.display());
    Ok(())
}

/// Byte budget for `prune`. No `--max-mb` means "no size cap": the literal
/// `u64::MAX / 2 * 1024 * 1024` overflows (debug builds panic, release wraps to
/// a bogus few-KiB cap), so the multiply saturates — the intent is an
/// unreachable cap, not arithmetic.
fn prune_max_bytes(max_mb: Option<u64>) -> u64 {
    max_mb.unwrap_or(u64::MAX / 2).saturating_mul(1024 * 1024)
}

/// `history prune`: delete expired runs, then enforce the size cap.
fn history_prune(keep_days: u64, max_mb: Option<u64>) -> Result<()> {
    let (removed, freed) = history::prune(keep_days, prune_max_bytes(max_mb))?;
    println!(
        "pruned {removed} run(s), freed {freed} B ({})",
        human_bytes(freed)
    );
    Ok(())
}

/// Does a read-only platform probe describe a Windows remote? `uname` under
/// Git-Bash/MSYS reports `MINGW64_NT…`, which `plan_remote_asset` leaves
/// unmapped, so the raw probe text is checked as well.
fn remote_is_windows(platform: &str, asset: Option<&str>) -> bool {
    asset.is_some_and(|a| a.starts_with("windows-"))
        || platform.contains("Windows_NT")
        || platform.contains("MINGW")
        || platform.contains("MSYS")
}

/// Read a remote file as RAW bytes: exactly one read-only `cat`.
///
/// `ssh::exec_remote` returns a `String` built with `from_utf8_lossy`, which
/// replaces every invalid sequence with U+FFFD — the worker log is a binary
/// frame stream, so lossy decoding would corrupt precisely the bytes `fetch`
/// exists to preserve. Hence this byte-exact reader over one channel (no
/// deploy, no write, no second command). Returns `(stdout, stderr, exit)`.
async fn read_remote_bytes(
    session: &russh::client::Handle<ssh::ClientHandler>,
    command: &str,
) -> Result<(Vec<u8>, Vec<u8>, Option<i32>)> {
    let mut channel = session.channel_open_session().await?;
    channel.exec(true, command).await?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut code = None;
    let mut eof = false;
    // Wait for BOTH eof and the exit status: "no such file" is only visible in
    // the status, and the status may arrive after Eof. A closed channel (`None`)
    // ends the loop either way.
    while !(eof && code.is_some()) {
        let msg = if eof {
            // After EOF the only thing left is the exit status. OpenSSH always
            // sends one, but a server that does not must not hang the fetch —
            // the status is then inferred from stderr/stdout below.
            match tokio::time::timeout(Duration::from_secs(5), channel.wait()).await {
                Ok(msg) => msg,
                Err(_) => break,
            }
        } else {
            channel.wait().await
        };
        match msg {
            Some(ChannelMsg::Data { ref data }) => out.extend_from_slice(data),
            Some(ChannelMsg::ExtendedData { ref data, ext: 1 }) => err.extend_from_slice(data),
            Some(ChannelMsg::ExitStatus { exit_status }) => code = Some(exit_status as i32),
            Some(ChannelMsg::Eof) => eof = true,
            Some(_) => {}
            None => break,
        }
    }
    Ok((out, err, code))
}

/// `history fetch <id> [--out PATH]` — pull the FULL remote worker log of a
/// recorded run.
///
/// READ-ONLY on the remote: connect, one read-only platform probe, one `cat`.
/// No deploy and no write. The log holds the binary frame protocol the local
/// CLI decodes, so the bytes are streamed verbatim (decoding them is a
/// follow-up) and a warning on stderr says so; `--out` keeps stdout clean.
async fn history_fetch(
    id: &str,
    out: Option<&Path>,
    port: Option<u16>,
    trace: &mut diagnostics::Trace,
) -> Result<()> {
    let records = load_index_or_empty()?;
    let Some(rec) = records.iter().find(|r| r.id == id) else {
        if records.is_empty() {
            note_empty_history();
        }
        return Err(anyhow!("no such run: {id} (see `rexec history list`)"));
    };
    // No pid means the worker never reported one: there is no remote log to
    // read, and the record itself is the answer.
    let pid = rec.pid.ok_or_else(|| {
        anyhow!(
            "run {id} has no remote PID, so there is no remote worker log to fetch — the worker \
             never started. `rexec history show {id}` has what was captured before it failed."
        )
    })?;
    let host = rec.host.clone();
    // The fetch's decisions go into THIS invocation's trace — never the
    // recorded run's: reading a record back is not the run that produced it.
    // Using the boundary's trace (empty for a `history` command) rather than a
    // throwaway local one is what makes a failed fetch print its resolution and
    // auth context, as every other command's failure does.
    let remote = resolve_host(&host, port, trace)?;
    let session = ssh::connect_traced(&remote, trace).await?;
    // Read-only platform probe (never deploys): a Windows remote keeps its log
    // at <home>\.rexec\logs\<pid>.log, which needs a different command path.
    let (platform, asset) = probe_remote_platform(&session).await;
    if remote_is_windows(&platform, asset.as_deref()) {
        let home = probe_windows_home(&session).await;
        let home = home.trim_end_matches('\\');
        return Err(anyhow!(
            "run {id} was on a Windows remote ({platform}): its worker log is at \
             {home}\\.rexec\\logs\\{pid}.log — fetch it with scp/sftp; `history fetch` reads the \
             POSIX path only"
        ));
    }
    let command = format!("cat \"$HOME/.rexec/logs/{pid}.log\"");
    let (bytes, err, code) = read_remote_bytes(&session, &command).await?;
    // `cat` reports a missing/unreadable file with a non-zero status plus an
    // error on stderr; a present-but-empty log must still succeed.
    let failed =
        code.is_some_and(|c| c != 0) || (code.is_none() && bytes.is_empty() && !err.is_empty());
    if failed {
        let detail = String::from_utf8_lossy(&err);
        let detail = detail.trim();
        let detail = if detail.is_empty() {
            String::new()
        } else {
            format!(" ({detail})")
        };
        return Err(anyhow!(
            "no worker log at ~/.rexec/logs/{pid}.log on {host}{detail} — the worker removes it \
             after a clean exit, and a different remote user has a different home"
        ));
    }
    // Say what these bytes are BEFORE dumping them: stderr, so a pipe stays
    // byte-pure.
    status!(
        "⚠ fetched {} B of raw worker frame stream (binary, not decoded) — `rexec history show \
         {id} --stdout/--stderr` is the decoded capture",
        bytes.len()
    );
    match out {
        Some(path) => {
            std::fs::write(path, &bytes).with_context(|| format!("writing {}", path.display()))?;
            status!("wrote {} bytes to {}", bytes.len(), path.display());
        }
        None => {
            use std::io::Write;
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            lock.write_all(&bytes)?;
            lock.flush()?;
        }
    }
    Ok(())
}

/// Dispatch `rexec history …`. `port` is the global `-p/--port`, used only by
/// `fetch`, which re-resolves the recorded host the same way a run does;
/// `trace` is this invocation's (empty) decision trace, so a failed fetch
/// reports its resolution/connect context like every other command.
async fn run_history(
    cmd: HistoryCmd,
    port: Option<u16>,
    trace: &mut diagnostics::Trace,
) -> Result<()> {
    match cmd {
        HistoryCmd::List {
            limit,
            host,
            failed,
        } => history_list(limit, host.as_deref(), failed),
        HistoryCmd::Show {
            id,
            stdout,
            stderr,
            trace,
            meta,
        } => history_show(&id, stdout, stderr, trace, meta),
        HistoryCmd::Grep {
            pattern,
            limit,
            host,
            failed,
            output,
        } => history_grep(&pattern, limit, host.as_deref(), failed, output),
        HistoryCmd::Stats { host } => history_stats(host.as_deref()),
        HistoryCmd::Path => {
            println!("{}", history::history_root()?.display());
            Ok(())
        }
        HistoryCmd::Prune { keep_days, max_mb } => history_prune(keep_days, max_mb),
        HistoryCmd::Fetch { id, out } => history_fetch(&id, out.as_deref(), port, trace).await,
    }
}

/// Serialize [`diagnostics::RunSummary`] as ONE line of JSON, by hand.
///
/// The output is a byte-for-byte contract (unit-tested): declaration order,
/// `error` omitted when absent, `log_path` as `null`. The hand-written writer
/// exists to keep that contract explicit; `serde_json` is available but not
/// used here so a dependency upgrade cannot silently change the wire format.
fn summary_json_line(summary: &diagnostics::RunSummary) -> String {
    let mut out = String::with_capacity(192);
    out.push_str("{\"host\":");
    out.push_str(&json_string(&summary.host));
    out.push_str(",\"resolved\":");
    out.push_str(&json_string(&summary.resolved));
    out.push_str(",\"pid\":");
    out.push_str(&json_number(summary.pid));
    out.push_str(",\"exit_code\":");
    out.push_str(&json_number(summary.exit_code));
    out.push_str(",\"duration_ms\":");
    out.push_str(&json_number(summary.duration_ms));
    out.push_str(",\"deployed\":");
    out.push_str(if summary.deployed { "true" } else { "false" });
    out.push_str(",\"stdout_bytes\":");
    out.push_str(&summary.stdout_bytes.to_string());
    out.push_str(",\"stderr_bytes\":");
    out.push_str(&summary.stderr_bytes.to_string());
    out.push_str(",\"log_path\":");
    out.push_str(&json_string_opt(summary.log_path.as_deref()));
    if let Some(error) = &summary.error {
        out.push_str(",\"error\":");
        out.push_str(&json_string(error));
    }
    out.push('}');
    out
}

/// JSON number for an optional numeric field (`null` when absent).
fn json_number<T: std::fmt::Display>(value: Option<T>) -> String {
    match value {
        Some(v) => v.to_string(),
        None => "null".to_string(),
    }
}

/// JSON string for an optional string field (`null` when absent).
fn json_string_opt(value: Option<&str>) -> String {
    match value {
        Some(v) => json_string(v),
        None => "null".to_string(),
    }
}

/// A JSON string in quotes. `"`, `\` and the control characters are escaped —
/// everything a JSON string may not carry literally (`\n`, `\r`, `\t`, `\b`,
/// `\f` short forms; other C0 controls and DEL as `\u00XX`).
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Append the decision trace to a failure, so an error arrives with its full
/// context in one shot (the transparency contract). Failures from before any
/// decision was recorded keep their original message.
fn attach_trace(err: anyhow::Error, trace: &diagnostics::Trace) -> anyhow::Error {
    let rendered = trace.render();
    if rendered.is_empty() {
        return err;
    }
    // `{:#}` renders anyhow's whole context chain; the runtime would print only
    // the outermost message.
    let mut msg = format!("{err:#}");
    if !msg.ends_with('\n') {
        msg.push('\n');
    }
    msg.push_str(rendered.trim_end());
    anyhow!(msg)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Restore the default SIGPIPE behaviour on unix. Rust ignores SIGPIPE at
    // startup, which turns a closed pipe into an EPIPE error — and `println!`
    // PANICS on that ("failed printing to stdout: Broken pipe"). Piping the
    // output-friendly subcommands (`history show <id> --stdout | head`,
    // `history list | head`) must instead end the process quietly, the way
    // cat/grep/ssh do. Fixing it here covers every print path at once.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();
    QUIET.store(cli.quiet, Ordering::Relaxed);
    JSON_SUMMARY.store(cli.json, Ordering::Relaxed);
    REVEAL_SECRETS.store(cli.reveal_secrets, Ordering::Relaxed);
    // `--socks5` wins over `REXEC_SOCKS5`; an unusable value fails here rather
    // than turning into a confusing connect error later.
    let socks5 = cli
        .socks5
        .clone()
        .or_else(|| std::env::var("REXEC_SOCKS5").ok())
        .filter(|s| !s.trim().is_empty());
    if let Some(proxy) = &socks5 {
        let parsed = parse_user_host_port(proxy.trim());
        let usable =
            !proxy.contains('@') && parsed.as_ref().map(|p| p.port.is_some()).unwrap_or(false);
        if !usable {
            eprintln!(
                "Error: --socks5/REXEC_SOCKS5 expects HOST:PORT (the SOCKS5 proxy address), got {proxy:?}"
            );
            std::process::exit(2);
        }
        let _ = SOCKS5_PROXY.set(proxy.trim().to_string());
    }
    // `--no-history` and `REXEC_HISTORY=0` both disable recording; the combined
    // rule is pure and unit-tested (`history::enabled()` is the runtime view).
    history::set_enabled(history_enabled(
        cli.no_history,
        std::env::var("REXEC_HISTORY").ok().as_deref(),
    ));
    diagnostics::OUTPUT_MODE.store(
        diagnostics::OutputMode::from_flags(cli.quiet, cli.verbose).as_u8(),
        Ordering::Relaxed,
    );

    // The JSON summary describes an execution run; `history` (and the internal
    // worker/attach commands) have no such summary to report. `list` has its
    // own JSON shape (a host array) and reads the global flag directly.
    let json = cli.json
        && !matches!(
            cli.action,
            Action::List { .. } | Action::History { .. } | Action::Worker | Action::Attach { .. }
        );
    let started = Instant::now();
    let mut trace = diagnostics::Trace::default();
    // Filled in progressively: a failure mid-run still reports what was
    // attempted and what was measured before it.
    let mut summary = diagnostics::RunSummary {
        host: cli.host.clone().unwrap_or_default(),
        resolved: String::new(),
        pid: None,
        exit_code: None,
        duration_ms: None,
        deployed: false,
        stdout_bytes: 0,
        stderr_bytes: 0,
        log_path: None,
        error: None,
    };
    // Filled by `run_command` when recording is on; read back at the boundary
    // below, on success AND failure, so a failed run is recorded too.
    let mut capture: Option<RunCapture> = None;

    let result: Result<()> = async {
        match (cli.host, cli.action, cli.port) {
            // ── Local operations ──
            (Some(host), Action::Init, port) => {
                let remote = resolve_host(&host, port, &mut trace)?;
                let mut session = ssh::connect_traced(&remote, &mut trace).await?;
                ssh::check_and_install_deps(&mut session).await?;
            }
            (
                Some(host),
                Action::Run {
                    sync,
                    env,
                    env_file,
                    command,
                },
                port,
            ) => {
                if command.is_empty() {
                    return Err(anyhow!(
                        "no command provided. Usage: rexec <host> run [--sync LOCAL:REMOTE] [--env KEY=VALUE]... -- <command...>"
                    ));
                }
                let remote = resolve_host(&host, port, &mut trace)?;
                summary.resolved = resolved_label(&remote);
                // Record the attempt BEFORE the pre-flight steps: a failed
                // `--sync` or env parse is exactly the kind of run history
                // should explain, and `run_command` (which fills in the
                // command/env and allocates the captures) is never reached for
                // them.
                if history::enabled() && capture.is_none() {
                    capture = Some(RunCapture::new("", &[]));
                }
                if let Some(sync_arg) = &sync {
                    let (local, remote_path) = parse_sync_arg(sync_arg)?;
                    trace.add(format!("sync: {} → {}", local.display(), remote_path));
                    do_sync(&local, &remote_path, &remote).await?;
                }
                let env_vars = collect_env(&env, &env_file)?;
                let command = command.join(" ");
                if let Some(cap) = capture.as_mut() {
                    cap.command = command.clone();
                    cap.env = env_vars.clone();
                }
                run_command(
                    &remote,
                    &host,
                    &command,
                    &env_vars,
                    &mut trace,
                    &mut summary,
                    &mut capture,
                )
                .await?;
            }
            (
                Some(host),
                Action::Script {
                    script,
                    interpreter,
                    sync_to,
                    env,
                    env_file,
                    args,
                },
                port,
            ) => {
                let remote = resolve_host(&host, port, &mut trace)?;
                summary.resolved = resolved_label(&remote);
                // Same early capture as `run`: a failure while parsing env or
                // during the script's own sync must still leave a record.
                if history::enabled() && capture.is_none() {
                    capture = Some(RunCapture::new("", &[]));
                }
                let env_vars = collect_env(&env, &env_file)?;
                run_script(
                    &remote,
                    &host,
                    &script,
                    interpreter.as_deref(),
                    sync_to.as_deref(),
                    &args,
                    &env_vars,
                    &mut trace,
                    &mut summary,
                    &mut capture,
                )
                .await?;
            }
            (Some(host), Action::Plan { command }, port) => {
                let remote = resolve_host(&host, port, &mut trace)?;
                let command = command.join(" ");
                plan_command(&remote, &host, &command, &mut trace, &mut summary).await?;
            }

            // ── Host listing (no host needed) ──
            (
                _,
                Action::List {
                    alias,
                    long,
                    filter,
                    user,
                    port,
                },
                _,
            ) => {
                list_hosts(alias.as_deref(), long, &filter, user.as_deref(), port)?;
            }

            // ── Local run history (no host: it is a local store) ──
            (None, Action::History { cmd }, port) => {
                run_history(cmd, port, &mut trace).await?;
            }
            (Some(_), Action::History { .. }, _) => {
                return Err(anyhow!(
                    "history is a local command and takes no host — use `rexec history …`"
                ));
            }

            // ── Remote operations (internal, invoked via SSH exec) ──
            (None, Action::Worker, _) => {
                remote::worker().await?;
            }
            (None, Action::Attach { pid, offset }, _) => {
                remote::attach(pid, offset).await?;
            }

            // ── Mismatches ──
            (Some(_), Action::Worker, _) | (Some(_), Action::Attach { .. }, _) => {
                return Err(anyhow!(
                    "worker/attach are internal commands, not used with a host"
                ));
            }
            (None, Action::Init, _) => {
                return Err(anyhow!("init requires a host"));
            }
            (None, Action::Run { .. }, _) => {
                return Err(anyhow!("run requires a host"));
            }
            (None, Action::Plan { .. }, _) => {
                return Err(anyhow!("plan requires a host"));
            }
            (None, Action::Script { .. }, _) => {
                return Err(anyhow!("script requires a host"));
            }
        }

        Ok(())
    }
    .await;

    summary.duration_ms = Some(started.elapsed().as_millis() as u64);
    // A timing line only makes sense once a decision was recorded; a pure
    // argument error must not grow a "decision trace" it never had.
    if !trace.lines().is_empty() {
        trace.add(format!(
            "timing: {} ms, stdout {} B, stderr {} B",
            summary.duration_ms.unwrap_or(0),
            summary.stdout_bytes,
            summary.stderr_bytes
        ));
    }

    match result {
        Ok(()) => {
            // Success is silent in normal mode: stdout/stderr carry the
            // command's own output and nothing else. `-v` adds the trace.
            if diagnostics::mode().trace_on_success() {
                let rendered = trace.render();
                if !rendered.is_empty() {
                    ensure_stderr_line_start();
                    eprint!("{rendered}");
                }
            }
            // Recorded before the JSON line: a best-effort history warning must
            // not land after the summary this contract keeps LAST on stderr.
            // The Ok path covers a non-zero remote exit too.
            record_history(capture.as_ref(), &summary, &trace);
            if json {
                // stderr, and last: stdout stays pure command output.
                ensure_stderr_line_start();
                eprintln!("{}", summary_json_line(&summary));
            }
            // A remote command that exited non-zero already printed its
            // warning line; rexec mirrors that status (ssh semantics) so
            // scripts and agents see the failure in `$?`.
            let remote = REMOTE_EXIT.load(Ordering::Relaxed);
            if remote != 0 {
                std::process::exit(remote_exit_status(remote));
            }
            Ok(())
        }
        Err(err) => {
            summary.error = Some(format!("{err:#}"));
            // Printed here rather than returned so the JSON line can stay the
            // LAST line on stderr. The format matches what the runtime prints
            // for a returned `Err` (std's `Termination` uses `Error: {err:?}`),
            // so failure output is unchanged for non-JSON users.
            ensure_stderr_line_start();
            eprintln!("Error: {:?}", attach_trace(err, &trace));
            // A failure is recorded too, as long as the run got far enough to
            // know the host and the command (run_command sets the capture
            // before its first remote touch). Before the JSON line, so a
            // history warning cannot displace the summary kept last on stderr.
            record_history(capture.as_ref(), &summary, &trace);
            if json {
                ensure_stderr_line_start();
                eprintln!("{}", summary_json_line(&summary));
            }
            std::process::exit(1);
        }
    }
}

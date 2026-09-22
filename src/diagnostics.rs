//! Diagnostics: the transparency contract.
//!
//! Principle (user-specified): errors and warnings print their FULL decision
//! context in one shot — the user must never re-run with `-v` just to find
//! out what was attempted; when nothing is wrong, output is silent (only the
//! command's own stdout/stderr).
//!
//! Modes (from global flags):
//! - Normal (default): command output only. Failures print the error plus the
//!   collected [`Trace`]. A non-zero remote exit prints a one-line warning
//!   (exit code + remote log path).
//! - `-v/--verbose`: also print the Trace and key facts (resolved target,
//!   remote PID, deploy decisions) on SUCCESS.
//! - `--json`: machine-readable single-line summary on STDERR (stdout stays
//!   pure command output); on failure the JSON carries the error and trace.
//! - `-q/--quiet`: legacy flag — success output was already silent, so this
//!   only suppresses the remaining progress lines that predate this module
//!   (sync/reconnect notices). Errors are NEVER suppressed by quiet.

use std::io::IsTerminal;
use std::sync::atomic::AtomicU8;

/// Selected output mode, parsed once from the CLI flags.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputMode {
    #[default]
    Normal,
    Quiet,
    Verbose,
}

impl OutputMode {
    pub fn from_flags(quiet: bool, verbose: bool) -> Self {
        match (quiet, verbose) {
            (true, _) => OutputMode::Quiet,
            (_, true) => OutputMode::Verbose,
            _ => OutputMode::Normal,
        }
    }

    /// Decision-trace lines are printed on success only in verbose mode.
    pub fn trace_on_success(self) -> bool {
        self == OutputMode::Verbose
    }

    /// Legacy progress lines (sync/reconnect) — verbose only; normal mode is
    /// silent on success.
    pub fn progress_lines(self) -> bool {
        self == OutputMode::Verbose
    }

    pub fn as_u8(self) -> u8 {
        match self {
            OutputMode::Normal => 0,
            OutputMode::Quiet => 1,
            OutputMode::Verbose => 2,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            1 => OutputMode::Quiet,
            2 => OutputMode::Verbose,
            _ => OutputMode::Normal,
        }
    }
}

/// Global mode, set once at startup (mirrors the QUIET static's pattern).
pub static OUTPUT_MODE: AtomicU8 = AtomicU8::new(0);

/// Current output mode (cheap load per use).
pub fn mode() -> OutputMode {
    OutputMode::from_u8(OUTPUT_MODE.load(std::sync::atomic::Ordering::Relaxed))
}

/// A recorded decision line ("foo → root@1.2.3.4:22 (key ~/.ssh/id_ed)",
/// "auth: agent rejected", "deploy: local 0.3.1 vs remote 0.3.0 → upload").
///
/// Entries are ALWAYS recorded (cheap), but rendered only on error (any
/// mode) or on success in verbose mode — attached to the failure message so
/// the full context arrives in one shot.
#[derive(Default)]
pub struct Trace {
    entries: Vec<String>,
}

impl Trace {
    pub fn add(&mut self, msg: impl Into<String>) {
        self.entries.push(msg.into());
    }

    /// Render as an indented block, ready to print under an error message.
    pub fn render(&self) -> String {
        if self.entries.is_empty() {
            return String::new();
        }
        let mut out = String::from("decision trace:\n");
        for e in &self.entries {
            out.push_str("  → ");
            out.push_str(e);
            out.push('\n');
        }
        out
    }

    pub fn lines(&self) -> &[String] {
        &self.entries
    }
}

/// Machine-readable result summary (`--json`, single line on stderr).
#[derive(serde::Serialize)]
pub struct RunSummary {
    pub host: String,
    pub resolved: String,
    pub pid: Option<u32>,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u64>,
    pub deployed: bool,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub log_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Should remote-stderr frames be colorized? Only on an interactive stderr —
/// piped/agent usage must stay byte-pure.
pub fn stderr_is_tty() -> bool {
    std::io::stderr().is_terminal()
}

/// ANSI red wrapper (no-op guarantee is the caller's job via `stderr_is_tty`).
pub fn red(s: &str) -> String {
    format!("\x1b[31m{s}\x1b[0m")
}

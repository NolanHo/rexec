//! Bundled CPython runtime for `rexec <host> script --python`.
//!
//! This module owns the managed-runtime payload lifecycle: resolving the pinned
//! python-build-standalone (PBS) asset for a remote, downloading and verifying it
//! into the local cache, uploading it over rexec's existing rsync-over-ssh
//! channel, unpacking it on the remote with `tar`, and writing the readiness
//! stamp. `main.rs` / `ssh.rs` keep only the wiring (CLI branches, the
//! `run_script` branch, remote execution primitives).
//!
//! Layout invariants (spec 「本地与远端布局」):
//! - Local cache: `~/.rexec/cache/<asset>` (same directory as the worker cache,
//!   file names do not collide). The download is written to `<asset>.part` and
//!   only renamed into place after *both* the sha256 and the byte count verify.
//! - Remote root: `<home>/.rexec/py/`. Nothing outside that directory may be
//!   deleted or rewritten.
//! - Interpreter: `<runtime_dir>/python/bin/python3`; the path must be
//!   shell-quoted at the call site.
//!
//! PBS publishes no `.sha256` asset for these files, so [`Payload::sha256`] is
//! the only integrity source and is hardcoded below.
//!
//! The lifecycle is: one read-only readiness probe (stamp + executable marker
//! in a single round trip) → a status-checked remote `tar` probe, taken only
//! when an install is actually needed (a ready runtime, and `python status`,
//! never require `tar`) → local cache hit or verified download → rsync
//! upload under a random nonce → remote byte-count check → `tar` unpack into a
//! nonce-named temp directory → `rm -rf <key>` + `mv <tmp> <key>` + a
//! deterministic nested-copy guard (`mv` into an existing directory nests the
//! source inside it with exit 0 instead of replacing it, so a racing install
//! can leave this run's tree at `<key>/<tmp>`; the guard removes exactly that
//! nonce-named path) → `<interpreter> -VV` → stamp write → tarball cleanup.
//! Every failure path removes the temp artefacts it created, the nested copy
//! included.
//!
//! The tests at the bottom of this file are the Red suite this implementation
//! turns green; not a single expected value below was changed.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use russh::client::Handle;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use crate::RemoteHost;
use crate::diagnostics;
use crate::ssh::ClientHandler;

/// libc flavor of the remote host, probed on the remote before any download.
///
/// The probe emits three signals (see [`parse_flavor`]): the
/// `getconf GNU_LIBC_VERSION` line (or `no-glibc`), the first
/// `/lib/ld-musl-*.so.1` path (or an empty line), and `alpine` when
/// `/etc/alpine-release` exists (or an empty line).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibcFlavor {
    /// glibc remote (the common case; glibc >= 2.17 required by the PBS gnu build).
    Gnu,
    /// musl remote (Alpine and friends).
    Musl,
}

/// A pinned python-build-standalone payload.
///
/// # Trust anchor
///
/// PBS publishes no `.sha256` asset for these archives, so [`Payload::sha256`]
/// is the only integrity source; it must stay hardcoded in the source and be
/// checked *before* the cached file is renamed into place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Payload {
    /// PBS asset file name, e.g. `cpython-3.13.16+20261001-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz`.
    pub asset: &'static str,
    /// Lowercase hex sha256 of the asset, 64 characters.
    pub sha256: &'static str,
    /// Exact asset size in bytes.
    pub size: u64,
}

/// CPython version shipped by the managed runtime.
pub const PYTHON_VERSION: &str = "3.13.16";

/// python-build-standalone release the pinned assets come from.
pub const PBS_RELEASE: &str = "20261001";

/// Remote runtime root, relative to the remote home directory: `<home>/.rexec/py/`.
///
/// Every path this module creates, rewrites or deletes lives under this root.
pub const REMOTE_PY_ROOT: &str = ".rexec/py";

/// Line the readiness probe prints when the interpreter is present and executable:
/// `test -x <abs interpreter> && echo __rexec_py_ok__`.
///
/// The `test -x` branch is silent when it fails, so a stamp match without this
/// marker means the runtime is gone (partial wipe), not executable (noexec mount)
/// or unusable (truncated unpack, missing shared library).
pub const READY_MARKER: &str = "__rexec_py_ok__";

/// Suffix every pinned asset carries; the runtime key is the asset without it.
const STRIPPED_SUFFIX: &str = "-install_only_stripped.tar.gz";

/// Base of the python-build-standalone release download URL.
const PBS_DOWNLOAD_BASE: &str =
    "https://github.com/astral-sh/python-build-standalone/releases/download";

/// Timeout for a read-only probe or a stamp step (spec 失败行为: 60s).
const PROBE_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for the remote unpack (spec 失败行为: 300s).
const EXTRACT_TIMEOUT: Duration = Duration::from_secs(300);

/// Timeout for the local download of the ~33 MiB payload.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);

/// Timeout for the ~33 MiB rsync upload.
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(600);

/// Bound for the best-effort cleanup and removal calls.
///
/// They run right after a failure — usually a timeout — on a remote that may
/// well have wedged, so they get a bound far shorter than any status-checked
/// step: cleanup must never turn a failed install into an unbounded hang, and
/// its result is discarded either way.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(15);

/// Bound for reaping a local child we just SIGKILLed.
///
/// `wait` returns only once the child is actually reaped, and SIGKILL cannot
/// end a process stuck in an uninterruptible (D-state) syscall — e.g. `curl -o`
/// or `rsync` writing into a hung network filesystem under `~/.rexec/cache`.
/// The timed-out transfer must therefore report its timeout instead of blocking
/// here forever; if this bound expires the child is left behind unreaped.
const KILL_REAP_TIMEOUT: Duration = Duration::from_secs(5);

/// The pinned trust-anchor table: `(remote asset label, libc flavor)` → payload.
///
/// Values are copied verbatim from the spec's 「固定载荷」 section (measured
/// twice, see `recon/payload-anchors.tsv`); python-build-standalone publishes no
/// `.sha256` asset, so these constants are the only integrity source.
const PAYLOADS: [(&str, LibcFlavor, Payload); 4] = [
    (
        "linux-amd64",
        LibcFlavor::Gnu,
        Payload {
            asset: "cpython-3.13.16+20261001-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
            sha256: "ffcb50e716789d1a6e1db5e745d4d194ac8ed9b015ccf5eabcaccb179a25e4a8",
            size: 35_067_590,
        },
    ),
    (
        "linux-arm64",
        LibcFlavor::Gnu,
        Payload {
            asset: "cpython-3.13.16+20261001-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz",
            sha256: "f94c8f69f3e68b026b916b3aa32b9b3bfff63fd7c95b2affa8272b1601d668fa",
            size: 29_311_682,
        },
    ),
    (
        "linux-amd64",
        LibcFlavor::Musl,
        Payload {
            asset: "cpython-3.13.16+20261001-x86_64-unknown-linux-musl-install_only_stripped.tar.gz",
            sha256: "31b1f560c68313c00bab4faa2452bc0a87e3e9f9ddf16b94d2265bd9d99afc2e",
            size: 27_746_339,
        },
    ),
    (
        "linux-arm64",
        LibcFlavor::Musl,
        Payload {
            asset: "cpython-3.13.16+20261001-aarch64-unknown-linux-musl-install_only_stripped.tar.gz",
            sha256: "6952e49f84fa720d61de783f7298410cbb98227ee9a0750340ec7385ae71420a",
            size: 27_941_356,
        },
    ),
];

/// Remote command that reports the system interpreter, if any.
pub(crate) const SYSTEM_PYTHON3_PROBE: &str = "command -v python3 2>/dev/null";

/// Remote `tar` gate, run before anything is downloaded or uploaded when an
/// install is needed: the payload can only be unpacked with the remote's `tar`,
/// and discovering that after a ~33 MiB download + upload wastes the transfer.
///
/// `command -v` is POSIX and BusyBox-portable and prints the resolved path; it
/// is silent (with a non-zero status) when the tool is absent.
const TAR_PROBE: &str = "command -v tar 2>/dev/null";

/// Remote three-signal libc flavor probe (see [`parse_flavor`]).
///
/// One shell line whose three commands print one line each: the glibc version
/// (or `no-glibc`), the first musl loader (or nothing) and the Alpine marker
/// (or nothing).
pub(crate) const FLAVOR_PROBE: &str = "{ getconf GNU_LIBC_VERSION 2>/dev/null || echo no-glibc; }; ls -d /lib/ld-musl-*.so.1 2>/dev/null | head -1; { [ -f /etc/alpine-release ] && echo alpine; } || true";

/// Remote asset label (`"linux-amd64"` / `"linux-arm64"`) + libc flavor → pinned payload.
///
/// Any other label (`macos-*`, `windows-*`, unknown) is an error: only Linux
/// remotes are supported, and the caller must not download or upload anything
/// for them.
pub fn payload_for(remote_asset: &str, flavor: LibcFlavor) -> Result<&'static Payload> {
    PAYLOADS
        .iter()
        .find(|(label, entry_flavor, _)| *label == remote_asset && *entry_flavor == flavor)
        .map(|(_, _, payload)| payload)
        .ok_or_else(|| {
            anyhow!(
                "no bundled CPython runtime for remote asset {remote_asset:?} ({flavor:?}) — the \
                 managed runtime supports Linux x86_64/aarch64 with glibc or musl only"
            )
        })
}

/// Runtime directory key: the asset name with its `-install_only_stripped.tar.gz`
/// suffix removed, e.g. `cpython-3.13.16+20261001-x86_64-unknown-linux-gnu`.
///
/// The key is what gets cached on the remote (`<home>/.rexec/py/<key>/`), so it
/// is derived from the Python version, not from the rexec version: upgrading
/// rexec must not retransfer ~33 MiB.
pub fn runtime_key(remote_asset: &str, flavor: LibcFlavor) -> Result<String> {
    let asset = payload_for(remote_asset, flavor)?.asset;
    asset
        .strip_suffix(STRIPPED_SUFFIX)
        .map(str::to_string)
        .ok_or_else(|| {
            anyhow!("pinned asset {asset:?} does not carry the {STRIPPED_SUFFIX} suffix")
        })
}

/// Download URL of the payload:
/// `https://github.com/astral-sh/python-build-standalone/releases/download/<PBS_RELEASE>/<asset>`.
///
/// `+` in the asset name must be percent-encoded as `%2B` — a literal `+` in a
/// URL path component is a space, which would 404.
pub fn download_url(payload: &Payload) -> String {
    // A literal `+` in a URL path component decodes to a space, so the PBS tag
    // (`...+20261001...`) would 404: percent-encode it.
    let asset = payload.asset.replace('+', "%2B");
    format!("{PBS_DOWNLOAD_BASE}/{PBS_RELEASE}/{asset}")
}

/// Absolute remote interpreter path: `{runtime_dir}/python/bin/python3`.
pub fn interpreter_path(runtime_dir: &str) -> String {
    format!("{runtime_dir}/python/bin/python3")
}

/// Remote stamp path: `{runtime_dir}/.stamp`.
pub fn stamp_path(runtime_dir: &str) -> String {
    format!("{runtime_dir}/.stamp")
}

/// First line of the stamp file: `rexec-python <key>`.
///
/// The stamp proves the interpreter actually ran (not merely that files exist),
/// which covers noexec mounts, missing shared libraries and truncated unpacks.
pub fn stamp_marker(key: &str) -> String {
    format!("rexec-python {key}")
}

/// The first line of `probe_output`, trimmed, or `""` when there is none.
fn first_line(probe_output: &str) -> &str {
    probe_output.lines().next().unwrap_or("").trim()
}

/// Whether a `cat <runtime_dir>/.stamp` probe output means the runtime is ready.
///
/// True when the first line, trimmed, equals `stamp_marker(key)`; the rest of the
/// output (the `-VV` line recorded at install time) is ignored. Empty output is
/// never current. Leading/trailing whitespace and CRLF line endings are
/// tolerated, because the probe is remote shell output.
pub fn stamp_is_current(probe_output: &str, key: &str) -> bool {
    // `lines()` already drops a trailing CR, and every line is trimmed, so CRLF
    // endings and incidental whitespace cannot defeat the comparison.
    first_line(probe_output) == stamp_marker(key)
}

/// Whether a single read-only probe round trip proves the managed runtime is usable.
///
/// The probe is
/// `cat <abs stamp> 2>/dev/null; test -x <abs interpreter> && echo __rexec_py_ok__`,
/// i.e. one round trip that covers both "the stamp was written by *this* key" and
/// "the interpreter is still there and executable" (a partial wipe, a noexec
/// mount, a truncated unpack and a missing shared library all fail it).
///
/// True iff [`stamp_is_current`] holds for the same output **and** some line of
/// the output, trimmed, is exactly [`READY_MARKER`]. `cat` is silent when the
/// stamp is missing and `test -x` is silent when it fails, so "stamp only"
/// (interpreter gone) and "marker only" (missing or foreign stamp) are both not
/// ready. Every line is compared after trimming, so CRLF endings and incidental
/// whitespace are tolerated.
pub fn runtime_is_ready(probe_output: &str, key: &str) -> bool {
    stamp_is_current(probe_output, key)
        && probe_output.lines().any(|line| line.trim() == READY_MARKER)
}

/// libc flavor of the remote, parsed from the three-signal probe output.
///
/// The probe prints three lines:
///
/// 1. `glibc <version>` when `getconf GNU_LIBC_VERSION` succeeds, else `no-glibc`;
/// 2. the first `/lib/ld-musl-*.so.1` path, else an empty line;
/// 3. `alpine` when `/etc/alpine-release` exists, else an empty line.
///
/// Precedence: a reported glibc wins outright — a glibc distro may well carry a
/// co-installed musl loader, and the gnu build is what it needs — otherwise a
/// musl loader or the Alpine marker means musl. With no signal at all the default
/// is [`LibcFlavor::Gnu`]. Missing lines count as empty signals and lines beyond
/// the third are ignored, so an empty probe output is `Gnu` as well.
pub fn parse_flavor(probe_output: &str) -> LibcFlavor {
    let mut lines = probe_output.lines().map(str::trim);

    // Signal 1: a reported glibc wins outright — a glibc distro may well carry a
    // co-installed musl loader, and the gnu build is what it needs.
    let glibc = lines.next().unwrap_or("");
    if glibc.starts_with("glibc") {
        return LibcFlavor::Gnu;
    }

    // Signals 2 and 3: a musl loader or the Alpine marker means musl. Lines
    // beyond the third are ignored (the iterator stops at three).
    let musl_loader = lines.next().unwrap_or("");
    let alpine = lines.next().unwrap_or("");
    if musl_loader.contains("ld-musl") || alpine == "alpine" {
        return LibcFlavor::Musl;
    }

    // No signal at all (or only `no-glibc`): the gnu build is the default.
    LibcFlavor::Gnu
}

/// Whether the managed runtime must be used, per the frozen truth table:
///
/// | force_managed | explicit | is_python_file | remote_python3 | remote_is_linux | result |
/// |---------------|----------|----------------|----------------|-----------------|--------|
/// | true          | any      | any            | any            | true            | true   |
/// | true          | any      | any            | any            | false           | false  |
/// | false         | Some(_)  | any            | any            | any             | false  |
/// | false         | None     | false          | any            | any             | false  |
/// | false         | None     | true           | true           | any             | false  |
/// | false         | None     | true           | false          | true            | true   |
/// | false         | None     | true           | false          | false           | false  |
///
/// Priority is `--interpreter` > `--python` > auto-detection. `--python` and
/// `--interpreter` together are a clap usage conflict (exit code 2), so the
/// `force_managed == true, explicit == Some(_)` cell is not reachable through the
/// CLI; the table is still authoritative for it.
///
/// **Non-Linux is always `false`**, including the `force_managed` row: the caller
/// reports the "`--python` needs a Linux remote" error *before* calling this
/// function, and on a non-Linux remote the automatic fallback keeps today's
/// literal `python3` plus a verbose-only note instead of downloading anything.
///
/// - `force_managed`: `--python` was given.
/// - `explicit`: `--interpreter CMD`.
/// - `is_python_file`: `detect_runner` would select `python3` (no shebang, `.py` extension).
/// - `remote_python3`: `command -v python3 2>/dev/null` found a system interpreter.
/// - `remote_is_linux`: the resolved remote asset label starts with `linux-`.
pub fn needs_managed_runtime(
    force_managed: bool,
    explicit: Option<&str>,
    is_python_file: bool,
    remote_python3: bool,
    remote_is_linux: bool,
) -> bool {
    // Non-Linux is always false, including the force row: the caller reports the
    // "--python needs a Linux remote" error before calling, and the automatic
    // fallback on a non-Linux remote keeps today's literal `python3`.
    if !remote_is_linux {
        return false;
    }
    if force_managed {
        return true;
    }
    if explicit.is_some() || !is_python_file {
        return false;
    }
    !remote_python3
}

/// Assemble the remote command line for `script`, byte-for-byte as v0.4.2 did
/// inline in `run_script` (`main.rs:4755-4774` of the baseline `776f734`).
///
/// Characterization contract:
///
/// - `runner == Some(cmd)` → `cmd '<script>' <arg>…`. The runner is emitted
///   **unquoted**, exactly as the pre-change code did: `--interpreter` takes a
///   command snippet (`python3 -u`), not a single argv word.
/// - `runner == None` (the local script starts with `#!`) →
///   `chmod +x '<script>' && '<script>' <arg>…`.
/// - `remote_script` and every argument are single-quoted with the existing
///   `shell_quote` (an embedded `'` becomes `'"'"'`), and the parts are joined
///   with a single space, so argument order is preserved.
/// - A NUL byte in the script path or in any argument is an error, because
///   `shell_quote` rejects NUL to prevent C-string truncation.
pub fn assemble_remote_command(
    runner: Option<&str>,
    remote_script: &str,
    args: &[String],
) -> Result<String> {
    let mut parts: Vec<String> = Vec::new();
    match runner {
        Some(r) => {
            // Emitted unquoted, exactly as v0.4.2 did: `--interpreter` takes a
            // command snippet (`python3 -u`), not a single argv word.
            parts.push(r.to_string());
            parts.push(crate::shell_quote(remote_script)?);
        }
        None => {
            // shebang: chmod +x then run directly
            let q = crate::shell_quote(remote_script)?;
            parts.push(format!("chmod +x {q} && {q}"));
        }
    }
    for a in args {
        parts.push(crate::shell_quote(a)?);
    }
    Ok(parts.join(" "))
}

/// Which of the `init` dependencies are missing, parsed from the probe output.
///
/// Recognized tools, in the order returned: `rsync`, `sh`, `tar`. `tar` joined
/// the list in this change (the managed runtime unpacks remotely with `tar`), so
/// `init` must no longer return early just because `rsync` exists.
///
/// A tool is missing when a line of `probe_output`, after trimming, starts with
/// `✗ ` followed by the tool name at a token boundary — the shape
/// `check_and_install_deps` prints in both its initial check and its
/// post-install verify pass (`✗ <tool>: NOT FOUND` and `✗ <tool>: STILL NOT
/// FOUND`; in the v0.4.2 baseline those passes covered only `rsync` and `sh`,
/// `tar` joined them in this change). The `✓ <tool>: <path>` lines, the
/// package-manager line and any other text are ignored; empty input therefore
/// reports nothing missing.
pub fn missing_remote_deps(probe_output: &str) -> Vec<&'static str> {
    /// Tools `init` checks, in the order [`missing_remote_deps`] reports them.
    const TOOLS: [&str; 3] = ["rsync", "sh", "tar"];

    let mut missing = Vec::new();
    for tool in TOOLS {
        let prefix = format!("✗ {tool}");
        let hit = probe_output.lines().any(|line| {
            let line = line.trim();
            match line.strip_prefix(&prefix) {
                // A token boundary after the tool name: `✗ tar: NOT FOUND` and
                // `✗ tar: STILL NOT FOUND` count, `✗ tar.gz: …` does not.
                Some(rest) => rest
                    .chars()
                    .next()
                    .is_none_or(|c| c == ':' || c.is_whitespace()),
                None => false,
            }
        });
        if hit {
            missing.push(tool);
        }
    }
    missing
}

// ── Remote layout ───────────────────────────────────────────────────────────

/// Every absolute remote path one runtime lifecycle touches.
///
/// `<home>` is the *resolved* absolute home (probed with `printf %s "$HOME"`);
/// all operands are written from these fields and shell-quoted at the call
/// site, so a home containing spaces or shell metacharacters cannot break out
/// of the command.
pub(crate) struct RuntimeTarget {
    /// `<home>/.rexec/py` — the remote runtime root.
    pub root: String,
    /// `<home>/.rexec/py/<key>` — the runtime directory.
    pub runtime_dir: String,
    /// `<home>/.rexec/py/<key>.tar.gz` — tarball base name; the upload appends
    /// a random nonce.
    pub tarball: String,
    /// `<runtime_dir>/python/bin/python3` (unquoted).
    pub interpreter: String,
    /// `<runtime_dir>/.stamp`.
    pub stamp: String,
    pub key: String,
    pub payload: &'static Payload,
    pub flavor: LibcFlavor,
}

/// Whether a runtime key is a single, safe path component.
///
/// The key is a PBS asset name from the pinned table, never user input — but it
/// becomes an `rm -rf` operand, so the destructive path stays provably simple:
/// non-empty, no `/` separator and no `..` anywhere in the name (any `..`
/// substring is refused, so a `..` component cannot survive either).
fn key_is_safe(key: &str) -> bool {
    !key.is_empty() && !key.contains('/') && !key.contains("..")
}

/// Resolve the runtime paths for a resolved remote home and platform label.
pub(crate) fn runtime_target(
    home: &str,
    remote_asset: &str,
    flavor: LibcFlavor,
) -> Result<RuntimeTarget> {
    let payload = payload_for(remote_asset, flavor)?;
    let key = runtime_key(remote_asset, flavor)?;
    if !key_is_safe(&key) {
        return Err(anyhow!(
            "refusing to build a runtime path from the unexpected key {key:?}"
        ));
    }
    let root = format!("{}/{}", home.trim_end_matches('/'), REMOTE_PY_ROOT);
    let runtime_dir = format!("{root}/{key}");
    Ok(RuntimeTarget {
        tarball: format!("{root}/{key}.tar.gz"),
        interpreter: interpreter_path(&runtime_dir),
        stamp: stamp_path(&runtime_dir),
        root,
        runtime_dir,
        key,
        payload,
        flavor,
    })
}

// ── Remote execution primitives ─────────────────────────────────────────────

/// Status-exact remote execution with a timeout: `(stdout, stderr, exit)`.
///
/// Wraps the crate's byte-exact reader (which, unlike [`crate::ssh::exec_remote`],
/// keeps the exit status) and bounds every step, so a hung remote cannot block
/// the CLI forever.
async fn exec_status(
    session: &Handle<ClientHandler>,
    command: &str,
    timeout: Duration,
    what: &str,
) -> Result<(String, String, Option<i32>)> {
    let (out, err, code) =
        tokio::time::timeout(timeout, crate::read_remote_bytes(session, command))
            .await
            .map_err(|_| {
                anyhow!(
                    "{what} timed out after {}s — remote command: `{command}`",
                    timeout.as_secs()
                )
            })??;
    Ok((
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
        code,
    ))
}

/// Remote-side detail for an error message: stderr first, stdout after it.
fn remote_detail(out: &str, err: &str) -> String {
    let err = err.trim();
    let out = out.trim();
    let mut parts = Vec::new();
    if !err.is_empty() {
        parts.push(err.to_string());
    }
    if !out.is_empty() {
        parts.push(out.to_string());
    }
    if parts.is_empty() {
        "(no output)".to_string()
    } else {
        parts.join(" | ")
    }
}

/// Run a remote command that must exit 0, returning its stdout.
async fn run_checked(
    session: &Handle<ClientHandler>,
    command: &str,
    timeout: Duration,
    what: &str,
) -> Result<String> {
    let (out, err, code) = exec_status(session, command, timeout, what).await?;
    match code {
        Some(0) => Ok(out),
        Some(c) => Err(anyhow!(
            "{what} failed on the remote (exit {c}): {}",
            remote_detail(&out, &err)
        )),
        None => Err(anyhow!(
            "{what} failed on the remote (no exit status reported): {}",
            remote_detail(&out, &err)
        )),
    }
}

/// Run a best-effort remote command under [`CLEANUP_TIMEOUT`]; `true` when it
/// completed without an error, `false` when it failed **or** exceeded the bound.
///
/// Unlike [`exec_status`] the result is deliberately coarse — both callers only
/// need "did this work" — and the bound exists so a wedged remote cannot hang
/// the CLI on the cleanup path.
async fn exec_best_effort(session: &Handle<ClientHandler>, command: &str) -> bool {
    matches!(
        tokio::time::timeout(CLEANUP_TIMEOUT, crate::ssh::exec_remote(session, command)).await,
        Ok(Ok(_))
    )
}

/// Remove our own remote temp artefacts, best effort, never a wildcard.
async fn cleanup_remote(
    session: &Handle<ClientHandler>,
    paths: &[&str],
    trace: &mut diagnostics::Trace,
) {
    for path in paths {
        let Ok(quoted) = crate::shell_quote(path) else {
            continue;
        };
        if !exec_best_effort(session, &format!("rm -rf {quoted}")).await {
            // `exec_best_effort` discards the remote exit status, so this fires
            // only when the call itself errored or hit `CLEANUP_TIMEOUT` — not
            // when `rm` ran and failed.
            trace.add(format!(
                "python: cleanup of the remote temp artefact {path} did not complete \
                 (call error or timeout) — remove it manually if it is still there"
            ));
        }
    }
}

/// 8 random hex characters, unique across machines (a local pid is not).
fn random_nonce() -> String {
    let nonce: u32 = rand::random();
    format!("{nonce:08x}")
}

// ── Read-only probes ────────────────────────────────────────────────────────

/// The absolute remote home (spec: `<home>` is always the resolved absolute path).
pub(crate) async fn probe_home(session: &Handle<ClientHandler>) -> Result<String> {
    let (out, _, _) = exec_status(
        session,
        "printf %s \"$HOME\"",
        PROBE_TIMEOUT,
        "remote home probe",
    )
    .await?;
    let home = out.trim().to_string();
    if home.is_empty() {
        return Err(anyhow!(
            "could not determine the remote HOME directory — the managed runtime lives under \
             <home>/.rexec/py"
        ));
    }
    Ok(home)
}

/// The remote libc flavor, from the three-signal probe.
pub(crate) async fn probe_flavor(session: &Handle<ClientHandler>) -> Result<LibcFlavor> {
    let (out, _, _) =
        exec_status(session, FLAVOR_PROBE, PROBE_TIMEOUT, "libc flavor probe").await?;
    Ok(parse_flavor(&out))
}

/// Whether the remote has a system `python3` (the automatic-fallback input).
pub(crate) async fn probe_system_python3(session: &Handle<ClientHandler>) -> Result<bool> {
    let (out, _, _) = exec_status(
        session,
        SYSTEM_PYTHON3_PROBE,
        PROBE_TIMEOUT,
        "remote python3 probe",
    )
    .await?;
    Ok(!out.trim().is_empty())
}

/// Whether the remote's `tar` is on PATH — one cheap, read-only round trip.
///
/// The authority is the exit status (`command -v` exits 0 when it resolves the
/// tool); output is the fallback for a server that reports no exit status, which
/// [`crate::read_remote_bytes`] explicitly tolerates.
async fn probe_remote_tar(session: &Handle<ClientHandler>) -> Result<bool> {
    let (out, _, code) = exec_status(session, TAR_PROBE, PROBE_TIMEOUT, "remote tar probe").await?;
    Ok(code == Some(0) || (code.is_none() && !out.trim().is_empty()))
}

/// The missing-`tar` remedy, worded once for both places that can diagnose it:
/// the pre-download gate and the unpack safety net. `init` is the command that
/// checks and installs `rsync`, `sh` and `tar`.
fn missing_tar_error(detail: &str) -> anyhow::Error {
    anyhow!(
        "the remote has no `tar`, which the managed CPython runtime needs to unpack \
         ({detail})\nhint: run `rexec <host> init` on that host to install tar, then retry"
    )
}

/// Whether a failed unpack is the not-found signal of a missing `tar` rather
/// than a genuine unpack error (for which the disk-space hint applies).
///
/// Signals, matching the shell's own vocabulary: exit 127 (`command not found`),
/// the `tar: not found` text BusyBox/musl emit, or any other `not found` in the
/// remote output. `detail` is already de-whitespaced by [`remote_detail`].
fn unpack_looks_like_missing_tar(code: Option<i32>, detail: &str) -> bool {
    code == Some(127) || detail.contains("not found")
}

/// The single-round-trip readiness probe: stamp text **and** the executable
/// marker, in that order.
pub(crate) fn readiness_probe(target: &RuntimeTarget) -> Result<String> {
    Ok(format!(
        "cat {} 2>/dev/null; test -x {} && echo {}",
        crate::shell_quote(&target.stamp)?,
        crate::shell_quote(&target.interpreter)?,
        READY_MARKER
    ))
}

/// One read-only round trip: `Some(<python -VV first line>)` when the runtime is
/// ready, `None` otherwise. Records `python: runtime {key} ready` on a hit.
pub(crate) async fn probe_ready(
    session: &Handle<ClientHandler>,
    target: &RuntimeTarget,
    trace: &mut diagnostics::Trace,
) -> Result<Option<String>> {
    let (out, _, _) = exec_status(
        session,
        &readiness_probe(target)?,
        PROBE_TIMEOUT,
        "python runtime readiness probe",
    )
    .await?;
    if !runtime_is_ready(&out, &target.key) {
        return Ok(None);
    }
    // The stamp's second line is the `-VV` output recorded at install time.
    let vv = out
        .lines()
        .nth(1)
        .map(str::trim)
        .unwrap_or_default()
        .to_string();
    trace.add(format!("python: runtime {} ready", target.key));
    Ok(Some(vv))
}

// ── Local payload cache ─────────────────────────────────────────────────────

/// `~/.rexec/cache` — the same directory the worker cache uses (file names do
/// not collide: worker entries are `rexec-v<version>-<asset>`).
fn cache_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("cannot determine home directory")?;
    let dir = home.join(".rexec").join("cache");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

/// Lowercase-hex sha256 of a file, streamed (the payload is ~33 MiB).
fn sha256_file_hex(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let mut hasher = Sha256::new();
    std::io::copy(&mut reader, &mut hasher)
        .with_context(|| format!("hashing {}", path.display()))?;
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Byte size *and* sha256 must match the pinned anchor. PBS publishes no
/// `.sha256` asset, so this is the only integrity check on the tarball.
fn verify_payload(path: &Path, payload: &Payload) -> Result<()> {
    let actual_size = std::fs::metadata(path)
        .with_context(|| format!("reading the size of {}", path.display()))?
        .len();
    if actual_size != payload.size {
        return Err(anyhow!(
            "byte size mismatch: expected {} bytes, got {actual_size}",
            payload.size
        ));
    }
    let actual_sha = sha256_file_hex(path)?;
    if actual_sha != payload.sha256 {
        return Err(anyhow!(
            "sha256 mismatch: expected {}, got {actual_sha}",
            payload.sha256
        ));
    }
    Ok(())
}

/// The local payload path: an existing cache entry (verified) or a fresh,
/// verified download. Writes `<asset>.part` and only renames it into place once
/// both the size and the sha256 verify; a mismatch deletes the `.part` file.
async fn fetch_payload(
    payload: &'static Payload,
    trace: &mut diagnostics::Trace,
) -> Result<PathBuf> {
    let cache_path = cache_dir()?.join(payload.asset);

    if cache_path.exists() {
        match verify_payload(&cache_path, payload) {
            Ok(()) => {
                trace.add(format!("python: cached {}", cache_path.display()));
                return Ok(cache_path);
            }
            Err(e) => {
                // A truncated cache entry is worse than no cache: drop it and
                // download again instead of uploading garbage.
                trace.add(format!(
                    "python: cached {} failed verification ({e:#}) — re-downloading",
                    cache_path.display()
                ));
                let _ = std::fs::remove_file(&cache_path);
            }
        }
    }

    let part_path = PathBuf::from(format!("{}.part", cache_path.display()));
    // A `.part` left over from a killed download is not trusted either.
    let _ = std::fs::remove_file(&part_path);

    let url = download_url(payload);
    trace.add(format!("python: downloading {url}"));
    crate::progress!(
        "⬇ Downloading CPython {PYTHON_VERSION} ({:.1} MiB) from python-build-standalone",
        payload.size as f64 / (1024.0 * 1024.0)
    );

    let mut child = tokio::process::Command::new("curl")
        .args(["-fSL", "--retry", "3", "-o"])
        .arg(&part_path)
        .arg(&url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            anyhow!(
                "local `curl` is required to download the CPython runtime but could not be \
                 spawned ({e}) — install curl and retry"
            )
        })?;

    // `wait_with_output` consumes the child, which would leave nothing to kill
    // when the transfer stalls, so wait and drain stderr together instead: the
    // concurrent read keeps a full stderr pipe from wedging the wait.
    let mut stderr_pipe = child.stderr.take().expect("stderr is piped");
    let mut stderr_buf: Vec<u8> = Vec::new();
    let waited = tokio::time::timeout(DOWNLOAD_TIMEOUT, async {
        tokio::join!(child.wait(), stderr_pipe.read_to_end(&mut stderr_buf))
    })
    .await;
    let (status, _) = match waited {
        Ok(joined) => joined,
        Err(_) => {
            // Kill the stalled download instead of orphaning it, then reap it so
            // the killed child cannot linger as a zombie — bounded, because
            // SIGKILL cannot end a child stuck in a D-state syscall and the
            // timeout below is the answer either way.
            let _ = child.start_kill();
            let _ = tokio::time::timeout(KILL_REAP_TIMEOUT, child.wait()).await;
            let _ = std::fs::remove_file(&part_path);
            return Err(anyhow!(
                "downloading {url} timed out after {}s",
                DOWNLOAD_TIMEOUT.as_secs()
            ));
        }
    };
    let status = status.context("failed to wait for curl")?;
    if !status.success() {
        let _ = std::fs::remove_file(&part_path);
        return Err(anyhow!(
            "downloading {url} failed: {}\nhint: the runtime comes from \
             astral-sh/python-build-standalone on github.com — check network access and retry",
            String::from_utf8_lossy(&stderr_buf).trim()
        ));
    }

    if let Err(e) = verify_payload(&part_path, payload) {
        // A mismatching download must never survive as a cache entry.
        let _ = std::fs::remove_file(&part_path);
        return Err(e.context(format!(
            "the downloaded CPython runtime at {} is not the pinned asset",
            part_path.display()
        )));
    }

    std::fs::rename(&part_path, &cache_path).with_context(|| {
        format!(
            "moving the verified download into the cache ({})",
            cache_path.display()
        )
    })?;
    trace.add(format!("python: cached {}", cache_path.display()));
    Ok(cache_path)
}

// ── Upload and install ──────────────────────────────────────────────────────

/// Upload the tarball with the *sync* ssh option builder (`sync_ssh_e`), so
/// `--port`, `ProxyJump` and `--socks5` all apply — the worker upload's
/// hardcoded options do not. `-s` (`--protect-args`) keeps the remote shell out
/// of the absolute destination path.
async fn upload_tarball(
    local: &Path,
    remote: &RemoteHost,
    remote_path: &str,
    trace: &mut diagnostics::Trace,
) -> Result<()> {
    let (rsync_host, _) = crate::rsync_endpoint(remote);
    let ssh_e = crate::sync_ssh_e(remote);
    let target = format!("{rsync_host}:{remote_path}");
    let local_str = local.to_string_lossy().into_owned();

    trace.add(format!("python: uploading {} → {target}", local.display()));
    crate::progress!("⬆ Uploading the CPython runtime to {target}");

    let mut child = tokio::process::Command::new("rsync")
        .args([
            "-az",
            "-s",
            "-e",
            ssh_e.as_str(),
            local_str.as_str(),
            target.as_str(),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            anyhow!(
                "local `rsync` is required to upload the CPython runtime but could not be spawned \
                 ({e}) — install rsync (on Windows run rexec from MSYS2/WSL) and retry"
            )
        })?;

    // As with the download: never `wait_with_output`, so the child we still own
    // can be killed when the upload stalls; stderr is drained concurrently so a
    // full pipe cannot wedge the wait.
    let mut stderr_pipe = child.stderr.take().expect("stderr is piped");
    let mut stderr_buf: Vec<u8> = Vec::new();
    let waited = tokio::time::timeout(UPLOAD_TIMEOUT, async {
        tokio::join!(child.wait(), stderr_pipe.read_to_end(&mut stderr_buf))
    })
    .await;
    let (status, _) = match waited {
        Ok(joined) => joined,
        Err(_) => {
            // Kill the stalled upload instead of orphaning it, then reap it
            // under the same bound (a D-state child cannot be killed into a
            // reap); the caller removes whatever partial file reached the
            // remote.
            let _ = child.start_kill();
            let _ = tokio::time::timeout(KILL_REAP_TIMEOUT, child.wait()).await;
            return Err(anyhow!(
                "rsync timed out after {}s while uploading the CPython runtime to {target}",
                UPLOAD_TIMEOUT.as_secs()
            ));
        }
    };
    let status = status.context("failed to wait for rsync")?;
    if !status.success() {
        return Err(anyhow!(
            "rsync failed with status {} while uploading the CPython runtime: {}",
            status,
            String::from_utf8_lossy(&stderr_buf).trim()
        ));
    }
    Ok(())
}

/// Hint for an unpack that failed for any reason other than a missing `tar`.
///
/// Used both when the unpack timed out and when it exited non-zero: the usual
/// cause of a 33 MiB archive failing to expand is a full disk.
const DISK_SPACE_HINT: &str = "hint: the remote may be out of disk space — the runtime unpacks \
                               to about 105 MiB; check `df -h` on the remote";

/// Why an unpacked interpreter may refuse to run — the reasons the spec's
/// failure table requires to be listed.
fn interpreter_failure_hint(target: &RuntimeTarget) -> String {
    format!(
        "hint: the interpreter at {} did not run. Possible causes: the {:?} build needs \
         glibc >= 2.17 (or a musl host for the musl build), the runtime directory is on a noexec \
         mount, or the unpack is truncated. Remove {} and retry `rexec <host> python install`.",
        target.interpreter, target.flavor, target.runtime_dir
    )
}

/// What an install did.
pub(crate) struct InstallOutcome {
    /// Absolute interpreter path (unquoted) the caller should run scripts with.
    pub interpreter: String,
    /// True when this call uploaded and unpacked the payload.
    pub deployed: bool,
}

/// Ensure the managed runtime is installed and ready.
///
/// `force` (`python install --reinstall`) skips the readiness probe and always
/// reinstalls. Without it, a ready runtime costs exactly one read-only round
/// trip. Idempotent: the swap is `rm -rf <key>` + `mv <tmp> <key>` + a
/// deterministic nested-copy guard.
///
/// Concurrency contract. `mv` into an existing directory nests the source
/// inside it and still exits 0, so two interleaved installs can both
/// `rm -rf <key>` and then both `mv`: the second `mv` lands its own nonce-named
/// tree at `<key>/<tmp>` instead of replacing `key`. The guard removes exactly
/// that path — the nonce makes it provably this run's own tree — so:
///
/// - last writer wins: the surviving `<key>` is one install's complete runtime;
/// - nothing is silently corrupted: `mv` never merges or overwrites, so
///   deleting the nested copy restores the winner's runtime byte for byte;
/// - the nesting is transient: it exists only between the loser's `mv` and its
///   guard, and the loser's failure paths remove it as well.
///
/// Known limitation (documented for the user-facing docs): a *running*
/// interpreter survives its directory being replaced (unlink semantics), but
/// that process's later attempts to start a *new* interpreter from the same
/// path may fail.
pub(crate) async fn install(
    session: &Handle<ClientHandler>,
    remote: &RemoteHost,
    target: &RuntimeTarget,
    force: bool,
    trace: &mut diagnostics::Trace,
) -> Result<InstallOutcome> {
    let outcome = |deployed: bool| InstallOutcome {
        interpreter: target.interpreter.clone(),
        deployed,
    };

    // 1. One read-only round trip (unless `--reinstall` forced a rebuild).
    if !force && probe_ready(session, target, trace).await?.is_some() {
        return Ok(outcome(false));
    }

    // 1b. The remote `tar` gate, before *anything* is downloaded or uploaded:
    // on a host without `tar` the ~33 MiB transfer is pure waste and the unpack
    // would fail with the wrong explanation. Read-only, one cheap round trip; a
    // ready runtime (step 1) and `python status` never reach it.
    if !probe_remote_tar(session).await? {
        return Err(missing_tar_error(
            "the pre-download `command -v tar` probe found nothing on the remote",
        ));
    }

    // 2. Local payload: verified cache hit or verified download.
    let cached = fetch_payload(target.payload, trace).await?;

    // One nonce for both temp names of this attempt, so the pair is traceable.
    let nonce = random_nonce();
    let tarball = format!("{}.{}", target.tarball, nonce);
    // The temp tree is a *sibling* of the runtime directory. Under a concurrent
    // swap our `mv` can instead nest it one level down at
    // `<runtime_dir>/<tmp_name>`, so both locations derive from this one
    // basename and can never drift apart.
    let tmp_name = format!("{}.tmp.{}", target.key, nonce);
    let tmp_dir = format!("{}/{}", target.root, tmp_name);
    let nested_tmp_dir = format!("{}/{}", target.runtime_dir, tmp_name);
    let quoted_runtime_dir = crate::shell_quote(&target.runtime_dir)?;

    // Steps 3-7. Every failure removes the temp artefacts created here.
    let steps: Result<()> = async {
        // 3. Upload next to the runtime root under a nonce name.
        run_checked(
            session,
            &format!("mkdir -p {}", crate::shell_quote(&target.root)?),
            PROBE_TIMEOUT,
            "creating the remote runtime root",
        )
        .await?;
        upload_tarball(&cached, remote, &tarball, trace).await?;
        let quoted_tarball = crate::shell_quote(&tarball)?;

        // 3b. The remote byte count must equal the pinned size.
        let out = run_checked(
            session,
            &format!("wc -c < {quoted_tarball}"),
            PROBE_TIMEOUT,
            "verifying the uploaded runtime size",
        )
        .await?;
        let actual: u64 = out
            .trim()
            .parse()
            .map_err(|_| anyhow!("could not parse the remote byte count from {out:?}"))?;
        if actual != target.payload.size {
            return Err(anyhow!(
                "the uploaded CPython runtime is incomplete on the remote: expected {} bytes, \
                 got {actual}",
                target.payload.size
            ));
        }

        // 4. Unpack into a nonce-named temp directory. `-C` comes *before* the
        // file operand (BusyBox-compatible), status-checked with a 300s bound.
        run_checked(
            session,
            &format!("mkdir -p {}", crate::shell_quote(&tmp_dir)?),
            PROBE_TIMEOUT,
            "creating the remote temp directory",
        )
        .await?;
        // Not `run_checked`: the failure branch below needs the exit code and the
        // remote output separately, to tell a missing `tar` from a real unpack
        // error. A timeout keeps the disk-space hint, exactly as before.
        let (unpack_out, unpack_err, unpack_code) = exec_status(
            session,
            &format!(
                "tar -C {} -xzf {quoted_tarball}",
                crate::shell_quote(&tmp_dir)?
            ),
            EXTRACT_TIMEOUT,
            "unpacking the CPython runtime on the remote",
        )
        .await
        .map_err(|e| e.context(DISK_SPACE_HINT))?;
        if unpack_code != Some(0) {
            let detail = match unpack_code {
                Some(code) => {
                    format!("exit {code}: {}", remote_detail(&unpack_out, &unpack_err))
                }
                None => format!(
                    "no exit status reported: {}",
                    remote_detail(&unpack_out, &unpack_err)
                ),
            };
            // Safety net behind step 1b: `tar` can be gone from PATH by now (the
            // gate is only a probe), so a not-found signal still gets the `init`
            // remedy instead of the disk-space hint.
            if unpack_looks_like_missing_tar(unpack_code, &detail) {
                return Err(missing_tar_error(&detail));
            }
            return Err(
                anyhow!("unpacking the CPython runtime on the remote failed ({detail})")
                    .context(DISK_SPACE_HINT),
            );
        }

        // 5. Swap in. `mv` into an existing directory nests (exit 0!), so the
        // old runtime directory is removed first — a precise absolute path,
        // never a wildcard. A racing install can recreate `<key>` between these
        // two commands; step 5a repairs exactly that interleaving.
        run_checked(
            session,
            &format!("rm -rf {quoted_runtime_dir}"),
            PROBE_TIMEOUT,
            "removing the old runtime directory",
        )
        .await?;
        run_checked(
            session,
            &format!("mv {} {quoted_runtime_dir}", crate::shell_quote(&tmp_dir)?),
            PROBE_TIMEOUT,
            "moving the unpacked runtime into place",
        )
        .await?;

        // 5a. Deterministic post-condition. If a racing install recreated
        // `<key>` after our `rm -rf`, the `mv` above nested this run's tree at
        // `<key>/<tmp_name>` instead of replacing it (exit 0, silent). The
        // nonce makes that path provably this run's own tree, and `mv` never
        // merges, so removing exactly that path restores the winner's runtime.
        // `-d` is the precise predicate (the entry is always a `mkdir -p`ed
        // directory) and is POSIX/BusyBox-portable — no `-e`, no glob, no
        // GNU-only flag.
        let quoted_nested = crate::shell_quote(&nested_tmp_dir)?;
        run_checked(
            session,
            &format!("if [ -d {quoted_nested} ]; then rm -rf {quoted_nested}; fi"),
            PROBE_TIMEOUT,
            "removing a nested copy left by a concurrent install",
        )
        .await?;

        // 5b. The interpreter must actually run: covers a truncated unpack, a
        // noexec mount and a too-old glibc in one status-checked step.
        let quoted_interpreter = crate::shell_quote(&target.interpreter)?;
        let vv_output = run_checked(
            session,
            &format!("{quoted_interpreter} -VV"),
            PROBE_TIMEOUT,
            "running the unpacked interpreter",
        )
        .await
        .map_err(|e| e.context(interpreter_failure_hint(target)))?;

        // 6. Stamp: proves the interpreter ran, and records its version line.
        let vv = vv_output.lines().next().unwrap_or_default().trim();
        run_checked(
            session,
            &format!(
                "printf '%s\\n' {} {} > {}",
                crate::shell_quote(&stamp_marker(&target.key))?,
                crate::shell_quote(vv)?,
                crate::shell_quote(&target.stamp)?
            ),
            PROBE_TIMEOUT,
            "writing the runtime stamp",
        )
        .await?;

        // 7. The full readiness invariant (stamp *and* marker) must now hold.
        // Checked without the trace line `probe_ready` adds: the two pinned
        // lines are emitted once, in order, after the whole sequence succeeds.
        let (probe_output, _, _) = exec_status(
            session,
            &readiness_probe(target)?,
            PROBE_TIMEOUT,
            "python runtime readiness probe",
        )
        .await?;
        if !runtime_is_ready(&probe_output, &target.key) {
            return Err(anyhow!(
                "the CPython runtime at {} did not pass the readiness check right after \
                 installation — remove that directory and retry `rexec <host> python install`",
                target.runtime_dir
            ));
        }
        Ok(())
    }
    .await;

    if let Err(e) = steps {
        cleanup_remote(session, &[&tarball, &tmp_dir, &nested_tmp_dir], trace).await;
        return Err(e);
    }

    // 8. Best effort: the stamp is written, so a failed removal must not fail
    // the install — and it is bounded, like every other cleanup call.
    if let Ok(quoted_tarball) = crate::shell_quote(&tarball) {
        let _ = exec_best_effort(session, &format!("rm -f {quoted_tarball}")).await;
    }

    trace.add(format!("python: runtime {} installed", target.key));
    trace.add(format!("python: runtime {} ready", target.key));
    crate::progress!(
        "✓ Installed CPython {PYTHON_VERSION} ({}) at {}",
        target.key,
        target.runtime_dir
    );
    Ok(outcome(true))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every expected value below is copied from the spec's 「固定载荷」、
    /// 「稳定接口」 and 「可观测面」 sections (PBS release 20261001), or read from
    /// the v0.4.2 baseline source for the two characterization functions
    /// (`assemble_remote_command`, `missing_remote_deps`) — never from this
    /// module's output. If an assertion here disagrees with the implementation,
    /// the implementation is wrong.
    const X86_64_GNU_ASSET: &str =
        "cpython-3.13.16+20261001-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz";
    const X86_64_GNU_SHA256: &str =
        "ffcb50e716789d1a6e1db5e745d4d194ac8ed9b015ccf5eabcaccb179a25e4a8";
    const X86_64_GNU_SIZE: u64 = 35_067_590;
    const X86_64_GNU_KEY: &str = "cpython-3.13.16+20261001-x86_64-unknown-linux-gnu";
    const X86_64_GNU_ASSET_LABEL: &str = "linux-amd64";

    /// The literal from the spec's 稳定接口 section; the exported constant must
    /// carry it (asserted inside a test that also exercises the probe parser).
    const READY_MARKER_LITERAL: &str = "__rexec_py_ok__";

    #[test]
    fn test_pinned_version_constants() {
        assert_eq!(PYTHON_VERSION, "3.13.16");
        assert_eq!(PBS_RELEASE, "20261001");
    }

    #[test]
    fn test_payload_for_pinned_table_four_combinations() {
        // (remote label, flavor, asset, size, sha256)
        let cases = [
            (
                "linux-amd64",
                LibcFlavor::Gnu,
                "cpython-3.13.16+20261001-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
                35_067_590_u64,
                "ffcb50e716789d1a6e1db5e745d4d194ac8ed9b015ccf5eabcaccb179a25e4a8",
            ),
            (
                "linux-arm64",
                LibcFlavor::Gnu,
                "cpython-3.13.16+20261001-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz",
                29_311_682_u64,
                "f94c8f69f3e68b026b916b3aa32b9b3bfff63fd7c95b2affa8272b1601d668fa",
            ),
            (
                "linux-amd64",
                LibcFlavor::Musl,
                "cpython-3.13.16+20261001-x86_64-unknown-linux-musl-install_only_stripped.tar.gz",
                27_746_339_u64,
                "31b1f560c68313c00bab4faa2452bc0a87e3e9f9ddf16b94d2265bd9d99afc2e",
            ),
            (
                "linux-arm64",
                LibcFlavor::Musl,
                "cpython-3.13.16+20261001-aarch64-unknown-linux-musl-install_only_stripped.tar.gz",
                27_941_356_u64,
                "6952e49f84fa720d61de783f7298410cbb98227ee9a0750340ec7385ae71420a",
            ),
        ];

        for (label, flavor, asset, size, sha256) in cases {
            let payload = payload_for(label, flavor)
                .unwrap_or_else(|err| panic!("payload_for({label}, {flavor:?}) failed: {err:#}"));
            assert_eq!(payload.asset, asset, "asset for {label}/{flavor:?}");
            assert_eq!(payload.size, size, "size for {label}/{flavor:?}");
            assert_eq!(payload.sha256, sha256, "sha256 for {label}/{flavor:?}");
        }
    }

    #[test]
    fn test_payload_for_rejects_non_linux_labels() {
        // macOS/Windows remotes are explicitly out of scope; unknown labels are
        // not silently mapped onto a Linux asset either.
        let labels = [
            "macos-amd64",
            "macos-arm64",
            "windows-amd64",
            "freebsd-amd64",
        ];

        for label in labels {
            for flavor in [LibcFlavor::Gnu, LibcFlavor::Musl] {
                assert!(
                    payload_for(label, flavor).is_err(),
                    "payload_for({label}, {flavor:?}) must be Err"
                );
            }
        }
    }

    #[test]
    fn test_runtime_key_x86_64_gnu() {
        let key =
            runtime_key("linux-amd64", LibcFlavor::Gnu).expect("linux-amd64/gnu is supported");
        assert_eq!(key, "cpython-3.13.16+20261001-x86_64-unknown-linux-gnu");
        assert!(
            !key.ends_with(".tar.gz"),
            "runtime key must have the -install_only_stripped.tar.gz suffix stripped, got {key:?}"
        );
    }

    #[test]
    fn test_runtime_key_rejects_non_linux_labels() {
        assert!(runtime_key("macos-arm64", LibcFlavor::Gnu).is_err());
        assert!(runtime_key("windows-amd64", LibcFlavor::Gnu).is_err());
    }

    #[test]
    fn test_key_is_safe_rejects_empty_separator_and_dotdot() {
        // The three shapes `runtime_target` refuses to build an `rm -rf` operand
        // from: an empty key, one containing a path separator, one equal to (or
        // containing) the `..` component.
        assert!(!key_is_safe(""));
        assert!(!key_is_safe("a/b"));
        assert!(!key_is_safe("/abs"));
        assert!(!key_is_safe(".."));
        assert!(!key_is_safe("cpython-..-gnu"));
    }

    #[test]
    fn test_key_is_safe_accepts_the_pinned_keys() {
        for (label, flavor) in [
            ("linux-amd64", LibcFlavor::Gnu),
            ("linux-arm64", LibcFlavor::Gnu),
            ("linux-amd64", LibcFlavor::Musl),
            ("linux-arm64", LibcFlavor::Musl),
        ] {
            let key = runtime_key(label, flavor).expect("pinned table entry");
            assert!(key_is_safe(&key), "pinned key {key:?} must pass the guard");
        }
    }

    #[test]
    fn test_runtime_target_uses_the_guarded_key() {
        let target =
            runtime_target("/home/u", "linux-amd64", LibcFlavor::Gnu).expect("pinned combination");
        assert!(key_is_safe(&target.key));
        assert_eq!(
            target.key,
            "cpython-3.13.16+20261001-x86_64-unknown-linux-gnu"
        );
        assert_eq!(
            target.runtime_dir,
            "/home/u/.rexec/py/cpython-3.13.16+20261001-x86_64-unknown-linux-gnu"
        );
    }

    #[test]
    fn test_download_url_percent_encodes_plus_for_x86_64_gnu() {
        let payload = Payload {
            asset: X86_64_GNU_ASSET,
            sha256: X86_64_GNU_SHA256,
            size: X86_64_GNU_SIZE,
        };

        let url = download_url(&payload);
        assert_eq!(
            url,
            "https://github.com/astral-sh/python-build-standalone/releases/download/20261001/cpython-3.13.16%2B20261001-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
        );
        assert!(
            url.contains("%2B"),
            "the '+' of the PBS tag must be percent-encoded, got {url:?}"
        );
        assert!(
            !url.contains('+'),
            "no literal '+' may survive in the URL, got {url:?}"
        );
    }

    #[test]
    fn test_interpreter_path_exact() {
        assert_eq!(
            interpreter_path("/home/u/.rexec/py/cpython-3.13.16+20261001-x86_64-unknown-linux-gnu"),
            "/home/u/.rexec/py/cpython-3.13.16+20261001-x86_64-unknown-linux-gnu/python/bin/python3"
        );
    }

    #[test]
    fn test_stamp_path_exact() {
        assert_eq!(
            stamp_path("/home/u/.rexec/py/cpython-3.13.16+20261001-x86_64-unknown-linux-gnu"),
            "/home/u/.rexec/py/cpython-3.13.16+20261001-x86_64-unknown-linux-gnu/.stamp"
        );
    }

    #[test]
    fn test_stamp_marker_exact() {
        assert_eq!(
            stamp_marker("cpython-3.13.16+20261001-x86_64-unknown-linux-gnu"),
            "rexec-python cpython-3.13.16+20261001-x86_64-unknown-linux-gnu"
        );
    }

    #[test]
    fn test_stamp_is_current_accepts_marker_first_line() {
        let key = X86_64_GNU_KEY;

        // Exactly the stamp file written at install time, first line only.
        assert!(stamp_is_current(&format!("rexec-python {key}"), key));

        // Stamp file with the recorded `-VV` line after the marker.
        assert!(stamp_is_current(
            &format!(
                "rexec-python {key}\nPython 3.13.16 (main, Oct  1 2026, 00:00:00) [GCC 13.2.0]\n"
            ),
            key
        ));
    }

    #[test]
    fn test_stamp_is_current_accepts_crlf_and_surrounding_whitespace() {
        let key = X86_64_GNU_KEY;

        assert!(stamp_is_current(
            &format!("  rexec-python {key}  \r\n"),
            key
        ));
        assert!(stamp_is_current(
            &format!("\trexec-python {key}\r\nPython 3.13.16\r\n"),
            key
        ));
    }

    #[test]
    fn test_stamp_is_current_rejects_empty_output() {
        assert!(!stamp_is_current("", X86_64_GNU_KEY));
        assert!(!stamp_is_current("   \n", X86_64_GNU_KEY));
    }

    #[test]
    fn test_stamp_is_current_rejects_different_key() {
        let key = X86_64_GNU_KEY;

        // Same PBS release, different artifact: a stale/mismatched runtime.
        assert!(!stamp_is_current(
            "rexec-python cpython-3.13.16+20261001-aarch64-unknown-linux-gnu",
            key
        ));
        assert!(!stamp_is_current(
            "rexec-python cpython-3.13.16+20261001-x86_64-unknown-linux-musl",
            key
        ));

        // The marker must match the whole first line, not just be a prefix of it.
        assert!(!stamp_is_current(&format!("rexec-python {key}-extra"), key));
    }

    #[test]
    fn test_stamp_is_current_rejects_marker_on_non_first_line() {
        let key = X86_64_GNU_KEY;

        assert!(!stamp_is_current(
            &format!("Python 3.13.16\nrexec-python {key}"),
            key
        ));
        assert!(!stamp_is_current(&format!("\nrexec-python {key}"), key));
    }

    #[test]
    fn test_runtime_is_ready_stamp_and_marker_together() {
        let key = X86_64_GNU_KEY;
        assert_eq!(
            READY_MARKER, READY_MARKER_LITERAL,
            "READY_MARKER must stay the spec literal"
        );

        // Exactly what the one round trip prints on a healthy runtime:
        // `cat <stamp>; test -x <interpreter> && echo __rexec_py_ok__`.
        let probe_output = format!(
            "rexec-python {key}\nPython 3.13.16 (main, Oct  1 2026, 00:00:00) [GCC 13.2.0]\n{READY_MARKER_LITERAL}\n"
        );
        assert!(
            runtime_is_ready(&probe_output, key),
            "a current stamp plus the executable marker is ready, got {probe_output:?}"
        );
    }

    #[test]
    fn test_runtime_is_ready_stamp_only_is_not_ready() {
        let key = X86_64_GNU_KEY;

        // The stamp survives a partial wipe (or a noexec mount): `test -x` fails
        // silently, so there is no marker line and the runtime is not ready.
        let probe_output = format!(
            "rexec-python {key}\nPython 3.13.16 (main, Oct  1 2026, 00:00:00) [GCC 13.2.0]\n"
        );
        assert!(!runtime_is_ready(&probe_output, key));
        assert!(!runtime_is_ready(&format!("rexec-python {key}"), key));
    }

    #[test]
    fn test_runtime_is_ready_marker_only_is_not_ready() {
        let key = X86_64_GNU_KEY;

        // Missing or empty stamp: `cat` prints nothing, only the marker arrives.
        assert!(!runtime_is_ready(READY_MARKER_LITERAL, key));
        assert!(!runtime_is_ready(&format!("{READY_MARKER_LITERAL}\n"), key));
    }

    #[test]
    fn test_runtime_is_ready_wrong_key_with_marker_is_not_ready() {
        let key = X86_64_GNU_KEY;

        // A stale runtime from another artifact of the same release, with a
        // working interpreter: the key must match exactly.
        for stale_key in [
            "cpython-3.13.16+20261001-aarch64-unknown-linux-gnu",
            "cpython-3.13.16+20261001-x86_64-unknown-linux-musl",
        ] {
            let probe_output =
                format!("rexec-python {stale_key}\nPython 3.13.16\n{READY_MARKER_LITERAL}\n");
            assert!(
                !runtime_is_ready(&probe_output, key),
                "stamp for {stale_key} must not count as ready for {key}"
            );
        }

        // The stamp itself must be the first line, exactly as stamp_is_current
        // requires: the marker line cannot be mistaken for stamp text.
        assert!(!runtime_is_ready(
            &format!("{READY_MARKER_LITERAL}\nrexec-python {key}\n"),
            key
        ));
    }

    #[test]
    fn test_runtime_is_ready_rejects_marker_substring_of_longer_line() {
        let key = X86_64_GNU_KEY;

        // A line that merely contains the marker is not the marker line: the
        // probe echoes it unadorned, so anything longer means a different line.
        for marker_line in [
            format!("{READY_MARKER_LITERAL} extra"),
            format!("prefix-{READY_MARKER_LITERAL}"),
            format!("{READY_MARKER_LITERAL}_suffix"),
        ] {
            let probe_output = format!("rexec-python {key}\n{marker_line}\n");
            assert!(
                !runtime_is_ready(&probe_output, key),
                "marker must be the whole line, got {marker_line:?}"
            );
        }
    }

    #[test]
    fn test_runtime_is_ready_tolerates_crlf_and_surrounding_whitespace() {
        let key = X86_64_GNU_KEY;

        // CRLF everywhere, as a remote shell pipes to a non-POSIX terminal.
        assert!(runtime_is_ready(
            &format!("rexec-python {key}\r\nPython 3.13.16\r\n{READY_MARKER_LITERAL}\r\n"),
            key
        ));

        // Indented stamp line and a padded marker line.
        assert!(runtime_is_ready(
            &format!("  rexec-python {key}  \r\n  {READY_MARKER_LITERAL}  \r\n"),
            key
        ));
    }

    #[test]
    fn test_parse_flavor_glibc_wins_over_musl_signals() {
        // A glibc host that also carries a musl loader (a co-installed `musl`
        // package is common) and, worse, an Alpine marker: glibc still wins.
        assert_eq!(
            parse_flavor("glibc 2.31\n/lib/ld-musl-x86_64.so.1\n"),
            LibcFlavor::Gnu
        );
        assert_eq!(
            parse_flavor("glibc 2.31\n/lib/ld-musl-x86_64.so.1\nalpine\n"),
            LibcFlavor::Gnu
        );
        assert_eq!(parse_flavor("glibc 2.31\n\n"), LibcFlavor::Gnu);
        assert_eq!(parse_flavor("glibc 2.17\r\n\r\n"), LibcFlavor::Gnu);
    }

    #[test]
    fn test_parse_flavor_musl_loader_without_glibc() {
        assert_eq!(
            parse_flavor("no-glibc\n/lib/ld-musl-x86_64.so.1\n"),
            LibcFlavor::Musl
        );
        // Same verdict when the loader line arrives without any glibc line.
        assert_eq!(
            parse_flavor("\n/lib/ld-musl-aarch64.so.1\n"),
            LibcFlavor::Musl
        );
        // `no-glibc` and the loader path with CRLF endings.
        assert_eq!(
            parse_flavor("no-glibc\r\n/lib/ld-musl-x86_64.so.1\r\n"),
            LibcFlavor::Musl
        );
    }

    #[test]
    fn test_parse_flavor_alpine_marker_without_glibc_or_loader() {
        assert_eq!(parse_flavor("no-glibc\n\nalpine\n"), LibcFlavor::Musl);
        // A trailing line beyond the three signals is ignored.
        assert_eq!(
            parse_flavor("no-glibc\n\nalpine\nextra junk\n"),
            LibcFlavor::Musl
        );
    }

    #[test]
    fn test_parse_flavor_defaults_to_gnu_without_any_signal() {
        // The probe emits `no-glibc` plus two empty lines on a plain glibc host
        // whose `getconf` is missing: no musl signal → the gnu default.
        assert_eq!(parse_flavor("no-glibc\n\n\n"), LibcFlavor::Gnu);
        assert_eq!(parse_flavor("no-glibc\n\n"), LibcFlavor::Gnu);
        assert_eq!(parse_flavor("no-glibc\n"), LibcFlavor::Gnu);
    }

    #[test]
    fn test_parse_flavor_empty_output_defaults_to_gnu() {
        assert_eq!(parse_flavor(""), LibcFlavor::Gnu);
        assert_eq!(parse_flavor("\n\n\n"), LibcFlavor::Gnu);
    }

    #[test]
    fn test_needs_managed_runtime_row1_force_managed_on_linux() {
        // Row 1: force_managed == true, remote_is_linux == true → true, for every
        // value of the other three columns ("任意"). The CLI rejects --python
        // together with --interpreter (clap conflict, exit code 2), so the
        // explicit == Some cells are defensive; the table is still authoritative.
        for explicit in [None, Some("python3"), Some("/usr/bin/python3")] {
            for is_python_file in [false, true] {
                for remote_python3 in [false, true] {
                    assert!(
                        needs_managed_runtime(true, explicit, is_python_file, remote_python3, true),
                        "row 1 violated for (true, {explicit:?}, {is_python_file}, {remote_python3}, true)"
                    );
                }
            }
        }
    }

    #[test]
    fn test_needs_managed_runtime_row2_force_managed_off_linux() {
        // Row 2: force_managed == true but the remote is not Linux → false for
        // every other column. The caller reports the --python-needs-Linux error
        // before calling, so this function never opts a non-Linux run in.
        for explicit in [None, Some("python3"), Some("/usr/bin/python3")] {
            for is_python_file in [false, true] {
                for remote_python3 in [false, true] {
                    assert!(
                        !needs_managed_runtime(
                            true,
                            explicit,
                            is_python_file,
                            remote_python3,
                            false
                        ),
                        "row 2 violated for (true, {explicit:?}, {is_python_file}, {remote_python3}, false)"
                    );
                }
            }
        }
    }

    #[test]
    fn test_needs_managed_runtime_row3_explicit_interpreter() {
        // Row 3: force_managed == false, explicit == Some(_) → false, for every
        // value of is_python_file / remote_python3 / remote_is_linux.
        for interpreter in ["python3", "/usr/bin/python3"] {
            for is_python_file in [false, true] {
                for remote_python3 in [false, true] {
                    for remote_is_linux in [false, true] {
                        assert!(
                            !needs_managed_runtime(
                                false,
                                Some(interpreter),
                                is_python_file,
                                remote_python3,
                                remote_is_linux
                            ),
                            "row 3 violated for (false, Some({interpreter:?}), {is_python_file}, {remote_python3}, {remote_is_linux})"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_needs_managed_runtime_row4_not_a_python_file() {
        // Row 4: force_managed == false, explicit == None, is_python_file == false
        // → false, whatever the remote has and whatever platform it runs.
        for remote_python3 in [false, true] {
            for remote_is_linux in [false, true] {
                assert!(
                    !needs_managed_runtime(false, None, false, remote_python3, remote_is_linux),
                    "row 4 violated for (false, None, false, {remote_python3}, {remote_is_linux})"
                );
            }
        }
    }

    #[test]
    fn test_needs_managed_runtime_row5_python_file_with_remote_python3() {
        // Row 5: a .py script with no explicit interpreter on a host that has
        // python3 keeps today's behavior byte for byte → system python3, no
        // managed runtime, on either platform.
        for remote_is_linux in [false, true] {
            assert!(
                !needs_managed_runtime(false, None, true, true, remote_is_linux),
                "row 5 violated for (false, None, true, true, {remote_is_linux})"
            );
        }
    }

    #[test]
    fn test_needs_managed_runtime_row6_python_file_without_remote_python3_on_linux() {
        // Row 6: the only auto-fallback case — .py file, no explicit interpreter,
        // no system python3, Linux remote.
        assert!(needs_managed_runtime(false, None, true, false, true));
    }

    #[test]
    fn test_needs_managed_runtime_row7_python_file_without_remote_python3_off_linux() {
        // Row 7: same situation on a non-Linux remote → keep today's literal
        // `python3` (the caller emits the verbose-only "Linux only" note).
        assert!(!needs_managed_runtime(false, None, true, false, false));
    }

    #[test]
    fn test_needs_managed_runtime_non_linux_is_always_false() {
        // "非 Linux 恒为 false" — exhaustive over the other four columns, so no
        // future reordering of the checks can opt a non-Linux remote in.
        for force_managed in [false, true] {
            for explicit in [None, Some("python3")] {
                for is_python_file in [false, true] {
                    for remote_python3 in [false, true] {
                        assert!(
                            !needs_managed_runtime(
                                force_managed,
                                explicit,
                                is_python_file,
                                remote_python3,
                                false
                            ),
                            "non-Linux must never use the managed runtime: ({force_managed}, {explicit:?}, {is_python_file}, {remote_python3}, false)"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_needs_managed_runtime_explicit_interpreter_beats_python_fallback() {
        // Redundant with row 3, kept as its own case: even in the exact
        // situation that triggers the automatic fallback (.py file, no system
        // python3 on a Linux remote), an explicit --interpreter means the
        // managed runtime must not be used.
        assert!(!needs_managed_runtime(
            false,
            Some("python3"),
            true,
            false,
            true
        ));
        assert!(!needs_managed_runtime(
            false,
            Some("/usr/bin/python3"),
            true,
            false,
            true
        ));
    }

    #[test]
    fn test_assemble_remote_command_runner_with_script() {
        // Characterization of main.rs:4755-4774 at v0.4.2 (776f734): the runner
        // is pushed verbatim and the script path is single-quoted.
        let command =
            assemble_remote_command(Some("python3"), "/home/u/.rexec/scripts/hello.py", &[])
                .expect("a python3 runner with a plain script path assembles");

        assert_eq!(
            command, "python3 '/home/u/.rexec/scripts/hello.py'",
            "runner must stay unquoted and the path single-quoted"
        );
    }

    #[test]
    fn test_assemble_remote_command_quotes_every_argument_and_preserves_order() {
        let args = vec![
            "--flag".to_string(),
            "value with space".to_string(),
            "it's".to_string(),
        ];

        let command = assemble_remote_command(Some("python3"), "/tmp/x.py", &args)
            .expect("quotable arguments assemble");

        assert_eq!(
            command, "python3 '/tmp/x.py' '--flag' 'value with space' 'it'\"'\"'s'",
            "each argument is shell_quote'd (embedded ' becomes '\"'\"') and order is preserved"
        );
    }

    #[test]
    fn test_assemble_remote_command_shebang_uses_chmod_and_direct_exec() {
        // runner == None: the local file has a `#!`, so the remote command is
        // `chmod +x '<p>' && '<p>' <args…>` — byte-identical to v0.4.2.
        let args = vec!["one".to_string(), "two".to_string()];

        let command = assemble_remote_command(None, "/tmp/s.py", &args)
            .expect("a shebang script assembles without a runner");

        assert_eq!(command, "chmod +x '/tmp/s.py' && '/tmp/s.py' 'one' 'two'");
    }

    #[test]
    fn test_assemble_remote_command_runner_is_emitted_unquoted() {
        // `--interpreter` takes a command snippet, not an argv word: v0.4.2
        // pushed it raw, and that literal behavior is locked here.
        let command = assemble_remote_command(Some("python3 -u"), "/tmp/x.py", &[])
            .expect("a multi-word runner assembles");

        assert_eq!(
            command, "python3 -u '/tmp/x.py'",
            "the runner must not be quoted"
        );
    }

    #[test]
    fn test_assemble_remote_command_quotes_empty_argument() {
        // An empty argument still becomes `''` (and therefore survives as an
        // argument instead of disappearing).
        let args = vec![String::new()];

        let command = assemble_remote_command(Some("sh"), "/tmp/s.sh", &args)
            .expect("an empty argument assembles");

        assert_eq!(command, "sh '/tmp/s.sh' ''");
    }

    #[test]
    fn test_assemble_remote_command_rejects_nul_in_argument() {
        // shell_quote rejects NUL bytes to prevent C-string truncation; the
        // assembly must propagate that error instead of emitting a command.
        let args = vec!["--flag".to_string(), "bad\0arg".to_string()];

        assert!(
            assemble_remote_command(Some("python3"), "/tmp/x.py", &args).is_err(),
            "a NUL byte in an argument must be an error"
        );
    }

    #[test]
    fn test_assemble_remote_command_rejects_nul_in_script_path() {
        assert!(
            assemble_remote_command(Some("python3"), "/tmp/bad\0name.py", &[]).is_err(),
            "a NUL byte in the remote script path must be an error"
        );
        assert!(
            assemble_remote_command(None, "/tmp/bad\0name.py", &[]).is_err(),
            "the shebang form must reject NUL in the path too"
        );
    }

    #[test]
    fn test_missing_remote_deps_all_present_is_empty() {
        // The exact shape `check_and_install_deps` prints when everything is there.
        let probe_output = "=== Checking dependencies ===\n\
                            ✓ rsync: /usr/bin/rsync\n\
                            ✓ sh: /bin/sh\n\
                            ✓ tar: /usr/bin/tar\n\
                            === Detecting package manager ===\n\
                            pm:apt-get\n";

        assert!(
            missing_remote_deps(probe_output).is_empty(),
            "nothing is missing when every tool reports ✓"
        );
    }

    #[test]
    fn test_missing_remote_deps_only_rsync_missing() {
        let probe_output = "=== Checking dependencies ===\n\
                            ✗ rsync: NOT FOUND\n\
                            ✓ sh: /bin/sh\n\
                            ✓ tar: /usr/bin/tar\n\
                            === Detecting package manager ===\n\
                            pm:apt-get\n";

        assert_eq!(missing_remote_deps(probe_output), vec!["rsync"]);
    }

    #[test]
    fn test_missing_remote_deps_only_tar_missing() {
        // The case today's early `if !missing_rsync { return Ok(()) }` skips: rsync
        // is present, tar is not — `init` must still report and install it.
        let probe_output = "=== Checking dependencies ===\n\
                            ✓ rsync: /usr/bin/rsync\n\
                            ✓ sh: /bin/sh\n\
                            ✗ tar: NOT FOUND\n\
                            === Detecting package manager ===\n\
                            pm:apk\n";

        assert_eq!(missing_remote_deps(probe_output), vec!["tar"]);

        // The verify pass after an install attempt uses a different suffix and
        // must be parsed the same way.
        let verify_output = "✓ rsync: /usr/bin/rsync\n\
                             ✓ sh: /bin/sh\n\
                             ✗ tar: STILL NOT FOUND\n";

        assert_eq!(missing_remote_deps(verify_output), vec!["tar"]);
    }

    #[test]
    fn test_missing_remote_deps_only_sh_missing() {
        let probe_output = "=== Checking dependencies ===\n\
                            ✓ rsync: /usr/bin/rsync\n\
                            ✗ sh: NOT FOUND\n\
                            ✓ tar: /usr/bin/tar\n";

        assert_eq!(missing_remote_deps(probe_output), vec!["sh"]);
    }

    #[test]
    fn test_missing_remote_deps_all_missing() {
        let probe_output = "=== Checking dependencies ===\n\
                            ✗ rsync: NOT FOUND\n\
                            ✗ sh: NOT FOUND\n\
                            ✗ tar: NOT FOUND\n\
                            === Detecting package manager ===\n\
                            pm:none\n";

        assert_eq!(
            missing_remote_deps(probe_output),
            vec!["rsync", "sh", "tar"]
        );
    }

    #[test]
    fn test_missing_remote_deps_ignores_unrelated_text() {
        // ✓ lines, tools outside the checked set, prose that merely mentions a
        // tool name, and `✗` lines whose tool name only shares a prefix must all
        // be ignored.
        let probe_output = "=== Checking dependencies ===\n\
                            ✓ rsync: /usr/bin/rsync\n\
                            ✓ sh: /bin/sh\n\
                            ✓ tar: /usr/bin/tar\n\
                            ✗ nohup: NOT FOUND\n\
                            ✗ curl: NOT FOUND\n\
                            ✗ rsyncd: NOT FOUND\n\
                            ✗ tar.gz: NOT FOUND\n\
                            Please install rsync manually.\n\
                            error: tar not found\n\
                            === Detecting package manager ===\n\
                            pm:none\n";

        assert!(
            missing_remote_deps(probe_output).is_empty(),
            "only `✗ <checked tool>` lines at a token boundary count as missing"
        );
    }

    #[test]
    fn test_missing_remote_deps_empty_input() {
        assert!(missing_remote_deps("").is_empty());
        assert!(missing_remote_deps("   \n\n").is_empty());
    }

    #[test]
    fn test_unpack_looks_like_missing_tar_accepts_every_not_found_signal() {
        // Exit 127 is the shell's `command not found`, with or without text.
        assert!(unpack_looks_like_missing_tar(Some(127), ""));
        assert!(unpack_looks_like_missing_tar(
            Some(127),
            "sh: 1: tar: not found"
        ));
        // The text signals, for a shell that reports the miss without 127.
        assert!(unpack_looks_like_missing_tar(Some(1), "tar: not found"));
        assert!(unpack_looks_like_missing_tar(None, "tar: not found"));
        assert!(unpack_looks_like_missing_tar(
            Some(2),
            "sh: tar: not found | no such tool"
        ));
    }

    #[test]
    fn test_unpack_looks_like_missing_tar_rejects_real_unpack_errors() {
        // A truncated archive, a missing tarball and a full disk all keep the
        // disk-space hint: they are not "tar is not installed".
        assert!(!unpack_looks_like_missing_tar(
            Some(2),
            "tar: unexpected EOF in archive | tar: Error is not recoverable: exiting now"
        ));
        assert!(!unpack_looks_like_missing_tar(
            Some(2),
            "tar: /home/u/.rexec/py/x.tar.gz: Cannot open: No such file or directory"
        ));
        assert!(!unpack_looks_like_missing_tar(
            Some(2),
            "tar: write error: No space left on device"
        ));
        assert!(!unpack_looks_like_missing_tar(None, ""));
    }

    #[test]
    fn test_missing_tar_error_exact_message_without_the_disk_hint() {
        // The exact user-visible remedy, and proof it does not carry the
        // disk-space hint that used to be the only explanation.
        let message = missing_tar_error("exit 127: tar: not found").to_string();
        assert_eq!(
            message,
            "the remote has no `tar`, which the managed CPython runtime needs to unpack \
             (exit 127: tar: not found)\nhint: run `rexec <host> init` on that host to install \
             tar, then retry"
        );
        assert!(
            !message.contains("disk space"),
            "the missing-tar remedy must not carry the disk-space hint, got {message}"
        );
    }

    #[test]
    fn test_payload_table_self_check() {
        let combos = [
            ("linux-amd64", LibcFlavor::Gnu),
            ("linux-arm64", LibcFlavor::Gnu),
            ("linux-amd64", LibcFlavor::Musl),
            ("linux-arm64", LibcFlavor::Musl),
        ];

        let mut assets: Vec<&str> = Vec::new();
        let mut digests: Vec<&str> = Vec::new();

        for (label, flavor) in combos {
            let payload = payload_for(label, flavor)
                .unwrap_or_else(|err| panic!("payload_for({label}, {flavor:?}) failed: {err:#}"));

            assert_eq!(
                payload.sha256.len(),
                64,
                "sha256 for {label}/{flavor:?} must be 64 hex chars, got {:?}",
                payload.sha256
            );
            assert!(
                payload
                    .sha256
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
                "sha256 for {label}/{flavor:?} must be lowercase hex, got {:?}",
                payload.sha256
            );
            assert!(
                payload.size > 1_000_000,
                "size for {label}/{flavor:?} looks like a truncated payload: {}",
                payload.size
            );
            assert!(
                payload.asset.ends_with("-install_only_stripped.tar.gz"),
                "asset for {label}/{flavor:?} must be an install_only_stripped tarball, got {:?}",
                payload.asset
            );
            assert!(
                !assets.contains(&payload.asset),
                "duplicate asset entry: {:?}",
                payload.asset
            );
            assert!(
                !digests.contains(&payload.sha256),
                "duplicate sha256 entry: {:?}",
                payload.sha256
            );

            assets.push(payload.asset);
            digests.push(payload.sha256);
        }

        assert_eq!(assets.len(), 4, "the pinned table has exactly four entries");
    }

    #[test]
    fn test_payload_for_and_runtime_key_agree_on_the_x86_64_gnu_asset() {
        // The key is the asset with its suffix stripped: pin both sides of that
        // relationship against spec literals.
        let payload = payload_for(X86_64_GNU_ASSET_LABEL, LibcFlavor::Gnu).expect("supported");
        let key = runtime_key(X86_64_GNU_ASSET_LABEL, LibcFlavor::Gnu).expect("supported");

        assert_eq!(payload.asset, X86_64_GNU_ASSET);
        assert_eq!(key, X86_64_GNU_KEY);
        assert_eq!(
            payload
                .asset
                .strip_suffix("-install_only_stripped.tar.gz")
                .expect("pinned asset carries the stripped suffix"),
            key
        );
    }
}

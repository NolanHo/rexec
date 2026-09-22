//! Local execution history.
//!
//! Stores one record per executed remote run so runs can be inspected and
//! analyzed later: the exact command (and env values — verbatim, by explicit
//! product decision), the captured output, exit status, timing and the
//! decision trace.
//!
//! Layout (all under the user's home, owner-only):
//!
//! ```text
//! ~/.rexec/history/index.jsonl              append-only, one RunRecord per line
//! ~/.rexec/history/runs/<id>/meta.json      the same record, pretty-printed
//! ~/.rexec/history/runs/<id>/stdout.log     captured stdout (capped)
//! ~/.rexec/history/runs/<id>/stderr.log     captured stderr (capped)
//! ```
//!
//! The JSONL index is the query surface (grep/jq/duckdb); the per-run dir is
//! the artifact store. Recording only ever APPENDS to the index (one line per
//! run, written after that run's artifacts), so a crashed run costs at most its
//! own line; `prune` is the one operation that rewrites the file, and it does so
//! atomically (tmp + rename, survivors copied verbatim).
//!
//! Secrecy posture (deliberate): commands and env VALUES are stored verbatim.
//! The files are created 0600 inside a 0700 tree, and capture can be disabled
//! per-run (`--no-history`) or globally (`REXEC_HISTORY=0`); there is no
//! redaction layer by design — see the module docs in the README.

use std::collections::{HashSet, VecDeque};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;

/// Per-stream capture cap. Outputs above this keep their head and tail (the
/// parts that answer "what did it start doing" and "how did it fail") and are
/// marked truncated in the record.
pub const CAPTURE_LIMIT: usize = 1024 * 1024;

/// Seconds per day, named so the civil-date arithmetic below reads as calendar
/// math rather than magic numbers.
const SECS_PER_DAY: u64 = 86_400;

/// Global recording switch. `true` by default: history is on unless the user
/// opted out (the CLI folds `--no-history` in via [`set_enabled`]).
static ENABLED: AtomicBool = AtomicBool::new(true);

/// Bounded head+tail capture for one output stream.
///
/// Frames arrive incrementally: the first `limit/2` bytes fill the head, the
/// rest is kept in a rolling tail of the remaining budget. `total` counts every
/// byte seen, so callers can report the true size even when truncated.
pub struct RingCapture {
    /// Filled until `head_limit` bytes are seen.
    head: Vec<u8>,
    head_limit: usize,
    /// Rolling window of the most recent bytes (after the head is full).
    tail: VecDeque<u8>,
    tail_limit: usize,
    /// Total bytes seen (not the captured size).
    total: u64,
}

impl RingCapture {
    /// `limit` is the total captured budget for this stream (head + tail).
    pub fn new(limit: usize) -> Self {
        // Half the budget each: the head is what the command started doing and
        // never moves, the tail is how it ended. Splitting evenly is the whole
        // point of the design — a plain prefix cap would hide the failure.
        // An odd `limit` puts its extra byte in the tail, so `head + tail`
        // equals `limit` exactly and a stream of exactly `limit` bytes is
        // never reported as truncated.
        let half = limit / 2;
        RingCapture {
            head: Vec::with_capacity(half),
            head_limit: half,
            tail: VecDeque::with_capacity(half),
            tail_limit: limit - half,
            total: 0,
        }
    }

    /// Feed one frame's bytes.
    pub fn push(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            // Zero-byte frames are common keepalives; nothing to count or copy.
            return;
        }
        self.total += bytes.len() as u64;

        let mut rest = bytes;
        if self.head.len() < self.head_limit {
            let take = (self.head_limit - self.head.len()).min(rest.len());
            self.head.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
        }
        if rest.is_empty() || self.tail_limit == 0 {
            return;
        }

        // Rolling tail: keep exactly the most recent `tail_limit` bytes. Bulk
        // slicing instead of a per-byte ring so a 1 MiB frame is a memcpy.
        let keep_from = rest.len().saturating_sub(self.tail_limit);
        let rest = &rest[keep_from..];
        // Keep only as much of the old tail as still fits in front of these
        // bytes (`0` when the frame alone fills the window).
        let keep = self.tail_limit - rest.len();
        if self.tail.len() > keep {
            let drop = self.tail.len() - keep;
            self.tail.drain(..drop);
        }
        self.tail.extend(rest.iter().copied());
    }

    /// Every byte seen.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// True when more was seen than captured.
    pub fn truncated(&self) -> bool {
        // Measured against the capture *capacity*, not against `captured()`
        // (which also carries the marker text — that must never count as
        // "captured" bytes).
        self.total > (self.head_limit + self.tail_limit) as u64
    }

    /// The captured bytes: head, then a `… [N bytes omitted] …` marker when
    /// truncated, then the tail. Suitable for writing to `<stream>.log`.
    pub fn captured(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.head.len() + self.tail.len() + 40);
        out.extend_from_slice(&self.head);
        if self.truncated() {
            // `total` counts head + omitted + tail, so this is exactly the run
            // of bytes that fell out of the middle.
            let omitted = self.total - self.head.len() as u64 - self.tail.len() as u64;
            out.extend_from_slice(omission_marker(omitted).as_bytes());
        }
        out.extend(self.tail.iter().copied());
        out
    }
}

/// The marker inserted between head and tail when a stream was capped.
///
/// Kept textual (and newline-padded) on purpose: the `.log` files are read by
/// humans and by `tail`/`grep`, and a reader must be able to tell that the
/// middle is missing rather than assume the stream was contiguous.
fn omission_marker(omitted: u64) -> String {
    format!("\n… [{omitted} bytes omitted] …\n")
}

/// One executed run. Serialized as one JSON line in `index.jsonl` and as
/// `meta.json`. Readers must ignore unknown keys (forward compatibility).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct RunRecord {
    /// `<UTC timestamp>-<pid>`, e.g. `20260922T041533Z-921501`.
    pub id: String,
    /// RFC 3339 UTC start time.
    pub ts_start: String,
    pub duration_ms: u64,
    /// Host as the user typed it.
    pub host: String,
    /// `user@host:port` after resolution, with the key when known.
    pub resolved: String,
    /// The command string exactly as executed (verbatim).
    pub command: String,
    /// Environment passed to the remote command (VERBATIM values).
    pub env: Vec<(String, String)>,
    pub exit_code: Option<i32>,
    pub pid: Option<u32>,
    /// Whether this run deployed the worker.
    pub deployed: bool,
    /// True bytes seen, even when capture was capped.
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub rexec_version: String,
    /// Decision trace (empty on a clean run unless `-v`).
    pub trace: Vec<String>,
}

/// Which captured artifact to read back.
#[derive(Clone, Copy)]
pub enum Artifact {
    Stdout,
    Stderr,
}

impl Artifact {
    /// Log file name inside the run dir.
    fn file_name(self) -> &'static str {
        match self {
            Artifact::Stdout => "stdout.log",
            Artifact::Stderr => "stderr.log",
        }
    }

    /// Human name for error messages.
    fn label(self) -> &'static str {
        match self {
            Artifact::Stdout => "stdout",
            Artifact::Stderr => "stderr",
        }
    }
}

/// `~/.rexec/history` (created 0700 on first write).
pub fn history_root() -> anyhow::Result<PathBuf> {
    let home = dirs::home_dir().context("cannot determine home directory")?;
    Ok(home.join(".rexec").join("history"))
}

/// `~/.rexec/history/index.jsonl`.
pub fn index_path() -> anyhow::Result<PathBuf> {
    Ok(history_root()?.join("index.jsonl"))
}

/// Whether recording is enabled: `REXEC_HISTORY` not `0`, and not disabled
/// per-run. (`--no-history` is folded in by the caller via `set_enabled`.)
pub fn enabled() -> bool {
    // The env var is read on every call (a cheap `var_os` lookup, no
    // allocation) rather than cached in a `OnceLock`: it is consulted a handful
    // of times per process, and a cache would make the value depend on which
    // call happened first — surprising in tests and in any embedding process
    // that flips the variable at runtime.
    ENABLED.load(Ordering::Relaxed) && !env_disabled()
}

/// `REXEC_HISTORY=0` disables recording globally. Only the exact string `0`
/// counts: an empty or misspelled value must not silently turn a run's
/// recording off.
fn env_disabled() -> bool {
    std::env::var_os("REXEC_HISTORY").is_some_and(|v| v == "0")
}

/// Called once at startup from the CLI flags/global switch.
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

/// Fresh id for a run started now.
pub fn new_id(pid: u32) -> String {
    format_id(now_secs(), pid)
}

/// Format a Unix timestamp as `new_id`'s stem `<YYYYMMDD>T<HHMMSS>Z-<pid>`.
///
/// Split out from [`new_id`] so the calendar math is testable without freezing
/// the clock.
///
/// Uniqueness rests on one run per process: the pid separates concurrent runs
/// and the timestamp separates successive runs of different processes. Two runs
/// in the same second from the *same* pid would collide (and reuse the run dir);
/// the CLI executes at most one run per process, so that cannot happen here.
fn format_id(unix_secs: u64, pid: u32) -> String {
    let days = (unix_secs / SECS_PER_DAY) as i64;
    let secs_of_day = unix_secs % SECS_PER_DAY;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z-{pid}",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// Days since 1970-01-01 → (year, month, day) in the proleptic Gregorian
/// calendar.
///
/// This is Howard Hinnant's `civil_from_days` decomposition (era/day-of-era →
/// year-of-era → month/day), written out here because the crate deliberately
/// takes no date dependency for a single timestamp.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // Shift the epoch to 0000-03-01 so leap days land at the end of the year
    // and the month arithmetic below needs no special case for February.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // day of era, [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year, [0, 365]
    let mp = (5 * doy + 2) / 153; // month index starting in March, [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Seconds since the Unix epoch, `0` if the clock is before it.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The run dir for `id`, with the id validated as a single path component.
///
/// `id` is user-supplied on the `history show <id>` path, so anything that
/// could escape `runs/` (separators, `..`) is rejected instead of being joined
/// blindly.
fn run_dir(root: &Path, id: &str) -> anyhow::Result<PathBuf> {
    if id.is_empty() || id == "." || id == ".." || id.contains(['/', '\\']) {
        anyhow::bail!("invalid run id {id:?}: expected <YYYYMMDD>T<HHMMSS>Z-<pid>");
    }
    Ok(root.join("runs").join(id))
}

/// Append the record to `index.jsonl` and write `runs/<id>/meta.json`
/// (+ the captured streams). Creates the tree 0700; files are 0600.
/// Best-effort by contract: history must never fail a run, so IO errors are
/// reported to stderr and swallowed by the caller.
///
/// Recording is additionally gated on [`enabled`]: when the global switch is
/// off (`--no-history`, `REXEC_HISTORY=0`) this is a silent no-op, so a caller
/// that forgets to check cannot leak the run the user asked not to record. The
/// files are the only boundary against disclosure — there is no redaction
/// layer, by design (module docs).
pub fn record(
    rec: &RunRecord,
    stdout: Option<&RingCapture>,
    stderr: Option<&RingCapture>,
) -> anyhow::Result<()> {
    if !enabled() {
        return Ok(());
    }
    record_in(&history_root()?, rec, stdout, stderr)
}

/// [`record`] against an explicit root (used by the unit tests, which must not
/// touch the real `~/.rexec`).
fn record_in(
    root: &Path,
    rec: &RunRecord,
    stdout: Option<&RingCapture>,
    stderr: Option<&RingCapture>,
) -> anyhow::Result<()> {
    let run = run_dir(root, &rec.id)?;
    // Every level is forced to 0700: `create_dir_all` honours the umask
    // (typically 0755) and this tree holds verbatim env values.
    create_private_dir(root)?;
    create_private_dir(&root.join("runs"))?;
    create_private_dir(&run)?;

    // The run dir is written before the index line: the line is the commit
    // point, so a crash leaves an orphan directory (harmless, cleaned up by
    // prune) instead of an index entry whose artifacts do not exist.
    let mut meta = serde_json::to_string_pretty(rec)
        .with_context(|| format!("serializing meta.json for run {}", rec.id))?;
    meta.push('\n');
    write_private(&run.join("meta.json"), meta.as_bytes())?;
    if let Some(capture) = stdout {
        write_private(&run.join("stdout.log"), &capture.captured())?;
    }
    if let Some(capture) = stderr {
        write_private(&run.join("stderr.log"), &capture.captured())?;
    }

    let idx = root.join("index.jsonl");
    let mut line = String::new();
    // A crash (or a full disk) in the middle of the previous append leaves the
    // last line without its terminator. Opening with one keeps THIS record
    // parseable instead of gluing it to the wreckage — the module docs promise
    // a crashed run costs at most its own line, and without this the next run
    // would pay for it too. (A concurrent append landing between the check and
    // the write can only add a blank line, which `load_index` skips.)
    if index_ends_mid_line(&idx) {
        line.push('\n');
    }
    // One `write` for JSON + newline: a line that is never split cannot leave a
    // half line behind, which is what lets `load_index` treat a partial line as
    // a crash artifact and skip it.
    line.push_str(&record_to_json(rec));
    line.push('\n');
    let mut file =
        open_append_private(&idx).with_context(|| format!("opening {}", idx.display()))?;
    file.write_all(line.as_bytes())
        .with_context(|| format!("appending run {} to {}", rec.id, idx.display()))?;
    Ok(())
}

/// The record as compact, single-line JSON (no trailing newline; the index
/// writer adds it). A stable name for callers that need the same encoding the
/// index uses.
///
/// Infallible for `RunRecord`: every field is a string, number, bool, `Option`
/// or `Vec` of those, so `serde_json` cannot hit an unserializable value. A
/// panic here would be a programming error, not user data.
pub fn record_to_json(rec: &RunRecord) -> String {
    serde_json::to_string(rec).expect("RunRecord is always serializable")
}

/// All records in the index, newest first. Malformed lines are skipped (the
/// index is append-only text; a partial line from a crash must not hide the
/// rest).
///
/// Skips are counted and reported on stderr (⚠ line, the same shape main.rs
/// uses for other repairs) because a silent skip would make `history list`
/// quietly incomplete.
pub fn load_index() -> anyhow::Result<Vec<RunRecord>> {
    load_index_in(&index_path()?)
}

/// [`load_index`] against an explicit path; creates nothing.
fn load_index_in(idx: &Path) -> anyhow::Result<Vec<RunRecord>> {
    // Read bytes rather than `read_to_string`: a torn append can also cut a
    // multi-byte UTF-8 sequence, and that one bad byte must not hide the whole
    // index.
    let raw = match std::fs::read(idx) {
        Ok(raw) => raw,
        // No index yet = no runs yet; asking for history must not create the
        // tree (that is `record`'s job).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(anyhow::Error::new(e).context(format!("reading {}", idx.display())));
        }
    };

    let mut out = Vec::new();
    let mut skipped = 0usize;
    let mut first_bad = 0usize;
    for (i, line) in raw.split(|b| *b == b'\n').enumerate() {
        let line = line.trim_ascii();
        // Blank lines (a trailing newline, a hand-edit) are not damage.
        if line.is_empty() {
            continue;
        }
        match serde_json::from_slice::<RunRecord>(line) {
            Ok(rec) => out.push(rec),
            Err(_) => {
                skipped += 1;
                if first_bad == 0 {
                    first_bad = i + 1;
                }
            }
        }
    }
    if skipped > 0 {
        eprintln!(
            "⚠ history: skipped {skipped} malformed line(s) in {} (first at line {first_bad})",
            idx.display()
        );
    }

    // Appends are the only write, so file order is chronological; every caller
    // wants the newest run first.
    out.reverse();
    Ok(out)
}

/// Read one captured stream for a run.
pub fn read_artifact(id: &str, which: Artifact) -> anyhow::Result<Vec<u8>> {
    read_artifact_in(&history_root()?, id, which)
}

/// [`read_artifact`] against an explicit root.
fn read_artifact_in(root: &Path, id: &str, which: Artifact) -> anyhow::Result<Vec<u8>> {
    let path = run_dir(root, id)?.join(which.file_name());
    std::fs::read(&path).with_context(|| {
        format!(
            "no captured {} for run {id} (looked in {}) — inspect the record with `rexec history show {id}`",
            which.label(),
            path.display()
        )
    })
}

/// Delete run directories older than `keep_days` and then, while the tree is
/// over `max_bytes`, the oldest runs. Rewrites the index to match. Returns
/// (removed_runs, bytes_freed).
pub fn prune(keep_days: u64, max_bytes: u64) -> anyhow::Result<(usize, u64)> {
    prune_in(&history_root()?, keep_days, max_bytes)
}

/// One eviction candidate: a run directory with the age and size prune reads
/// from disk.
#[derive(Debug)]
struct RunEntry {
    id: String,
    /// Directory mtime, seconds since the epoch.
    mtime_secs: u64,
    /// Recursive size of the run dir.
    size: u64,
}

/// [`prune`] against an explicit root.
fn prune_in(root: &Path, keep_days: u64, max_bytes: u64) -> anyhow::Result<(usize, u64)> {
    let runs_dir = root.join("runs");
    let entries = run_entries(&runs_dir);
    // The size phase must account for everything under the root, not just the
    // run dirs, or an oversized index would keep the tree over budget forever.
    let tree_bytes = tree_size(root);
    let evicted = select_evictions(&entries, tree_bytes, now_secs(), keep_days, max_bytes);
    if evicted.is_empty() {
        return Ok((0, 0));
    }

    let doomed: HashSet<&str> = evicted.iter().map(String::as_str).collect();
    // Rewrite the index FIRST. If that fails, nothing has been deleted yet, so
    // the index still describes the tree exactly — whereas the reverse order
    // (delete, then rewrite) leaves `history list` showing runs whose files are
    // already gone whenever the rewrite fails (a directory in the way, ENOSPC,
    // a crash between the phases).
    let idx = root.join("index.jsonl");
    if idx.exists() {
        let raw = std::fs::read(&idx).with_context(|| format!("reading {}", idx.display()))?;
        let kept = keep_index_lines(&raw, &doomed);
        rewrite_index(&idx, &kept)?;
    }

    let mut removed = 0usize;
    let mut freed = 0u64;
    for entry in &entries {
        if !doomed.contains(entry.id.as_str()) {
            continue;
        }
        // `entry.size` was measured above; the dir is about to disappear, so
        // re-statting it would just race with itself.
        match std::fs::remove_dir_all(runs_dir.join(&entry.id)) {
            Ok(()) => {
                removed += 1;
                // Freed counts the removed run dirs; the index shrinks by a few
                // bytes more on the rewrite, which is noise.
                freed += entry.size;
            }
            // A dir that cannot be removed stays on disk as an orphan: the
            // index no longer lists it, and a later prune still sees it (it is
            // collected from the filesystem, not from the index), so nothing
            // is lost and nothing dangles.
            Err(_) => continue,
        }
    }

    Ok((removed, freed))
}

/// Pure eviction policy: which run ids `prune` drops, oldest first.
///
/// Two phases, in order: (1) everything older than the `keep_days` cutoff goes;
/// (2) while the tree is still over `max_bytes`, the oldest survivors go. The
/// newest run is never evicted by either phase — history exists to explain the run you just
/// did, and a `max_bytes` smaller than a single run would otherwise wipe the
/// whole tree on every prune. `tree_bytes` is the current total tree size, so
/// the size phase reflects bytes actually on disk. Split out from `prune_in` so
/// the policy is testable without a filesystem.
fn select_evictions(
    entries: &[RunEntry],
    tree_bytes: u64,
    now_secs: u64,
    keep_days: u64,
    max_bytes: u64,
) -> Vec<String> {
    // Older than the cutoff = strictly before `now - keep_days`. `keep_days = 0`
    // therefore prunes everything from an earlier second — except the newest
    // run, which the loop below protects unconditionally.
    let cutoff = now_secs.saturating_sub(keep_days.saturating_mul(SECS_PER_DAY));

    let mut ordered: Vec<&RunEntry> = entries.iter().collect();
    // Oldest first; the id breaks ties so equal (or coarse) mtimes still evict
    // deterministically.
    ordered.sort_by(|a, b| {
        a.mtime_secs
            .cmp(&b.mtime_secs)
            .then_with(|| a.id.cmp(&b.id))
    });

    let mut evicted = Vec::new();
    let mut remaining = tree_bytes;
    let mut survivors: Vec<&RunEntry> = Vec::new();
    // The newest run is never evicted — not even by the age phase. History
    // exists to explain the run you just did; on a rarely used machine that run
    // may be the only record, and an age cutoff must not silently empty the
    // tree. (A run can still be removed explicitly by deleting its dir.)
    let newest = ordered.last().map(|e| e.id.clone());
    for entry in ordered {
        if Some(&entry.id) == newest.as_ref() {
            survivors.push(entry);
            continue;
        }
        if entry.mtime_secs < cutoff {
            remaining = remaining.saturating_sub(entry.size);
            evicted.push(entry.id.clone());
        } else {
            survivors.push(entry);
        }
    }
    while remaining > max_bytes && survivors.len() > 1 {
        let victim = survivors.remove(0);
        remaining = remaining.saturating_sub(victim.size);
        evicted.push(victim.id.clone());
    }
    evicted
}

/// The run dirs under `runs/`, with the age and size prune needs.
///
/// A dir whose mtime cannot be read is left out entirely: prune may only delete
/// what it can reason about, and "unknown date" must not be read as "ancient".
fn run_entries(runs_dir: &Path) -> Vec<RunEntry> {
    let Ok(dir) = std::fs::read_dir(runs_dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in dir.flatten() {
        let path = entry.path();
        // `symlink_metadata`: a symlinked dir is skipped rather than followed,
        // matching `tree_size` and keeping a link cycle from hanging prune.
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        let Some(mtime_secs) = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs()))
        else {
            continue;
        };
        out.push(RunEntry {
            id: entry.file_name().to_string_lossy().into_owned(),
            mtime_secs,
            size: tree_size(&path),
        });
    }
    out
}

/// Index bytes minus the lines belonging to `removed` runs.
///
/// Surviving lines are copied **verbatim** instead of being re-serialized, so
/// keys written by a newer rexec survive a prune in an older one (the struct is
/// documented to ignore unknown keys). Unparseable lines are kept too: their run
/// cannot be identified, and readers already skip them.
fn keep_index_lines(raw: &[u8], removed: &HashSet<&str>) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    for line in raw.split_inclusive(|b| *b == b'\n') {
        let keep = match serde_json::from_slice::<RunRecord>(line.trim_ascii()) {
            Ok(rec) => !removed.contains(rec.id.as_str()),
            Err(_) => true,
        };
        if keep {
            out.extend_from_slice(line);
        }
    }
    out
}

/// Replace `idx` with `contents`, writing `<name>.tmp` first.
///
/// The index is the only query surface, so it must never be observed half
/// written: `rename(2)` swaps the whole file in one step on unix. On Windows
/// the destination has to be removed first (a small non-atomic window, only
/// during an explicit user-run prune).
fn rewrite_index(idx: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let mut tmp_name = idx.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".tmp");
    let tmp = idx.with_file_name(tmp_name);

    write_private(&tmp, contents).with_context(|| format!("writing {}", tmp.display()))?;
    #[cfg(unix)]
    {
        std::fs::rename(&tmp, idx)
            .with_context(|| format!("renaming {} to {}", tmp.display(), idx.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::remove_file(idx);
        std::fs::rename(&tmp, idx)
            .with_context(|| format!("renaming {} to {}", tmp.display(), idx.display()))?;
    }
    Ok(())
}

/// Create `dir` (and parents) owner-only, 0700.
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        // No POSIX mode bits on Windows; the user profile ACL is the boundary.
        // Nothing to do.
    }
    Ok(())
}

/// Write `bytes` to `path`, creating it 0600.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = private_options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(bytes)
}

/// Open `path` for appending, creating it 0600.
fn open_append_private(path: &Path) -> std::io::Result<std::fs::File> {
    private_options().create(true).append(true).open(path)
}

/// `OpenOptions` whose create mode is owner-only on unix.
///
/// The mode applies only when the file is created; the index is created once by
/// the first run, and every other file lives in a fresh 0700 run dir, so no
/// caller needs to re-tighten an existing file.
fn private_options() -> std::fs::OpenOptions {
    let mut opts = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts
}

/// True when `path` exists, is non-empty and does not end in a newline — i.e.
/// the previous append was cut short mid-line.
///
/// Best-effort by design: any IO error reads as "nothing to repair", because
/// this check must never turn a history bookkeeping detail into a failed run.
fn index_ends_mid_line(path: &Path) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let Ok(len) = file.metadata().map(|meta| meta.len()) else {
        return false;
    };
    if len == 0 || file.seek(SeekFrom::End(-1)).is_err() {
        return false;
    }
    let mut last = [0u8; 1];
    matches!(file.read(&mut last), Ok(1)) && last[0] != b'\n'
}

/// Total size of the history tree in bytes (for `stats`/`prune` reporting).
pub fn tree_size(root: &Path) -> u64 {
    // `symlink_metadata` (not `metadata`): following links would let a symlink
    // out of the tree, or a link cycle, blow up the walk. A symlink itself
    // counts as nothing.
    let Ok(meta) = std::fs::symlink_metadata(root) else {
        return 0;
    };
    if meta.is_file() {
        return meta.len();
    }
    if !meta.is_dir() {
        return 0;
    }
    let Ok(dir) = std::fs::read_dir(root) else {
        return 0;
    };
    dir.flatten().map(|e| tree_size(&e.path())).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway history root under the system temp dir, removed on drop —
    /// including when an assertion panics. The pid keeps parallel `cargo test`
    /// processes apart, the name keeps tests inside one process apart.
    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("rexec-history-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create temp root");
            TempRoot(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A record with every field non-default, so a serialization bug cannot hide
    /// behind an empty value.
    fn sample_record(id: &str) -> RunRecord {
        RunRecord {
            id: id.to_string(),
            ts_start: "2026-09-22T04:15:33Z".to_string(),
            duration_ms: 1234,
            host: "web-1".to_string(),
            resolved: "root@10.0.0.5:22 (key ~/.ssh/id_ed)".to_string(),
            command: "printf 'a\\nb'\t\"quoted\"".to_string(),
            env: vec![("A".to_string(), "b=c".to_string())],
            exit_code: Some(0),
            pid: Some(4242),
            deployed: false,
            stdout_bytes: 12,
            stderr_bytes: 0,
            stdout_truncated: true,
            stderr_truncated: false,
            rexec_version: "0.3.1".to_string(),
            trace: vec!["resolved → web-1".to_string()],
        }
    }

    fn write_file(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn fake_run(root: &Path, id: &str, payload: &[u8]) -> PathBuf {
        let dir = root.join("runs").join(id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("stdout.log"), payload).unwrap();
        dir
    }

    fn entry(id: &str, mtime_secs: u64, size: u64) -> RunEntry {
        RunEntry {
            id: id.to_string(),
            mtime_secs,
            size,
        }
    }

    // -- ids -----------------------------------------------------------------

    #[test]
    fn test_format_id_epoch_zero() {
        assert_eq!(format_id(0, 4242), "19700101T000000Z-4242");
    }

    #[test]
    fn test_format_id_known_timestamps() {
        // 1e9 = the Unix "billennium", 2001-09-09T01:46:40Z.
        assert_eq!(format_id(1_000_000_000, 7), "20010909T014640Z-7");
        // 2000-02-29T00:00:00Z: a leap day in a century leap year.
        assert_eq!(format_id(951_782_400, 1), "20000229T000000Z-1");
        // 2027-01-15T08:00:00Z, i.e. a plain modern timestamp.
        assert_eq!(format_id(1_800_000_000, 9), "20270115T080000Z-9");
    }

    #[test]
    fn test_new_id_shape_and_pid_suffix() {
        let id = new_id(1234);
        assert!(id.ends_with("-1234"), "pid suffix missing from {id}");
        // <8 digits>T<6 digits>Z-<pid>
        let (stamp, pid) = id.rsplit_once('-').unwrap();
        assert_eq!(pid, "1234");
        assert_eq!(stamp.len(), 16, "unexpected stamp {stamp}");
        assert_eq!(&stamp[8..9], "T");
        assert!(stamp.ends_with('Z'));
        assert!(stamp[..8].bytes().all(|b| b.is_ascii_digit()));
        assert!(stamp[9..15].bytes().all(|b| b.is_ascii_digit()));
    }

    // -- capture -------------------------------------------------------------

    #[test]
    fn test_ring_capture_small_passthrough() {
        let mut cap = RingCapture::new(8);
        cap.push(b"abc");
        assert_eq!(cap.total(), 3);
        assert!(!cap.truncated());
        // Nothing was dropped, so the capture is the input itself.
        assert_eq!(cap.captured(), b"abc");
    }

    #[test]
    fn test_ring_capture_exactly_limit_is_byte_identical() {
        let limit = 8;
        let input: Vec<u8> = (0..limit as u8).collect();
        let mut cap = RingCapture::new(limit);
        cap.push(&input);
        assert_eq!(cap.total(), limit as u64);
        assert!(!cap.truncated(), "a full-but-not-over capture is complete");
        assert_eq!(cap.captured(), input);
    }

    #[test]
    fn test_ring_capture_over_limit_head_tail_and_marker() {
        let limit = 8;
        // 12 bytes into an 8-byte budget: 4 head, 4 tail, 4 omitted.
        let input: Vec<u8> = (0..12u8).collect();
        let mut cap = RingCapture::new(limit);
        cap.push(&input);

        assert_eq!(cap.total(), 12);
        assert!(cap.truncated());

        let mut expected = Vec::new();
        expected.extend_from_slice(&input[..4]); // head preserved
        expected.extend_from_slice("\n… [4 bytes omitted] …\n".as_bytes());
        expected.extend_from_slice(&input[8..]); // tail = the last 4 bytes
        assert_eq!(cap.captured(), expected);

        // The marker must not be mistaken for captured payload.
        assert!(cap.captured().len() > limit);
    }

    #[test]
    fn test_ring_capture_many_small_frames_equal_one_big_push() {
        let limit = 8;
        let input: Vec<u8> = (0..40u8).collect();
        let mut framed = RingCapture::new(limit);
        for b in &input {
            framed.push(std::slice::from_ref(b));
        }
        let mut bulk = RingCapture::new(limit);
        bulk.push(&input);

        assert_eq!(framed.total(), bulk.total());
        assert_eq!(framed.truncated(), bulk.truncated());
        assert_eq!(framed.captured(), bulk.captured());
        // Frame boundaries must not blur into the result: still head + tail.
        assert_eq!(&framed.captured()[..4], &input[..4]);
        assert_eq!(
            &framed.captured()[framed.captured().len() - 4..],
            &input[36..]
        );
    }

    #[test]
    fn test_ring_capture_zero_byte_push_is_noop() {
        let mut cap = RingCapture::new(8);
        cap.push(b"");
        assert_eq!(cap.total(), 0);
        assert_eq!(cap.captured(), b"");

        cap.push((0..20u8).collect::<Vec<u8>>().as_slice());
        let before = cap.captured();
        let total = cap.total();
        cap.push(b"");
        assert_eq!(cap.total(), total);
        assert_eq!(cap.captured(), before);
    }

    // -- serialization -------------------------------------------------------

    #[test]
    fn test_record_to_json_round_trip_special_characters() {
        let mut rec = sample_record("20260922T041533Z-4242");
        // Quotes, newlines, tabs, backslashes and non-ASCII must survive both
        // directions byte for byte.
        rec.command = "printf 'a\\nb' \"quoted\"\ttab \\\\ … 日本語 🚀".to_string();
        rec.env = vec![
            ("PATH".to_string(), "/a b:/c\"d".to_string()),
            ("NOTE".to_string(), "line1\nline2\t\\end ✓".to_string()),
        ];

        let json = record_to_json(&rec);
        // One line is the contract for index.jsonl: real newlines must be
        // escaped, never emitted.
        assert!(!json.contains('\n'), "compact JSON must stay on one line");
        assert!(
            json.contains("\\n"),
            "newlines must be escaped, not dropped"
        );

        let parsed: RunRecord = serde_json::from_str(&json).expect("round-trip parse");
        assert_eq!(parsed.command, rec.command);
        assert_eq!(parsed.env, rec.env);
        assert_eq!(parsed.id, rec.id);
        assert_eq!(parsed.pid, rec.pid);
        assert_eq!(parsed.exit_code, rec.exit_code);
        assert_eq!(parsed.trace, rec.trace);
        // Re-serializing the parsed record yields the same bytes: nothing was
        // normalized away by the round trip.
        assert_eq!(record_to_json(&parsed), json);
    }

    // -- record / load / read ------------------------------------------------

    #[test]
    fn test_record_writes_tree_and_index() {
        let root = TempRoot::new("record");
        let mut out = RingCapture::new(8);
        out.push(b"0123456789ab"); // truncated: head 0123, tail 89ab
        let mut err = RingCapture::new(8);
        err.push(b"boom");

        let first = sample_record("20260922T041533Z-1");
        let second = sample_record("20260922T041534Z-2");
        record_in(root.path(), &first, Some(&out), Some(&err)).unwrap();
        record_in(root.path(), &second, None, None).unwrap();

        let idx = root.path().join("index.jsonl");
        let lines = std::fs::read_to_string(&idx).unwrap();
        assert_eq!(lines.lines().count(), 2, "one JSON line per run");
        let parsed_first: RunRecord = serde_json::from_str(lines.lines().next().unwrap()).unwrap();
        assert_eq!(parsed_first.command, first.command);

        // meta.json is the same record, pretty-printed.
        let meta: RunRecord = serde_json::from_str(
            &std::fs::read_to_string(root.path().join("runs").join(&first.id).join("meta.json"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(meta.id, first.id);
        assert_eq!(meta.command, first.command);
        assert_eq!(meta.env, first.env);

        // Loaded newest first, and the artifacts come back through
        // read_artifact.
        let loaded = load_index_in(&idx).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].id, second.id);
        assert_eq!(loaded[1].id, first.id);
        assert_eq!(
            read_artifact_in(root.path(), &first.id, Artifact::Stdout).unwrap(),
            out.captured()
        );
        assert_eq!(
            read_artifact_in(root.path(), &first.id, Artifact::Stderr).unwrap(),
            b"boom"
        );
        assert!(loaded[0].stdout_truncated);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            // Verbatim env values live here: the tree must be owner-only.
            assert_eq!(mode(root.path()), 0o700);
            assert_eq!(mode(&root.path().join("runs")), 0o700);
            assert_eq!(mode(&root.path().join("runs").join(&first.id)), 0o700);
            assert_eq!(mode(&idx), 0o600);
            assert_eq!(
                mode(&root.path().join("runs").join(&first.id).join("meta.json")),
                0o600
            );
            assert_eq!(
                mode(&root.path().join("runs").join(&first.id).join("stdout.log")),
                0o600
            );
        }
    }

    #[test]
    fn test_load_index_missing_is_empty_and_creates_nothing() {
        let root = TempRoot::new("load-missing");
        let loaded = load_index_in(&root.path().join("index.jsonl")).unwrap();
        assert!(loaded.is_empty());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn test_load_index_skips_malformed_lines() {
        let root = TempRoot::new("load-malformed");
        let idx = root.path().join("index.jsonl");
        let a = record_to_json(&sample_record("20260922T041533Z-1"));
        let b = record_to_json(&sample_record("20260922T041534Z-2"));
        // A crash-partial line in the middle (and a non-UTF-8 one) must not hide
        // the runs around it.
        let mut raw = Vec::new();
        raw.extend_from_slice(a.as_bytes());
        raw.push(b'\n');
        raw.extend_from_slice(b"{\"id\": \"20260922T04153");
        raw.push(b'\n');
        raw.extend_from_slice(b"\xff\xfe not json at all\n");
        raw.extend_from_slice(b"\n");
        raw.extend_from_slice(b.as_bytes());
        raw.push(b'\n');
        std::fs::write(&idx, &raw).unwrap();

        let loaded = load_index_in(&idx).unwrap();
        assert_eq!(loaded.len(), 2, "the two intact records survive");
        assert_eq!(loaded[0].id, "20260922T041534Z-2"); // newest first
        assert_eq!(loaded[1].id, "20260922T041533Z-1");
    }

    #[test]
    fn test_read_artifact_missing_points_at_show() {
        let root = TempRoot::new("read-missing");
        let err = read_artifact_in(root.path(), "20260922T041533Z-1", Artifact::Stdout)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("rexec history show 20260922T041533Z-1"),
            "error must point at the show command: {err}"
        );
    }

    #[test]
    fn test_read_artifact_rejects_path_escape() {
        let root = TempRoot::new("read-escape");
        for id in ["../secrets", "a/b", "", ".."] {
            assert!(
                read_artifact_in(root.path(), id, Artifact::Stderr).is_err(),
                "id {id:?} must not be joined onto the runs dir"
            );
        }
    }

    // -- eviction policy -----------------------------------------------------

    #[test]
    fn test_select_evictions_cutoff_drops_old_runs() {
        let now = 1_000 * SECS_PER_DAY;
        let entries = vec![
            entry("old", now - 10 * SECS_PER_DAY, 1),
            entry("fresh", now - SECS_PER_DAY, 1),
        ];
        // Under budget overall: only the age phase may evict.
        let evicted = select_evictions(&entries, 2, now, 7, u64::MAX);
        assert_eq!(evicted, vec!["old".to_string()]);
    }

    #[test]
    fn test_select_evictions_size_phase_is_oldest_first() {
        let now = 1_000 * SECS_PER_DAY;
        let entries = vec![
            entry("c", now - 1, 40),
            entry("a", now - 3, 40),
            entry("b", now - 2, 40),
        ];
        // No run is older than the cutoff; the tree (120) must come down to 40.
        let evicted = select_evictions(&entries, 120, now, 3650, 40);
        assert_eq!(evicted, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn test_select_evictions_never_drops_the_newest() {
        let now = 1_000 * SECS_PER_DAY;
        let entries = vec![entry("old", now - 100, 10), entry("new", now - 1, 10)];
        // max_bytes = 0 cannot be satisfied by a single 10-byte run; the newest
        // still survives so `stats`/`show` keep working.
        let evicted = select_evictions(&entries, 20, now, 3650, 0);
        assert_eq!(evicted, vec!["old".to_string()]);

        // Same with a single run: nothing left to evict.
        let only = vec![entry("new", now - 1, 10)];
        assert!(select_evictions(&only, 10, now, 3650, 0).is_empty());
    }

    #[test]
    fn test_select_evictions_under_budget_is_noop() {
        let now = 1_000 * SECS_PER_DAY;
        let entries = vec![entry("a", now - 2, 10), entry("b", now - 1, 10)];
        assert!(select_evictions(&entries, 20, now, 30, 1024).is_empty());
        // keep_days = 0 cuts at "now": a run from an earlier second is older
        // than the cutoff, a run from exactly `now` is not (`<`, not `<=`).
        assert_eq!(
            select_evictions(&entries, 20, now - 1, 0, 1024),
            vec!["a".to_string()]
        );
        assert!(select_evictions(&[entry("now", now, 10)], 10, now, 0, 1024).is_empty());
    }

    // -- prune ---------------------------------------------------------------

    #[test]
    fn test_prune_size_phase_removes_oldest_and_rewrites_index() {
        let root = TempRoot::new("prune-size");
        // Ids sort like their ages, so the tie-break on equal mtimes still
        // evicts the intended (older) run first.
        let old = fake_run(root.path(), "20260101T000000Z-1", b"old-run");
        let new = fake_run(root.path(), "20260102T000000Z-2", b"new-run");
        let old_bytes = tree_size(&old);
        let idx = root.path().join("index.jsonl");
        let mut raw = record_to_json(&sample_record("20260101T000000Z-1"));
        raw.push('\n');
        raw.push_str(&record_to_json(&sample_record("20260102T000000Z-2")));
        raw.push('\n');
        std::fs::write(&idx, raw.as_bytes()).unwrap();

        // keep_days huge (age phase off), max_bytes 0 (size phase on).
        let (removed, freed) = prune_in(root.path(), u64::MAX, 0).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(freed, old_bytes);
        assert!(!old.exists());
        assert!(new.exists());

        let survivors = std::fs::read_to_string(&idx).unwrap();
        assert!(!survivors.contains("20260101T000000Z-1"));
        assert!(survivors.contains("20260102T000000Z-2"));
        let loaded = load_index_in(&idx).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "20260102T000000Z-2");
        // The temporary file is renamed into place, never left behind.
        assert!(!root.path().join("index.jsonl.tmp").exists());
    }

    #[test]
    fn test_prune_under_budget_and_missing_root_are_noops() {
        let root = TempRoot::new("prune-noop");
        fake_run(root.path(), "20260102T000000Z-2", b"payload");
        let idx = root.path().join("index.jsonl");
        let line = record_to_json(&sample_record("20260102T000000Z-2"));
        std::fs::write(&idx, format!("{line}\n")).unwrap();
        let before = std::fs::read(&idx).unwrap();

        assert_eq!(prune_in(root.path(), 3650, u64::MAX).unwrap(), (0, 0));
        // Nothing was evicted, so the index was not rewritten at all.
        assert_eq!(std::fs::read(&idx).unwrap(), before);
        assert!(root.path().join("runs").join("20260102T000000Z-2").exists());

        // A root that does not exist is not an error and is not created.
        let missing = root.path().join("nope");
        assert_eq!(prune_in(&missing, 1, 1).unwrap(), (0, 0));
        assert!(!missing.exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_prune_age_phase_removes_only_old_runs() {
        use std::fs::FileTimes;
        use std::time::Duration;

        let root = TempRoot::new("prune-age");
        let old = fake_run(root.path(), "20260101T000000Z-1", b"old");
        let new = fake_run(root.path(), "20260102T000000Z-2", b"new");
        let idx = root.path().join("index.jsonl");
        let mut raw = record_to_json(&sample_record("20260101T000000Z-1"));
        raw.push('\n');
        raw.push_str(&record_to_json(&sample_record("20260102T000000Z-2")));
        raw.push('\n');
        std::fs::write(&idx, raw.as_bytes()).unwrap();

        // Age the older run by 10 days; keep_days = 7 must then drop it while
        // the fresh run survives well under the (unlimited) size budget.
        let when = SystemTime::now() - Duration::from_secs(10 * SECS_PER_DAY);
        std::fs::File::open(&old)
            .unwrap()
            .set_times(FileTimes::new().set_modified(when))
            .unwrap();

        let (removed, freed) = prune_in(root.path(), 7, u64::MAX).unwrap();
        assert_eq!(removed, 1);
        assert!(freed > 0);
        assert!(!old.exists());
        assert!(new.exists());
        let survivors = std::fs::read_to_string(&idx).unwrap();
        assert!(!survivors.contains("20260101T000000Z-1"));
        assert!(survivors.contains("20260102T000000Z-2"));
    }

    #[test]
    fn test_prune_age_phase_keeps_the_only_old_run() {
        use std::fs::FileTimes;
        use std::time::Duration;

        // A lone run older than the cutoff is the only history there is; the
        // age phase must not silently empty the tree (disaster recovery: this
        // is the run you would want to inspect).
        let root = TempRoot::new("prune-age-even-oldest");
        let only = fake_run(root.path(), "20260101T000000Z-1", b"old");
        let idx = root.path().join("index.jsonl");
        let mut raw = record_to_json(&sample_record("20260101T000000Z-1"));
        raw.push('\n');
        std::fs::write(&idx, raw.as_bytes()).unwrap();

        let when = SystemTime::now() - Duration::from_secs(40 * SECS_PER_DAY);
        std::fs::File::open(&only)
            .unwrap()
            .set_times(FileTimes::new().set_modified(when))
            .unwrap();

        let (removed, freed) = prune_in(root.path(), 30, u64::MAX).unwrap();
        assert_eq!(
            removed, 0,
            "the newest (only) run must survive the age phase"
        );
        assert_eq!(freed, 0);
        assert!(only.exists(), "run dir must still exist");
        assert!(
            std::fs::read_to_string(&idx)
                .unwrap()
                .contains("20260101T000000Z-1")
        );
    }

    #[test]
    fn test_prune_index_rewrite_failure_deletes_nothing() {
        use std::fs::FileTimes;
        use std::time::Duration;

        // The index is rewritten BEFORE any directory is deleted: a failure
        // there must leave the tree exactly as it was, never an index pointing
        // at runs whose files are already gone.
        let root = TempRoot::new("prune-rewrite-fail");
        let old = fake_run(root.path(), "20260101T000000Z-1", b"old");
        let new = fake_run(root.path(), "20260102T000000Z-2", b"new");
        let idx = root.path().join("index.jsonl");
        let mut raw = record_to_json(&sample_record("20260101T000000Z-1"));
        raw.push('\n');
        raw.push_str(&record_to_json(&sample_record("20260102T000000Z-2")));
        raw.push('\n');
        std::fs::write(&idx, raw.as_bytes()).unwrap();

        // Age only the OLDER run: the newest is protected, so the age phase
        // evicts exactly one run and therefore has to rewrite the index.
        let when = SystemTime::now() - Duration::from_secs(40 * SECS_PER_DAY);
        std::fs::File::open(&old)
            .unwrap()
            .set_times(FileTimes::new().set_modified(when))
            .unwrap();

        // Block the atomic rewrite: `index.jsonl.tmp` cannot be created as a
        // file while a directory sits there.
        std::fs::create_dir_all(root.path().join("index.jsonl.tmp")).unwrap();

        let err = prune_in(root.path(), 30, u64::MAX);
        assert!(err.is_err(), "the blocked rewrite must surface as an error");
        assert!(
            old.exists(),
            "nothing may be deleted when the rewrite fails"
        );
        assert!(new.exists());
        let survivors = std::fs::read_to_string(&idx).unwrap();
        assert!(
            survivors.contains("20260101T000000Z-1"),
            "the index must still describe every surviving run"
        );
        assert!(survivors.contains("20260102T000000Z-2"));
    }

    #[test]
    fn test_prune_keeps_unparseable_index_lines() {
        let root = TempRoot::new("prune-partial");
        let old = fake_run(root.path(), "20260101T000000Z-1", b"old");
        let new = fake_run(root.path(), "20260102T000000Z-2", b"new");
        let idx = root.path().join("index.jsonl");
        let mut raw = record_to_json(&sample_record("20260101T000000Z-1"));
        raw.push('\n');
        raw.push_str("{\"id\": \"20260101T0000"); // crash partial, unattributable
        raw.push('\n');
        raw.push_str(&record_to_json(&sample_record("20260102T000000Z-2")));
        raw.push('\n');
        std::fs::write(&idx, raw.as_bytes()).unwrap();

        let (removed, _) = prune_in(root.path(), u64::MAX, 0).unwrap();
        assert_eq!(removed, 1);
        assert!(!old.exists());
        assert!(new.exists(), "the newest run is never evicted");
        let survivors = std::fs::read_to_string(&idx).unwrap();
        assert!(survivors.contains("20260102T000000Z-2"));
        assert!(
            survivors.contains("{\"id\": \"20260101T0000"),
            "an unattributable line must not be silently dropped: {survivors}"
        );
    }

    // -- size / switch -------------------------------------------------------

    #[test]
    fn test_tree_size_sums_recursively() {
        let root = TempRoot::new("tree-size");
        write_file(&root.path().join("index.jsonl"), b"123");
        write_file(&root.path().join("runs/a/stdout.log"), b"12345");
        write_file(&root.path().join("runs/a/nested/meta.json"), b"1234567");
        write_file(&root.path().join("runs/b/stderr.log"), b"12");
        assert_eq!(tree_size(root.path()), 3 + 5 + 7 + 2);
        // Empty dirs and missing paths add nothing.
        std::fs::create_dir_all(root.path().join("runs/empty")).unwrap();
        assert_eq!(tree_size(root.path()), 17);
        assert_eq!(tree_size(&root.path().join("missing")), 0);
    }

    #[test]
    fn test_enabled_truth_table() {
        // The switch is process-global, so read the ambient env instead of
        // mutating it (a test must not race the rest of the test binary).
        let env_off = std::env::var_os("REXEC_HISTORY").is_some_and(|v| v == "0");
        set_enabled(true);
        assert_eq!(enabled(), !env_off, "switch on → the env decides");
        set_enabled(false);
        assert!(!enabled(), "switch off → disabled regardless of env");
        set_enabled(true);
        assert_eq!(enabled(), !env_off);
    }

    // -- odd limits / torn appends -------------------------------------------

    #[test]
    fn test_ring_capture_odd_limit_uses_the_whole_budget() {
        // The extra byte of an odd limit goes to the tail, so the budget is
        // usable in full: exactly `limit` bytes are not truncation.
        let limit = 5usize;
        let full: Vec<u8> = (0..limit as u8).collect();
        let mut cap = RingCapture::new(limit);
        cap.push(&full);
        assert_eq!(cap.total(), limit as u64);
        assert!(!cap.truncated(), "head + tail must cover the whole budget");
        assert_eq!(cap.captured(), full);

        // One byte over is truncation, and the oldest byte is the one dropped:
        // head = first 2 bytes, tail = last 3.
        let mut cap = RingCapture::new(limit);
        cap.push(&(0..=limit as u8).collect::<Vec<u8>>());
        assert!(cap.truncated());
        let mut expected = vec![0, 1];
        expected.extend_from_slice("\n… [1 bytes omitted] …\n".as_bytes());
        expected.extend_from_slice(&[3, 4, 5]);
        assert_eq!(cap.captured(), expected);
    }

    #[test]
    fn test_record_after_a_torn_append_keeps_the_new_line_parseable() {
        let root = TempRoot::new("record-torn");
        // A crashed append left a line with no terminator.
        write_file(
            &root.path().join("index.jsonl"),
            b"{\"id\": \"20260922T04153",
        );
        record_in(
            root.path(),
            &sample_record("20260922T041600Z-9"),
            None,
            None,
        )
        .unwrap();

        let raw = std::fs::read_to_string(root.path().join("index.jsonl")).unwrap();
        assert!(
            raw.starts_with("{\"id\": \"20260922T04153\n"),
            "the torn line must be terminated, not glued to the new one: {raw}"
        );
        // The torn line is skipped; this run's line survives.
        let loaded = load_index_in(&root.path().join("index.jsonl")).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "20260922T041600Z-9");
    }

    #[test]
    fn test_record_does_not_add_blank_lines_to_a_healthy_index() {
        let root = TempRoot::new("record-healthy");
        record_in(
            root.path(),
            &sample_record("20260922T041533Z-1"),
            None,
            None,
        )
        .unwrap();
        record_in(
            root.path(),
            &sample_record("20260922T041534Z-2"),
            None,
            None,
        )
        .unwrap();
        let raw = std::fs::read_to_string(root.path().join("index.jsonl")).unwrap();
        assert!(!raw.starts_with('\n'), "no repair newline on a clean index");
        assert!(
            !raw.contains("\n\n"),
            "no blank line between records: {raw:?}"
        );
        assert_eq!(
            load_index_in(&root.path().join("index.jsonl"))
                .unwrap()
                .len(),
            2
        );
    }
}

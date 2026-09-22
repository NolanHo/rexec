---
name: rexec
description: "Remote code execution + folder sync over SSH. Use when the user wants to run commands on a remote server, sync local folders/files to remote, or execute scripts remotely with SSH disconnect resilience. Activates on keywords: rexec, remote exec, remote sync, sync and run."
---

# rexec — Remote Execution + Folder Sync over SSH

Sync local files/folders and run commands on a remote host over SSH. Commands survive SSH disconnects: the remote worker keeps running, and the CLI auto-reconnects and resumes output.

## Binary

```
rexec   # ~/.local/bin/rexec   (source: /root/Code/rexec)
```

Run `rexec <host> init` once per new host to check/install remote deps (rsync, sh).

## Usage

```bash
# Sync a folder + run a command
rexec <host> run --sync ./project:/home/user/project -- "python main.py"

# Run only (no sync)
rexec <host> run -- "bash deploy.sh"

# ssh-config alias or user@host:port both work (for run AND --sync)
rexec prod run -- "systemctl status nginx"
rexec root@1.2.3.4:2222 run --sync ./deploy.sh:/opt/deploy.sh -- "bash /opt/deploy.sh"
# A name that is not a configured alias is an error (with near-miss suggestions):
# literal targets need an explicit user@host, IP or dotted hostname.

# Override port globally (applies to SSH and rsync)
rexec -p 2222 root@1.2.3.4 run -- "df -h"

# Sync + run a local script in one step
rexec <host> script ./deploy.sh -- arg1 arg2

# List hosts from ~/.ssh/config
rexec list

# Inspect past runs (local record: command, env, output, exit, trace)
rexec history list -n 10 --failed
rexec history show 20260922T041533Z-921501 --stderr | tail -20
rexec history grep sk-live --output

# Dry run: what a run WOULD do (resolution, deploy decision, launch command)
rexec <host> plan -- "python main.py"

# Why did it do that? -v prints the decision trace (resolution, auth, deploy)
rexec -v <host> run -- "df -h"

# Machine-readable summary on stderr (stdout stays pure command output)
rexec --json <host> run -- "uname -a"

# Quiet: only errors/warnings remain (errors are never suppressed)
rexec -q <host> run -- "echo hi"
```

### Output contract

- **Success is silent**: stdout/stderr carry the command's own output and nothing else — except the first-connect known-hosts notice (`⚠ Accepting new host key for …`, as `ssh` prints) and the non-zero-exit warning. `-v/--verbose` adds the decision trace (resolved target, auth attempts, platform/deploy decision, remote PID, reconnects, timings).
- **Errors/warnings carry full context in one shot** — no re-run with `-v` needed. An unknown host alias fails listing near-miss suggestions from the configured aliases (prefix/substring matches) plus the hint to use `user@host` for a literal host (an alias is never silently treated as a raw hostname). A worker that dies before starting reports its own stderr and the launch command.
- **Non-zero remote exit** prints exactly one warning line to stderr: `⚠ remote exit <code> (log: ~/.rexec/logs/<pid>.log)`; exit code 0 prints nothing. rexec's own exit status **mirrors the remote code** (ssh semantics) — a signal-killed remote process (reported as `-1`) exits `255`; piping stdout into an early-exiting reader (`| head`) ends the process on SIGPIPE (141) instead.
- **`--json`** writes one JSON line to stderr, last (after the trace/warning): `host`, `resolved`, `pid`, `exit_code`, `duration_ms`, `deployed`, `stdout_bytes`, `stderr_bytes`, `log_path` (`null` for now — the warning line carries the remote log path), `error` (failure only), always in that order. stdout is never polluted.

### `run` options

| Option | Description |
|--------|-------------|
| `--sync LOCAL:REMOTE` | rsync a local **file or folder** to the remote before running. Folders sync *contents* with `--delete`; a single file is sent as-is. |
| `-e KEY=VALUE` / `--env KEY=VALUE` | Set an env var on the remote command. Repeatable. Secrets never appear in the remote `ps`. |
| `--env-file PATH` | Read `KEY=VALUE` lines from a local file (supports `#` comments and `export ` prefix). Repeatable. |
| `-- <command...>` | Command to run on the remote (joined; executed by the worker from a private script file). |

### Global options

| Option | Description |
|--------|-------------|
| `-p PORT` / `--port PORT` | SSH port (overrides `host:port` and ssh-config `Port`) |
| `-v` / `--verbose` | Print the decision trace (resolution, auth, deploy, reconnect) even on success; errors always carry it |
| `--json` | Emit one machine-readable result summary line on stderr (`run`/`script`/`plan`/`init`; local-only subcommands like `list`/`history` ignore it) |
| `--no-history` | Do not record this run in the local execution history (same as `REXEC_HISTORY=0`) |
| `--reveal-secrets` | Print secret values (env vars) instead of `***`; they are recorded locally either way |
| `-q` / `--quiet` | Suppress remaining warning/progress lines (errors are never suppressed) |

### `plan` — dry run (no execution, no deploy)

```bash
rexec <host> plan -- "<command>"
```

Connects, resolves the host, probes the remote platform and installed worker, then prints the resolution, deploy decision (`nothing — up-to-date` / `upload self` / `download <asset> from <url>`), the exact launch command and the script-file indirection note; exits 0. Use it to check what a run would do — including why a worker would be re-uploaded — without touching the remote state.


### `script` — sync and run a local script

```bash
rexec <host> script [--interpreter CMD] [--sync-to REMOTE_DIR] [-e K=V] [--env-file F] <local_script> [-- args...]
```

Syncs the script to `~/.rexec/scripts/` (or `--sync-to`), then runs it. Interpreter auto-detected: `#!` shebang runs directly; `.py` → `python3`; else `sh`. Override with `--interpreter`.

### `list` — show configured hosts

```bash
rexec list [alias]
```

Reads `~/.ssh/config` and prints each host's alias/hostname/port/user (pure-wildcard entries skipped). Pass an alias for single-host details.

### `history` — recorded runs

**Secrets**: env values are stored verbatim in the owner-only history tree but masked (`***`) in every printed surface — `history show`/`--meta`/`grep` match lines and the `-e`/env-file parse warnings. `--reveal-secrets` prints them. Command text is shown as-is, so pass secrets via `-e`/`--env-file` (which never appear in `ps`), not inline.

Every `run`/`script` is recorded locally (nothing leaves the machine):

```text
~/.rexec/history/index.jsonl           append-only, one JSON record per run
~/.rexec/history/runs/<id>/meta.json   the same record, pretty-printed
~/.rexec/history/runs/<id>/stdout.log  captured stdout (capped, head+tail)
~/.rexec/history/runs/<id>/stderr.log  captured stderr (capped, head+tail)
```

`<id>` is `<UTC timestamp>-<pid>`, e.g. `20260922T041533Z-921501`. stdout is pure data (pipe it); notes go to stderr.

```bash
rexec history list -n 5 --failed           # id, start, host, exit, duration_ms, command
rexec history show <id>                    # summary: header, command, env, trace, artifact paths
rexec history show <id> --stderr | tail -50  # raw bytes of one artifact only (--stdout/--stderr/--trace/--meta)
rexec history grep sk-live --output        # case-insensitive substring over command + env VALUES (+ captured output)
rexec history stats                        # runs, failures, per-host, p50/p95 duration, captured bytes, tree size
rexec history fetch <id> --out /tmp/worker.log  # FULL remote log, read-only over SSH (raw frame stream, not decoded)
rexec history prune --keep-days 7 --max-mb 500  # keep the tree small (the newest run is always kept)
rexec history path                         # where the tree lives
```

- Each stream is capped at **1 MiB**: head + tail kept, middle replaced by `… [N bytes omitted] …`. The record's `stdout_bytes`/`stderr_bytes` are the true totals.
- `--no-history` (one invocation) or `REXEC_HISTORY=0` (environment) disables recording; reading and pruning still work.
- **Commands and env VALUES are stored verbatim — no redaction, by product decision** (an `-e API_KEY=…` value is in `index.jsonl` in clear text). Owner-only tree: dirs 0700, files 0600. Use `--no-history` for runs whose arguments must not be persisted.


### Environment variables

Pass secrets or config without inline `export`/escaping pain:

```bash
rexec <host> run -e API_KEY=sk-xxx -e DEBUG=1 -- "python app.py"

# Or load many from a local file (KEY=VALUE per line):
rexec <host> run --env-file ./secrets.env -- "python app.py"
```

Env vars are sent to the remote over the SSH channel and applied to the command — they are **not** exposed in the remote process's command line (`ps`).

### Syncing files vs folders

```bash
# Folder: syncs directory contents (trailing slash optional on LOCAL)
rexec dev run --sync ./src:/opt/app/src -- "make build"

# Single file: send one script and run it
rexec dev run --sync ./deploy.sh:/opt/app/deploy.sh -- "bash /opt/app/deploy.sh"
```

- Folders use `rsync --delete`: remote files absent locally are removed — keep the remote path dedicated to your project.
- For a single file, the remote **parent directory must exist** (rsync does not create it).

## Tips

- **Long-running jobs: run rexec in the background.** rexec streams until the remote process exits, which may outlast a foreground shell's timeout (and get killed mid-stream). Launch long jobs with a background command — `&`, `nohup`, or your agent's background-task tool — so the remote worker isn't cut off. If interrupted, rexec prints the remote PID; the worker keeps running (see Disconnect behavior to resume).
- **Output not streaming?** When stdout is not a TTY (pipes, `cmd | tail`, docker build), programs block-buffer their output, so rexec shows nothing until they flush or exit. Avoid `| tail`/`| head`; stream the command directly, or force line buffering with `stdbuf -oL -eL <cmd>` / `PYTHONUNBUFFERED=1` (pass via `-e`).
- **Local edit → sync → remote run** is the recommended loop: edit locally, then `rexec <host> run --sync ./dir:/remote/dir -- "..."` pushes and executes in one step.
- **Output is silent on success — nothing to filter.** stdout/stderr hold only the command's own output (exceptions: the first-connect known-hosts notice and the non-zero-exit warning), so `rexec <host> run -- "..." | ...` needs no `grep -v`. Add `-v` for the decision trace, `--json` for a one-line machine-readable summary on stderr (never on stdout), and `-q` to also drop the remaining warning/progress lines. Failures never lose context: the error always carries the trace, and a non-zero remote exit prints a one-line warning with the remote log path.
- **`pkill -f`/`pgrep -f` won't match the worker or its shell by command text.** The command and env vars are sent over stdin, not argv, and the command runs from a private script file (`sh ~/.rexec/run/<pid>.sh`, mode 0600, deleted on exit) instead of `sh -c <cmd>` — no process in the chain exposes the command text in its cmdline, so the classic `sh -c "pkill -f foo"` self-kill cannot happen. Target processes still match `pkill -f` normally (their cmdlines are their own). Caveat: a pattern that matches the chain's fixed strings (`rexec`, `.sh`, `run/`) still hits — scope patterns to command content. Also note `$0` inside the command is now the script path, not `sh`.

## Disconnect behavior

- **SSH drops:** the remote worker keeps running and writing to a log; the CLI reconnects (backoff 1s→30s, up to 10 tries) and resumes output from the last byte — no data lost. (Linux/macOS remotes; Windows remotes are experimental and do not guarantee survival.) Reconnect progress lines are verbose-only (`-v`); a recovered run stays silent, and a failed reconnect reports the remote PID plus the decision trace.
- **CLI killed (Ctrl+C / SIGTERM):** prints the remote PID; the remote process continues. Re-attach later with `ssh <host> "~/.rexec/rexec attach --pid <PID> --offset 0"` (Linux/macOS remotes; on a Windows remote use the full `%USERPROFILE%\.rexec\rexec.exe` path under cmd).

## Prerequisites

- Local (macOS/Linux/Windows): `curl`, SSH keys (Windows locals: identity-file/default-key auth only — agent auth is unix-socket only). `rsync` too — on Windows get it from MSYS2 (`pacman -S rsync`) or WSL; without it `--sync`/folder sync are unavailable.
- Remote: Linux/macOS supported — `rsync`, `sh` (`rexec <host> init` verifies/installs). Remote Windows is experimental: it compiles, but is not live-verified and disconnect survival is not guaranteed; `--sync`/`script` cannot target a Windows remote.
- Windows locals: use MSYS2/WSL-style `--sync` paths (`/c/proj:/remote/dir`). A drive path (`C:\proj:...`) is rejected, because `LOCAL:REMOTE` splitting would read `C` as the host.
- Cross-platform (e.g. macOS local → Linux remote) works out of the box: the worker is downloaded from GitHub Releases (needs a released tag matching the rexec version; cached in `~/.rexec/cache/`). Same-platform pairs deploy the running binary directly.

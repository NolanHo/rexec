# rexec — Remote Code Execution + Folder Sync

A CLI to sync local files/folders and run commands on remote hosts over SSH, designed to survive SSH disconnections. The remote worker keeps running after SSH drops; the CLI auto-reconnects and resumes output from the last byte.

**Platforms**: local macOS/Linux/Windows → remote Linux/macOS supported, remote Windows **experimental** (it compiles, but is not live-verified and disconnect survival is not guaranteed there). When the two differ (e.g. macOS local → Linux remote), the worker binary for the remote is downloaded from GitHub Releases automatically — the remote needs no internet access. rsync-dependent features (`--sync`, folder sync) need an `rsync` from MSYS2 or WSL when the local side is Windows.

## Features

- **Folder/file sync**: rsync a local file or folder to the remote before running
- **Script run**: one-command sync + run a local script (`script` subcommand)
- **Host listing**: list SSH hosts from `~/.ssh/config` (`list` subcommand)
- **Disconnect resilience**: remote worker ignores SIGHUP and writes to a log; CLI reconnects with backoff and resumes from the last byte (Linux/macOS remotes; Windows remotes are experimental and do not guarantee disconnect survival)
- **Auto binary deploy**: deploys a version-matched worker to the remote on first use — uploads itself when platforms match, otherwise downloads the prebuilt worker from GitHub Releases (e.g. macOS local → Linux remote)
- **Secrets/command out of argv**: env vars and the command are sent over stdin and the command runs from a private script file — neither appears on any cmdline, so `pkill -f`/`pgrep -f` can't match them by command content (env vars are still visible in `/proc/<pid>/environ` to the same user)
- **SSH config**: resolves host aliases from `~/.ssh/config` (Include-expanded); `user@host:port` literals work everywhere (run **and** sync). An unknown alias is an error with near-miss suggestions — it is never silently treated as a raw hostname (use `user@host` for literal hosts)
- **Silent on success, full context on failure**: a successful run prints only the command's own stdout/stderr; `-v` adds the decision trace (resolution, auth, deploy, reconnect). Failures always print the error plus that trace in one shot, and a non-zero remote exit prints a one-line warning with the remote log path
- **Dry run**: `plan` shows resolution, platform, deploy decision and launch command without executing or deploying
- **Execution history**: every `run`/`script` that reaches the remote is recorded locally (`~/.rexec/history`) — command and env verbatim, output capped at 1 MiB per stream (head+tail), exit code/timing/decision trace — and queried with `rexec history list|show|grep|stats|fetch|prune`; `--no-history` or `REXEC_HISTORY=0` turns recording off. Failures before the worker is contacted (unknown alias, bad `--sync` path, malformed `-e`) are not recorded
- **Machine-readable**: `--json` emits one JSON summary line on stderr (stdout stays pure command output; `run`/`script`/`plan`/`init` only)
- **Quiet mode**: `-q` suppresses the remaining warning/progress lines (errors are never suppressed)

## Install

```bash
# From source
cargo build --release
cp target/release/remote-exec ~/.local/bin/rexec

# Or download a prebuilt binary (linux/macos/windows × amd64/arm64 — pick your platform)
curl -fL -o ~/.local/bin/rexec \
  https://github.com/Menghuan1918/rexec/releases/latest/download/rexec-macos-arm64
chmod +x ~/.local/bin/rexec

# Windows: same assets, named rexec.exe (no chmod step)
curl.exe -fL -o rexec.exe \
  https://github.com/Menghuan1918/rexec/releases/latest/download/rexec-windows-amd64
```

## Usage

```bash
# Check and install remote dependencies (run once per host)
rexec <host> init

# Sync a folder and run a command
rexec <host> run --sync local_dir:remote_dir -- "bash deploy.sh"

# Run a command without syncing
rexec <host> run -- "python train.py --epochs 100"

# ssh-config alias OR user@host:port — both work for run and --sync
rexec my-server run --sync ./project:/home/user/project -- "python main.py"
rexec root@192.168.1.100:2222 run --sync ./deploy.sh:/opt/deploy.sh -- "bash /opt/deploy.sh"

# Override the port (applies to both SSH and rsync)
rexec -p 2222 root@192.168.1.100 run -- "df -h"

# Sync + run a local script in one step (interpreter auto-detected)
rexec <host> script ./deploy.sh -- arg1 arg2
rexec <host> script --interpreter python3 ./train.py -- --epochs 10
rexec <host> script -e API_KEY=sk-xxx ./fetch.py

# List hosts from ~/.ssh/config
rexec list
rexec list my-server

# Inspect past runs (local record: command, env, output, exit, trace)
rexec history list -n 10
rexec history show 20260922T041533Z-921501
rexec history show 20260922T041533Z-921501 --stderr | tail -20

# Show what a run WOULD do — resolution, deploy decision, launch command —
# without executing the command and without deploying anything
rexec my-server plan -- "python train.py --epochs 100"

# Ask why: -v prints the decision trace (resolution, auth, deploy, reconnect)
rexec -v my-server run -- "df -h"

# Machine-readable summary on stderr (stdout stays pure command output)
rexec --json my-server run -- "uname -a"

# Suppress the remaining warnings/progress (errors are never suppressed)
rexec -q my-server run -- "echo only-this"
```

### Output contract

- **Success is silent.** In normal mode stdout/stderr carry the command's own output and nothing else — the one exception is the first-connect known-hosts notice (`⚠ Accepting new host key for …`, the same warning `ssh` prints) and the non-zero-exit warning below. `-v/--verbose` adds the decision trace (resolved target, auth attempts, platform/deploy decision, remote PID, reconnect events, timings).
- **Errors and warnings carry their full context in one shot.** A failure prints the error plus the decision trace — no need to re-run with `-v`. An unknown host alias fails with near-miss suggestions from the configured aliases (prefix/substring matches) and the hint to use `user@host` for a literal host. If the worker dies before it starts, the error includes the worker's own stderr and the launch command that was attempted.
- **A non-zero remote exit prints one warning line** to stderr: `⚠ remote exit <code> (log: ~/.rexec/logs/<pid>.log)`. Exit code 0 prints nothing. **rexec's own exit status mirrors the remote code** (like `ssh`), so `rexec … && next` and scripts checking `$?` see the failure; a signal-killed remote process (no real code, reported as `-1`) exits `255`. Caveat: when stdout is piped into a reader that exits early (`| head`), the process ends on SIGPIPE (141) before the remote code can be propagated.
- **`--json` emits exactly one JSON line on stderr, last** (after the trace/warning), with stable field order: `host`, `resolved`, `pid`, `exit_code`, `duration_ms`, `deployed`, `stdout_bytes`, `stderr_bytes`, `log_path` (always `null` for now — the warning line carries the remote log path), and `error` only on failure. stdout is never polluted.
- **`ProxyJump` is honoured, and the route is visible.** A jump chain from the ssh config (including chained jumps: `nebula99 → lyg2004 → js4`) is tunnelled with `direct-tcpip` channels — each hop authenticates on its own with its own `User`/`IdentityFile`, exactly like `ssh -J`. `plan` prints the route (`route: via 192.168.4.70:42200 → 10.30.40.4:22`) and `-v` traces every hop (`connect: jump 1/2 … connected in 167ms`). Jump sessions get keepalives so an idle tunnel is not reaped. `--sync` hands rsync the alias (or an explicit `-J` chain for literal targets) so the ssh rsync spawns takes the same route.
- **`ProxyCommand` is honored when it is a SOCKS5 proxy, and said out loud when it is not.** The recognizable shapes — `nc -X 5 -x HOST[:PORT] %h %p`, `nc -x HOST[:PORT] %h %p`, `ncat --proxy HOST[:PORT] --proxy-type socks5 %h %p`, `connect [-5] -S HOST[:PORT] %h %p` (port defaults to 1080) — are used as a real SOCKS5 CONNECT (no-auth only) for the first hop, and show up in the route (`route: via socks5 127.0.0.1:1080`) and the trace. Any other ProxyCommand (a `ssh -W` jump host — the warning points at `ProxyJump` instead — SOCKS4/HTTP proxies, `socat`'s ambiguous grammar, unknown flags) keeps the one-line warning naming the route actually used (`⚠ ssh config: proxycommand=… for <host> is not implemented; connecting directly to …`). Every other unsupported directive (`SendEnv`, `StrictHostKeyChecking`, `LocalForward`, …) stays silent.

### `plan` — dry run

```bash
rexec <host> plan -- "<command>"
```

Connects, resolves the host, probes the remote platform and the installed worker, then prints the resolution, the deploy decision (`nothing — up-to-date` / `upload self` / `download <asset> from <url>`), the exact launch command, and the script-file indirection note. It exits 0 **without executing the command and without deploying anything** — safe to run against production hosts.

### `run` options

| Option | Description |
|--------|-------------|
| `--sync LOCAL:REMOTE` | rsync a local **file or folder** to the remote before running. Folders sync contents with `--delete`; a single file is sent as-is. |
| `-e KEY=VALUE` / `--env KEY=VALUE` | Set an env var on the remote command. Repeatable. Not exposed in `ps`. |
| `--env-file PATH` | Read `KEY=VALUE` lines from a local file (supports `#` comments and `export ` prefix). Repeatable. |
| `-- <command...>` | Command to run on the remote (joined; executed by the worker from a private script file). |

On Windows the local side of `--sync` must be an MSYS2/WSL-style path (`/c/proj`), not a drive path: `C:\proj:/remote/dir` is rejected, since `LOCAL:REMOTE` splitting would read `C` as a host. `--sync` and the `script` subcommand (both rsync-based) work with Linux/macOS remotes only — they cannot target a Windows remote.

### Global options

| Option | Description |
|--------|-------------|
| `-p PORT` / `--port PORT` | SSH port (overrides `host:port` and ssh-config `Port`) |
| `-v` / `--verbose` | Print the decision trace (resolution, auth, deploy, reconnect, timings) even on success. Errors always carry it |
| `--json` | Emit one machine-readable result summary line on stderr (see Output contract). Applies to `run`/`script`/`plan`/`init`; `list` emits its own host array; `history …` ignores it |
| `--no-history` | Do not record this run in the local execution history (same as `REXEC_HISTORY=0`); reading `rexec history …` still works |
| `--socks5 HOST:PORT` | Route the first hop through this SOCKS5 proxy (no-auth). Overrides ssh-config `ProxyCommand`; also settable via `REXEC_SOCKS5`. With `ProxyJump`, the proxy covers the first jump leg |
| `--reveal-secrets` | Print secret values (env vars) instead of `***` in output. Values are **recorded** locally either way; without this flag every printed surface masks them |
| `-q` / `--quiet` | Suppress the remaining warning/progress lines. Errors are never suppressed |

Run/plan/sync/script usage is unchanged otherwise: `rexec [-p PORT] [-v] [--json] [--no-history] [--reveal-secrets] [--socks5 HOST:PORT] <alias|user@host:port> <subcommand> ...`.

### `script` — sync and run a local script

```bash
rexec <host> script [--interpreter CMD] [--sync-to REMOTE_DIR] [-e K=V] [--env-file F] <local_script> [-- args...]
```

Syncs the script to `~/.rexec/scripts/` (or `--sync-to`), then runs it. The interpreter is auto-detected: a `#!` shebang runs the script directly; otherwise `.py` → `python3`, else `sh`. Override with `--interpreter`. Args after `--` are passed to the script.

### `list` — show configured hosts

```bash
rexec list [alias]
```

Reads `~/.ssh/config` (Include-expanded) and prints the host inventory. The default table is `ALIAS  HOST:PORT  DESCRIPTION`: the port is part of *which machine* this is (one gateway address carries a different forwarded port per machine, so a bare hostname identifies nothing), which is why it sits next to the hostname rather than behind a flag. `--long` adds user/identity, and passing an alias prints the resolved details for that one host.

```bash
rexec list                      # alias, host:port, description
rexec list --long               # + user, identity
rexec list my-server            # resolved details for one alias
rexec list --filter prod        # substring over alias/host:port/user/description
rexec list -f 'web*' -f staging # repeatable; every pattern must match (globs hit alias/hostname/host:port)
rexec list -f 26001             # the port is visible in the table, so it is searchable
rexec list --user root --port 2222
rexec list --json               # machine-readable array
```

- **Descriptions** come from either place (the sidecar wins when both exist):
  - a `# rexec: <text>` comment line directly above a `Host` line in the ssh config — including `Include`d files, since the config is read through the Include-expanding loader; it attaches to every concrete pattern on that line;
  - `~/.rexec/hosts.conf`, one `alias = description` per line (`#` comments allowed) — for annotating aliases without editing their config. It only *annotates* hosts that exist in the ssh config; it never defines a host.
- **Filtering**: `--filter/-f PATTERN` is a case-insensitive substring over alias, `host:port`, user and description; with `*`/`?` it is a glob over alias, hostname and `host:port` instead. Repeatable (all must match), and `--user`/`--port` are exact field filters. An empty result prints a note on stderr and exits 0.
- Pure-wildcard entries (`Host *`) are skipped: there is no alias to run.

### `history` — recorded runs

Every `run` and `script` execution is recorded locally — nothing is sent anywhere:

```text
~/.rexec/history/index.jsonl              append-only, one JSON record per run (the query surface)
~/.rexec/history/runs/<id>/meta.json      the same record, pretty-printed
~/.rexec/history/runs/<id>/stdout.log     captured stdout (capped)
~/.rexec/history/runs/<id>/stderr.log     captured stderr (capped)
```

`<id>` is `<UTC timestamp>-<pid>`, e.g. `20260922T041533Z-921501`. stdout carries pure data (tables, raw artifacts) so it can be piped; notes and warnings go to stderr.

| Command | What it does |
|---------|--------------|
| `rexec history list [-n N] [--host H] [--failed]` | table of recent runs, newest first: id, start, host, exit code (`-` when never observed), duration_ms, command |
| `rexec history show <id>` | human summary: header fields, command, env, decision trace, artifact paths |
| `rexec history show <id> --stdout` / `--stderr` | ONLY that artifact's raw bytes (pipe-friendly; an empty capture prints nothing); a missing capture file prints a note on stderr and still exits 0 |
| `rexec history show <id> --trace` / `--meta` | the decision trace, one line per entry / the raw stored JSON record line |
| `rexec history grep <pattern> [-n N] [--host H] [--failed] [--output]` | case-insensitive plain substring (no regex) over command + env values, one line per match prefixed by run id; `--output` also searches the captured stdout/stderr |
| `rexec history stats [--host H]` | runs, failures, per-host counts, duration p50/p95, captured bytes, on-disk tree size |
| `rexec history path` | print the history root |
| `rexec history prune [--keep-days N] [--max-mb N]` | delete run directories older than N days (default 30, by directory mtime), then the oldest runs until the tree fits the size cap; the newest run is never evicted by either phase |
| `rexec history fetch <id> [--out P]` | pull the FULL remote worker log (`~/.rexec/logs/<pid>.log`) over SSH — read-only (one `cat` after a read-only platform probe, no deploy, no writes on the remote) |

```bash
rexec history list -n 5 --failed          # the last 5 failures
rexec history grep 'python train.py'      # runs whose command contains this text
rexec history grep sk-live --output       # env VALUES too (keys are not searched), plus captured output
rexec history show 20260922T041533Z-921501 --stderr | tail -50
rexec history fetch 20260922T041533Z-921501 --out /tmp/worker.log
rexec history prune --keep-days 7 --max-mb 500
```

- **Capture cap**: each stream is capped at 1 MiB — the head and the tail are kept and the middle is replaced by a `… [N bytes omitted] …` marker, so one chatty run cannot fill the disk while its start and its failure stay readable. `stdout_bytes`/`stderr_bytes` in the record are the true byte totals even when the capture was capped: `show` marks a truncated stream and `stats` sums the true totals.
- **Switches**: `--no-history` disables recording for one invocation; `REXEC_HISTORY=0` disables it for the whole environment. Both leave reading (`rexec history …`) and pruning fully working.
- **Secrets: recorded locally, never printed by default.** Env values (from `-e/--env`/`--env-file`) and the command text are stored VERBATIM in the owner-only history tree (`~/.rexec/history` 0700, files 0600, nothing leaves the machine) — that is deliberate, so a past run can be analyzed. Every surface rexec PRINTS masks env values as `***` (the `history` views, `--meta`, `history grep` match lines, and the `-e`/env-file parse warnings, which would otherwise echo the value that failed to parse) so a key cannot reach terminal scrollback, CI logs or an agent transcript just because rexec ran; `--reveal-secrets` opts into the plaintext. Caveats: the command TEXT is shown as-is (put secrets in `-e`/`--env-file` rather than inline), and a captured stream (`history show --stdout/--stderr`) is the remote command's own output — rexec cannot know which bytes of it are secret. Use `--no-history` / `REXEC_HISTORY=0` for a run whose arguments or output must not be persisted at all.
- **`fetch` prints the worker's raw binary frame stream** (the same bytes the CLI decodes live) — it is not decoded output; `show --stdout/--stderr` is the decoded capture. A missing pid (the worker never started) or a Windows remote fails with a clear message instead of guessing a path.

## How it works

1. If `--sync` is given, runs `rsync -az [--delete] -e "ssh [-p PORT] ..."` to sync the local file/folder to the remote. The port from `host:port` or `--port` is passed to rsync via `ssh -p` (so `user@host:port` works for sync too).
2. Connects via russh (pure Rust SSH), authenticates via agent → identity-file → default keys (Windows locals: identity-file/default keys only — russh's agent client speaks the unix socket protocol).
3. Ensures `~/.rexec/rexec` exists on the remote and matches the local version. If the remote platform matches the local one, it uploads the running binary via rsync; otherwise it downloads the version-pinned worker from GitHub Releases (cached in `~/.rexec/cache/`, so each version/target is downloaded once) and rsyncs that over.
4. Starts `~/.rexec/rexec worker` over the SSH channel. The **command and env vars are sent over stdin** (not argv), so neither appears in the remote worker's `ps`/`pkill -f`/`pgrep -f` output.
5. The worker ignores SIGHUP, writes the command to a private script (`~/.rexec/run/<pid>.sh`, mode 0600, removed on exit; stale ones swept on startup), spawns `sh <script>`, and streams stdout/stderr back via a binary frame protocol — writing every frame to `~/.rexec/logs/<pid>.log` and to the SSH channel. The script-file indirection keeps command text out of every process's cmdline, so `sh -c "pkill -f foo"`-style self-kills cannot happen.
6. On SSH disconnect: the worker keeps running; the CLI reconnects with exponential backoff (1s→30s, max 10) and resumes from the last byte offset via `~/.rexec/rexec attach --pid <PID> --offset <N>`.
7. On process completion: exit code 0 is silent (the log file is removed); a non-zero exit prints the one-line warning with the remote log path. `-v` additionally reports the resolved target, remote PID, deploy decision and timings.

## SSH Disconnection Behavior

- Remote process **continues running** (worker ignores SIGHUP — not killed when SSH drops)
- Local CLI **auto-reconnects** with exponential backoff (1s→30s, max 10)
- Output **resumes from the last byte offset** — no data lost
- If reconnection fails after 10 retries, prints the remote PID and exits
- The log file persists at `~/.rexec/logs/<pid>.log` on the remote (cleaned up on exit code 0)
- Re-attach manually: `ssh <host> "~/.rexec/rexec attach --pid <PID> --offset 0"`

## `init` Command

Checks that `rsync` and `sh` exist on the remote host. If `rsync` is missing, auto-detects the package manager (`apt-get`/`yum`/`dnf`/`apk`/`pacman`) and installs it. (`nohup` is not required — the worker handles disconnect survival via SIGHUP.)

```bash
rexec my-server init
```

## Build

```bash
cargo build --release
# Binary at target/release/remote-exec
```

### Releasing

Push a tag to trigger both release workflows: `.github/workflows/release.yml` builds native binaries for linux/macos/windows × amd64/arm64 and attaches them to a GitHub Release, while `.github/workflows/publish.yml` publishes the crate to [crates.io](https://crates.io/crates/remote-exec) via trusted publishing (OIDC token exchange, no API token stored as a secret). A tag can also be published manually: `gh workflow run publish.yml -f tag=v0.4.1`.

```bash
git tag v0.4.1 && git push origin v0.4.1
```

Cross-platform deploys (e.g. macOS local → Linux remote) download these release assets pinned to the running version, so a version must be released before it can deploy a mismatched remote platform.

## Dependencies

- `russh` — pure Rust SSH client
- `ssh2-config` — parse ~/.ssh/config
- `clap` — CLI parsing
- `tokio` — async runtime
- `anyhow` — error handling
- `dirs`, `libc`, `rsa`, `russh-keys`, `rand`
- `rsync` (system) — required for sync (local + remote; on Windows install it via MSYS2 or WSL)
- `curl` (system) — required locally, to download cross-platform workers from GitHub Releases
- `sh` (system) — required on a Linux/macOS remote

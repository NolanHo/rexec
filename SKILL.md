---
name: rexec
description: "Remote code execution + folder sync over SSH. Use when the user wants to run commands on a remote server, sync local folders to remote, or execute scripts remotely with SSH disconnect resilience. Activates on keywords: rexec, remote exec, remote sync, sync and run."
---

# rexec — Remote Code Execution + Folder Sync

A CLI tool to sync local folders and execute commands on remote hosts over SSH. Commands survive SSH disconnections via `nohup` wrapping, with auto-reconnect and log streaming.

## Binary

```
rexec  (installed at ~/.local/bin/rexec)
```

Source: `~/Code/remote-exec`

## Quick Start

```bash
# 1. First time on a new host: check remote dependencies (rsync, sh, nohup)
rexec <host> init

# 2. Sync folder + run command (one-liner)
rexec <host> run --sync ./project:/home/user/project -- "python main.py"

# 3. Run command only (no sync)
rexec <host> run -- "bash deploy.sh"

# 4. Use with ssh config alias
rexec my-server run --sync ./src:/opt/app/src -- "cd /opt/app && make build"
```

## Commands

### `init` — Check and install remote dependencies

```bash
rexec <host> init
```

Checks if `rsync`, `sh`, `nohup` exist on the remote. If missing, auto-detects the package manager (`apt-get`/`yum`/`dnf`/`apk`/`pacman`) and installs them. Run this once before first use on a new host.

Example output (all deps present):
```
Checking remote dependencies...

=== Checking dependencies ===
✓ rsync: /usr/bin/rsync
✓ sh: /usr/bin/sh
✓ nohup: /usr/bin/nohup
=== Detecting package manager ===
pm:apt-get

✓ All dependencies satisfied.
```

If deps are missing, it will auto-install via the detected package manager and verify after installation.

### `run` — Execute a command on the remote host

```bash
rexec <host> run [--sync LOCAL:REMOTE] -- <command...>
```

Options:
- `--sync LOCAL:REMOTE` — rsync a local **directory** to remote before executing. Example: `--sync ./code:/opt/app/code`
  - ⚠ `--sync` only accepts directories, not individual files. To sync a single script, put it in a directory and sync that directory.
  - Both local and remote paths are normalized to end with `/` so rsync syncs directory contents (not the directory itself).
- Trailing arguments after `--` are joined and passed to `sh -c` on the remote

Example output:
```
✓ Synced /tmp/rexec_test_dir -> ali:/tmp/rexec_test_dir/
Remote PID: 84450 | Log: /tmp/rexec_815090_1905907165.log
hello from ali
✓ Remote process exited
```

## Best Practices — Local Edit → Sync → Remote Execute

When doing remote development, testing, or deployment, **always prefer editing code locally first, then syncing to the remote and executing there**. Local editing is more convenient and leverages your local toolchain (IDE, version control, linting).

### The Workflow

1. **Edit locally** — modify scripts, code, or config files in your local workspace
2. **Sync + run** — use `rexec <host> run --sync LOCAL_DIR:REMOTE_DIR -- "command"` to push changes and execute in one step

### Examples

```bash
# Edit code locally, then sync + run tests on remote
rexec dev-server run --sync ./project:/home/dev/project -- "cd /home/dev/project && python -m pytest"

# Edit deploy script locally, then sync + execute on production
rexec prod run --sync ./scripts:/opt/deploy -- "bash /opt/deploy/deploy.sh --env production"

# Edit config locally, then sync + restart service
rexec prod run --sync ./config:/opt/app/config -- "systemctl restart myapp"

# Iterative development: edit → sync → test → repeat
rexec dev run --sync ./src:/workspace/src -- "cd /workspace && cargo test"
```

### Key Rules

- **`--sync` only accepts directories**, not individual files. Put a single script in a directory and sync that directory.
- **`--sync` uses `rsync --delete`** — files on the remote that don't exist locally will be removed. Make sure the remote path is dedicated to your project.
- **One-liner workflow**: `rexec run --sync` combines sync and execution, so you can iterate quickly without separate scp/rsync commands.
- **Long-running jobs**: even if SSH drops, the remote process continues (nohup). CLI auto-reconnects and resumes log streaming.

## How It Works

1. **Sync** (if `--sync` given): runs `rsync -az --delete -e ssh LOCAL/ HOST:REMOTE/`
2. **Connect**: establishes SSH via russh (pure Rust, no libssh2), authenticates via agent → identity file → default keys
3. **Execute**: wraps command in `nohup sh -c '...' > /tmp/rexec_<local_pid>_<rand>.log 2>&1 &`
4. **Follow**: polls the remote log file, streaming new content to local stdout
5. **Reconnect**: on SSH disconnect, exponential backoff (1s→30s, max 10 retries), resumes from last byte offset
6. **Complete**: detects process exit via `kill -0 <pid>`, prints final output

## Interruption & Disconnection Behavior

### Local rexec killed (SIGINT / SIGTERM / Ctrl+C)

When rexec receives SIGINT or SIGTERM, it prints the remote PID and log file path before exiting:

```
line 1 at 17:11:41
line 2 at 17:11:42
line 3 at 17:11:43

⚠ Interrupted by signal. Remote process still running.
  PID: 84450  Log: /tmp/rexec_815090_1905907165.log
```

The remote process **continues running** — it is not affected by the local rexec being killed. To check on it later:

```bash
ssh <host> "ps -p 84450 && tail -f /tmp/rexec_815090_1905907165.log"
```

### SSH connection drops

- Remote process **continues running** via `nohup` (not killed when SSH drops)
- Local CLI **auto-reconnects** with exponential backoff (1s→2s→...→30s, max 10 retries)
- Log output **resumes from last byte offset** — no data lost
- If reconnection fails after 10 retries, prints remote log file path and exits
- The log file persists at `/tmp/rexec_<local_pid>_<rand>.log` on the remote

```
⚠ Connection lost: <error>. Remote process still running.
  PID: 84450  Log: /tmp/rexec_815090_1905907165.log
  Retry 1/10 in 1s...
✓ Reconnected. Resuming log follow...
```

## Host Specification

Supports both `~/.ssh/config` aliases and direct `user@host:port` format:

```bash
# Uses ~/.ssh/config alias (resolves HostName, Port, User, IdentityFile)
rexec prod run -- "systemctl status nginx"

# Direct connection
rexec root@192.168.1.100:2222 run -- "df -h"
```

## Typical Workflows

### Local development → remote execution

```bash
# Edit code locally, sync and run on remote
rexec dev-server run --sync ./project:/home/dev/project -- "cd /home/dev/project && python -m pytest"
```

### Deploy script

```bash
# Put deploy.sh in a directory (sync only accepts dirs)
rexec prod run --sync ./scripts:/opt/deploy -- "bash /opt/deploy/deploy.sh --env production"
```

### Long-running training job

```bash
rexec gpu-01 run --sync ./training:/workspace/training -- "cd /workspace/training && python train.py --epochs 100"
# If SSH drops, process continues. CLI retries and shows output when reconnected.
# If CLI is killed, it prints the remote PID and log path. Resume with:
#   ssh gpu-01 "tail -f /tmp/rexec_<pid>_<rand>.log"
```

### Verify a host is ready

```bash
rexec my-server init
# Checks rsync/sh/nohup, installs if missing, verifies after install
```

## Prerequisites

- **Local**: `rsync` installed, `ssh` agent or keys configured
- **Remote**: `rsync`, `sh`, `nohup` (run `rexec <host> init` to verify/install)
- **SSH config**: host alias in `~/.ssh/config` or direct `user@host:port`

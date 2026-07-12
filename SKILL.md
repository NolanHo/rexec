---
name: rexec
description: "Remote code execution + folder sync over SSH. Use when the user wants to run commands on a remote server, sync local folders to remote, or execute scripts remotely with SSH disconnect resilience. Activates on keywords: rexec, remote exec, remote sync, sync and run."
---

# rexec — Remote Code Execution + Folder Sync

A CLI tool to sync local folders and execute commands on remote hosts over SSH. Commands survive SSH disconnections via a peer-architecture worker binary, with auto-reconnect and frame-based log streaming.

## Binary

```
rexec  (installed at ~/.local/bin/rexec)
```

Source: `/root/code/rexec`

## Quick Start

```bash
# 1. First time on a new host: check remote dependencies (rsync, sh)
rexec <host> init

# 2. Sync folder + run command (one-liner)
rexec <host> run --sync ./project:/home/user/project -- "python main.py"

# 3. Run command only (no sync)
rexec <host> run -- "bash deploy.sh"

# 4. Use with ssh config alias
rexec my-server run --sync ./src:/opt/app/src -- "cd /opt/app && make build"
```

## Architecture

rexec uses a **peer-architecture** design: the same `rexec` binary runs on both local and remote hosts.

```
Local rexec ──SSH Channel──→ ~/.rexec/rexec worker -- "cmd"
                   ↑                    │
                   │  binary frames      ├── spawn child process (sh -c "cmd")
                   │  (stdout/stderr)   ├── write ~/.rexec/logs/<pid>.log (always)
                   │                    └── stream frames via SSH channel (when connected)
                   │
            on disconnect:
                   ↓
Local rexec ──SSH Channel──→ ~/.rexec/rexec attach --pid <pid> --offset <n>
                                │
                                ├── replay log from offset (missed data)
                                └── tail log for live output
```

Key design decisions:
- **No `nohup`**: the rexec worker ignores SIGHUP and manages the child process directly
- **No `dd`/`stat` polling**: output is streamed via binary frames over the SSH channel
- **Log file as source of truth**: the worker always writes to `~/.rexec/logs/<pid>.log` first, then tries to send via SSH channel. If the channel is disconnected, the log file still has all data.
- **Binary frame protocol**: `[1 byte type][4 bytes BE length][payload]` — efficient, no parsing overhead

## Commands

### `init` — Check and install remote dependencies

```bash
rexec <host> init
```

Checks if `rsync`, `sh`, `nohup` exist on the remote. If missing, auto-detects the package manager (`apt-get`/`yum`/`dnf`/`apk`/`pacman`) and installs them. Run this once before first use on a new host.

### `run` — Execute a command on the remote host

```bash
rexec <host> run [--sync LOCAL:REMOTE] -- <command...>
```

Options:
- `--sync LOCAL:REMOTE` — rsync a local **directory** to remote before executing. Example: `--sync ./code:/opt/app/code`
  - ⚠ `--sync` only accepts directories, not individual files. To sync a single script, put it in a directory and sync that directory.
  - Both local and remote paths are normalized to end with `/` so rsync syncs directory contents (not the directory itself).
- Trailing arguments after `--` are joined and passed to `sh -c` on the remote

What happens on `run`:
1. If `--sync` given: runs `rsync -az --delete -e ssh LOCAL/ HOST:REMOTE/`
2. SSH connect (russh, pure Rust)
3. Auto-deploys rexec binary to `~/.rexec/rexec` on remote (version-checked, only uploads if missing/outdated)
4. SSH exec: `~/.rexec/rexec worker -- "command"`
5. Reads binary frames from the SSH channel, writes to local stdout/stderr
6. On disconnect: reconnects and runs `~/.rexec/rexec attach --pid <pid> --offset <n>` to resume

### `worker` / `attach` — Internal subcommands (not user-facing)

These run on the remote host via SSH exec:
- `rexec worker -- "cmd"` — spawns child process, writes log + streams output via frames
- `rexec attach --pid <pid> --offset <n>` — replays log from offset, then tails live

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
- **Long-running jobs**: even if SSH drops, the remote worker continues running. CLI auto-reconnects and resumes output streaming.

## How It Works

1. **Sync** (if `--sync` given): runs `rsync -az --delete -e ssh LOCAL/ HOST:REMOTE/`
2. **Connect**: establishes SSH via russh (pure Rust), authenticates via agent → identity file → default keys
3. **Deploy**: checks `~/.rexec/rexec --version` on remote; if missing or outdated, uploads the local binary via SSH channel (`cat > ~/.rexec/rexec`)
4. **Execute**: SSH exec `~/.rexec/rexec worker -- "command"` — the worker spawns `sh -c "cmd"`, writes output to log file + streams frames via SSH channel
5. **Stream**: local rexec reads binary frames from the SSH channel, writes to local stdout/stderr
6. **Reconnect**: on SSH disconnect, exponential backoff (1s→30s, max 10 retries), then runs `~/.rexec/rexec attach --pid <pid> --offset <n>` to replay missed log data and resume live streaming
7. **Complete**: receives `EXITED` frame with exit code, prints result

## Interruption & Disconnection Behavior

### Local rexec killed (SIGINT / SIGTERM / Ctrl+C)

When rexec receives SIGINT or SIGTERM, it prints the remote PID before exiting:

```
line 1 at 17:11:41
line 2 at 17:11:42
line 3 at 17:11:43

⚠ Interrupted by signal. Remote process still running.
  PID: 84450
```

The remote worker **continues running** — it ignores SIGHUP and manages the child process independently. To check on it later:

```bash
ssh <host> "ps -p 84450"
# Or re-attach manually:
ssh <host> "~/.rexec/rexec attach --pid 84450 --offset 0"
```

### SSH connection drops

- Remote worker **continues running** — it ignores SIGHUP, keeps writing to `~/.rexec/logs/<pid>.log`
- Local CLI **auto-reconnects** with exponential backoff (1s→2s→...→30s, max 10 retries)
- Output **resumes from last byte offset** — no data lost
- If reconnection fails after 10 retries, prints remote PID and exits

```
⚠ Connection lost. Remote process still running.
  PID: 84450
  Retry 1/10 in 1s...
✓ Reconnected. Resuming...
```

## Remote File Layout

```
~/.rexec/
├── rexec              # rexec binary (auto-deployed, version-checked)
└── logs/
    └── <pid>.log      # frame-encoded output log (binary, not plain text)
```

The log file uses the same binary frame format as the SSH channel — `attach` reads it and forwards raw frames, no re-encoding needed.

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
rexec dev-server run --sync ./project:/home/dev/project -- "cd /home/dev/project && python -m pytest"
```

### Long-running training job

```bash
rexec gpu-01 run --sync ./training:/workspace/training -- "cd /workspace/training && python train.py --epochs 100"
# If SSH drops, the worker continues. CLI retries and resumes output.
# If CLI is killed, it prints the remote PID. Resume with:
#   ssh gpu-01 "~/.rexec/rexec attach --pid <pid> --offset 0"
```

### Verify a host is ready

```bash
rexec my-server init
# Checks rsync/sh/nohup, installs if missing, verifies after install
```

## Prerequisites

- **Local**: `rsync` installed, `ssh` agent or keys configured
- **Remote**: `rsync`, `sh` (run `rexec <host> init` to verify/install)
- **SSH config**: host alias in `~/.ssh/config` or direct `user@host:port`

# rexec — Remote Code Execution + Folder Sync

A simple CLI tool to sync local folders and execute commands on remote hosts over SSH, designed to survive SSH disconnections.

## Features

- **Folder sync**: rsync local directory to remote before execution
- **Remote execution**: commands run via `nohup`, surviving SSH disconnects
- **Log following**: streams remote output back to local terminal with offset tracking
- **Auto-reconnect**: exponential backoff reconnection on SSH disconnect
- **Dependency check**: `init` command checks and auto-installs remote deps
- **SSH config**: resolves host aliases from `~/.ssh/config`
- **Authentication**: SSH agent → identity file → default keys

## Install

```bash
cargo build --release
cp target/release/rexec ~/.local/bin/
```

## Usage

```bash
# Check and install remote dependencies (run once per host)
rexec <host> init

# Sync a folder and run a command
rexec <host> run --sync local_dir:remote_dir -- "bash deploy.sh"

# Run a command without syncing
rexec <host> run -- "python train.py --epochs 100"

# Use with ssh config alias
rexec my-server run --sync ./project:/home/user/project -- "cd /home/user/project && python main.py"

# Direct user@host:port
rexec root@192.168.1.100:22 run -- "df -h"
```

## How it works

1. If `--sync` is given, runs `rsync -az --delete -e ssh` to sync the local folder to remote
2. Connects via russh (pure Rust SSH), authenticates via agent/keys
3. Wraps the command in `nohup sh -c '...' > /tmp/rexec_<pid>_<rand>.log 2>&1 &`
4. Polls the remote log file, streaming new content to local stdout
5. On SSH disconnect: exponential backoff retry (1s→30s, max 10), resumes from last offset
6. On process completion: prints exit status

## SSH Disconnection Behavior

- Remote process **continues running** via `nohup` (not killed when SSH drops)
- Local CLI **auto-reconnects** with exponential backoff
- Log output **resumes from last byte offset** — no data lost
- If reconnection fails after 10 retries, prints remote log file path and exits
- The log file persists at `/tmp/rexec_<pid>_<rand>.log` on the remote

## `init` Command

Checks if `rsync`, `sh`, `nohup` exist on the remote host. If missing, auto-detects the package manager (`apt-get`/`yum`/`dnf`/`apk`/`pacman`) and installs them.

```bash
rexec my-server init
```

## Build

```bash
cargo build --release
# Binary at target/release/rexec
```

## Dependencies

- `russh` — pure Rust SSH client
- `ssh2-config` — parse ~/.ssh/config
- `rsync` (system) — required for folder sync (local + remote)

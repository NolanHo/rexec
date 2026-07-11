use std::io::BufReader;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use ssh2_config::{ParseRule, SshConfig};

mod ssh;

#[derive(Parser)]
#[command(name = "rexec", about = "Remote code execution + folder sync over SSH")]
struct Cli {
    /// SSH host alias (resolved via ~/.ssh/config) or user@host:port
    host: String,

    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Check remote dependencies (rsync, sh, nohup) and install if missing
    Init,

    /// Execute a command on the remote host
    Run {
        /// Sync a local folder to a remote folder before executing
        #[arg(long, value_name = "LOCAL:REMOTE")]
        sync: Option<String>,

        /// Command to execute on the remote host (passed to sh -c)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

#[derive(Clone)]
pub struct RemoteHost {
    pub hostname: String,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub identity_file: Option<PathBuf>,
}

fn parse_sync_arg(arg: &str) -> Result<(PathBuf, String)> {
    let (local, remote) = arg
        .split_once(':')
        .ok_or_else(|| anyhow!("--sync must be LOCAL:REMOTE, got '{}'", arg))?;
    if local.is_empty() || remote.is_empty() {
        return Err(anyhow!("--sync LOCAL and REMOTE must both be non-empty"));
    }
    Ok((PathBuf::from(local), remote.to_string()))
}

fn resolve_host(host: &str) -> Result<RemoteHost> {
    // If host looks like user@host:port, parse directly
    if host.contains('@') || (host.contains(':') && !host.chars().next().unwrap().is_alphabetic()) {
        return parse_user_host_port(host);
    }

    // Otherwise resolve via ~/.ssh/config
    let ssh_config_path = dirs::home_dir()
        .context("cannot determine home directory")?
        .join(".ssh/config");

    if !ssh_config_path.exists() {
        return Ok(RemoteHost {
            hostname: host.to_string(),
            port: None,
            user: None,
            identity_file: None,
        });
    }

    let config_str = std::fs::read_to_string(&ssh_config_path)
        .with_context(|| format!("reading {}", ssh_config_path.display()))?;
    let mut reader = BufReader::new(config_str.as_bytes());
    let config = SshConfig::default().parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)?;

    let host_config = config.query(host);

    Ok(RemoteHost {
        hostname: host_config.host_name.clone().unwrap_or_else(|| host.to_string()),
        port: host_config.port,
        user: host_config.user.clone(),
        identity_file: host_config
            .identity_file
            .as_ref()
            .and_then(|v| v.first().cloned()),
    })
}

fn parse_user_host_port(s: &str) -> Result<RemoteHost> {
    let (user, rest) = if let Some((u, r)) = s.split_once('@') {
        (Some(u.to_string()), r)
    } else {
        (None, s)
    };

    let (hostname, port) = if let Some((h, p)) = rest.rsplit_once(':') {
        (h.to_string(), Some(p.parse::<u16>()?))
    } else {
        (rest.to_string(), None)
    };

    Ok(RemoteHost {
        hostname,
        port,
        user,
        identity_file: None,
    })
}

async fn do_sync(local: &PathBuf, remote: &str, host: &str) -> Result<()> {
    if !local.is_dir() {
        return Err(anyhow!("local sync path '{}' is not a directory", local.display()));
    }

    let local_str = local.to_string_lossy();
    let local_arg = if local_str.ends_with('/') {
        local_str.into_owned()
    } else {
        format!("{}/", local_str)
    };

    let remote_arg = if remote.ends_with('/') {
        remote.to_string()
    } else {
        format!("{}/", remote)
    };

    // SSH options to prevent hanging:
    //   BatchMode=yes         — never prompt for password (fail instead)
    //   ConnectTimeout=10     — fail if can't connect in 10s
    //   StrictHostKeyChecking=accept-new — accept new host keys, reject changed ones
    //   ServerAliveInterval=5 — send keepalive every 5s
    //   ServerAliveCountMax=3 — give up after 3 missed keepalives (15s total)
    let ssh_opts = "-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=5 -o ServerAliveCountMax=3";

    let mut child = tokio::process::Command::new("rsync")
        .args([
            "-az", "--delete",
            "-e", &format!("ssh {}", ssh_opts),
            &local_arg,
            &format!("{}:{}", host, remote_arg),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .context("failed to spawn rsync")?;

    // Wait with timeout — rsync can hang indefinitely on network issues
    let timeout = Duration::from_secs(300); // 5 minutes
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
            // Timeout reached — kill the rsync process
            let _ = child.kill().await;
            return Err(anyhow!(
                "rsync timed out after {} seconds. \
                 Use `rsync -az --delete -e ssh {}:{}` manually to diagnose.",
                timeout.as_secs(),
                host, remote_arg
            ));
        }
    }

    println!("✓ Synced {} -> {}:{}", local.display(), host, remote_arg);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let remote = resolve_host(&cli.host)?;

    match cli.action {
        Action::Init => {
            let mut session = ssh::connect(&remote).await?;
            ssh::check_and_install_deps(&mut session).await?;
        }
        Action::Run { sync, command } => {
            if command.is_empty() {
                return Err(anyhow!("no command provided. Usage: rexec <host> run [--sync LOCAL:REMOTE] -- <command...>"));
            }

            // If --sync is given, perform rsync first
            if let Some(sync_arg) = &sync {
                let (local, remote_path) = parse_sync_arg(sync_arg)?;
                do_sync(&local, &remote_path, &cli.host).await?;
            }

            let command = command.join(" ");
            let mut session = ssh::connect(&remote).await?;
            ssh::run_and_follow(&mut session, &remote, &command).await?;
        }
    }

    Ok(())
}

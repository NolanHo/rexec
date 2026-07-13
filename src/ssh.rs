use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use russh::client;
use russh::keys::PrivateKeyWithHashAlg;
use russh::keys::PrivateKey;
use russh::{ChannelMsg, client::AuthResult};

use crate::RemoteHost;

/// Attempt to load a private key from a path.
fn load_private_key(path: &Path) -> Result<PrivateKey> {
    PrivateKey::from_openssh(&std::fs::read_to_string(path)?)
        .with_context(|| format!("loading private key from {}", path.display()))
}

/// Try to authenticate using SSH agent first, then fall back to identity files.
async fn authenticate(
    session: &mut client::Handle<ClientHandler>,
    remote: &RemoteHost,
) -> Result<()> {
    let user = remote
        .user
        .clone()
        .unwrap_or_else(|| std::env::var("USER").unwrap_or_else(|_| "root".to_string()));

    // 1. Try SSH agent
    if try_agent_auth(session, &user).await.is_ok() {
        return Ok(());
    }

    // 2. Try identity file from ssh config
    if let Some(id_file) = &remote.identity_file
        && let Ok(key) = load_private_key(id_file) {
            let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(key), None);
            let result = session
                .authenticate_publickey(&user, key_with_hash)
                .await?;
            if matches!(result, AuthResult::Success) {
                return Ok(());
            }
        }

    // 3. Try default ~/.ssh/id_rsa, id_ed25519, id_ecdsa
    let home = dirs::home_dir().context("cannot determine home directory")?;
    for name in &["id_rsa", "id_ed25519", "id_ecdsa"] {
        let path = home.join(".ssh").join(name);
        if path.exists()
            && let Ok(key) = load_private_key(&path) {
                let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(key), None);
                let result = session
                    .authenticate_publickey(&user, key_with_hash)
                    .await?;
                if matches!(result, AuthResult::Success) {
                    return Ok(());
                }
            }
    }

    Err(anyhow!(
        "all authentication methods failed (agent, identity_file, default keys)"
    ))
}

/// Try to authenticate via SSH agent.
async fn try_agent_auth(
    session: &mut client::Handle<ClientHandler>,
    user: &str,
) -> Result<()> {
    let mut agent = russh::keys::agent::client::AgentClient::connect_env()
        .await
        .context("connecting to SSH agent")?;
    let identities = agent.request_identities().await?;

    for identity in identities {
        let result = session
            .authenticate_publickey_with(user, identity, None, &mut agent)
            .await
            .map_err(|e| anyhow!("agent signing error: {:?}", e))?;
        if matches!(result, AuthResult::Success) {
            return Ok(());
        }
    }

    Err(anyhow!("no agent identity was accepted"))
}

/// SSH client handler with known_hosts verification (accept-new semantics).
#[derive(Clone)]
pub struct ClientHandler {
    host: String,
    port: u16,
}

impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        let home = match dirs::home_dir() {
            Some(h) => h,
            None => return Ok(true), // can't verify without home dir
        };
        let known_hosts_path = home.join(".ssh/known_hosts");

        // Check against known_hosts: accept-new semantics
        // - Ok(true)  → Key matches known_hosts → accept
        // - Ok(false) → Host not in known_hosts → accept and persist (first connect)
        // - Err(_)    → Key changed for known host → reject (potential MITM)
        match russh::keys::check_known_hosts_path(
            &self.host,
            self.port,
            server_public_key,
            &known_hosts_path,
        ) {
            Ok(true) => Ok(true),
            Ok(false) => {
                // Host not in known_hosts — accept and persist
                eprintln!(
                    "⚠ Accepting new host key for {}:{} (not in known_hosts)",
                    self.host, self.port
                );
                // Best-effort: write key to known_hosts for future verification
                let _ = russh::keys::known_hosts::learn_known_hosts_path(
                    &self.host,
                    self.port,
                    server_public_key,
                    &known_hosts_path,
                );
                Ok(true)
            }
            Err(_) => Ok(false), // Key changed — reject (potential MITM)
        }
    }
}

/// Establish SSH connection and authenticate.
/// Both TCP connect and authentication are guarded by timeouts to prevent hangs.
pub async fn connect(remote: &RemoteHost) -> Result<client::Handle<ClientHandler>> {
    let port = remote.port.unwrap_or(22);
    let addr = format!("{}:{}", remote.hostname, port);

    // Parse the hostname for TCP connect (strip any bracket notation)
    let tcp_host = remote.hostname.trim_start_matches('[').trim_end_matches(']');

    // 1. TCP connect with 15s timeout
    let tcp_stream = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::net::TcpStream::connect((tcp_host, port)),
    )
    .await
    .with_context(|| format!("TCP connect timed out (15s) to {}", addr))?
    .with_context(|| format!("TCP connecting to {}", addr))?;

    // 2. SSH handshake with 15s timeout
    let config = Arc::new(client::Config::default());
    let handler = ClientHandler {
        host: tcp_host.to_string(),
        port,
    };
    let mut session = tokio::time::timeout(
        Duration::from_secs(15),
        russh::client::connect_stream(config, tcp_stream, handler),
    )
    .await
    .with_context(|| format!("SSH handshake timed out (15s) with {}", addr))?
    .with_context(|| format!("SSH handshake with {}", addr))?;

    // 3. Authenticate with 15s timeout
    tokio::time::timeout(
        Duration::from_secs(15),
        authenticate(&mut session, remote),
    )
    .await
    .with_context(|| format!("Authentication timed out (15s) for {}", addr))?
    .with_context(|| format!("Authenticating to {}", addr))?;

    Ok(session)
}

/// Upload the local rexec binary to ~/.rexec/rexec on the remote host.
pub async fn upload_binary(session: &mut client::Handle<ClientHandler>) -> Result<()> {
    // Read local binary
    let self_path = std::fs::read_link("/proc/self/exe").context("reading /proc/self/exe")?;
    let binary = std::fs::read(&self_path)
        .with_context(|| format!("reading binary {}", self_path.display()))?;

    // Create remote directory and receive binary via cat
    let mut channel = session.channel_open_session().await?;
    channel
        .exec(
            true,
            "mkdir -p ~/.rexec/logs && cat > ~/.rexec/rexec && chmod +x ~/.rexec/rexec",
        )
        .await?;

    // Send binary data in chunks (SSH max packet ~32768)
    for chunk in binary.chunks(32768) {
        channel.data(chunk).await?;
    }
    channel.eof().await?;

    // Wait for completion
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::ExitStatus { exit_status } => {
                if exit_status != 0 {
                    return Err(anyhow!("upload failed (exit {})", exit_status));
                }
            }
            ChannelMsg::Eof => break,
            _ => {}
        }
    }

    Ok(())
}

/// Ensure the remote host has a matching rexec binary. Upload if missing or outdated.
pub async fn ensure_remote_binary(session: &mut client::Handle<ClientHandler>) -> Result<()> {
    let local_version = env!("CARGO_PKG_VERSION");
    let expected = format!("rexec {}", local_version);

    // Check remote version
    let remote_output = exec_remote(session, "~/.rexec/rexec --version 2>/dev/null").await?;
    let remote_version = remote_output.trim();

    if remote_version == expected {
        return Ok(()); // Already up to date
    }

    // Upload binary
    upload_binary(session).await?;
    eprintln!("✓ Deployed rexec v{} to remote", local_version);
    Ok(())
}

/// Run a command on the remote and collect stdout as a string.
/// Uses lossy UTF-8 conversion to handle non-UTF-8 output gracefully.
pub async fn exec_remote(
    session: &client::Handle<ClientHandler>,
    command: &str,
) -> Result<String> {
    let mut channel = session.channel_open_session().await?;
    channel.exec(true, command).await?;

    let mut output = Vec::new();
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { ref data } => {
                output.extend_from_slice(data);
            }
            ChannelMsg::ExitStatus { .. } => {}
            ChannelMsg::Eof => break,
            _ => {}
        }
    }
    Ok(String::from_utf8_lossy(&output).into_owned())
}

/// Check remote dependencies and install if missing.
///
/// Required: rsync, sh. The worker uses SIGHUP ignoring via libc,
/// not the `nohup` command, so nohup is no longer a dependency.
pub async fn check_and_install_deps(session: &mut client::Handle<ClientHandler>) -> Result<()> {
    println!("Checking remote dependencies...\n");

    // Check deps in one round-trip
    let check_cmd = r#"echo "=== Checking dependencies ===";
for tool in rsync sh; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "✓ $tool: $(command -v $tool)";
  else
    echo "✗ $tool: NOT FOUND";
  fi
done;
echo "=== Detecting package manager ===";
if command -v apt-get >/dev/null 2>&1; then
  echo "pm:apt-get";
elif command -v yum >/dev/null 2>&1; then
  echo "pm:yum";
elif command -v dnf >/dev/null 2>&1; then
  echo "pm:dnf";
elif command -v apk >/dev/null 2>&1; then
  echo "pm:apk";
elif command -v pacman >/dev/null 2>&1; then
  echo "pm:pacman";
else
  echo "pm:none";
fi"#;

    let output = exec_remote(session, check_cmd).await?;
    print!("{}", output);

    // Parse which deps are missing
    let missing_rsync = output.contains("✗ rsync");
    let missing_sh = output.contains("✗ sh");

    if missing_sh {
        return Err(anyhow!("'sh' not found on remote — this is a critical dependency. Please install a POSIX shell manually."));
    }

    if !missing_rsync {
        println!("\n✓ All dependencies satisfied.");
        return Ok(());
    }

    // Detect package manager
    let pm = if output.contains("pm:apt-get") {
        "apt-get"
    } else if output.contains("pm:yum") {
        "yum"
    } else if output.contains("pm:dnf") {
        "dnf"
    } else if output.contains("pm:apk") {
        "apk"
    } else if output.contains("pm:pacman") {
        "pacman"
    } else {
        "none"
    };

    if pm == "none" {
        eprintln!("\n⚠ Could not detect a package manager on the remote host.");
        eprintln!("  Missing: rsync");
        eprintln!("  Please install it manually.");
        return Err(anyhow!("no package manager detected, cannot auto-install"));
    }

    println!("\nInstalling missing dependencies via {}...", pm);

    let install_cmd = match pm {
        "apt-get" => "sudo apt-get update -qq && sudo apt-get install -y -qq rsync".to_string(),
        "yum" => "sudo yum install -y -q rsync".to_string(),
        "dnf" => "sudo dnf install -y -q rsync".to_string(),
        "apk" => "sudo apk add --quiet rsync".to_string(),
        "pacman" => "sudo pacman -S --noconfirm --quiet rsync".to_string(),
        _ => return Err(anyhow!("unsupported package manager")),
    };

    println!("Running: {}\n", install_cmd);
    let install_output = exec_remote(session, &install_cmd).await?;
    print!("{}", install_output);

    // Verify installation
    println!("\n=== Verifying installation ===");
    let verify_cmd = r#"for tool in rsync sh; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "✓ $tool: $(command -v $tool)";
  else
    echo "✗ $tool: STILL NOT FOUND";
  fi
done"#;

    let verify_output = exec_remote(session, verify_cmd).await?;
    print!("{}", verify_output);

    if verify_output.contains("STILL NOT FOUND") {
        return Err(anyhow!("some dependencies are still missing after installation"));
    }

    println!("\n✓ All dependencies satisfied.");
    Ok(())
}

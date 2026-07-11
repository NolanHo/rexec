use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use russh::client;
use russh::keys::PrivateKeyWithHashAlg;
use russh::keys::PrivateKey;
use russh::{ChannelMsg, client::AuthResult};

use crate::RemoteHost;

/// Attempt to load a private key from a path.
fn load_private_key(path: &PathBuf) -> Result<PrivateKey> {
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
    if let Some(id_file) = &remote.identity_file {
        if let Ok(key) = load_private_key(id_file) {
            let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(key), None);
            let result = session
                .authenticate_publickey(&user, key_with_hash)
                .await?;
            if matches!(result, AuthResult::Success) {
                return Ok(());
            }
        }
    }

    // 3. Try default ~/.ssh/id_rsa, id_ed25519, id_ecdsa
    let home = dirs::home_dir().context("cannot determine home directory")?;
    for name in &["id_rsa", "id_ed25519", "id_ecdsa"] {
        let path = home.join(".ssh").join(name);
        if path.exists() {
            if let Ok(key) = load_private_key(&path) {
                let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(key), None);
                let result = session
                    .authenticate_publickey(&user, key_with_hash)
                    .await?;
                if matches!(result, AuthResult::Success) {
                    return Ok(());
                }
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

#[derive(Clone)]
pub struct ClientHandler;

impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
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
    let mut session = tokio::time::timeout(
        Duration::from_secs(15),
        russh::client::connect_stream(config, tcp_stream, ClientHandler),
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

/// Execute a command on the remote host using nohup, then follow the output file.
///
/// The command is wrapped in `nohup sh -c '...' > logfile 2>&1 &` so it survives
/// SSH disconnection. We then read the logfile incrementally to stream output.
pub async fn run_and_follow(
    session: &mut client::Handle<ClientHandler>,
    remote: &RemoteHost,
    command: &str,
) -> Result<()> {
    // Generate a unique log file path on the remote
    let log_file = format!(
        "/tmp/rexec_{}_{}.log",
        std::process::id(),
        rand::random::<u32>()
    );

    // Build the remote wrapper: nohup sh -c 'CMD' > LOG 2>&1 & echo $!
    let wrapper = format!(
        "nohup sh -c {} > {} 2>&1 & echo $! > {}.pid; disown 2>/dev/null; cat {}.pid",
        shell_quote(command),
        log_file,
        log_file,
        log_file
    );

    // Start the command in background
    let mut channel = session.channel_open_session().await?;
    channel.exec(true, wrapper.as_str()).await?;

    // Read the PID from the wrapper output
    let mut pid = String::new();
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { ref data } => {
                pid.push_str(std::str::from_utf8(data).unwrap_or(""));
            }
            ChannelMsg::ExitStatus { .. } => {}
            ChannelMsg::Eof => break,
            _ => {}
        }
    }
    let pid = pid.trim().to_string();

    if pid.is_empty() {
        eprintln!("⚠ Warning: could not determine remote PID");
    } else {
        eprintln!("Remote PID: {} | Log: {}", pid, log_file);
    }

    // Small delay for the nohup process to start writing
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Follow the log file, with reconnection on SSH disconnect
    follow_log(session, remote, &log_file, &pid).await
}

/// Follow the remote log file, streaming new content to stdout.
/// On SSH disconnect, retry with exponential backoff.
/// On local SIGINT/SIGTERM, print remote info and exit.
async fn follow_log(
    session: &mut client::Handle<ClientHandler>,
    remote: &RemoteHost,
    log_file: &str,
    pid: &str,
) -> Result<()> {
    let mut offset: u64 = 0;
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(30);
    let max_retries = 10;
    let mut retries = 0;

    // Install signal handler: prints remote info on Ctrl+C / kill
    let (sig_tx, mut sig_rx) = tokio::sync::mpsc::channel::<()>(1);
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigint = signal(SignalKind::interrupt()).unwrap();
        let mut sigterm = signal(SignalKind::terminate()).unwrap();
        loop {
            tokio::select! {
                _ = sigint.recv() => break,
                _ = sigterm.recv() => break,
            }
        }
        let _ = sig_tx.send(()).await;
    });

    loop {
        tokio::select! {
            // Signal received — print remote info and exit
            _ = sig_rx.recv() => {
                eprintln!(
                    "\n⚠ Interrupted by signal. Remote process still running.\n  PID: {}  Log: {}",
                    pid, log_file
                );
                return Ok(());
            }
            // Normal log polling
            result = read_log_tail(session, log_file, offset) => {
                match result {
                    Ok((data, new_offset, eof)) => {
                        if !data.is_empty() {
                            use std::io::Write;
                            let stdout = std::io::stdout();
                            let mut lock = stdout.lock();
                            lock.write_all(&data)?;
                            lock.flush()?;
                        }
                        offset = new_offset;
                        backoff = Duration::from_secs(1);
                        retries = 0;

                        if eof {
                            let alive = check_process_alive(session, pid).await.unwrap_or(false);
                            if !alive {
                                if let Ok((data, new_offset, _)) =
                                    read_log_tail(session, log_file, offset).await
                                {
                                    if !data.is_empty() {
                                        use std::io::Write;
                                        let stdout = std::io::stdout();
                                        let mut lock = stdout.lock();
                                        lock.write_all(&data)?;
                                        lock.flush()?;
                                    }
                                    let _ = new_offset;
                                }
                                println!("\n✓ Remote process exited");
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(500)).await;
                        }
                    }
                    Err(e) => {
                        retries += 1;
                        eprintln!(
                            "\n⚠ Connection lost: {}. Remote process still running.\n  PID: {}  Log: {}\n  Retry {}/{} in {:?}...",
                            e, pid, log_file, retries, max_retries, backoff
                        );

                        if retries >= max_retries {
                            eprintln!(
                                "✗ Max retries reached. Remote process is still running.\n  PID: {}  Log: {}",
                                pid, log_file
                            );
                            return Err(anyhow!(
                                "connection lost after {} retries. Remote log: {}",
                                max_retries,
                                log_file
                            ));
                        }

                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(max_backoff);

                        match connect(remote).await {
                            Ok(new_session) => {
                                *session = new_session;
                                eprintln!("✓ Reconnected. Resuming log follow...");
                            }
                            Err(_) => {
                                continue;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Read log file content from the given offset.
/// Returns (data, new_offset, reached_eof_on_file).
async fn read_log_tail(
    session: &client::Handle<ClientHandler>,
    log_file: &str,
    offset: u64,
) -> Result<(Vec<u8>, u64, bool)> {
    // Check file size
    let stat_cmd = format!("stat -c %s {} 2>/dev/null || echo 0", shell_quote(log_file));

    let mut channel = session.channel_open_session().await?;
    channel.exec(true, stat_cmd.as_str()).await?;

    let mut output = String::new();
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { ref data } => {
                output.push_str(std::str::from_utf8(data).unwrap_or(""));
            }
            ChannelMsg::ExitStatus { .. } => {}
            ChannelMsg::Eof => break,
            _ => {}
        }
    }

    let file_size: u64 = output.trim().parse().unwrap_or(0);

    if file_size <= offset {
        return Ok((vec![], offset, true));
    }

    // Read new content using dd
    let read_cmd = format!(
        "dd if={} bs=1 skip={} count={} 2>/dev/null",
        shell_quote(log_file),
        offset,
        file_size - offset
    );

    let mut channel = session.channel_open_session().await?;
    channel.exec(true, read_cmd.as_str()).await?;

    let mut data = Vec::new();
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data: ref chunk } => {
                data.extend_from_slice(chunk);
            }
            ChannelMsg::ExitStatus { .. } => {}
            ChannelMsg::Eof => break,
            _ => {}
        }
    }

    Ok((data, file_size, false))
}

/// Check if a process with the given PID is still running on the remote.
async fn check_process_alive(
    session: &client::Handle<ClientHandler>,
    pid: &str,
) -> Result<bool> {
    if pid.is_empty() {
        return Ok(false);
    }

    let cmd = format!("kill -0 {} 2>/dev/null && echo alive || echo dead", pid);
    let mut channel = session.channel_open_session().await?;
    channel.exec(true, cmd.as_str()).await?;

    let mut output = String::new();
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { ref data } => {
                output.push_str(std::str::from_utf8(data).unwrap_or(""));
            }
            ChannelMsg::ExitStatus { .. } => {}
            ChannelMsg::Eof => break,
            _ => {}
        }
    }

    Ok(output.contains("alive"))
}

/// Simple shell quoting for a single argument.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

/// Run a command on the remote and collect stdout as a string.
pub async fn exec_remote(
    session: &client::Handle<ClientHandler>,
    command: &str,
) -> Result<String> {
    let mut channel = session.channel_open_session().await?;
    channel.exec(true, command).await?;

    let mut output = String::new();
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { ref data } => {
                output.push_str(std::str::from_utf8(data).unwrap_or(""));
            }
            ChannelMsg::ExitStatus { .. } => {}
            ChannelMsg::Eof => break,
            _ => {}
        }
    }
    Ok(output)
}

/// Check remote dependencies and install if missing.
///
/// Required: rsync, sh, nohup. We detect the package manager and install.
pub async fn check_and_install_deps(session: &mut client::Handle<ClientHandler>) -> Result<()> {
    println!("Checking remote dependencies...\n");

    // Check all three deps in one round-trip
    // Output format: rsync:/usr/bin/rsync\nsh:/bin/sh\nnohup:/usr/bin/nohup\npm:apt-get
    let check_cmd = r#"echo "=== Checking dependencies ===";
for tool in rsync sh nohup; do
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
    let missing_rsunc = output.contains("✗ rsync");
    let missing_nohup = output.contains("✗ nohup");
    // sh is always present, but check anyway
    let missing_sh = output.contains("✗ sh");

    if missing_sh {
        return Err(anyhow!("'sh' not found on remote — this is a critical dependency. Please install a POSIX shell manually."));
    }

    let any_missing = missing_rsunc || missing_nohup;
    if !any_missing {
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
        eprintln!("  Missing: rsync={}, nohup={}", missing_rsunc, missing_nohup);
        eprintln!("  Please install them manually.");
        return Err(anyhow!("no package manager detected, cannot auto-install"));
    }

    println!("\nInstalling missing dependencies via {}...", pm);

    // Build install command based on package manager
    let mut packages: Vec<&str> = Vec::new();
    if missing_rsunc {
        packages.push("rsync");
    }
    // nohup is part of coreutils on most systems, or part of 'busybox' on Alpine
    if missing_nohup {
        match pm {
            "apk" => packages.push("busybox"),
            _ => packages.push("coreutils"),
        }
    }

    let install_cmd = match pm {
        "apt-get" => format!("sudo apt-get update -qq && sudo apt-get install -y -qq {}", packages.join(" ")),
        "yum" => format!("sudo yum install -y -q {}", packages.join(" ")),
        "dnf" => format!("sudo dnf install -y -q {}", packages.join(" ")),
        "apk" => format!("sudo apk add --quiet {}", packages.join(" ")),
        "pacman" => format!("sudo pacman -S --noconfirm --quiet {}", packages.join(" ")),
        _ => return Err(anyhow!("unsupported package manager")),
    };

    println!("Running: {}\n", install_cmd);
    let install_output = exec_remote(session, &install_cmd).await?;
    print!("{}", install_output);

    // Verify installation
    println!("\n=== Verifying installation ===");
    let verify_cmd = r#"for tool in rsync sh nohup; do
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

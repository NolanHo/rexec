use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use russh::client;
use russh::keys::HashAlg;
use russh::keys::PrivateKey;
use russh::keys::PrivateKeyWithHashAlg;
use russh::{ChannelMsg, client::AuthResult};

use crate::RemoteHost;

/// Public GitHub repository hosting prebuilt worker releases. When the remote
/// platform differs from the local one, the worker binary for the remote is
/// downloaded from this repository's Releases instead of deploying the local
/// (incompatible) binary.
const GITHUB_REPO: &str = "Menghuan1918/rexec";

/// Attempt to load a private key from a path.
///
/// Tries OpenSSH's own format first (`-----BEGIN OPENSSH PRIVATE KEY-----`).
/// Falls back to legacy PKCS#1 PEM (`-----BEGIN RSA PRIVATE KEY-----`), which
/// `PrivateKey::from_openssh` rejects because it only accepts the OpenSSH PEM
/// label. PKCS#8 (`-----BEGIN PRIVATE KEY-----`) is also handled via the same
/// RSA path.
fn load_private_key(path: &Path) -> Result<PrivateKey> {
    let pem = std::fs::read_to_string(path)
        .with_context(|| format!("reading private key from {}", path.display()))?;

    match PrivateKey::from_openssh(&pem) {
        Ok(key) => Ok(key),
        Err(openssh_err) => {
            // Legacy PEM formats that `PrivateKey::from_openssh` rejects
            // (it only accepts the `OPENSSH PRIVATE KEY` label). Parse the raw
            // RSA key directly, then wrap it into an SSH PrivateKey for russh
            // to sign with. Try PKCS#1 (`RSA PRIVATE KEY`) then PKCS#8
            // (`PRIVATE KEY`).
            let rsa_key = {
                use rsa::pkcs1::DecodeRsaPrivateKey;
                rsa::RsaPrivateKey::from_pkcs1_pem(&pem)
            }
            .or_else(|_| {
                use rsa::pkcs8::DecodePrivateKey;
                rsa::RsaPrivateKey::from_pkcs8_pem(&pem)
            })
            .with_context(|| format!("parsing {} as OpenSSH/PKCS#1/PKCS#8", path.display()))?;
            let keypair = russh::keys::ssh_key::private::RsaKeypair::try_from(&rsa_key)
                .context("converting RSA key to SSH keypair")?;
            let key_data = russh::keys::ssh_key::private::KeypairData::Rsa(keypair);
            PrivateKey::new(key_data, String::new())
                .with_context(|| format!("building PrivateKey from {}", path.display()))
                .map_err(|e| e.context(openssh_err))
        }
    }
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
        && let Ok(key) = load_private_key(id_file)
    {
        // RSA: None would map to legacy ssh-rsa (SHA-1), which modern OpenSSH
        // rejects; explicitly use rsa-sha2-256.
        let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(key), Some(HashAlg::Sha256));
        let result = session.authenticate_publickey(&user, key_with_hash).await?;
        if matches!(result, AuthResult::Success) {
            return Ok(());
        }
    }

    // 3. Try default ~/.ssh/id_rsa, id_ed25519, id_ecdsa
    let home = dirs::home_dir().context("cannot determine home directory")?;
    for name in &["id_rsa", "id_ed25519", "id_ecdsa"] {
        let path = home.join(".ssh").join(name);
        if path.exists()
            && let Ok(key) = load_private_key(&path)
        {
            let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(key), Some(HashAlg::Sha256));
            let result = session.authenticate_publickey(&user, key_with_hash).await?;
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
async fn try_agent_auth(session: &mut client::Handle<ClientHandler>, user: &str) -> Result<()> {
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
                crate::status!(
                    "⚠ Accepting new host key for {}:{} (not in known_hosts)",
                    self.host,
                    self.port
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
    let tcp_host = remote
        .hostname
        .trim_start_matches('[')
        .trim_end_matches(']');

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
    tokio::time::timeout(Duration::from_secs(15), authenticate(&mut session, remote))
        .await
        .with_context(|| format!("Authentication timed out (15s) for {}", addr))?
        .with_context(|| format!("Authenticating to {}", addr))?;

    Ok(session)
}

/// Upload a worker binary to ~/.rexec/rexec on the remote host.
///
/// `src_path` is either the locally running binary (same platform as the
/// remote) or a prebuilt release artifact downloaded for the remote platform.
///
/// Uses `rsync` over SSH (same mechanism as `--sync`) instead of streaming the
/// binary through a russh channel. Streaming a multi-MB payload via
/// `channel.data()` deadlocks on channel flow control once the send window is
/// exhausted, leaving a truncated remote binary that segfaults on launch.
pub async fn upload_binary(
    session: &mut client::Handle<ClientHandler>,
    host: &str,
    src_path: &Path,
) -> Result<()> {
    // Ensure the remote dir exists and learn the remote home's absolute path so
    // rsync can target it without relying on `~` expansion.
    let home = exec_remote(session, "mkdir -p ~/.rexec/logs && printf '%s' ~").await?;
    let home = home.trim().to_string();
    if home.is_empty() {
        return Err(anyhow!("could not determine remote HOME for worker upload"));
    }
    let remote_target = format!("{}:{}/.rexec/rexec", host, home.trim_end_matches('/'));

    let ssh_opts = "-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=5 -o ServerAliveCountMax=3";
    let ssh_e = format!("ssh {}", ssh_opts);
    let src_str = src_path.to_string_lossy().into_owned();

    let child = tokio::process::Command::new("rsync")
        .args([
            "-az",
            "-e",
            ssh_e.as_str(),
            src_str.as_str(),
            remote_target.as_str(),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn rsync for worker upload")?;

    let output = tokio::time::timeout(Duration::from_secs(300), child.wait_with_output())
        .await
        .context("rsync timed out while uploading worker")?
        .context("failed to wait for rsync")?;

    if !output.status.success() {
        return Err(anyhow!(
            "rsync failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    // Belt-and-suspenders: ensure the executable bit survives any umask quirk.
    exec_remote(session, "chmod +x ~/.rexec/rexec").await?;

    Ok(())
}

/// Ensure the remote host has a matching rexec binary. Upload if missing or outdated.
///
/// The worker source is chosen by platform: when the remote OS/arch matches the
/// local one, the running binary itself is deployed; otherwise (e.g. macOS
/// local → Linux remote) a prebuilt worker is downloaded from GitHub Releases
/// first — the local binary would not run on the remote.
pub async fn ensure_remote_binary(
    session: &mut client::Handle<ClientHandler>,
    host: &str,
) -> Result<()> {
    let local_version = env!("CARGO_PKG_VERSION");
    let expected = format!("rexec {}", local_version);

    // Check remote version
    let remote_output = exec_remote(session, "~/.rexec/rexec --version 2>/dev/null").await?;
    let remote_version = remote_output.trim();

    if remote_version == expected {
        return Ok(()); // Already up to date
    }

    let remote_asset = detect_remote_asset(session).await?;
    let src_path = if remote_asset == local_asset() {
        // Same platform: deploy the running binary. Canonicalize so a
        // symlinked install (e.g. `cargo install`) isn't copied as a link by
        // `rsync -a`.
        std::env::current_exe()
            .context("resolving current executable")?
            .canonicalize()
            .context("canonicalizing executable path")?
    } else {
        download_worker(&remote_asset).await?
    };

    // Upload binary
    upload_binary(session, host, &src_path).await?;
    crate::status!("✓ Deployed rexec v{} to remote", local_version);
    Ok(())
}

/// Release-asset suffix for the platform rexec is running on,
/// e.g. "macos-arm64" or "linux-amd64".
fn local_asset() -> String {
    let arch = if std::env::consts::ARCH == "x86_64" {
        "amd64"
    } else {
        "arm64"
    };
    format!("{}-{arch}", std::env::consts::OS)
}

/// Map `uname -sm` output (e.g. "Linux x86_64") to a release-asset suffix
/// (e.g. "linux-amd64"). Only Linux remotes are supported.
fn uname_asset(uname: &str) -> Result<String> {
    let mut parts = uname.split_whitespace();
    let arch = match (parts.next(), parts.next()) {
        (Some("Linux"), Some("x86_64")) => "amd64",
        (Some("Linux"), Some("aarch64")) => "arm64",
        _ => {
            return Err(anyhow!(
                "remote platform {:?} is not supported — the remote must be Linux (amd64/arm64)",
                uname.trim()
            ));
        }
    };
    Ok(format!("linux-{arch}"))
}

/// Detect the remote platform via `uname -sm` and map it to a release-asset
/// suffix (e.g. "linux-amd64").
async fn detect_remote_asset(session: &client::Handle<ClientHandler>) -> Result<String> {
    let uname = exec_remote(session, "uname -sm").await?;
    uname_asset(&uname)
}

/// Download the prebuilt worker for `asset` (e.g. "linux-amd64") from GitHub
/// Releases into the local cache (~/.rexec/cache), reusing an existing copy.
///
/// The download is pinned to the running binary's version: the remote version
/// check compares against `CARGO_PKG_VERSION`, so falling back to "latest"
/// would re-deploy on every run. Requires a release tagged `v{version}` to
/// exist (created by the release workflow on tag push).
async fn download_worker(asset: &str) -> Result<PathBuf> {
    let version = env!("CARGO_PKG_VERSION");
    let home = dirs::home_dir().context("cannot determine home directory")?;
    let cache_dir = home.join(".rexec").join("cache");
    std::fs::create_dir_all(&cache_dir)
        .with_context(|| format!("creating {}", cache_dir.display()))?;
    let cache_path = cache_dir.join(format!("rexec-v{version}-{asset}"));

    if cache_path.exists() {
        return Ok(cache_path);
    }

    let url = format!(
        "https://github.com/{}/releases/download/v{version}/rexec-{asset}",
        GITHUB_REPO
    );
    crate::status!("⬇ Downloading worker (rexec-{asset}) from GitHub Releases");

    // Download to a .part file and rename into place afterwards, so an
    // interrupted download can never be mistaken for a complete worker.
    let tmp_path = PathBuf::from(format!("{}.part", cache_path.display()));
    let child = tokio::process::Command::new("curl")
        .args(["-fSL", "--retry", "3", "-o"])
        .arg(&tmp_path)
        .arg(&url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn curl — is curl installed?")?;
    let output = tokio::time::timeout(Duration::from_secs(300), child.wait_with_output())
        .await
        .context("curl timed out while downloading worker")?
        .context("failed to wait for curl")?;
    if !output.status.success() {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(anyhow!(
            "downloading worker from {url} failed: {}\n\
             hint: no GitHub release exists for v{version} yet — push tag v{version} to trigger \
             the release workflow, or run rexec from a machine matching the remote platform",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    std::fs::rename(&tmp_path, &cache_path)
        .with_context(|| format!("moving downloaded worker to {}", cache_path.display()))?;
    Ok(cache_path)
}

/// Run a command on the remote and collect stdout as a string.
/// Uses lossy UTF-8 conversion to handle non-UTF-8 output gracefully.
pub async fn exec_remote(session: &client::Handle<ClientHandler>, command: &str) -> Result<String> {
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
        return Err(anyhow!(
            "'sh' not found on remote — this is a critical dependency. Please install a POSIX shell manually."
        ));
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
        return Err(anyhow!(
            "some dependencies are still missing after installation"
        ));
    }

    println!("\n✓ All dependencies satisfied.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uname_asset_linux() {
        assert_eq!(uname_asset("Linux x86_64\n").unwrap(), "linux-amd64");
        assert_eq!(uname_asset("Linux aarch64").unwrap(), "linux-arm64");
        assert_eq!(uname_asset("  Linux   x86_64  ").unwrap(), "linux-amd64");
    }

    #[test]
    fn test_uname_asset_unsupported() {
        assert!(uname_asset("Darwin arm64").is_err());
        assert!(uname_asset("Linux riscv64").is_err());
        assert!(uname_asset("").is_err());
        assert!(uname_asset("Linux").is_err());
    }

    #[test]
    fn test_local_asset_is_normalized() {
        // Uses asset naming ("macos-arm64"/"linux-amd64"), never uname naming,
        // so a Linux local only matches a Linux remote of the same arch.
        let asset = local_asset();
        assert!(
            ["macos-amd64", "macos-arm64", "linux-amd64", "linux-arm64"].contains(&asset.as_str())
        );
    }
}

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use russh::client;
use russh::keys::HashAlg;
use russh::keys::PrivateKey;
use russh::keys::PrivateKeyWithHashAlg;
use russh::{ChannelMsg, client::AuthResult};
use russh_sftp::client::SftpSession;
use tokio::io::AsyncWriteExt;

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
/// Windows: russh 0.51's agent client only speaks the Unix domain-socket
/// protocol (connect_env is unix-only); the named-pipe Windows agent is not
/// supported — fall through to identity-file auth with a clear error.
#[cfg(unix)]
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

#[cfg(windows)]
async fn try_agent_auth(_session: &mut client::Handle<ClientHandler>, _user: &str) -> Result<()> {
    // NOTE: this error is currently SWALLOWED by the caller's `.is_ok()`
    // probe — the user sees the generic "all authentication methods failed",
    // not this message. Kept as an Err so agent auth is explicitly skipped
    // on Windows locals (identity-file auth follows). russh 0.51's agent
    // client only speaks the Unix domain-socket protocol (`connect_env` is
    // unix-only); wiring the Windows named-pipe agent (Pageant/OpenSSH agent
    // via `connect_pageant`) is a possible follow-up.
    Err(anyhow!(
        "SSH agent auth is not supported on Windows (unix socket only) — use an identity file"
    ))
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

/// Home directory of a WINDOWS remote, as a native `C:\Users\...` path.
///
/// `%USERPROFILE%` is probed FIRST (via explicit `cmd /c`, so a PowerShell
/// default shell still expands it) because this commit's Windows deploy paths
/// need backslash-absolute Windows paths: a Git-Bash default shell would
/// answer `$HOME` with an MSYS-style `/c/Users/...` (or the literal `$HOME`
/// when printf resolves from Git's usr/bin), which would poison the SFTP
/// target. Any answer that is not a drive-letter path is rejected so the
/// caller fails loudly instead of uploading to an impossible path.
async fn remote_home_windows(session: &client::Handle<ClientHandler>) -> Result<String> {
    let profile = exec_remote(session, "cmd /c \"echo %USERPROFILE%\"").await?;
    let profile = profile.trim().trim_matches('"');
    let is_drive_path = profile
        .get(0..2)
        .is_some_and(|p| p.as_bytes()[0].is_ascii_alphabetic() && p.as_bytes()[1] == b':');
    if is_drive_path {
        return Ok(profile.to_string());
    }

    // Fall back to $HOME in case someone replaced cmd; same drive-path check.
    let home = exec_remote(session, "printf %s \"$HOME\"").await?;
    let home = home.trim();
    let is_drive_path = home
        .get(0..2)
        .is_some_and(|p| p.as_bytes()[0].is_ascii_alphabetic() && p.as_bytes()[1] == b':');
    if is_drive_path {
        return Ok(home.to_string());
    }

    Err(anyhow!(
        "could not determine a native Windows home directory on the remote \
         (%USERPROFILE% and $HOME are both non-drive-letter paths)"
    ))
}

/// Upload a worker binary to ~/.rexec/rexec on a Linux/macOS remote host.
///
/// `src_path` is either the locally running binary (same platform as the
/// remote) or a prebuilt release artifact downloaded for the remote platform.
///
/// Uses `rsync` over SSH (same mechanism as `--sync`) instead of streaming the
/// binary through a russh channel. Streaming a multi-MB payload via
/// `channel.data()` deadlocks on channel flow control once the send window is
/// exhausted, leaving a truncated remote binary that segfaults on launch.
/// Windows remotes have no rsync — see `upload_binary_sftp`.
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
        .map_err(|e| {
            // A Windows-local → Linux-remote deploy runs rsync from the local
            // CLI; without MSYS2/WSL there is no rsync to spawn.
            if e.kind() == std::io::ErrorKind::NotFound && cfg!(windows) {
                anyhow::Error::new(e).context(
                    "rsync not found — install it via MSYS2 (pacman -S rsync) or use WSL; \
                     worker deploy to Linux/macOS remotes needs it",
                )
            } else {
                anyhow::Error::new(e).context("failed to spawn rsync for worker upload")
            }
        })?;

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

/// Upload the worker binary to `<home>\.rexec\rexec.exe` over SFTP.
///
/// Windows remotes have neither rsync nor `chmod`, so the binary is written
/// through the SFTP subsystem instead. `home` is the remote profile directory
/// already resolved by `remote_home_windows`.
async fn upload_binary_sftp(
    session: &client::Handle<ClientHandler>,
    src_path: &Path,
    home: &str,
) -> Result<()> {
    // Remote paths are plain strings, so build them with Windows separators for
    // the Windows remote; `Path::join` would use the *local* separator instead.
    let home = home.trim_end_matches('\\');
    let dir = format!("{home}\\.rexec");
    let logs_dir = format!("{dir}\\logs");
    let exe_path = format!("{dir}\\rexec.exe");
    let tmp_path = format!("{exe_path}.tmp");
    let old_path = format!("{exe_path}.old");

    let data = std::fs::read(src_path)
        .with_context(|| format!("reading worker binary {}", src_path.display()))?;

    // The SFTP subsystem needs a channel of its own: an `exec` channel cannot be
    // turned into a subsystem afterwards.
    let channel = session
        .channel_open_session()
        .await
        .context("opening SFTP channel")?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .context("requesting the sftp subsystem (is it enabled in the remote sshd config?)")?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .context("starting SFTP session")?;

    // `create_dir` fails when the directory already exists, which is the normal
    // case on redeploys; a genuinely missing parent is reported by the file
    // creation below, so these results are deliberately ignored.
    let _ = sftp.create_dir(dir.as_str()).await;
    let _ = sftp.create_dir(logs_dir.as_str()).await;

    // Upload to a temp name, then swap into place. Windows locks a RUNNING
    // executable against write/delete, but renaming it away is allowed — so
    // in-place truncate-open (`create`) would fail with a sharing violation
    // whenever a worker from a previous run is still alive. The swap is:
    //   write <exe>.tmp → rename <exe> to <exe>.old → rename <exe>.tmp to <exe>
    // A crash mid-way leaves at most a stale .tmp/.old, which the next deploy
    // overwrites — never a truncated <exe>.
    let mut file = sftp
        .create(tmp_path.as_str())
        .await
        .with_context(|| format!("creating {tmp_path} over SFTP"))?;
    file.write_all(&data)
        .await
        .with_context(|| format!("writing {tmp_path} over SFTP"))?;
    // `shutdown` closes the remote file handle; skipping it can drop the last
    // write requests when the session is dropped. `flush` only does work when
    // the server advertises the fsync extension, but costs nothing.
    file.flush().await.context("flushing uploaded worker")?;
    file.shutdown().await.context("closing uploaded worker")?;

    let _ = sftp.remove_file(old_path.as_str()).await; // stale swap target from an earlier deploy
    let _ = sftp.rename(exe_path.as_str(), old_path.as_str()).await; // allowed even while running
    sftp.rename(tmp_path.as_str(), exe_path.as_str())
        .await
        .with_context(|| format!("swapping {tmp_path} into {exe_path}"))?;

    // Verify the remote size: a truncated worker only fails later, at launch
    // time (see the flow-control note on `upload_binary`).
    if let Some(remote_len) = sftp
        .metadata(exe_path.as_str())
        .await
        .with_context(|| format!("verifying {exe_path} after upload"))?
        .size
        && remote_len != data.len() as u64
    {
        return Err(anyhow!(
            "worker upload to {exe_path} is incomplete: {remote_len} of {} bytes",
            data.len()
        ));
    }

    // Best effort: the upload is complete at this point, so a failed close must
    // not mask it.
    let _ = sftp.close().await;

    Ok(())
}

/// What `ensure_remote_binary` learned about the remote — callers need it to
/// build platform-correct launch commands (POSIX `~` does not expand under
/// cmd.exe/PowerShell, and Windows paths need quoting).
pub struct RemoteEnv {
    pub is_windows: bool,
    /// Absolute home path for Windows remotes (`C:\Users\...`); empty for
    /// POSIX remotes, whose launch commands use `~` literally.
    pub home: String,
}

impl RemoteEnv {
    /// The `channel.exec` command that starts the worker on this remote.
    pub fn worker_command(&self) -> String {
        if self.is_windows {
            // Explicit `cmd /c` (a bare quoted path is a parse error under a
            // PowerShell default shell). Verified shape for cmd.exe — the
            // OpenSSH-for-Windows DEFAULT shell: its /c quote-stripping
            // (cmd /? rule 2) turns `""<path>" args"` into `"<path>" args`.
            // KNOWN LIMITATION: under a PowerShell DefaultShell this only
            // works for space-less profile paths (PS argument-mode parsing
            // closes the `""` immediately and splits at the unquoted space —
            // see PowerShell/Win32-OpenSSH#1082). Windows remotes are
            // experimental; cmd.exe is the supported default.
            format!(
                "cmd /c \"\"{}\\.rexec\\rexec.exe\" worker\"",
                self.home.trim_end_matches('\\')
            )
        } else {
            "~/.rexec/rexec worker".to_string()
        }
    }

    /// The `channel.exec` command that attaches to a running worker.
    pub fn attach_command(&self, pid: u32, offset: u64) -> String {
        if self.is_windows {
            format!(
                "cmd /c \"\"{}\\.rexec\\rexec.exe\" attach --pid {} --offset {}\"",
                self.home.trim_end_matches('\\'),
                pid,
                offset
            )
        } else {
            format!("~/.rexec/rexec attach --pid {pid} --offset {offset}")
        }
    }
}

/// Ensure the remote host has a matching rexec binary. Upload if missing or outdated.
///
/// The worker source is chosen by platform: when the remote OS/arch matches the
/// local one, the running binary itself is deployed; otherwise (e.g. macOS
/// local → Linux remote) a prebuilt worker is downloaded from GitHub Releases
/// first — the local binary would not run on the remote.
///
/// Returns the remote's platform environment so the caller can launch the
/// worker with a platform-correct command.
pub async fn ensure_remote_binary(
    session: &mut client::Handle<ClientHandler>,
    host: &str,
) -> Result<RemoteEnv> {
    let local_version = env!("CARGO_PKG_VERSION");
    let expected = format!("rexec {}", local_version);

    // Detect the platform FIRST: the POSIX probe below must not run on a
    // Windows remote — `2>/dev/null` is not a cmd/PowerShell redirect (cmd
    // would create a stray `<drive>:\dev\null` when `<drive>:\dev` exists),
    // and the round trip is wasted there anyway.
    let remote_asset = detect_remote_asset(session).await?;
    let is_windows = remote_asset.starts_with("windows-");

    if is_windows {
        let home = remote_home_windows(session).await?;
        // Probe via explicit `cmd /c`: a bare quoted path is a parse error
        // under a PowerShell default shell (it would need the & call
        // operator), which would make this probe ALWAYS look failed and
        // re-upload the worker on every run.
        let probe = format!(
            "cmd /c \"\"{}\\.rexec\\rexec.exe\" --version\"",
            home.trim_end_matches('\\')
        );
        let up_to_date = exec_remote(session, &probe).await?.trim() == expected;
        if up_to_date {
            return Ok(RemoteEnv {
                is_windows: true,
                home,
            });
        }
    } else {
        // Check remote version. This probe needs a POSIX shell and `~`
        // expansion — guaranteed on the Linux/macOS remotes detected above.
        let remote_output = exec_remote(session, "~/.rexec/rexec --version 2>/dev/null").await?;
        if remote_output.trim() == expected {
            return Ok(RemoteEnv {
                is_windows: false,
                home: String::new(),
            }); // Already up to date
        }
    }

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

    // Upload binary: Windows has no rsync, so it takes the SFTP path with the
    // `.exe` worker name.
    let env = if is_windows {
        let home = remote_home_windows(session).await?;
        upload_binary_sftp(session, &src_path, &home).await?;
        RemoteEnv {
            is_windows: true,
            home,
        }
    } else {
        upload_binary(session, host, &src_path).await?;
        RemoteEnv {
            is_windows: false,
            home: String::new(),
        }
    };
    crate::status!("✓ Deployed rexec v{} to remote", local_version);
    Ok(env)
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

/// Map remote platform probe output to a release-asset suffix (e.g.
/// "linux-amd64", "windows-arm64").
///
/// Accepts either `uname -sm` output ("Linux x86_64", "Darwin arm64") or the
/// Windows probe output ("Windows_NT AMD64", see `detect_remote_asset`).
fn uname_asset(probe: &str) -> Result<String> {
    let tokens: Vec<&str> = probe.split_whitespace().collect();

    // Windows probe output. The marker is searched for instead of being read
    // from a fixed position so leading or trailing text cannot defeat detection.
    if tokens.contains(&"Windows_NT") {
        let arch = if tokens.contains(&"AMD64") {
            "amd64"
        } else if tokens.contains(&"ARM64") {
            "arm64"
        } else {
            return Err(unsupported_platform(probe));
        };
        return Ok(format!("windows-{arch}"));
    }

    let asset = match (tokens.first(), tokens.get(1)) {
        (Some(&"Linux"), Some(&"x86_64")) => "linux-amd64",
        (Some(&"Linux"), Some(&"aarch64")) => "linux-arm64",
        (Some(&"Darwin"), Some(&"x86_64")) => "macos-amd64",
        (Some(&"Darwin"), Some(&"arm64")) => "macos-arm64",
        _ => return Err(unsupported_platform(probe)),
    };
    Ok(asset.to_string())
}

/// Error for a remote platform rexec ships no worker binary for.
fn unsupported_platform(probe: &str) -> anyhow::Error {
    anyhow!(
        "remote platform {:?} is not supported — the remote must be Linux (x86_64/aarch64), \
         macOS (x86_64/arm64), or Windows (AMD64/ARM64)",
        probe.trim()
    )
}

/// Detect the remote platform and map it to a release-asset suffix
/// (e.g. "linux-amd64", "windows-amd64").
///
/// POSIX remotes answer `uname -sm`. Windows remotes have no `uname`, so when
/// that probe yields nothing the platform is asked of `cmd.exe` instead. `cmd`
/// is invoked explicitly because the remote's default SSH shell may be
/// PowerShell, where `%PROCESSOR_ARCHITECTURE%` is not expanded by the shell
/// itself but a nested `cmd /c` does expand it.
async fn detect_remote_asset(session: &client::Handle<ClientHandler>) -> Result<String> {
    // `exec_remote` discards the exit status, so a missing `uname` surfaces as
    // empty stdout rather than an error. A Git-for-Windows remote (default
    // shell = Git Bash) HAS a uname that prints e.g. "MINGW64_NT-10.0 ...",
    // which uname_asset rejects — so fall back to the cmd probe whenever the
    // uname output cannot be mapped, not only when it is empty.
    let uname = exec_remote(session, "uname -sm").await?;
    if !uname.trim().is_empty()
        && let Ok(asset) = uname_asset(&uname)
    {
        return Ok(asset);
    }

    let windows = exec_remote(
        session,
        r#"cmd /c "echo Windows_NT %PROCESSOR_ARCHITECTURE%""#,
    )
    .await?;
    uname_asset(&windows).map_err(|e| {
        anyhow!(
            "remote platform could not be detected (uname: {uname:?}, cmd probe: {windows:?}): {e}"
        )
    })
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
/// Required on Linux/macOS: rsync, sh. The worker uses SIGHUP ignoring via
/// libc, not the `nohup` command, so nohup is no longer a dependency.
///
/// Windows remotes have neither rsync nor sh — and the deploy path uploads over
/// SFTP there — so only `cmd` is required. It ships with the OS and cannot be
/// installed, hence the check never installs anything.
pub async fn check_and_install_deps(session: &mut client::Handle<ClientHandler>) -> Result<()> {
    println!("Checking remote dependencies...\n");

    // Platform gate. A failed probe falls through to the POSIX checks, so an
    // unusual remote keeps the previous behaviour instead of failing here.
    if let Ok(asset) = detect_remote_asset(session).await
        && asset.starts_with("windows-")
    {
        return check_windows_deps(session).await;
    }

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

/// Windows dependency check: `cmd` is the only requirement, because the remote
/// SSH server itself needs it to run any command at all (and the worker spawns
/// commands through it). It ships with Windows, so nothing can be installed.
async fn check_windows_deps(session: &client::Handle<ClientHandler>) -> Result<()> {
    println!("Windows remote detected — rsync and sh are not applicable.\n");

    // `where` is a PowerShell alias for `Where-Object`, so it is reached through
    // `cmd /c` to invoke the real where.exe under either default shell.
    let output = exec_remote(session, "cmd /c where cmd").await?;
    let path = output.trim();
    if path.is_empty() {
        return Err(anyhow!(
            "'cmd' not found on remote — the Windows worker needs cmd.exe to run commands"
        ));
    }

    println!("✓ cmd: {}", path.lines().next().unwrap_or(path));
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
    fn test_uname_asset_darwin() {
        assert_eq!(uname_asset("Darwin x86_64\n").unwrap(), "macos-amd64");
        assert_eq!(uname_asset("Darwin arm64").unwrap(), "macos-arm64");
        assert_eq!(uname_asset("  Darwin   arm64  ").unwrap(), "macos-arm64");
    }

    #[test]
    fn test_uname_asset_windows() {
        // Output of `cmd /c "echo Windows_NT %PROCESSOR_ARCHITECTURE%"`.
        assert_eq!(
            uname_asset("Windows_NT AMD64\r\n").unwrap(),
            "windows-amd64"
        );
        assert_eq!(uname_asset("Windows_NT ARM64").unwrap(), "windows-arm64");
        // `%PROCESSOR_ARCHITECTURE%` can come back empty (e.g. unset env), which
        // is unsupported rather than silently mapped to an arch.
        assert!(uname_asset("Windows_NT").is_err());
    }

    #[test]
    fn test_uname_asset_unsupported() {
        assert!(uname_asset("Linux riscv64").is_err());
        assert!(uname_asset("Darwin i386").is_err());
        assert!(uname_asset("FreeBSD amd64").is_err());
        assert!(uname_asset("Windows_NT x86").is_err());
        assert!(uname_asset("").is_err());
        assert!(uname_asset("Linux").is_err());
    }

    #[test]
    fn test_local_asset_is_normalized() {
        // Uses asset naming ("macos-arm64"/"linux-amd64"), never uname naming,
        // so a Linux local only matches a Linux remote of the same arch.
        let asset = local_asset();
        assert!(
            [
                "macos-amd64",
                "macos-arm64",
                "linux-amd64",
                "linux-arm64",
                "windows-amd64",
                "windows-arm64",
            ]
            .contains(&asset.as_str())
        );
    }
}

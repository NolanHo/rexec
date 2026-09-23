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
use crate::diagnostics;

/// Public GitHub repository hosting prebuilt worker releases. When the remote
/// platform differs from the local one, the worker binary for the remote is
/// downloaded from this repository's Releases instead of deploying the local
/// (incompatible) binary. This fork builds its own release assets (upstream
/// does not carry this fork's versions) — keep in sync with wherever releases
/// are actually published.
const GITHUB_REPO: &str = "NolanHo/rexec";

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
///
/// Every attempt is recorded in `trace`. The auth ORDER and the control flow are
/// untouched — the trace lines are the only addition (the errors themselves are
/// still returned/propagated exactly as before).
async fn authenticate(
    session: &mut client::Handle<ClientHandler>,
    remote: &RemoteHost,
    trace: &mut diagnostics::Trace,
) -> Result<()> {
    let user = remote
        .user
        .clone()
        .unwrap_or_else(|| std::env::var("USER").unwrap_or_else(|_| "root".to_string()));
    trace.add(format!("auth: user {user}"));

    // 1. Try SSH agent
    if try_agent_auth(session, &user, trace).await.is_ok() {
        return Ok(());
    }

    // 2. Try identity file from ssh config
    if let Some(id_file) = &remote.identity_file {
        match load_private_key(id_file) {
            Ok(key) => {
                // RSA: None would map to legacy ssh-rsa (SHA-1), which modern OpenSSH
                // rejects; explicitly use rsa-sha2-256.
                let key_with_hash =
                    PrivateKeyWithHashAlg::new(Arc::new(key), Some(HashAlg::Sha256));
                let result = match session.authenticate_publickey(&user, key_with_hash).await {
                    Ok(result) => result,
                    Err(e) => {
                        trace.add(format!(
                            "auth: identity file {} → failed: {e:#}",
                            id_file.display()
                        ));
                        return Err(e.into());
                    }
                };
                if matches!(result, AuthResult::Success) {
                    trace.add(format!(
                        "auth: identity file {} → success",
                        id_file.display()
                    ));
                    return Ok(());
                }
                trace.add(format!(
                    "auth: identity file {} → rejected",
                    id_file.display()
                ));
            }
            // An unreadable identity file used to fall through silently; the
            // trace records it so the failure context is complete in one shot.
            Err(e) => trace.add(format!(
                "auth: identity file {} → failed: {e:#}",
                id_file.display()
            )),
        }
    }

    // 3. Try default ~/.ssh/id_rsa, id_ed25519, id_ecdsa
    let home = dirs::home_dir().context("cannot determine home directory")?;
    for name in &["id_rsa", "id_ed25519", "id_ecdsa"] {
        let path = home.join(".ssh").join(name);
        if !path.exists() {
            trace.add(format!(
                "auth: default keys {} → not present",
                path.display()
            ));
            continue;
        }
        let key = match load_private_key(&path) {
            Ok(key) => key,
            Err(e) => {
                trace.add(format!(
                    "auth: default keys {} → failed: {e:#}",
                    path.display()
                ));
                continue;
            }
        };
        let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(key), Some(HashAlg::Sha256));
        let result = match session.authenticate_publickey(&user, key_with_hash).await {
            Ok(result) => result,
            Err(e) => {
                trace.add(format!(
                    "auth: default keys {} → failed: {e:#}",
                    path.display()
                ));
                return Err(e.into());
            }
        };
        if matches!(result, AuthResult::Success) {
            trace.add(format!("auth: default keys {} → success", path.display()));
            return Ok(());
        }
        trace.add(format!("auth: default keys {} → rejected", path.display()));
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
async fn try_agent_auth(
    session: &mut client::Handle<ClientHandler>,
    user: &str,
    trace: &mut diagnostics::Trace,
) -> Result<()> {
    let mut agent = match russh::keys::agent::client::AgentClient::connect_env().await {
        Ok(agent) => agent,
        Err(e) => {
            let e = anyhow::Error::new(e).context("connecting to SSH agent");
            trace.add(format!("auth: agent → failed: {e:#}"));
            return Err(e);
        }
    };
    let identities = match agent.request_identities().await {
        Ok(identities) => identities,
        Err(e) => {
            let e = anyhow::Error::new(e);
            trace.add(format!("auth: agent → failed: {e:#}"));
            return Err(e);
        }
    };
    let count = identities.len();

    for identity in identities {
        let result = session
            .authenticate_publickey_with(user, identity, None, &mut agent)
            .await
            .map_err(|e| anyhow!("agent signing error: {:?}", e));
        let result = match result {
            Ok(result) => result,
            Err(e) => {
                trace.add(format!("auth: agent (identities: {count}) → failed: {e:#}"));
                return Err(e);
            }
        };
        if matches!(result, AuthResult::Success) {
            trace.add(format!("auth: agent (identities: {count}) → success"));
            return Ok(());
        }
    }

    let err = anyhow!("no agent identity was accepted");
    trace.add(format!(
        "auth: agent (identities: {count}) → rejected: {err:#}"
    ));
    Err(err)
}

#[cfg(windows)]
async fn try_agent_auth(
    _session: &mut client::Handle<ClientHandler>,
    _user: &str,
    trace: &mut diagnostics::Trace,
) -> Result<()> {
    // NOTE: this error used to be SWALLOWED by the caller's `.is_ok()` probe —
    // the user saw the generic "all authentication methods failed", not this
    // message. It is now recorded in the trace (the Err is still returned so
    // agent auth is explicitly skipped on Windows locals; identity-file auth
    // follows). russh 0.51's agent client only speaks the Unix domain-socket
    // protocol (`connect_env` is unix-only); wiring the Windows named-pipe
    // agent (Pageant/OpenSSH agent via `connect_pageant`) is a possible
    // follow-up.
    let err = anyhow!(
        "SSH agent auth is not supported on Windows (unix socket only) — use an identity file"
    );
    trace.add(format!("auth: agent → failed: {err:#}"));
    Err(err)
}

/// SSH client handler with known_hosts verification (accept-new semantics).
#[derive(Clone)]
pub struct ClientHandler {
    host: String,
    port: u16,
    /// known_hosts decisions seen during the handshake. The handler is moved
    /// into the connection future, so it cannot borrow the caller's `Trace`;
    /// the lines are parked here and drained into the trace by `connect_traced`
    /// once the handshake returns (success or failure).
    notes: Arc<std::sync::Mutex<Vec<String>>>,
}

impl ClientHandler {
    /// Park a trace line produced during the handshake (see `notes`).
    fn note(&self, msg: impl Into<String>) {
        if let Ok(mut notes) = self.notes.lock() {
            notes.push(msg.into());
        }
    }
}

impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        let home = match dirs::home_dir() {
            Some(h) => h,
            None => {
                self.note("known_hosts: no home directory — host key accepted unverified");
                return Ok(true); // can't verify without home dir
            }
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
            Ok(true) => {
                self.note("known_hosts: existing host key accepted");
                Ok(true)
            }
            Ok(false) => {
                // Host not in known_hosts — accept and persist
                crate::status!(
                    "⚠ Accepting new host key for {}:{} (not in known_hosts)",
                    self.host,
                    self.port
                );
                self.note("known_hosts: new host accepted");
                // Best-effort: write key to known_hosts for future verification
                let _ = russh::keys::known_hosts::learn_known_hosts_path(
                    &self.host,
                    self.port,
                    server_public_key,
                    &known_hosts_path,
                );
                Ok(true)
            }
            Err(_) => {
                self.note(format!(
                    "known_hosts: host key CHANGED for {}:{} — rejected (possible MITM)",
                    self.host, self.port
                ));
                Ok(false) // Key changed — reject (potential MITM)
            }
        }
    }
}

/// A live SSH session plus the jump-host sessions that carry it.
///
/// Callers keep using it as `&client::Handle<ClientHandler>` (it derefs), so a
/// `ProxyJump` chain changes nothing at the call sites. The jump handles are
/// parked here because they own the reply channel of the sessions the tunnel
/// runs over: keeping them alive for as long as the session is the honest
/// lifetime, whatever russh's driver does internally.
pub struct SshSession {
    handle: client::Handle<ClientHandler>,
    _jumps: Vec<client::Handle<ClientHandler>>,
}

impl std::ops::Deref for SshSession {
    type Target = client::Handle<ClientHandler>;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl std::ops::DerefMut for SshSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.handle
    }
}

/// A bidirectional byte stream usable as an SSH transport.
///
/// Rust trait objects may carry only one non-auto trait, so `AsyncRead +
/// AsyncWrite` needs a local supertrait instead of a bare `dyn` object.
trait ByteStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> ByteStream for T {}

/// An SSH transport: a TCP socket, or a `direct-tcpip` channel tunnelled
/// through one or more jump hosts.
type TunnelStream = std::pin::Pin<Box<dyn ByteStream + Send>>;

/// Establish SSH connection and authenticate, honouring a `ProxyJump` chain.
/// Both TCP connect and authentication are guarded by timeouts to prevent hangs.
///
/// Thin wrapper over [`connect_traced`] for callers that do not collect a
/// decision trace. Kept as the pre-trace API: every in-crate caller now uses
/// the traced variant, so the wrapper would otherwise be flagged as unused.
#[allow(dead_code)]
pub async fn connect(remote: &RemoteHost) -> Result<SshSession> {
    connect_traced(remote, &mut diagnostics::Trace::default()).await
}

/// [`connect`] with a decision trace.
///
/// Records the route (direct or jump chain), the TCP/handshake outcome (only
/// failures are interesting), the known_hosts decision, and every authentication
/// attempt, so a failure can print its full context in one shot.
pub async fn connect_traced(
    remote: &RemoteHost,
    trace: &mut diagnostics::Trace,
) -> Result<SshSession> {
    trace.add(format!(
        "connect: route {}",
        crate::jump_chain_label(remote)
    ));

    if remote.jump.is_empty() {
        let tcp = tcp_connect(remote, trace, "target").await?;
        let handle = handshake_and_auth(tcp, remote, trace, "target", target_config()).await?;
        return Ok(SshSession {
            handle,
            _jumps: Vec::new(),
        });
    }

    // Jump chain: the outermost hop is reached over plain TCP, every following
    // hop (and finally the target) through a `direct-tcpip` channel opened on
    // the session before it — the same thing `ssh -J` does.
    let total = remote.jump.len();
    let mut jumps: Vec<client::Handle<ClientHandler>> = Vec::new();

    let first = &remote.jump[0];
    let tcp = tcp_connect(first, trace, &format!("jump 1/{total}")).await?;
    let mut current =
        handshake_and_auth(tcp, first, trace, &format!("jump 1/{total}"), hop_config()).await?;

    for (i, hop) in remote.jump.iter().enumerate().skip(1) {
        let tunnel = open_tunnel(&current, hop, trace).await?;
        jumps.push(current);
        current = handshake_and_auth(
            tunnel,
            hop,
            trace,
            &format!("jump {}/{total}", i + 1),
            hop_config(),
        )
        .await?;
    }

    let tunnel = open_tunnel(&current, remote, trace).await?;
    jumps.push(current);
    let handle = handshake_and_auth(tunnel, remote, trace, "target", target_config()).await?;
    Ok(SshSession {
        handle,
        _jumps: jumps,
    })
}

/// Client config for the target session: today's defaults.
fn target_config() -> Arc<client::Config> {
    Arc::new(client::Config::default())
}

/// Client config for a jump session.
///
/// The tunnel carries the *target's* bytes, so a quiet target (an attached
/// worker waiting for output) means a quiet jump connection — and
/// `Config::default()` sends no keepalives, so a NAT/firewall idle reap would
/// kill the tunnel with no error until the next write. The target session keeps
/// the defaults so direct connections behave exactly as before.
fn hop_config() -> Arc<client::Config> {
    Arc::new(client::Config {
        keepalive_interval: Some(Duration::from_secs(30)),
        ..client::Config::default()
    })
}

/// TCP connect to a hop, with the 15s guard and a trace line on failure.
///
/// When the hop carries a SOCKS5 proxy (`ProxyCommand nc -x …`, or an explicit
/// `--socks5`), the socket is a CONNECT tunnel through that proxy instead of a
/// direct connection.
async fn tcp_connect(
    remote: &RemoteHost,
    trace: &mut diagnostics::Trace,
    role: &str,
) -> Result<tokio::net::TcpStream> {
    let port = remote.port.unwrap_or(22);
    let addr = format!("{}:{}", remote.hostname, port);
    trace.add(format!("connect: {role} {addr}"));

    // Parse the hostname for TCP connect (strip any bracket notation)
    let tcp_host = remote
        .hostname
        .trim_start_matches('[')
        .trim_end_matches(']');

    if let Some(proxy) = &remote.socks5 {
        return socks5_connect(proxy, tcp_host, port, trace)
            .await
            .with_context(|| format!("{role} {addr} via SOCKS5 proxy {proxy}"));
    }

    let tcp = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::net::TcpStream::connect((tcp_host, port)),
    )
    .await
    .with_context(|| format!("TCP connect timed out (15s) to {}", addr))
    .and_then(|r| r.with_context(|| format!("TCP connecting to {}", addr)));
    match tcp {
        Ok(stream) => Ok(stream),
        Err(e) => {
            trace.add(format!("connect: TCP connect to {addr} failed: {e:#}"));
            Err(e)
        }
    }
}

/// Connect to `host:port` through a SOCKS5 proxy (`proxy` is `HOST:PORT`).
///
/// Implements just enough of RFC 1928 for a CLI: no-auth method negotiation,
/// one `CONNECT`, and reply decoding. The returned socket is the tunnelled
/// stream, ready to be used as an SSH transport. No authentication methods are
/// attempted — a proxy that demands one gets a clear error instead of a
/// mysterious hang.
async fn socks5_connect(
    proxy: &str,
    host: &str,
    port: u16,
    trace: &mut diagnostics::Trace,
) -> Result<tokio::net::TcpStream> {
    let proxy_addr_parsed = crate::parse_user_host_port(proxy)
        .with_context(|| format!("parsing SOCKS5 proxy address {proxy:?}"))?;
    let proxy_port = proxy_addr_parsed
        .port
        .ok_or_else(|| anyhow!("SOCKS5 proxy {proxy:?} has no port"))?;
    let proxy_host = proxy_addr_parsed
        .hostname
        .trim_start_matches('[')
        .trim_end_matches(']');
    let proxy_label = format!("{proxy_host}:{proxy_port}");
    let target = format!("{host}:{port}");
    crate::progress!("⇢ socks5 {proxy_label} → {target}");
    trace.add(format!("connect: socks5 {proxy_label} → {target}"));

    let started = std::time::Instant::now();
    let mut stream = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::net::TcpStream::connect((proxy_host, proxy_port)),
    )
    .await
    .with_context(|| format!("SOCKS5 proxy {proxy_label} timed out (15s)"))
    .and_then(|r| r.with_context(|| format!("Connecting to SOCKS5 proxy {proxy_label}")))?;

    tokio::time::timeout(
        Duration::from_secs(15),
        socks5_handshake(&mut stream, host, port),
    )
    .await
    .with_context(|| {
        format!(
            "SOCKS5 handshake with {proxy_label} timed out (15s) — the proxy may not route {target}"
        )
    })?
    .with_context(|| format!("SOCKS5 CONNECT {target} through {proxy_label}"))?;

    trace.add(format!(
        "connect: socks5 tunnel to {target} established in {}ms",
        started.elapsed().as_millis()
    ));
    Ok(stream)
}

/// RFC 1928 no-auth negotiation, then one `CONNECT` for `host:port`.
///
/// The ATYP is picked from the host itself: an IP literal is sent as IPv4/IPv6
/// (no client-side DNS), a name as DOMAINNAME so the proxy resolves it — which
/// is what makes a WireGuard-internal name resolvable on the far side.
async fn socks5_handshake(stream: &mut tokio::net::TcpStream, host: &str, port: u16) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Greeting: VER=5, NMETHODS=1, METHODS=[0x00 "no authentication"].
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .context("sending the SOCKS5 greeting")?;
    let mut method = [0u8; 2];
    stream
        .read_exact(&mut method)
        .await
        .context("reading the SOCKS5 method reply")?;
    match method {
        [0x05, 0x00] => {}
        [0x05, 0x02] => {
            return Err(anyhow!(
                "SOCKS5 proxy requires username/password authentication, which rexec does not support"
            ));
        }
        [0x05, 0xff] => {
            return Err(anyhow!(
                "SOCKS5 proxy offers no acceptable authentication method"
            ));
        }
        [ver, m] => {
            return Err(anyhow!(
                "unexpected SOCKS5 method reply (version {ver:#04x}, method {m:#04x})"
            ));
        }
    }

    let mut req = vec![0x05, 0x01, 0x00];
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            req.push(0x01);
            req.extend_from_slice(&v4.octets());
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            req.push(0x04);
            req.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            let bytes = host.as_bytes();
            if bytes.len() > 255 {
                return Err(anyhow!("hostname {host:?} is too long for SOCKS5"));
            }
            req.push(0x03);
            req.push(bytes.len() as u8);
            req.extend_from_slice(bytes);
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&req)
        .await
        .context("sending the SOCKS5 CONNECT request")?;

    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .context("reading the SOCKS5 CONNECT reply")?;
    if head[0] != 0x05 {
        return Err(anyhow!("unexpected SOCKS5 reply version {:#04x}", head[0]));
    }
    if head[1] != 0x00 {
        let reason = match head[1] {
            0x01 => "general SOCKS server failure",
            0x02 => "connection not allowed by ruleset",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown SOCKS5 failure",
        };
        return Err(anyhow!(
            "SOCKS5 proxy could not reach {host}:{port}: {reason} ({:#04x})",
            head[1]
        ));
    }

    // Consume BND.ADDR/BND.PORT so the socket is positioned at the tunnel data.
    let skip = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .context("reading the SOCKS5 bound-address length")?;
            usize::from(len[0]) + 2
        }
        other => {
            return Err(anyhow!(
                "SOCKS5 reply carries unsupported address type {other:#04x}"
            ));
        }
    };
    let mut bound = vec![0u8; skip];
    stream
        .read_exact(&mut bound)
        .await
        .context("reading the SOCKS5 bound address")?;
    Ok(())
}

/// Open a `direct-tcpip` channel to `to` through `from`, as a stream usable as
/// the next hop's SSH transport.
///
/// The originator address/port are advisory (the server logs them); `127.0.0.1:0`
/// is what several clients send when they do not bind a local socket.
async fn open_tunnel(
    from: &client::Handle<ClientHandler>,
    to: &RemoteHost,
    trace: &mut diagnostics::Trace,
) -> Result<TunnelStream> {
    let host = to
        .hostname
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = to.port.unwrap_or(22);
    let addr = format!("{host}:{port}");
    trace.add(format!(
        "connect: opening direct-tcpip tunnel to {addr} through the previous hop"
    ));
    let channel = tokio::time::timeout(
        Duration::from_secs(15),
        from.channel_open_direct_tcpip(host, port as u32, "127.0.0.1", 0),
    )
    .await
    .with_context(|| format!("Tunnel to {addr} timed out (15s)"))
    .and_then(|r| r.with_context(|| format!("Opening a tunnel to {addr} through the jump host")))?;
    crate::progress!("↣ tunnel to {addr}");
    Ok(Box::pin(channel.into_stream()))
}

/// SSH handshake + authentication over an already-open transport.
///
/// `role` names the hop in trace output (`target`, `jump 1/2`, …): with a jump
/// chain in play, "connected to 10.30.40.4:22" is ambiguous, and knowing which
/// hop failed is exactly what the trace is for. `config` is per-role because a
/// jump session needs keepalives the target session does not (see `hop_config`).
async fn handshake_and_auth<R>(
    stream: R,
    remote: &RemoteHost,
    trace: &mut diagnostics::Trace,
    role: &str,
    config: Arc<client::Config>,
) -> Result<client::Handle<ClientHandler>>
where
    R: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let port = remote.port.unwrap_or(22);
    let addr = format!("{}:{}", remote.hostname, port);
    let tcp_host = remote
        .hostname
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();

    // 2. SSH handshake with 15s timeout
    let started = std::time::Instant::now();
    let handler = ClientHandler {
        host: tcp_host,
        port,
        notes: Arc::new(std::sync::Mutex::new(Vec::new())),
    };
    let notes = Arc::clone(&handler.notes);
    let handshake = tokio::time::timeout(
        Duration::from_secs(15),
        russh::client::connect_stream(config, stream, handler),
    )
    .await
    .with_context(|| format!("SSH handshake timed out (15s) with {}", addr))
    .and_then(|r| r.with_context(|| format!("SSH handshake with {}", addr)));

    // The handler — which owns the known_hosts notes — is consumed by the
    // handshake future and is not reachable through the returned session, so
    // drain them here. Also on failure: a rejected host key is exactly the case
    // that needs the context.
    if let Ok(mut pending) = notes.lock() {
        for line in pending.drain(..) {
            trace.add(line);
        }
    }

    let mut session = match handshake {
        Ok(session) => session,
        Err(e) => {
            trace.add(format!(
                "connect: {role} SSH handshake with {addr} failed: {e:#}"
            ));
            return Err(e);
        }
    };
    trace.add(format!(
        "connect: {role} {addr} connected in {}ms",
        started.elapsed().as_millis()
    ));

    // 3. Authenticate with 15s timeout
    let auth = tokio::time::timeout(
        Duration::from_secs(15),
        authenticate(&mut session, remote, &mut *trace),
    )
    .await
    .with_context(|| format!("Authentication timed out (15s) for {}", addr))
    .and_then(|r| r.with_context(|| format!("Authenticating to {}", addr)));
    match auth {
        Ok(()) => {}
        Err(e) => {
            trace.add(format!(
                "connect: {role} authentication to {addr} failed: {e:#}"
            ));
            return Err(e);
        }
    }

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
async fn remote_home_windows(
    session: &client::Handle<ClientHandler>,
    trace: &mut diagnostics::Trace,
) -> Result<String> {
    let profile = exec_remote(session, "cmd /c \"echo %USERPROFILE%\"").await?;
    let profile = profile.trim().trim_matches('"');
    let is_drive_path = profile
        .get(0..2)
        .is_some_and(|p| p.as_bytes()[0].is_ascii_alphabetic() && p.as_bytes()[1] == b':');
    if is_drive_path {
        trace.add(format!("worker: remote home {profile} (%USERPROFILE%)"));
        return Ok(profile.to_string());
    }

    // Fall back to $HOME in case someone replaced cmd; same drive-path check.
    let home = exec_remote(session, "printf %s \"$HOME\"").await?;
    let home = home.trim();
    let is_drive_path = home
        .get(0..2)
        .is_some_and(|p| p.as_bytes()[0].is_ascii_alphabetic() && p.as_bytes()[1] == b':');
    if is_drive_path {
        trace.add(format!("worker: remote home {home} ($HOME fallback)"));
        return Ok(home.to_string());
    }

    trace
        .add("worker: remote home undetected (%USERPROFILE% and $HOME are not drive-letter paths)");
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
    trace: &mut diagnostics::Trace,
) -> Result<()> {
    // Ensure the remote dir exists and learn the remote home's absolute path so
    // rsync can target it without relying on `~` expansion.
    let home = exec_remote(session, "mkdir -p ~/.rexec/logs && printf '%s' ~").await?;
    let home = home.trim().to_string();
    if home.is_empty() {
        return Err(anyhow!("could not determine remote HOME for worker upload"));
    }
    let remote_target = format!("{}:{}/.rexec/rexec", host, home.trim_end_matches('/'));
    trace.add(format!("worker: remote home {home} (~)"));

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

    trace.add(format!("worker: uploaded to {remote_target}"));
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
    trace: &mut diagnostics::Trace,
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

    trace.add(format!(
        "worker: uploaded to {exe_path} ({} bytes, sftp)",
        data.len()
    ));
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
    /// True when THIS call actually deployed (uploaded/downloaded) the
    /// worker — false when the remote was already up to date. Lets callers
    /// report the deploy fact without re-probing.
    pub deployed: bool,
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
///
/// Thin wrapper over [`ensure_remote_binary_traced`] for callers that do not
/// collect a decision trace. Kept as the pre-trace API: every in-crate caller
/// now uses the traced variant, so the wrapper would otherwise be flagged as
/// unused.
#[allow(dead_code)]
pub async fn ensure_remote_binary(
    session: &mut client::Handle<ClientHandler>,
    host: &str,
) -> Result<RemoteEnv> {
    ensure_remote_binary_traced(session, host, &mut diagnostics::Trace::default()).await
}

/// [`ensure_remote_binary`] with a decision trace: records the detected remote
/// platform, the remote home probe, the version comparison, the worker-source
/// decision, and the upload outcome.
pub async fn ensure_remote_binary_traced(
    session: &mut client::Handle<ClientHandler>,
    host: &str,
    trace: &mut diagnostics::Trace,
) -> Result<RemoteEnv> {
    let local_version = env!("CARGO_PKG_VERSION");
    let expected = format!("rexec {}", local_version);

    // Detect the platform FIRST: the POSIX probe below must not run on a
    // Windows remote — `2>/dev/null` is not a cmd/PowerShell redirect (cmd
    // would create a stray `<drive>:\dev\null` when `<drive>:\dev` exists),
    // and the round trip is wasted there anyway.
    let remote_asset = detect_remote_asset(session, trace).await?;
    let is_windows = remote_asset.starts_with("windows-");

    if is_windows {
        let home = remote_home_windows(session, trace).await?;
        // Probe via explicit `cmd /c`: a bare quoted path is a parse error
        // under a PowerShell default shell (it would need the & call
        // operator), which would make this probe ALWAYS look failed and
        // re-upload the worker on every run.
        let probe = format!(
            "cmd /c \"\"{}\\.rexec\\rexec.exe\" --version\"",
            home.trim_end_matches('\\')
        );
        let remote_output = exec_remote(session, &probe).await?;
        let up_to_date = remote_output.trim() == expected;
        trace.add(format!(
            "worker: local {local_version} vs remote {} → {}",
            remote_version_label(&remote_output),
            if up_to_date { "up to date" } else { "upload" }
        ));
        if up_to_date {
            return Ok(RemoteEnv {
                is_windows: true,
                home,
                deployed: false,
            });
        }
    } else {
        // Check remote version. This probe needs a POSIX shell and `~`
        // expansion — guaranteed on the Linux/macOS remotes detected above.
        let remote_output = exec_remote(session, "~/.rexec/rexec --version 2>/dev/null").await?;
        let up_to_date = remote_output.trim() == expected;
        trace.add(format!(
            "worker: local {local_version} vs remote {} → {}",
            remote_version_label(&remote_output),
            if up_to_date { "up to date" } else { "upload" }
        ));
        if up_to_date {
            return Ok(RemoteEnv {
                is_windows: false,
                home: String::new(),
                deployed: false,
            }); // Already up to date
        }
    }

    let src_path = if remote_asset == local_asset() {
        // Same platform: deploy the running binary. Canonicalize so a
        // symlinked install (e.g. `cargo install`) isn't copied as a link by
        // `rsync -a`.
        let exe = std::env::current_exe()
            .context("resolving current executable")?
            .canonicalize()
            .context("canonicalizing executable path")?;
        trace.add(format!("worker: source local binary {}", exe.display()));
        exe
    } else {
        download_worker(&remote_asset, trace).await?
    };

    // Upload binary: Windows has no rsync, so it takes the SFTP path with the
    // `.exe` worker name.
    let env = if is_windows {
        let home = remote_home_windows(session, trace).await?;
        upload_binary_sftp(session, &src_path, &home, trace).await?;
        RemoteEnv {
            is_windows: true,
            home,
            deployed: true,
        }
    } else {
        upload_binary(session, host, &src_path, trace).await?;
        RemoteEnv {
            is_windows: false,
            home: String::new(),
            deployed: true,
        }
    };
    // Success is silent by default; deploy notices are verbose-only (the
    // trace already records the decision for error contexts).
    crate::progress!("✓ Deployed rexec v{} to remote", local_version);
    Ok(env)
}

/// Remote worker version for a trace line: the probe prints `rexec <version>`,
/// so the prefix is dropped to sit next to the local version. Anything else
/// (missing binary, a shell error on stdout) is kept verbatim — whitespace is
/// flattened so a trace entry stays one line, and that text is what explains
/// the re-upload decision.
fn remote_version_label(probe: &str) -> String {
    let flat = probe.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.is_empty() {
        return "absent".to_string();
    }
    flat.strip_prefix("rexec ")
        .map(str::to_string)
        .unwrap_or(flat)
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
async fn detect_remote_asset(
    session: &client::Handle<ClientHandler>,
    trace: &mut diagnostics::Trace,
) -> Result<String> {
    // `exec_remote` discards the exit status, so a missing `uname` surfaces as
    // empty stdout rather than an error. A Git-for-Windows remote (default
    // shell = Git Bash) HAS a uname that prints e.g. "MINGW64_NT-10.0 ...",
    // which uname_asset rejects — so fall back to the cmd probe whenever the
    // uname output cannot be mapped, not only when it is empty.
    let uname = exec_remote(session, "uname -sm").await?;
    if !uname.trim().is_empty()
        && let Ok(asset) = uname_asset(&uname)
    {
        trace.add(format!("platform: {asset} (uname {:?})", uname.trim()));
        return Ok(asset);
    }

    let windows = exec_remote(
        session,
        r#"cmd /c "echo Windows_NT %PROCESSOR_ARCHITECTURE%""#,
    )
    .await?;
    match uname_asset(&windows) {
        Ok(asset) => {
            trace.add(format!(
                "platform: {asset} (windows probe {:?})",
                windows.trim()
            ));
            Ok(asset)
        }
        Err(e) => {
            trace.add(format!(
                "platform: undetected (uname {:?}, windows probe {:?})",
                uname.trim(),
                windows.trim()
            ));
            Err(anyhow!(
                "remote platform could not be detected (uname: {uname:?}, cmd probe: {windows:?}): {e}"
            ))
        }
    }
}

/// Download the prebuilt worker for `asset` (e.g. "linux-amd64") from GitHub
/// Releases into the local cache (~/.rexec/cache), reusing an existing copy.
///
/// The download is pinned to the running binary's version: the remote version
/// check compares against `CARGO_PKG_VERSION`, so falling back to "latest"
/// would re-deploy on every run. Requires a release tagged `v{version}` to
/// exist (created by the release workflow on tag push).
async fn download_worker(asset: &str, trace: &mut diagnostics::Trace) -> Result<PathBuf> {
    let version = env!("CARGO_PKG_VERSION");
    let home = dirs::home_dir().context("cannot determine home directory")?;
    let cache_dir = home.join(".rexec").join("cache");
    std::fs::create_dir_all(&cache_dir)
        .with_context(|| format!("creating {}", cache_dir.display()))?;
    let cache_path = cache_dir.join(format!("rexec-v{version}-{asset}"));

    let url = format!(
        "https://github.com/{}/releases/download/v{version}/rexec-{asset}",
        GITHUB_REPO
    );

    if cache_path.exists() {
        trace.add(format!(
            "worker: download rexec-{asset} from {url} (cached)"
        ));
        return Ok(cache_path);
    }
    trace.add(format!(
        "worker: download rexec-{asset} from {url} (cache miss)"
    ));
    crate::progress!("⬇ Downloading worker (rexec-{asset}) from GitHub Releases");

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
    // This function prints its findings directly, so the probe's trace lines go
    // to a throwaway trace.
    let mut probe_trace = diagnostics::Trace::default();
    if let Ok(asset) = detect_remote_asset(session, &mut probe_trace).await
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A fake SOCKS5 proxy: performs the no-auth negotiation, records the
    /// CONNECT target, answers with `connect_reply`, and (on success) echoes
    /// five bytes so the caller can prove the tunnel carries data.
    ///
    /// Returns the proxy address and a handle yielding the CONNECT target as
    /// `host:port` (`None` when the exchange stopped at the method reply).
    async fn fake_proxy(
        method_reply: u8,
        connect_reply: u8,
    ) -> (String, tokio::task::JoinHandle<Option<String>>) {
        fake_proxy_with_bnd(method_reply, connect_reply, 0x01).await
    }

    /// [`fake_proxy`] with control over the BND.ADDR address type in the reply
    /// (`0x01` = 4-byte IPv4 + port, `0x03` = length-prefixed domain + port).
    async fn fake_proxy_with_bnd(
        method_reply: u8,
        connect_reply: u8,
        bnd_atyp: u8,
    ) -> (String, tokio::task::JoinHandle<Option<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            sock.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00], "no-auth greeting");
            sock.write_all(&[0x05, method_reply]).await.unwrap();
            if method_reply != 0x00 {
                return None;
            }

            let mut head = [0u8; 4];
            sock.read_exact(&mut head).await.unwrap();
            assert_eq!(&head[..3], &[0x05, 0x01, 0x00], "CONNECT request header");
            let mut port = [0u8; 2];
            let target = match head[3] {
                0x01 => {
                    let mut v4 = [0u8; 4];
                    sock.read_exact(&mut v4).await.unwrap();
                    sock.read_exact(&mut port).await.unwrap();
                    format!(
                        "{}.{}.{}.{}:{}",
                        v4[0],
                        v4[1],
                        v4[2],
                        v4[3],
                        u16::from_be_bytes(port)
                    )
                }
                0x03 => {
                    let mut len = [0u8; 1];
                    sock.read_exact(&mut len).await.unwrap();
                    let mut name = vec![0u8; usize::from(len[0])];
                    sock.read_exact(&mut name).await.unwrap();
                    sock.read_exact(&mut port).await.unwrap();
                    format!(
                        "{}:{}",
                        String::from_utf8(name).unwrap(),
                        u16::from_be_bytes(port)
                    )
                }
                0x04 => {
                    let mut v6 = [0u8; 16];
                    sock.read_exact(&mut v6).await.unwrap();
                    sock.read_exact(&mut port).await.unwrap();
                    format!("[::1]:{}", u16::from_be_bytes(port))
                }
                other => panic!("unexpected ATYP {other:#04x}"),
            };

            let mut reply = vec![0x05, connect_reply, 0x00, bnd_atyp];
            match bnd_atyp {
                0x01 => reply.extend_from_slice(&[0, 0, 0, 0, 0, 0]),
                0x03 => {
                    // length-prefixed "bnd" + port
                    reply.push(3);
                    reply.extend_from_slice(b"bnd");
                    reply.extend_from_slice(&[0, 0]);
                }
                other => panic!("unconfigured BND ATYP {other:#04x}"),
            }
            sock.write_all(&reply).await.unwrap();
            if connect_reply == 0x00 {
                let mut buf = [0u8; 5];
                sock.read_exact(&mut buf).await.unwrap();
                sock.write_all(&buf).await.unwrap();
            }
            Some(target)
        });
        (addr.to_string(), handle)
    }

    #[tokio::test]
    async fn test_socks5_connect_tunnels_ipv4_and_traces() {
        let (proxy, fake) = fake_proxy(0x00, 0x00).await;
        let mut trace = diagnostics::Trace::default();
        let mut stream = socks5_connect(&proxy, "10.173.91.2", 22, &mut trace)
            .await
            .unwrap();

        stream.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello", "tunnel must carry both directions");

        assert_eq!(fake.await.unwrap().as_deref(), Some("10.173.91.2:22"));
        let lines = trace.lines().join("\n");
        assert!(
            lines.contains(&format!("socks5 {proxy} → 10.173.91.2:22")),
            "{lines}"
        );
        assert!(
            lines.contains("socks5 tunnel to 10.173.91.2:22 established"),
            "{lines}"
        );
    }

    #[tokio::test]
    async fn test_socks5_connect_sends_domain_names_as_domains() {
        // A name must go on the wire as DOMAINNAME (the proxy resolves it) —
        // that is what makes WireGuard-internal names work from here.
        let (proxy, fake) = fake_proxy(0x00, 0x00).await;
        let mut trace = diagnostics::Trace::default();
        let mut stream = socks5_connect(&proxy, "wg-internal.example", 2222, &mut trace)
            .await
            .unwrap();
        stream.write_all(b"probe").await.unwrap();
        let mut echoed = [0u8; 5];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(
            fake.await.unwrap().as_deref(),
            Some("wg-internal.example:2222")
        );
    }

    #[tokio::test]
    async fn test_socks5_connect_ipv6_literal_uses_atyp4() {
        let (proxy, fake) = fake_proxy(0x00, 0x00).await;
        let mut trace = diagnostics::Trace::default();
        let mut stream = socks5_connect(&proxy, "::1", 22, &mut trace).await.unwrap();
        stream.write_all(b"six16").await.unwrap();
        let mut echoed = [0u8; 5];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"six16");
        assert_eq!(fake.await.unwrap().as_deref(), Some("[::1]:22"));
    }

    #[tokio::test]
    async fn test_socks5_connect_consumes_domain_bnd_address() {
        // A proxy may answer with a BND.ADDR of any ATYP; a length-prefixed
        // domain is the one with a variable size, so a mis-parse would desync
        // the tunnel. The echo proves the socket sits exactly on the data.
        let (proxy, _fake) = fake_proxy_with_bnd(0x00, 0x00, 0x03).await;
        let mut trace = diagnostics::Trace::default();
        let mut stream = socks5_connect(&proxy, "10.173.91.2", 22, &mut trace)
            .await
            .unwrap();
        stream.write_all(b"abcde").await.unwrap();
        let mut echoed = [0u8; 5];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"abcde");
    }

    #[tokio::test]
    async fn test_socks5_connect_reports_truncated_reply() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            sock.read_exact(&mut greeting).await.unwrap();
            sock.write_all(&[0x05, 0x00]).await.unwrap();
            let mut head = [0u8; 4];
            sock.read_exact(&mut head).await.unwrap();
            // …and then close without a CONNECT reply.
        });
        let mut trace = diagnostics::Trace::default();
        let err = socks5_connect(&addr.to_string(), "10.173.91.2", 22, &mut trace)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("CONNECT reply"), "{msg}");
    }

    #[tokio::test]
    async fn test_socks5_connect_reports_missing_auth_support() {
        let (proxy, _fake) = fake_proxy(0x02, 0x00).await;
        let mut trace = diagnostics::Trace::default();
        let err = socks5_connect(&proxy, "10.173.91.2", 22, &mut trace)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("authentication"), "{msg}");
    }

    #[tokio::test]
    async fn test_socks5_connect_reports_refusal_code() {
        let (proxy, _fake) = fake_proxy(0x00, 0x05).await;
        let mut trace = diagnostics::Trace::default();
        let err = socks5_connect(&proxy, "10.173.91.2", 22, &mut trace)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("connection refused"), "{msg}");
        assert!(msg.contains("10.173.91.2:22"), "{msg}");
    }

    #[tokio::test]
    async fn test_socks5_connect_rejects_unusable_proxy_address() {
        let mut trace = diagnostics::Trace::default();
        let err = socks5_connect("127.0.0.1", "10.173.91.2", 22, &mut trace)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("no port"), "{err:#}");
    }

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

    #[test]
    fn test_remote_version_label() {
        // The worker's `--version` prints "rexec <version>"; the prefix is
        // dropped so the trace can show local vs remote side by side.
        assert_eq!(remote_version_label("rexec 0.3.0\n"), "0.3.0");
        assert_eq!(remote_version_label("rexec 0.3.1"), "0.3.1");
        // Nothing came back (missing worker, swallowed stderr) → "absent".
        assert_eq!(remote_version_label(""), "absent");
        assert_eq!(remote_version_label("  \r\n\t"), "absent");
        // Unmappable output is kept verbatim (and flattened) — that text is
        // what explains why the worker is being re-uploaded.
        assert_eq!(
            remote_version_label(
                "'C:\\Users\\x\\.rexec\\rexec.exe' is not recognized\nas an internal or external command"
            ),
            "'C:\\Users\\x\\.rexec\\rexec.exe' is not recognized as an internal or external command"
        );
    }
}

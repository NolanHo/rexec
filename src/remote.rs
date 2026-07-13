//! Remote-side logic: worker and attach modes.
//!
//! These run on the remote host, started via SSH exec by the local rexec.
//! Communication with the local side uses the binary frame protocol over
//! stdin/stdout (which are connected to the SSH channel).

use std::io::SeekFrom;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::protocol::{Frame, FrameReader, FrameType};

/// Write a frame to both the log file and stdout (SSH channel).
///
/// Log file is written first (source of truth), then stdout.
/// If stdout write fails (SSH disconnected), the flag is cleared
/// and subsequent writes skip stdout — the log file still has all data.
///
/// Returns Ok(true) on success, Ok(false) if the log file write failed
/// (non-fatal — child process should still be waited on).
async fn write_frame(
    frame: &Frame,
    log: &mut tokio::fs::File,
    stdout: &mut tokio::io::Stdout,
    stdout_ok: &mut bool,
) -> Result<bool> {
    let encoded = frame.encode();
    // Log file first — source of truth
    if log.write_all(&encoded).await.is_err() || log.flush().await.is_err() {
        // Log file write failed (disk full, etc.) — non-fatal
        // Continue streaming to stdout if possible, just can't reconnect later
        return Ok(false);
    }
    // Then try stdout (SSH channel)
    if *stdout_ok && stdout.write_all(&encoded).await.is_err() {
        *stdout_ok = false;
    }
    Ok(true)
}

/// Worker mode: spawn a child process, stream its output via the frame protocol.
///
/// Runs on the remote host. stdin/stdout are connected to the SSH channel.
/// Output is written to both the log file (always) and stdout (when connected).
/// SIGHUP is ignored so the worker survives SSH disconnection.
///
/// The child process is always waited on, even if the worker encounters errors.
/// The log file is cleaned up on successful exit (exit code 0).
pub async fn worker(command: &str) -> Result<()> {
    // Ignore SIGHUP — survive SSH disconnect
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }

    let pid = std::process::id();

    // Create log directory and file
    let home = dirs::home_dir().context("cannot determine home directory")?;
    let log_dir = home.join(".rexec").join("logs");
    std::fs::create_dir_all(&log_dir)
        .with_context(|| format!("creating {}", log_dir.display()))?;
    let log_path = log_dir.join(format!("{}.log", pid));
    let mut log_file = tokio::fs::File::create(&log_path)
        .await
        .with_context(|| format!("creating {}", log_path.display()))?;

    let mut stdout = tokio::io::stdout();
    let mut stdout_ok = true;

    // Spawn child process
    let mut child = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn child process")?;

    let mut child_stdout = child.stdout.take().unwrap();
    let mut child_stderr = child.stderr.take().unwrap();

    // Send Started frame (non-fatal if log write fails)
    write_frame(&Frame::started(pid), &mut log_file, &mut stdout, &mut stdout_ok).await?;

    // Channel for collecting output frames from stdout/stderr readers
    let (frame_tx, mut frame_rx) = mpsc::channel::<Frame>(256);

    // stdout reader task
    let tx_out = frame_tx.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match child_stdout.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx_out.send(Frame::stdout(buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // stderr reader task
    let tx_err = frame_tx.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match child_stderr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx_err.send(Frame::stderr(buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Drop last sender so frame_rx closes when both readers finish
    drop(frame_tx);

    // Main writer loop: write frames to log + stdout
    // Errors are non-fatal — we still need to wait for the child process
    while let Some(frame) = frame_rx.recv().await {
        let _ = write_frame(&frame, &mut log_file, &mut stdout, &mut stdout_ok).await;
    }

    // Always wait for child to exit, regardless of write errors
    let status = child.wait().await?;
    let exit_code = status.code().unwrap_or(-1);

    // Send Exited frame
    let _ = write_frame(
        &Frame::exited(exit_code),
        &mut log_file,
        &mut stdout,
        &mut stdout_ok,
    )
    .await;

    // Final flush
    let _ = log_file.flush().await;
    let _ = stdout.flush().await;

    // Clean up log file on successful exit (exit code 0)
    if exit_code == 0 {
        let _ = tokio::fs::remove_file(&log_path).await;
    }

    Ok(())
}

/// Attach mode: replay log from offset, then tail live.
///
/// Runs on the remote host. Reads the log file written by a worker process
/// and streams it to stdout (SSH channel). Used for reconnection after
/// SSH disconnect.
///
/// Uses a single file handle for the duration of the session.
/// Uses `read()` (not `read_exact()`) to handle partial writes gracefully.
pub async fn attach(pid: u32, offset: u64) -> Result<()> {
    let home = dirs::home_dir().context("cannot determine home directory")?;
    let log_path = home
        .join(".rexec")
        .join("logs")
        .join(format!("{}.log", pid));

    if !log_path.exists() {
        // Log file may have been deleted by the worker after successful exit.
        // Check if the process is still alive — if dead, assume success.
        let alive = unsafe { libc::kill(pid as i32, 0) == 0 };
        if !alive {
            // Worker exited and cleaned up — synthesize success exit
            let mut stdout = tokio::io::stdout();
            let frame = Frame::exited(0);
            stdout.write_all(&frame.encode()).await?;
            stdout.flush().await?;
            return Ok(());
        }
        return Err(anyhow!("log file not found for PID {} and process is alive", pid));
    }

    let mut stdout = tokio::io::stdout();
    let mut offset = offset;
    let mut reader = FrameReader::new();

    // Open file once and reuse
    let mut file = tokio::fs::File::open(&log_path).await?;
    file.seek(SeekFrom::Start(offset)).await?;

    loop {
        // Check current file size
        let file_size = match file.metadata().await {
            Ok(m) => m.len(),
            Err(_) => {
                // Can't stat — synthesize exit
                let frame = Frame::exited(-1);
                stdout.write_all(&frame.encode()).await?;
                stdout.flush().await?;
                return Ok(());
            }
        };

        if file_size > offset {
            // Seek to the new data position and read what's available
            file.seek(SeekFrom::Start(offset)).await?;

            let to_read = (file_size - offset) as usize;
            // Cap read size to avoid huge allocations
            let read_size = to_read.min(65536);
            let mut buf = vec![0u8; read_size];

            // Use read() not read_exact() — may return fewer bytes
            let n = match file.read(&mut buf).await {
                Ok(0) => 0,
                Ok(n) => n,
                Err(_) => 0, // Read error — try again next iteration
            };

            if n > 0 {
                offset += n as u64;

                // Write raw bytes to stdout (frames are already encoded in the log)
                stdout.write_all(&buf[..n]).await?;
                stdout.flush().await?;

                // Parse to check for EXITED frame
                reader.push(&buf[..n]);
                while let Some(frame) = reader.next_frame() {
                    if frame.frame_type == FrameType::Exited {
                        return Ok(()); // Process exited — done
                    }
                }
            }
        }

        // Check if worker process is still alive
        let alive = unsafe { libc::kill(pid as i32, 0) == 0 };
        if !alive && file_size <= offset {
            // Worker is dead and no more data to read.
            // Give one more chance for the filesystem to sync.
            tokio::time::sleep(Duration::from_millis(200)).await;
            let new_size = file.metadata().await.map(|m| m.len()).unwrap_or(0);
            if new_size <= offset {
                // Still no new data — synthesize exit
                let frame = Frame::exited(-1);
                stdout.write_all(&frame.encode()).await?;
                stdout.flush().await?;
                return Ok(());
            }
            // New data appeared — loop will read it
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

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
async fn write_frame(
    frame: &Frame,
    log: &mut tokio::fs::File,
    stdout: &mut tokio::io::Stdout,
    stdout_ok: &mut bool,
) -> Result<()> {
    let encoded = frame.encode();
    // Log file first — source of truth
    log.write_all(&encoded).await?;
    log.flush().await?; // fdatasync — ensure data on disk
    // Then try stdout (SSH channel)
    if *stdout_ok
        && stdout.write_all(&encoded).await.is_err() {
            *stdout_ok = false;
        }
    Ok(())
}

/// Worker mode: spawn a child process, stream its output via the frame protocol.
///
/// Runs on the remote host. stdin/stdout are connected to the SSH channel.
/// Output is written to both the log file (always) and stdout (when connected).
/// SIGHUP is ignored so the worker survives SSH disconnection.
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
        .stdin(Stdio::null()) // no stdin for now
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn child process")?;

    let mut child_stdout = child.stdout.take().unwrap();
    let mut child_stderr = child.stderr.take().unwrap();

    // Send Started frame
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
                        break; // channel closed
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
    while let Some(frame) = frame_rx.recv().await {
        write_frame(&frame, &mut log_file, &mut stdout, &mut stdout_ok).await?;
    }

    // All output drained — wait for child to exit
    let status = child.wait().await?;

    // Send Exited frame
    let exit_code = status.code().unwrap_or(-1);
    write_frame(
        &Frame::exited(exit_code),
        &mut log_file,
        &mut stdout,
        &mut stdout_ok,
    )
    .await?;

    // Final flush
    let _ = log_file.flush().await;
    let _ = stdout.flush().await;

    Ok(())
}

/// Attach mode: replay log from offset, then tail live.
///
/// Runs on the remote host. Reads the log file written by a worker process
/// and streams it to stdout (SSH channel). Used for reconnection after
/// SSH disconnect.
pub async fn attach(pid: u32, offset: u64) -> Result<()> {
    let home = dirs::home_dir().context("cannot determine home directory")?;
    let log_path = home
        .join(".rexec")
        .join("logs")
        .join(format!("{}.log", pid));

    if !log_path.exists() {
        return Err(anyhow!("log file not found for PID {}", pid));
    }

    let mut stdout = tokio::io::stdout();
    let mut offset = offset;
    let mut reader = FrameReader::new();

    loop {
        // Check current file size
        let file_size = match tokio::fs::metadata(&log_path).await {
            Ok(m) => m.len(),
            Err(_) => {
                // Log file deleted — synthesize exit
                let frame = Frame::exited(-1);
                stdout.write_all(&frame.encode()).await?;
                stdout.flush().await?;
                return Ok(());
            }
        };

        if file_size > offset {
            // Read new data from offset
            let mut file = tokio::fs::File::open(&log_path).await?;
            file.seek(SeekFrom::Start(offset)).await?;

            let to_read = (file_size - offset) as usize;
            let mut buf = vec![0u8; to_read];
            file.read_exact(&mut buf).await?;
            offset = file_size;

            // Write raw bytes to stdout (frames are already encoded in the log)
            stdout.write_all(&buf).await?;
            stdout.flush().await?;

            // Parse to check for EXITED frame
            reader.push(&buf);
            while let Some(frame) = reader.next_frame() {
                if frame.frame_type == FrameType::Exited {
                    return Ok(()); // Process exited — done
                }
            }
        }

        // Check if worker process is still alive
        let alive = unsafe { libc::kill(pid as i32, 0) == 0 };
        if !alive && file_size <= offset {
            // Worker is dead and no more data to read.
            // Give one more chance for the filesystem to sync.
            tokio::time::sleep(Duration::from_millis(200)).await;
            let new_size = tokio::fs::metadata(&log_path).await.map(|m| m.len()).unwrap_or(0);
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

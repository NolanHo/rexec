//! Binary frame protocol for rexec communication over SSH channels.
//!
//! Frame format: [1 byte type][4 bytes BE length][payload]
//!
//! Frames are written identically to both the SSH channel (live stream)
//! and the log file (durable storage). This means the byte offset in the
//! log file always equals the total bytes sent over the channel.

/// Frame type identifier.
///
/// Output frames (remote → local) use 0x01–0x0F.
/// Input frames (local → remote) use 0x10–0x1F.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    // ── Output: remote → local ──
    /// Child process stdout data.
    Stdout = 0x01,
    /// Child process stderr data.
    Stderr = 0x02,
    /// Worker started. Payload: 4-byte PID (u32 BE).
    Started = 0x03,
    /// Child process exited. Payload: 4-byte exit code (i32 BE).
    Exited = 0x04,

    // ── Input: local → remote ──
    /// Data for child process stdin.
    Stdin = 0x10,
    /// Terminal resize. Payload: 2-byte cols (u16 BE) + 2-byte rows (u16 BE).
    Resize = 0x11,
    /// Send signal to child. Payload: 4-byte signum (i32 BE).
    Signal = 0x12,
    /// stdin EOF (no payload).
    Eof = 0x13,
}

impl FrameType {
    /// Parse a raw byte into a FrameType.
    /// Returns None for unknown byte values.
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0x01 => Self::Stdout,
            0x02 => Self::Stderr,
            0x03 => Self::Started,
            0x04 => Self::Exited,
            0x10 => Self::Stdin,
            0x11 => Self::Resize,
            0x12 => Self::Signal,
            0x13 => Self::Eof,
            _ => return None,
        })
    }
}

/// Header size: 1 byte type + 4 bytes length.
pub const HEADER_LEN: usize = 5;

/// A single protocol frame.
pub struct Frame {
    pub frame_type: FrameType,
    pub data: Vec<u8>,
}

impl Frame {
    pub fn new(frame_type: FrameType, data: Vec<u8>) -> Self {
        Self { frame_type, data }
    }

    /// Encode to wire format: [type: 1B][len: 4B BE][data].
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_LEN + self.data.len());
        buf.push(self.frame_type as u8);
        buf.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Encoded size (header + payload).
    #[allow(dead_code)]
    pub fn encoded_len(&self) -> usize {
        HEADER_LEN + self.data.len()
    }

    // ── Convenience constructors ──

    pub fn stdout(data: impl Into<Vec<u8>>) -> Self {
        Self::new(FrameType::Stdout, data.into())
    }

    pub fn stderr(data: impl Into<Vec<u8>>) -> Self {
        Self::new(FrameType::Stderr, data.into())
    }

    pub fn started(pid: u32) -> Self {
        Self::new(FrameType::Started, pid.to_be_bytes().to_vec())
    }

    pub fn exited(code: i32) -> Self {
        Self::new(FrameType::Exited, code.to_be_bytes().to_vec())
    }

    #[allow(dead_code)]
    pub fn stdin(data: impl Into<Vec<u8>>) -> Self {
        Self::new(FrameType::Stdin, data.into())
    }

    // ── Payload parsers ──

    pub fn as_pid(&self) -> Option<u32> {
        if self.frame_type == FrameType::Started && self.data.len() == 4 {
            Some(u32::from_be_bytes(self.data[..].try_into().unwrap()))
        } else {
            None
        }
    }

    pub fn as_exit_code(&self) -> Option<i32> {
        if self.frame_type == FrameType::Exited && self.data.len() == 4 {
            Some(i32::from_be_bytes(self.data[..].try_into().unwrap()))
        } else {
            None
        }
    }
}

/// Incremental frame parser for streaming data (e.g. from SSH channel messages).
///
/// Push data as it arrives, then pull complete frames.
pub struct FrameReader {
    buf: Vec<u8>,
}

impl Default for FrameReader {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameReader {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Append incoming bytes.
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Total bytes consumed by all frames returned so far.
    #[allow(dead_code)]
    pub fn consumed(&self) -> u64 {
        self.buf.len() as u64
    }

    /// Try to parse the next complete frame from the buffer.
    /// Returns None if not enough data yet.
    pub fn next_frame(&mut self) -> Option<Frame> {
        if self.buf.len() < HEADER_LEN {
            return None;
        }
        let len = u32::from_be_bytes([
            self.buf[1],
            self.buf[2],
            self.buf[3],
            self.buf[4],
        ]) as usize;

        // Sanity check: reject absurdly large frames (max 16 MiB)
        if len > 16 * 1024 * 1024 {
            // Corrupted stream — drain buffer to force reconnection
            self.buf.clear();
            return None;
        }

        let total = HEADER_LEN + len;
        if self.buf.len() < total {
            return None;
        }

        let frame_type = FrameType::from_byte(self.buf[0])?;
        let data = self.buf[HEADER_LEN..total].to_vec();
        self.buf.drain(0..total);
        Some(Frame {
            frame_type,
            data,
        })
    }
}

/// Read frames from a byte slice (e.g. log file content).
/// Returns parsed frames and the total bytes consumed.
#[allow(dead_code)]
pub fn parse_frames(data: &[u8]) -> (Vec<Frame>, usize) {
    let mut reader = FrameReader::new();
    reader.push(data);
    let mut frames = Vec::new();
    while let Some(frame) = reader.next_frame() {
        frames.push(frame);
    }
    let consumed = data.len() - reader.consumed() as usize;
    (frames, consumed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let frame = Frame::stdout(b"hello world".to_vec());
        let encoded = frame.encode();
        assert_eq!(encoded.len(), HEADER_LEN + 11);

        let mut reader = FrameReader::new();
        reader.push(&encoded);
        let decoded = reader.next_frame().unwrap();
        assert_eq!(decoded.frame_type, FrameType::Stdout);
        assert_eq!(decoded.data, b"hello world");
        assert!(reader.next_frame().is_none());
    }

    #[test]
    fn test_partial_frame() {
        let frame = Frame::stdout(b"hello".to_vec());
        let encoded = frame.encode();

        let mut reader = FrameReader::new();
        reader.push(&encoded[..3]); // partial header
        assert!(reader.next_frame().is_none());

        reader.push(&encoded[3..]); // rest
        let decoded = reader.next_frame().unwrap();
        assert_eq!(decoded.data, b"hello");
    }

    #[test]
    fn test_multiple_frames_in_one_push() {
        let f1 = Frame::stdout(b"aaa".to_vec());
        let f2 = Frame::stderr(b"bbb".to_vec());
        let f3 = Frame::exited(0);

        let mut combined = Vec::new();
        combined.extend_from_slice(&f1.encode());
        combined.extend_from_slice(&f2.encode());
        combined.extend_from_slice(&f3.encode());

        let mut reader = FrameReader::new();
        reader.push(&combined);

        let d1 = reader.next_frame().unwrap();
        assert_eq!(d1.frame_type, FrameType::Stdout);
        assert_eq!(d1.data, b"aaa");

        let d2 = reader.next_frame().unwrap();
        assert_eq!(d2.frame_type, FrameType::Stderr);
        assert_eq!(d2.data, b"bbb");

        let d3 = reader.next_frame().unwrap();
        assert_eq!(d3.frame_type, FrameType::Exited);
        assert_eq!(d3.as_exit_code(), Some(0));

        assert!(reader.next_frame().is_none());
    }

    #[test]
    fn test_parse_frames_consumed() {
        let f1 = Frame::stdout(b"aaa".to_vec());
        let f2 = Frame::exited(0);
        let mut data = Vec::new();
        data.extend_from_slice(&f1.encode());
        data.extend_from_slice(&f2.encode());

        let (frames, consumed) = parse_frames(&data);
        assert_eq!(frames.len(), 2);
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_started_pid_roundtrip() {
        let frame = Frame::started(12345);
        assert_eq!(frame.as_pid(), Some(12345));
    }

    #[test]
    fn test_unknown_byte_rejected() {
        let frame_type = FrameType::from_byte(0xFF);
        assert!(frame_type.is_none());
    }

    #[test]
    fn test_no_value_collision() {
        // Ensure output and input types don't share the same byte value
        let all_types = [
            FrameType::Stdout, FrameType::Stderr,
            FrameType::Started, FrameType::Exited,
            FrameType::Stdin, FrameType::Resize,
            FrameType::Signal, FrameType::Eof,
        ];
        let mut seen = std::collections::HashSet::new();
        for ft in &all_types {
            assert!(seen.insert(*ft as u8), "duplicate byte value: {:#04x}", *ft as u8);
        }
    }
}

//! The writer side of the Frame Streams protocol
//! (<https://farsightsec.github.io/fstrm/>), bidirectional, as
//! golang-framestream's `Encoder` with `Bidirectional: true` speaks it:
//! READY (with the content type) → ACCEPT → START, then data frames (a
//! 32-bit big-endian length and the payload), and STOP → FINISH on close.
//! Control frames are escaped by a zero length.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter};

pub const CONTENT_TYPE: &[u8] = b"protobuf:dnstap.Dnstap";

pub const CONTROL_ACCEPT: u32 = 1;
pub const CONTROL_START: u32 = 2;
pub const CONTROL_STOP: u32 = 3;
pub const CONTROL_READY: u32 = 4;
pub const CONTROL_FINISH: u32 = 5;
const CONTROL_FIELD_CONTENT_TYPE: u32 = 1;
const CONTROL_FRAME_LENGTH_MAX: u32 = 512;

/// An escaped control frame with its content types.
pub fn control_frame(typ: u32, content_types: &[&[u8]]) -> Vec<u8> {
    let mut body = typ.to_be_bytes().to_vec();
    for ct in content_types {
        body.extend_from_slice(&CONTROL_FIELD_CONTENT_TYPE.to_be_bytes());
        body.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        body.extend_from_slice(ct);
    }
    let mut out = vec![0, 0, 0, 0];
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

fn decode_err(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("decoding error: {what}"))
}

/// Read an escaped control frame of type `want`; its content types.
pub async fn read_control<R: AsyncRead + Unpin>(r: &mut R, want: u32) -> io::Result<Vec<Vec<u8>>> {
    if r.read_u32().await? != 0 {
        return Err(decode_err("expected a control frame"));
    }
    let len = r.read_u32().await?;
    if !(4..=CONTROL_FRAME_LENGTH_MAX).contains(&len) {
        return Err(decode_err("bad control frame length"));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    let typ = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let mut rest = &body[4..];
    let mut types = Vec::new();
    while rest.len() > 8 {
        let ft = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
        let fl = u32::from_be_bytes([rest[4], rest[5], rest[6], rest[7]]) as usize;
        rest = &rest[8..];
        if ft != CONTROL_FIELD_CONTENT_TYPE || fl > rest.len() {
            return Err(decode_err("bad control field"));
        }
        types.push(rest[..fl].to_vec());
        rest = &rest[fl..];
    }
    if !rest.is_empty() {
        return Err(decode_err("trailing control frame bytes"));
    }
    if typ != want {
        return Err(decode_err("unexpected control frame type"));
    }
    Ok(types)
}

/// A connected Frame Streams writer.
pub struct Encoder<S> {
    w: BufWriter<S>,
    timeout: Duration,
}

async fn timed<T>(t: Duration, f: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout(t, f)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "i/o timeout"))?
}

impl<S: AsyncRead + AsyncWrite + Unpin> Encoder<S> {
    /// Do the bidirectional handshake on `s`. `timeout` bounds every write
    /// and every read of a control frame.
    pub async fn new(s: S, timeout: Duration) -> io::Result<Self> {
        let mut w = BufWriter::new(s);
        timed(timeout, async {
            w.write_all(&control_frame(CONTROL_READY, &[CONTENT_TYPE])).await?;
            w.flush().await
        })
        .await?;
        let accepted = timed(timeout, read_control(w.get_mut(), CONTROL_ACCEPT)).await?;
        // like ChooseContentType: no types on either side means "any"
        let content_type: &[u8] = if accepted.is_empty() {
            &[]
        } else if accepted.iter().any(|t| t == CONTENT_TYPE) {
            CONTENT_TYPE
        } else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "content type mismatch"));
        };
        let start = if content_type.is_empty() {
            control_frame(CONTROL_START, &[])
        } else {
            control_frame(CONTROL_START, &[content_type])
        };
        timed(timeout, async {
            w.write_all(&start).await?;
            w.flush().await
        })
        .await?;
        Ok(Self { w, timeout })
    }

    /// Buffer one data frame (written out when the buffer fills or on
    /// [`flush`](Self::flush)).
    pub async fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        let w = &mut self.w;
        timed(self.timeout, async {
            w.write_all(&(frame.len() as u32).to_be_bytes()).await?;
            w.write_all(frame).await
        })
        .await
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        timed(self.timeout, self.w.flush()).await
    }

    /// STOP, then wait for FINISH.
    pub async fn close(mut self) -> io::Result<()> {
        let w = &mut self.w;
        timed(self.timeout, async {
            w.write_all(&control_frame(CONTROL_STOP, &[])).await?;
            w.flush().await
        })
        .await?;
        timed(self.timeout, read_control(self.w.get_mut(), CONTROL_FINISH)).await?;
        let _ = self.w.shutdown().await;
        Ok(())
    }
}

/// The reader side, for tests and the benchmark sink: accept the
/// handshake on `s`, then hand every data frame to `f` until STOP.
pub async fn read_stream<S, F>(mut s: S, mut f: F) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(Vec<u8>),
{
    let types = read_control(&mut s, CONTROL_READY).await?;
    let accept: Vec<&[u8]> = types.iter().map(|t| t.as_slice()).collect();
    s.write_all(&control_frame(CONTROL_ACCEPT, &accept)).await?;
    s.flush().await?;
    read_control(&mut s, CONTROL_START).await?;
    loop {
        let len = s.read_u32().await?;
        if len == 0 {
            // a control frame: STOP
            let clen = s.read_u32().await?;
            let mut body = vec![0u8; clen as usize];
            s.read_exact(&mut body).await?;
            if body.len() >= 4 && u32::from_be_bytes([body[0], body[1], body[2], body[3]]) == CONTROL_STOP {
                s.write_all(&control_frame(CONTROL_FINISH, &[])).await?;
                s.flush().await?;
                return Ok(());
            }
            continue;
        }
        let mut buf = vec![0u8; len as usize];
        s.read_exact(&mut buf).await?;
        f(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn handshake_frames_and_close() {
        let (a, b) = tokio::io::duplex(4096);
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            read_stream(b, |f| got.push(f)).await.unwrap();
            got
        });
        let mut enc = Encoder::new(a, Duration::from_secs(1)).await.unwrap();
        enc.write_frame(b"one").await.unwrap();
        enc.write_frame(b"two").await.unwrap();
        enc.flush().await.unwrap();
        enc.close().await.unwrap();
        assert_eq!(reader.await.unwrap(), vec![b"one".to_vec(), b"two".to_vec()]);
    }

    #[test]
    fn control_encoding() {
        // golang-framestream: escape, length, type, content type field
        let f = control_frame(CONTROL_READY, &[b"ab"]);
        assert_eq!(
            f,
            [0, 0, 0, 0, 0, 0, 0, 14, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 2, b'a', b'b']
        );
    }

    #[tokio::test]
    async fn mismatched_content_type() {
        let (a, mut b) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            read_control(&mut b, CONTROL_READY).await.unwrap();
            b.write_all(&control_frame(CONTROL_ACCEPT, &[b"other"])).await.unwrap();
            let _ = b.read_u8().await;
        });
        assert!(Encoder::new(a, Duration::from_secs(1)).await.is_err());
    }
}

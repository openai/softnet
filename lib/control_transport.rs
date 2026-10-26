use crate::network::MAX_VMS;
use anyhow::{Context, Result, anyhow, bail};
use bytes::BytesMut;
use nix::sys::socket::{SockType, getsockopt, sockopt};
use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio_util::codec::{Decoder, LinesCodec};
use unix_ancillary::AsyncUnixStreamExt;

const READ_BUFFER_BYTES: usize = 4096;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_FRAME_FDS: usize = MAX_VMS;

pub(crate) struct ControlTransport {
    socket: UnixStream,
    buffered: BytesMut,
}

#[derive(Debug)]
pub(crate) struct Frame {
    pub(crate) line: Result<String>,
    pub(crate) fds: Vec<OwnedFd>,
}

impl ControlTransport {
    pub(crate) fn new(control_fd: RawFd) -> Result<Self> {
        // SAFETY: fcntl checks whether the descriptor is open before taking ownership
        if unsafe { libc::fcntl(control_fd, libc::F_GETFD) } == -1 {
            return Err(io::Error::last_os_error()).context("invalid control file descriptor");
        }

        // SAFETY: fcntl verified the descriptor is open, so we transfer the ownership
        let stream = unsafe { StdUnixStream::from_raw_fd(control_fd) };

        // Validate the inherited socket before registering it with Tokio
        let socket_type = getsockopt(&stream, sockopt::SockType)
            .context("control file descriptor is not a socket")?;

        if socket_type != SockType::Stream {
            bail!("control file descriptor is not a Unix stream socket");
        }

        stream
            .peer_addr()
            .context("control descriptor is not a connected Unix socket")?;

        // Tokio requires the socket to be nonblocking before doing UnixStream::from_std()
        stream.set_nonblocking(true)?;

        Ok(Self {
            socket: UnixStream::from_std(stream)?,
            buffered: BytesMut::with_capacity(READ_BUFFER_BYTES),
        })
    }

    pub(crate) async fn next(&mut self) -> io::Result<Option<Frame>> {
        // Resume with bytes read beyond the previous frame's newline
        let mut input = std::mem::take(&mut self.buffered);
        let mut fds = Vec::new();
        let mut frame_error = None;
        let mut buffer = [0_u8; READ_BUFFER_BYTES];

        // Keep the decoder unlimited so oversized requests can be read through their newline before rejection
        let mut codec = LinesCodec::new();

        loop {
            // Decode first so bytes after this frame's newline do not count toward its size
            let buffered_length = input.len();
            let line = codec.decode(&mut input).transpose();

            // The size limit excludes the newline but includes any carriage return removed by the codec
            let length = if line.is_some() {
                buffered_length - input.len() - 1
            } else {
                input.len()
            };

            if length > MAX_REQUEST_BYTES {
                frame_error
                    .get_or_insert_with(|| anyhow!("request exceeds the maximum frame size"));
            }

            // Return the frame only after its newline, including any error recorded while reading it
            if let Some(line) = line {
                let line = match frame_error {
                    Some(error) => Err(error),
                    None => line.context("invalid UTF-8 in control frame"),
                };

                // Close all descriptors belonging to a rejected frame
                if line.is_err() {
                    fds.clear();
                }

                // Keep any bytes after this frame's newline for the next call
                self.buffered = input;

                return Ok(Some(Frame { line, fds }));
            }

            // Discard invalid frame data and close its descriptors while reading up to the newline
            if frame_error.is_some() {
                input.clear();
                fds.clear();

                // Reset the decoder's search position after clearing its input
                codec = LinesCodec::new();
            }

            // Let other tasks run even while a large request keeps the socket readable
            tokio::task::consume_budget().await;

            // POSIX §2.10.11 states that:
            //
            // >A receive operation shall never return data or ancillary data from more than one segment.
            //
            // macOS is UNIX 03 certified [2], which requires conformance to these POSIX socket semantics.
            //
            // [1]: https://pubs.opengroup.org/onlinepubs/000095399/functions/xsh_chap02_10.html#tag_02_10_11
            // [2]: https://www.opengroup.org/openbrand/register/apple.htm

            // Receive one extra descriptor so oversized batches can be detected and rejected
            let (received, received_fds) = self
                .socket
                .recv_fds_into::<{ MAX_FRAME_FDS + 1 }>(&mut buffer)
                .await?;

            if received == 0 {
                // Discard any remaining bytes when the stream ends because a request must end with a newline
                return Ok(None);
            }

            // Accept descriptors only with the first bytes of a new frame
            if !received_fds.is_empty() {
                if !input.is_empty() || frame_error.is_some() {
                    frame_error.get_or_insert_with(|| {
                        anyhow!("descriptors must accompany the first byte of a frame")
                    });
                } else if received_fds.len() > MAX_FRAME_FDS {
                    frame_error
                        .get_or_insert_with(|| anyhow!("too many descriptors attached to a frame"));
                }
            }

            // Accumulate bytes and descriptors until a complete frame can be decoded
            fds.extend(received_fds);
            input.extend_from_slice(&buffer[..received]);
        }
    }

    pub(crate) async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.socket.write_all(bytes).await?;
        self.socket.write_all(b"\n").await
    }
}

#[cfg(test)]
#[path = "control_transport_test.rs"]
mod tests;

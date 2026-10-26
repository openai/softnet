use super::{ControlTransport, MAX_FRAME_FDS, MAX_REQUEST_BYTES, READ_BUFFER_BYTES};
use futures_util::FutureExt;
use std::io::{Read, Write};
use std::os::fd::IntoRawFd;
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use tokio::io::AsyncWriteExt;
use unix_ancillary::{AsyncUnixStreamExt, UnixStreamExt};

fn socket_pair() -> (ControlTransport, UnixStream) {
    let (socket, peer) = UnixStream::pair().unwrap();
    let control = ControlTransport::new(socket.into_raw_fd()).unwrap();

    (control, peer)
}

fn assert_peer_closed(peer: &mut UnixStream) {
    peer.set_nonblocking(true).unwrap();

    assert_eq!(peer.read(&mut [0_u8]).unwrap(), 0);
}

#[tokio::test]
async fn receives_maximum_batch_in_descriptor_order() {
    let (mut socket, peer) = socket_pair();
    let (descriptors, peers): (Vec<_>, Vec<_>) = (0..MAX_FRAME_FDS)
        .map(|_| UnixDatagram::pair().unwrap())
        .unzip();
    let references = descriptors.iter().collect::<Vec<_>>();
    peer.send_fds_all(b"batch\n", &references).unwrap();

    // Distinct datagrams identify every VM socket's position in the batch
    for (index, peer) in peers.iter().enumerate() {
        assert_eq!(peer.send(&[index as u8]).unwrap(), 1);
    }

    let frame = socket.next().await.unwrap().unwrap();
    assert_eq!(frame.line.as_deref().unwrap(), "batch");
    assert_eq!(frame.fds.len(), MAX_FRAME_FDS);

    // Close sender copies after Darwin has installed the complete rights batch
    drop(descriptors);

    for (index, fd) in frame.fds.into_iter().enumerate() {
        let datagram = UnixDatagram::from(fd);
        let mut byte = [0];
        assert_eq!(datagram.recv(&mut byte).unwrap(), 1);
        assert_eq!(byte, [index as u8]);
    }
}

#[tokio::test]
async fn fragmented_bulk_frames_preserve_following_descriptor_boundaries() {
    let (mut socket, mut peer) = socket_pair();
    let (first, mut first_peer) = UnixStream::pair().unwrap();
    let (second, mut second_peer) = UnixStream::pair().unwrap();
    let mut bytes = vec![b'x'; 2 * READ_BUFFER_BYTES + 17];
    bytes.push(b'\n');
    let fragment_length = READ_BUFFER_BYTES + 37;
    peer.send_fds_all(&bytes[..1], &[&first]).unwrap();
    peer.write_all(&bytes[1..fragment_length]).unwrap();
    drop(first);
    socket.socket.readable().await.unwrap();

    // Retain the first attachment while waiting for the rest of a large frame
    let mut pending = Box::pin(socket.next());
    assert!(pending.as_mut().now_or_never().is_none());

    // Complete the frame while its read remains pending
    peer.set_nonblocking(true).unwrap();
    let mut peer = tokio::net::UnixStream::from_std(peer).unwrap();
    let (frame, write) = tokio::join!(pending, async {
        peer.write_all(&bytes[fragment_length..]).await?;
        peer.send_fds_all(b"attached\nplain\nlast\r\n", &[&second])
            .await
    });
    write.unwrap();
    drop(second);
    let frame = frame.unwrap().unwrap();

    assert_eq!(
        frame.line.as_ref().unwrap().len(),
        2 * READ_BUFFER_BYTES + 17
    );
    assert_eq!(frame.fds.len(), 1);
    drop(frame);
    assert_peer_closed(&mut first_peer);

    let frame = socket.next().await.unwrap().unwrap();
    assert_eq!(frame.line.as_deref().unwrap(), "attached");
    assert_eq!(frame.fds.len(), 1);
    drop(frame);
    assert_peer_closed(&mut second_peer);

    let frame = socket.next().await.unwrap().unwrap();
    assert_eq!(frame.line.as_deref().unwrap(), "plain");
    assert!(frame.fds.is_empty());

    let frame = socket.next().await.unwrap().unwrap();
    assert_eq!(frame.line.as_deref().unwrap(), "last");
    assert!(frame.fds.is_empty());
}

#[tokio::test]
async fn cancelling_a_partial_frame_closes_its_descriptors() {
    let (mut socket, mut peer) = socket_pair();
    let (descriptor, mut descriptor_peer) = UnixStream::pair().unwrap();
    peer.send_fds_all(b"{", &[&descriptor; MAX_FRAME_FDS])
        .unwrap();
    drop(descriptor);
    socket.socket.readable().await.unwrap();

    // Poll the partial frame, then cancel its pending read
    assert!(socket.next().now_or_never().is_none());

    assert_peer_closed(&mut descriptor_peer);
    drop(socket);
    assert_peer_closed(&mut peer);
}

#[tokio::test]
async fn unterminated_batch_closes_every_descriptor() {
    let (mut socket, peer) = socket_pair();
    let (descriptor, mut descriptor_peer) = UnixStream::pair().unwrap();
    peer.send_fds_all(b"{", &[&descriptor; MAX_FRAME_FDS])
        .unwrap();
    drop(descriptor);
    drop(peer);

    // EOF rejects the truncated JSON frame and releases all its attachments
    assert!(socket.next().await.unwrap().is_none());
    assert_peer_closed(&mut descriptor_peer);
}

#[tokio::test]
async fn rejects_mid_frame_descriptors_and_recovers_at_newline() {
    // Reject attachments even when they follow a complete read chunk
    for prefix_length in [1, READ_BUFFER_BYTES + 13] {
        let (mut socket, mut peer) = socket_pair();
        let (descriptor, mut descriptor_peer) = UnixStream::pair().unwrap();
        peer.write_all(&vec![b'{'; prefix_length]).unwrap();
        peer.send_fds_all(b"}\n{}\n", &[&descriptor]).unwrap();
        drop(descriptor);

        let frame = socket.next().await.unwrap().unwrap();

        assert!(frame.line.is_err());
        assert!(frame.fds.is_empty());
        assert_peer_closed(&mut descriptor_peer);
        assert_eq!(socket.next().await.unwrap().unwrap().line.unwrap(), "{}");
    }
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn descriptor_only_messages_close_received_descriptors() {
    use std::io::IoSlice;
    use std::os::fd::AsFd;
    use unix_ancillary::{SocketAncillary, cmsg_sendmsg};

    let (mut socket, mut peer) = socket_pair();
    let (first, mut first_peer) = UnixStream::pair().unwrap();
    let (second, mut second_peer) = UnixStream::pair().unwrap();
    peer.write_all(b"{").unwrap();

    // Darwin accepts descriptor-only sends with one empty payload slice
    for descriptor in [&first, &second] {
        let mut storage = vec![0; SocketAncillary::buffer_size_for_rights(1)];
        let mut ancillary = SocketAncillary::new(&mut storage);
        ancillary.add_fds(&[descriptor.as_fd()]).unwrap();
        assert_eq!(
            cmsg_sendmsg(peer.as_fd(), &[IoSlice::new(b"")], &ancillary).unwrap(),
            0
        );
    }

    peer.write_all(b"}\n").unwrap();
    drop(first);
    drop(second);

    assert!(socket.next().await.unwrap().is_none());
    assert_peer_closed(&mut first_peer);
    drop(socket);
    assert_peer_closed(&mut second_peer);
}

#[tokio::test]
async fn excessive_attachments_close_every_descriptor_without_kernel_truncation() {
    for count in [MAX_FRAME_FDS + 1, 253] {
        let (mut socket, mut peer) = socket_pair();
        let (descriptor, mut descriptor_peer) = UnixStream::pair().unwrap();
        let descriptors = vec![&descriptor; count];
        peer.send_fds_all(b"{}\n", &descriptors).unwrap();
        peer.write_all(b"next\n").unwrap();
        drop(descriptor);

        let frame = socket.next().await.unwrap().unwrap();

        assert!(frame.line.is_err());
        assert!(frame.fds.is_empty());
        assert_peer_closed(&mut descriptor_peer);
        assert_eq!(socket.next().await.unwrap().unwrap().line.unwrap(), "next");
    }
}

#[tokio::test]
async fn validates_owned_descriptor_and_signals_eof_on_drop() {
    let file = std::fs::File::open("/dev/null").unwrap();
    assert!(ControlTransport::new(file.into_raw_fd()).is_err());

    let (datagram, peer) = UnixDatagram::pair().unwrap();
    assert!(ControlTransport::new(datagram.into_raw_fd()).is_err());
    assert!(peer.send(&[0]).is_err());

    // A connected TCP stream passes the type check but must fail Unix address validation
    let internet_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let internet = std::net::TcpStream::connect(internet_listener.local_addr().unwrap()).unwrap();
    assert!(ControlTransport::new(internet.into_raw_fd()).is_err());

    let path = std::env::temp_dir().join(format!("softnet-control-{}.sock", std::process::id()));
    let listener = UnixListener::bind(&path).unwrap();
    assert!(ControlTransport::new(listener.into_raw_fd()).is_err());
    std::fs::remove_file(path).unwrap();

    assert!(ControlTransport::new(-1).is_err());

    let (socket, mut peer) = UnixStream::pair().unwrap();
    let control = ControlTransport::new(socket.into_raw_fd()).unwrap();
    drop(control);

    assert_peer_closed(&mut peer);
}

#[tokio::test]
async fn frame_size_limit_preserves_descriptor_ownership_and_recovers() {
    for size in [MAX_REQUEST_BYTES, MAX_REQUEST_BYTES + 1] {
        let (mut socket, peer) = socket_pair();
        let (descriptor, mut descriptor_peer) = UnixStream::pair().unwrap();
        peer.send_fds_all(b"x", &[&descriptor]).unwrap();
        drop(descriptor);
        peer.set_nonblocking(true).unwrap();
        let mut peer = tokio::net::UnixStream::from_std(peer).unwrap();
        let mut bytes = vec![b'x'; size - 1];
        bytes.extend_from_slice(b"\nnext\n");

        // Exercise both sides of the frame limit through actual socket input
        let (write, frame) = tokio::join!(peer.write_all(&bytes), socket.next());
        write.unwrap();
        let frame = frame.unwrap().unwrap();
        if size == MAX_REQUEST_BYTES {
            assert_eq!(frame.line.as_ref().unwrap().len(), size);
            assert_eq!(frame.fds.len(), 1);
        } else {
            assert!(frame.line.is_err());
            assert!(frame.fds.is_empty());
        }

        drop(frame);
        assert_peer_closed(&mut descriptor_peer);
        assert_eq!(socket.next().await.unwrap().unwrap().line.unwrap(), "next");
    }
}

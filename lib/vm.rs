use anyhow::{Context, Result, bail};
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixDatagram;

pub struct VM {
    sock: UnixDatagram,
}

impl VM {
    pub fn new(vm_fd: RawFd) -> Result<VM> {
        let vm_fd = duplicate_vm_fd(vm_fd)?;

        // SAFETY: duplicate_vm_fd only returns a valid descriptor that it owns.
        let sock = unsafe { UnixDatagram::from_raw_fd(vm_fd) };
        sock.set_nonblocking(true)?;

        Ok(VM { sock })
    }

    pub fn write(&self, pkt: &[u8]) -> std::io::Result<usize> {
        self.sock.send(pkt)
    }

    pub fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.sock.recv(buf)
    }
}

fn duplicate_vm_fd(vm_fd: RawFd) -> Result<RawFd> {
    if vm_fd < 0 {
        bail!("invalid VM file descriptor {vm_fd}: value must be non-negative");
    }

    // SAFETY: fcntl duplicates the descriptor without transferring ownership of vm_fd.
    let duplicated_fd = unsafe { libc::fcntl(vm_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated_fd == -1 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("failed to duplicate VM file descriptor {vm_fd}"));
    }

    if let Err(error) = validate_vm_fd(duplicated_fd) {
        // SAFETY: duplicated_fd is an open descriptor owned by this function.
        unsafe { libc::close(duplicated_fd) };
        return Err(error);
    }

    Ok(duplicated_fd)
}

fn validate_vm_fd(vm_fd: RawFd) -> Result<()> {
    // SAFETY: fcntl only reads descriptor state and does not take ownership.
    if unsafe { libc::fcntl(vm_fd, libc::F_GETFD) } == -1 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("failed to inspect VM file descriptor {vm_fd}"));
    }

    let mut socket_type = 0;
    let mut socket_type_len = size_of::<libc::c_int>() as libc::socklen_t;

    // SAFETY: socket_type and socket_type_len are valid writable buffers of the sizes given.
    if unsafe {
        libc::getsockopt(
            vm_fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut socket_type_len,
        )
    } == -1
    {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("VM file descriptor {vm_fd} is not a socket"));
    }

    if socket_type != libc::SOCK_DGRAM {
        bail!("VM file descriptor {vm_fd} is not a Unix datagram socket");
    }

    let mut address: libc::sockaddr_storage = unsafe { zeroed() };
    let mut address_len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;

    // SAFETY: address and address_len are valid writable buffers of the sizes given.
    if unsafe {
        libc::getsockname(
            vm_fd,
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut address_len,
        )
    } == -1
    {
        return Err(io::Error::last_os_error()).with_context(|| {
            format!("failed to inspect the address family of VM file descriptor {vm_fd}")
        });
    }

    if address.ss_family as libc::c_int != libc::AF_UNIX {
        bail!("VM file descriptor {vm_fd} is not a Unix socket");
    }

    Ok(())
}

impl AsRawFd for VM {
    fn as_raw_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::VM;
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::{UnixDatagram, UnixStream};

    #[test]
    fn test_new_rejects_negative_fd() {
        let error = VM::new(-1).err().unwrap();

        assert_eq!(
            error.to_string(),
            "invalid VM file descriptor -1: value must be non-negative"
        );
    }

    #[test]
    fn test_new_rejects_non_socket_fd_without_taking_ownership() {
        let file = File::open("/dev/null").unwrap();
        let error = VM::new(file.as_raw_fd()).err().unwrap();

        assert!(error.to_string().contains("is not a socket"));
        assert!(file.metadata().is_ok());
    }

    #[test]
    fn test_new_rejects_closed_fd() {
        let (socket, _peer) = UnixDatagram::pair().unwrap();
        let vm_fd = socket.as_raw_fd();
        drop(socket);

        let error = VM::new(vm_fd).err().unwrap();

        assert!(
            error
                .to_string()
                .contains("failed to duplicate VM file descriptor")
        );
    }

    #[test]
    fn test_new_rejects_non_datagram_socket() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        let error = VM::new(stream.as_raw_fd()).err().unwrap();

        assert!(error.to_string().contains("not a Unix datagram socket"));
    }

    #[test]
    fn test_new_does_not_close_original_fd_when_vm_is_dropped() {
        let (socket, _peer) = UnixDatagram::pair().unwrap();
        let vm = VM::new(socket.as_raw_fd()).unwrap();
        drop(vm);

        let socket_fd_is_open = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFD) != -1 };

        if socket_fd_is_open {
            drop(socket);
        } else {
            // Avoid double-closing the descriptor if this test catches an unsafe implementation.
            std::mem::forget(socket);
        }

        assert!(socket_fd_is_open);
    }
}

use nix::sys::socket::{
    bind, recvfrom, sendto, socket, AddressFamily, LinkAddr, MsgFlags, SockFlag, SockProtocol,
    SockType, SockaddrLike, SockaddrStorage,
};
use nix::unistd::close;
use std::os::fd::RawFd;
use std::sync::Arc;
use tracing::debug;

struct FileDesc {
    fd: RawFd,
}

impl FileDesc {
    fn new(fd: RawFd) -> Self {
        Self { fd }
    }
}

impl Drop for FileDesc {
    fn drop(&mut self) {
        close(self.fd).unwrap();
    }
}

pub struct Sender {
    socket: Arc<FileDesc>,
    addr: LinkAddr,
}

impl Sender {
    pub fn sendto(&self, packet: Vec<u8>) -> nix::Result<usize> {
        sendto(self.socket.fd, &packet, &self.addr, MsgFlags::empty())
    }
}

pub struct Receiver {
    socket: Arc<FileDesc>,
    pub buf: Vec<u8>,
}

impl Receiver {
    pub fn recvfrom(&mut self) -> nix::Result<(usize, Option<SockaddrStorage>)> {
        recvfrom::<SockaddrStorage>(self.socket.fd, &mut self.buf)
    }
}

pub fn channel(ifindex: usize, [a, b, c, d, e, f]: [u8; 6]) -> (Sender, Receiver) {
    let socket = socket(
        AddressFamily::Packet,
        SockType::Raw,
        SockFlag::empty(),
        SockProtocol::EthAll,
    )
    .unwrap();
    debug!(?socket, ?ifindex);
    let sockaddr = &nix::libc::sockaddr_ll {
        sll_family: nix::libc::AF_PACKET as nix::libc::sa_family_t,
        sll_protocol: (nix::libc::ETH_P_IP as u16).to_be(),
        sll_ifindex: ifindex as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 6,
        sll_addr: [a, b, c, d, e, f, 0, 0],
    };
    let addr = unsafe {
        LinkAddr::from_raw(
            sockaddr as *const nix::libc::sockaddr_ll as *const nix::libc::sockaddr,
            None,
        )
        .unwrap()
    };
    debug!(?addr);
    bind(socket, &addr).unwrap();
    let fd = Arc::new(FileDesc::new(socket));
    let sender = Sender {
        socket: fd.clone(),
        addr,
    };
    let receiver = Receiver {
        socket: fd.clone(),
        buf: vec![0; 4096],
    };
    (sender, receiver)
}

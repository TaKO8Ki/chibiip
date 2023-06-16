use nix::sys::socket::{
    bind, recvfrom, sendto, socket, AddressFamily, LinkAddr, MsgFlags, SockFlag, SockProtocol,
    SockType, SockaddrLike, SockaddrStorage,
};
use nix::unistd::close;
use tracing::debug;

use crate::ether::{EthType, EthernetFrame};
use crate::net::get_local_ip_addr;
use crate::utils::iptobyte;

#[derive(Debug)]
pub struct Arp {
    hardware_type: Vec<u8>,
    protocol_type: Vec<u8>,
    hardware_size: Vec<u8>,
    protocol_size: Vec<u8>,
    opcode: Vec<u8>,
    pub sender_mac_addr: Vec<u8>,
    sender_ip_addr: [u8; 4],
    target_mac_addr: Vec<u8>,
    target_ip_addr: [u8; 4],
}

pub fn send_arp(ifname: &str, target_ip: &str) {
    let ni = get_local_ip_addr(Some(ifname)).unwrap().unwrap();
    debug!(
        "ip_addr={:?}, target_ip={:?}",
        ni.ip_addr.to_be_bytes().to_vec(),
        iptobyte(target_ip)
    );

    let ethernet = EthernetFrame::new(
        vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ni.mac_addr.to_vec(),
        EthType::Arp,
    );
    let arp_req = Arp::new(
        ni.mac_addr.to_vec(),
        ni.ip_addr.to_be_bytes(),
        iptobyte(target_ip),
    );

    let mut send_arp = vec![];
    send_arp.append(&mut ethernet.to_byte_array());
    send_arp.append(&mut arp_req.to_byte_array());
    debug!(?send_arp);

    let arpreply = arp_req.send(ni.mac_addr, send_arp, ni.ifindex).unwrap();
    println!("arp reply: {}", arpreply.get_sender_hw_addr());
}

impl Arp {
    pub fn new(mac_addr: Vec<u8>, sender_ip_addr: [u8; 4], target_ip_addr: [u8; 4]) -> Self {
        Self {
            hardware_type: vec![0x00, 0x01],
            protocol_type: vec![0x08, 0x00],
            hardware_size: vec![0x06],
            protocol_size: vec![0x04],
            opcode: vec![0x00, 0x01],
            sender_mac_addr: mac_addr,
            sender_ip_addr,
            target_mac_addr: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            target_ip_addr,
        }
    }

    pub fn get_sender_hw_addr(&self) -> String {
        match self.sender_mac_addr[..] {
            [a, b, c, d, e, f] => format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                a, b, c, d, e, f
            ),
            _ => unreachable!(),
        }
    }

    pub fn to_byte_array(&self) -> Vec<u8> {
        let mut byte = vec![];
        byte.append(&mut self.hardware_type.clone());
        byte.append(&mut self.protocol_type.clone());
        byte.append(&mut self.hardware_size.clone());
        byte.append(&mut self.protocol_size.clone());
        byte.append(&mut self.opcode.clone());
        byte.append(&mut self.sender_mac_addr.clone());
        byte.append(&mut self.sender_ip_addr.to_vec());
        byte.append(&mut self.target_mac_addr.clone());
        byte.append(&mut self.target_ip_addr.to_vec());
        byte
    }

    pub fn send(
        &self,
        [a, b, c, d, e, f]: [u8; 6],
        packet: Vec<u8>,
        ifindex: usize,
    ) -> Option<Self> {
        let send_fd = socket(
            AddressFamily::Packet,
            SockType::Raw,
            SockFlag::empty(),
            SockProtocol::EthAll,
        )
        .unwrap();
        debug!(?send_fd, ?ifindex);
        let sockaddr = &nix::libc::sockaddr_ll {
            sll_family: nix::libc::AF_PACKET as nix::libc::sa_family_t,
            sll_protocol: (nix::libc::ETH_P_ALL as u16).to_be(),
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
        bind(send_fd, &addr).unwrap();

        let ret = sendto(send_fd, &packet, &addr, MsgFlags::empty()).unwrap();
        debug!(?ret);
        debug!("receiving.......");

        let mut recv_buf = vec![0; 4096];
        while let Ok((ret, addr)) = recvfrom::<SockaddrStorage>(send_fd, &mut recv_buf) {
            if !recv_buf.is_empty() {
                debug!(?recv_buf, ?ret, ?addr);
                if recv_buf[12] == 0x08
                    && recv_buf[13] == 0x06
                    && recv_buf[20] == 0x00
                    && recv_buf[21] == 0x02
                {
                    close(send_fd).unwrap();
                    return Some(Self::parse_arp_packet(&recv_buf[14..]));
                }
            }
        }

        None
    }

    fn parse_arp_packet(packet: &[u8]) -> Self {
        Arp {
            hardware_type: vec![packet[0], packet[1]],
            protocol_type: vec![packet[2], packet[3]],
            hardware_size: vec![packet[4]],
            protocol_size: vec![packet[5]],
            opcode: vec![packet[6], packet[7]],
            sender_mac_addr: vec![
                packet[8], packet[9], packet[10], packet[11], packet[12], packet[13],
            ],
            sender_ip_addr: [packet[14], packet[15], packet[16], packet[17]],
            target_mac_addr: vec![
                packet[18], packet[19], packet[20], packet[21], packet[22], packet[23],
            ],
            target_ip_addr: [packet[24], packet[25], packet[26], packet[27]],
        }
    }
}

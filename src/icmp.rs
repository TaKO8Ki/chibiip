use crate::arp::Arp;
use crate::ether::{EthType, EthernetFrame};
use crate::ip::{IpHeader, IpProtocol};
use crate::utils::{checksum, get_local_ip_addr, iptobyte, sum_byte_arr};

use nix::sys::socket::{
    bind, recvfrom, sendto, socket, AddressFamily, LinkAddr, MsgFlags, SockFlag, SockProtocol,
    SockType, SockaddrLike, SockaddrStorage,
};
use nix::unistd::close;
use tracing::debug;

struct Icmp {
    pub r#type: Vec<u8>,
    code: Vec<u8>,
    check_sum: [u8; 2],
    identification: Vec<u8>,
    sequence_number: Vec<u8>,
    data: Vec<u8>,
}

pub fn send_icmp(ifname: &str, target_ip: &str) {
    let (mac_addr, ip_addr, ifindex) = get_local_ip_addr(Some(ifname)).unwrap();
    debug!(
        "ip_addr={:?}, target_ip={:?}",
        ip_addr.unwrap().to_be_bytes().to_vec(),
        iptobyte(target_ip)
    );

    let ethernet = EthernetFrame::new(
        vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        mac_addr.unwrap().to_vec(),
        EthType::Arp,
    );
    let arp_req = Arp::new(
        mac_addr.unwrap().to_vec(),
        ip_addr.unwrap().to_be_bytes().to_vec(),
        iptobyte(target_ip),
    );

    let mut send_arp = vec![];
    send_arp.append(&mut ethernet.to_byte_array());
    send_arp.append(&mut arp_req.to_byte_array());
    debug!(?send_arp);

    let arpreply = arp_req
        .send(mac_addr.unwrap(), send_arp, ifindex.unwrap())
        .unwrap();

    let icmp_packet = Icmp::new();
    let mut header = IpHeader::new(
        ip_addr.unwrap().to_be_bytes().to_vec(),
        iptobyte(target_ip),
        IpProtocol::Ip,
    );
    header.total_packet_length =
        ((header.to_byte_array().len() + icmp_packet.to_byte_array().len()) as u16).to_be_bytes();
    header.check_sum = checksum(sum_byte_arr(header.to_byte_array()));

    let mut send_icmp = vec![];
    send_icmp.append(
        &mut EthernetFrame::new(
            arpreply.sender_mac_addr,
            mac_addr.unwrap().to_vec(),
            EthType::Ipv4,
        )
        .to_byte_array(),
    );
    send_icmp.append(&mut header.to_byte_array());
    send_icmp.append(&mut icmp_packet.to_byte_array());
    debug!(?send_icmp);

    let icmp_reply = icmp_packet
        .send(mac_addr.unwrap(), send_icmp, ifindex.unwrap())
        .unwrap();
    if icmp_reply.r#type[0] == 0 {
        println!("ICMP Reply is {}, OK!", icmp_reply.r#type[0]);
    }
}

impl Icmp {
    fn new() -> Self {
        let mut icmp = Self {
            r#type: vec![0x08],
            code: vec![0x00],
            check_sum: [0x00, 0x00],
            identification: vec![0x00, 0x10],
            sequence_number: vec![0x00, 0x01],
            data: vec![0x01, 0x02],
        };

        icmp.check_sum = checksum(sum_byte_arr(icmp.to_byte_array()));
        icmp
    }

    fn to_byte_array(&self) -> Vec<u8> {
        let mut byte = vec![];
        byte.append(&mut self.r#type.clone());
        byte.append(&mut self.code.clone());
        byte.append(&mut self.check_sum.clone().to_vec());
        byte.append(&mut self.identification.clone());
        byte.append(&mut self.sequence_number.clone());
        byte.append(&mut self.data.clone());
        byte
    }

    fn send(&self, [a, b, c, d, e, f]: [u8; 6], packet: Vec<u8>, ifindex: usize) -> Option<Self> {
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
        loop {
            match recvfrom::<SockaddrStorage>(send_fd, &mut recv_buf) {
                Ok((ret, addr)) => {
                    if !recv_buf.is_empty() {
                        debug!(?recv_buf, ?ret, ?addr);
                        if recv_buf[23] == 0x01 {
                            close(send_fd).unwrap();
                            // return parseICMP(recvBuf[34:])
                        }
                    }
                }
                Err(err) => panic!("recvfrom error: {}", err),
            }
        }

        None
    }
}

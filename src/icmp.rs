use crate::arp::Arp;
use crate::ether::{EthType, EthernetFrame};
use crate::ip::{IpHeader, IpProtocol};
use crate::socket::channel;
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

    fn send(
        &self,
        [a, b, c, d, e, f]: [u8; 6],
        packet: Vec<u8>,
        ifindex: usize,
    ) -> Result<Self, String> {
        let (sender, mut receiver) = channel(ifindex, [a, b, c, d, e, f]);
        let ret = sender.sendto(packet).unwrap();
        debug!(?ret);
        debug!("receiving.......");

        loop {
            match receiver.recvfrom() {
                Ok((ret, addr)) => {
                    if !receiver.buf.is_empty() {
                        debug!(?receiver.buf, ?ret, ?addr);
                        if receiver.buf[23] == 0x01 {
                            return Ok(Self::parse_icmp(&receiver.buf[34..]));
                        }
                    }
                }
                Err(err) => return Err(format!("recvfrom error: {}", err)),
            }
        }
    }

    fn parse_icmp(packet: &[u8]) -> Self {
        Self {
            r#type: vec![packet[0]],
            code: vec![packet[1]],
            check_sum: [packet[2], packet[3]],
            identification: vec![packet[4], packet[5]],
            sequence_number: vec![packet[6], packet[7]],
            data: vec![packet[8], packet[9]],
        }
    }
}

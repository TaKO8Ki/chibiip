use crate::arp::Arp;
use crate::ether::{EthType, EthernetFrame};
use crate::ip::{IpHeader, IpProtocol};
use crate::net::get_local_ip_addr;
use crate::socket::channel;
use crate::utils::{checksum, iptobyte, sum_byte_arr};

use tracing::debug;

struct UdpHeader {
    source_port: [u8; 2],
    dest_port: [u8; 2],
    packet_lenth: [u8; 2],
    checksum: [u8; 2],
}

struct UdpDummyHeader {
    source_ip_addr: Vec<u8>,
    dst_ip_addr: Vec<u8>,
    protocol: Vec<u8>,
    length: [u8; 2],
}

impl UdpHeader {
    fn new(source_port: [u8; 2], dest_port: [u8; 2]) -> Self {
        UdpHeader {
            source_port,
            dest_port,
            packet_lenth: [0x00, 0x00],
            checksum: [0x00, 0x00],
        }
    }

    fn to_byte_array(&self) -> Vec<u8> {
        let mut byte = vec![];
        byte.append(&mut self.source_port.clone().to_vec());
        byte.append(&mut self.dest_port.clone().to_vec());
        byte.append(&mut self.packet_lenth.clone().to_vec());
        byte.append(&mut self.checksum.clone().to_vec());
        byte
    }

    fn send(&self, local_mac_addr: [u8; 6], packet: Vec<u8>, ifindex: usize) -> Result<(), String> {
        let (sender, _) = channel(ifindex, local_mac_addr);
        let ret = sender.sendto(packet).unwrap();
        debug!(?ret);
        debug!("udp packet sent");

        Ok(())
    }
}

impl UdpDummyHeader {
    fn new(ip_header: IpHeader) -> Self {
        Self {
            source_ip_addr: ip_header.source_ip_addr,
            dst_ip_addr: ip_header.dst_ip_addr,
            protocol: vec![0x00, 0x11],
            length: [0x00, 0x00],
        }
    }

    fn to_byte_array(&self) -> Vec<u8> {
        let mut byte = vec![];
        byte.append(&mut self.source_ip_addr.to_vec());
        byte.append(&mut self.dst_ip_addr.to_vec());
        byte.append(&mut self.protocol.to_vec());
        byte.append(&mut self.length.to_vec());
        byte
    }
}

pub fn send_udp(ifname: &str, target_ip: &str) {
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
        ni.ip_addr.to_be_bytes().to_vec(),
        iptobyte(target_ip),
    );

    let mut send_arp = vec![];
    send_arp.append(&mut ethernet.to_byte_array());
    send_arp.append(&mut arp_req.to_byte_array());
    debug!(?send_arp);

    let source_port: u16 = 42279;
    let dest_port: u16 = 12345;
    let mut udp_header = UdpHeader::new(source_port.to_be_bytes(), dest_port.to_be_bytes());
    let udpdata = "foobar".as_bytes();
    let mut header = IpHeader::new(
        ni.ip_addr.to_be_bytes().to_vec(),
        iptobyte(target_ip),
        IpProtocol::Ip,
    );
    header.total_packet_length =
        ((header.to_byte_array().len() + udp_header.to_byte_array().len() + udpdata.len()) as u16)
            .to_be_bytes();
    udp_header.packet_lenth =
        ((udp_header.to_byte_array().len() + udpdata.len()) as u16).to_be_bytes();

    header.check_sum = checksum(sum_byte_arr(header.to_byte_array()));

    let mut dummy_header = UdpDummyHeader::new(header.clone());
    dummy_header.length = udp_header.packet_lenth;

    udp_header.checksum = checksum(
        sum_byte_arr(dummy_header.to_byte_array())
            + sum_byte_arr(udp_header.to_byte_array())
            + sum_byte_arr(udpdata.to_vec()),
    );

    let mut packet = vec![];
    packet.append(
        &mut EthernetFrame::new(arp_req.sender_mac_addr, ni.mac_addr.to_vec(), EthType::Ipv4)
            .to_byte_array(),
    );
    packet.append(&mut header.to_byte_array());
    packet.append(&mut udp_header.to_byte_array());
    packet.append(&mut udpdata.to_vec());
    debug!(?packet);

    udp_header.send(ni.mac_addr, packet, ni.ifindex).unwrap();
}

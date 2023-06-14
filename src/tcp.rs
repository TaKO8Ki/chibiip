use std::os::fd::RawFd;

use crate::{
    ip::IpHeader,
    utils::{checksum, iptobyte, sum_byte_arr},
};
use nix::{
    sys::socket::{recvfrom, sendto, setsockopt, socket, MsgFlags, SockaddrIn},
    unistd::close,
};
use rand::Rng;
use tracing::debug;

pub struct TcpHeader {
    source_port: [u8; 2],
    dest_port: [u8; 2],
    sequence_number: [u8; 4],
    acknowlege_number: [u8; 4],
    header_length: u8,
    control_flags: u8,
    window_size: [u8; 2],
    checksum: [u8; 2],
    urgent_pointer: [u8; 2],
    tcp_option_byte: Vec<u8>,
    tcp_data: Vec<u8>,
}

pub struct TcpDummyHeader {
    source_ip_addr: [u8; 4],
    dst_ip_addr: [u8; 4],
    protocol: [u8; 2],
    length: [u8; 2],
}

impl TcpDummyHeader {
    fn new(header: IpHeader, len: u8) -> Self {
        Self {
            source_ip_addr: header.source_ip_addr,
            dst_ip_addr: header.dst_ip_addr,
            protocol: [0x00, 0x06],
            length: [0x00, len],
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

#[derive(Debug, Clone)]
enum TcpFlag {
    Syn,
    Ack,
    PshAck,
    FinAck,
}

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const SYNACK: u8 = 0x12;
const PSHACK: u8 = 0x18;
const FINACK: u8 = 0x11;

impl TcpHeader {
    fn new(source_port: [u8; 2], dest_port: [u8; 2], tcpflag: TcpFlag) -> Self {
        let tcpflag_byte = match tcpflag {
            TcpFlag::Syn => SYN,
            TcpFlag::Ack => ACK,
            TcpFlag::PshAck => PSHACK,
            TcpFlag::FinAck => FINACK,
        };

        Self {
            source_port,
            dest_port,
            sequence_number: [0x00, 0x00, 0x00, 0x00],
            acknowlege_number: [0x00, 0x00, 0x00, 0x00],
            header_length: 0x00,
            control_flags: tcpflag_byte,
            window_size: [0xfa, 0xf0],
            checksum: [0x00, 0x00],
            urgent_pointer: [0x00, 0x00],
            tcp_option_byte: vec![],
            tcp_data: vec![],
        }
    }

    fn parse(buf: Vec<u8>) -> Self {
        Self {
            source_port: [buf[0], buf[1]],
            dest_port: [buf[2], buf[3]],
            sequence_number: [buf[4], buf[5], buf[6], buf[7]],
            acknowlege_number: [buf[8], buf[9], buf[10], buf[11]],
            header_length: buf[12],
            control_flags: buf[13],
            window_size: [buf[14], buf[15]],
            checksum: [buf[16], buf[17]],
            urgent_pointer: [buf[18], buf[19]],
            tcp_option_byte: vec![],
            tcp_data: vec![],
        }
    }

    fn to_byte_array(&self) -> Vec<u8> {
        let mut byte = vec![];
        byte.append(&mut self.source_port.to_vec());
        byte.append(&mut self.dest_port.to_vec());
        byte.append(&mut self.sequence_number.to_vec());
        byte.append(&mut self.acknowlege_number.to_vec());
        byte.push(self.header_length);
        byte.push(self.control_flags);
        byte.append(&mut self.window_size.to_vec());
        byte.append(&mut self.checksum.to_vec());
        byte.append(&mut self.urgent_pointer.to_vec());
        byte.append(&mut self.tcp_option_byte.to_vec());
        byte.append(&mut self.tcp_data.to_vec());
        byte
    }
}

#[derive(Debug)]
pub struct TcpIp {
    dest_ip: String,
    dest_port: u16,
    tcp_flag: TcpFlag,
    seq_number: [u8; 4],
    ack_number: [u8; 4],
    data: Vec<u8>,
}

fn create_sequence_number() -> [u8; 4] {
    let mut rng = rand::thread_rng();
    let n1: u32 = rng.gen();
    n1.to_be_bytes()
}

impl TcpIp {
    fn tcp_ip_packet(&self) -> Vec<u8> {
        let local_ip = crate::utils::iptobyte(&self.dest_ip);
        debug!(?local_ip);
        let mut ipheader = IpHeader::new(local_ip.clone(), local_ip, crate::ip::IpProtocol::Tcp);

        let mut tcpheader = TcpHeader::new(
            42279u16.to_be_bytes(),
            self.dest_port.to_be_bytes(),
            self.tcp_flag.clone(),
        );

        match self.tcp_flag {
            TcpFlag::Ack | TcpFlag::PshAck | TcpFlag::FinAck => {
                tcpheader.sequence_number = self.seq_number;
                tcpheader.acknowlege_number = self.ack_number;
            }
            TcpFlag::Syn => tcpheader.sequence_number = create_sequence_number(),
        }

        ipheader.total_packet_length = if let TcpFlag::PshAck = self.tcp_flag {
            (20u16 + tcpheader.to_byte_array().len() as u16 + self.data.len() as u16).to_be_bytes()
        } else {
            (20u16 + tcpheader.to_byte_array().len() as u16).to_be_bytes()
        };

        let num = tcpheader.to_byte_array().len();
        ipheader.check_sum = checksum(sum_byte_arr(ipheader.to_byte_array()));
        tcpheader.header_length = (num << 2) as u8;

        let dummy_header = if let TcpFlag::PshAck = self.tcp_flag {
            TcpDummyHeader::new(ipheader.clone(), (num + self.data.len()) as u8)
        } else {
            TcpDummyHeader::new(ipheader.clone(), num as u8)
        };

        let mut sum =
            sum_byte_arr(dummy_header.to_byte_array()) + sum_byte_arr(tcpheader.to_byte_array());
        if let TcpFlag::PshAck = self.tcp_flag {
            if self.data.len() % 2 != 0 {
                let mut checksum_data = self.data.clone();
                checksum_data.push(0x00);
                sum += sum_byte_arr(checksum_data);
            } else {
                sum += sum_byte_arr(self.data.clone())
            }
        }
        tcpheader.checksum = checksum(sum);

        let mut tcpip_packet = vec![];
        tcpip_packet.append(&mut ipheader.to_byte_array());
        tcpip_packet.append(&mut tcpheader.to_byte_array());
        if let TcpFlag::PshAck = self.tcp_flag {
            tcpip_packet.append(&mut self.data.clone())
        }

        tcpip_packet
    }

    fn start_tcp_connection(
        &self,
        send_fd: RawFd,
    ) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let syn_packet = self.tcp_ip_packet();
        let dest_ip = iptobyte(&self.dest_ip);

        let [a, b, c, d] = dest_ip[..] else {
            panic!("Invalid IP address: {}", self.dest_ip)
        };
        let addr = SockaddrIn::new(a, b, c, d, self.dest_port);

        let ret = sendto(send_fd, &syn_packet, &addr, MsgFlags::empty()).unwrap();
        debug!(?syn_packet, "Send SYN packet");

        let synack = recv_ip_socket(send_fd, dest_ip);

        // 0x12 = SYNACK, 0x11 = FINACK, 0x10 = ACK
        if synack.control_flags == SYNACK
            || synack.control_flags == FINACK
            || synack.control_flags == ACK
        {
            let ack = TcpIp {
                dest_ip: self.dest_ip.clone(),
                dest_port: self.dest_port,
                tcp_flag: TcpFlag::Ack,
                seq_number: synack.acknowlege_number,
                ack_number: calc_sequence_number(synack.sequence_number, 1),
                data: vec![],
            };
            let ack_packet = ack.tcp_ip_packet();
            let ret = sendto(send_fd, &ack_packet, &addr, MsgFlags::empty()).unwrap();
            return Ok(Some(ack));
        }

        Ok(None)
    }

    pub fn synack_finack(localip: &str) {
        use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType};
        use std::{thread, time::Duration};

        let port = 8080;

        let syn = TcpIp {
            dest_ip: localip.to_string(),
            dest_port: port,
            tcp_flag: TcpFlag::Syn,
            seq_number: [0; 4],
            ack_number: [0; 4],
            data: vec![],
        };

        let send_fd = socket(
            AddressFamily::Inet,
            SockType::Raw,
            SockFlag::empty(),
            SockProtocol::Tcp,
        )
        .unwrap();
        unsafe {
            nix::libc::setsockopt(
                send_fd,
                nix::libc::IPPROTO_IP,
                nix::libc::IP_HDRINCL,
                (&1 as *const nix::libc::c_int) as *const nix::libc::c_void,
                std::mem::size_of::<nix::libc::c_int>() as nix::libc::socklen_t,
            )
        };
        let ack = syn.start_tcp_connection(send_fd).unwrap().unwrap();
        debug!("TCP Connection is success!!");

        thread::sleep(Duration::from_millis(10));

        let fin = TcpIp {
            dest_ip: localip.to_string(),
            dest_port: port,
            tcp_flag: TcpFlag::FinAck,
            seq_number: ack.seq_number,
            ack_number: ack.ack_number,
            data: vec![],
        };
        fin.start_tcp_connection(send_fd).unwrap();
        debug!("TCP Connection Close is success!!");
        close(send_fd).unwrap();
    }
}

fn calc_sequence_number(packet: [u8; 4], add: u32) -> [u8; 4] {
    let sum = ((packet[0] as u32) << 24)
        | ((packet[1] as u32) << 16)
        | ((packet[2] as u32) << 8)
        | packet[3] as u32 + add;

    sum.to_be_bytes()
}

fn recv_ip_socket(fd: RawFd, dest_ip: [u8; 4]) -> TcpHeader {
    let mut buf = vec![0; 128];
    loop {
        let (ret, addr) = recvfrom::<SockaddrIn>(fd, &mut buf).unwrap();
        debug!(?ret, ?addr);
        if !buf.is_empty() {
            let ip = IpHeader::parse(buf[0..20].to_vec());
            debug!(?ip.protocol, ?ip.source_ip_addr, ?dest_ip);
            debug!(
                "condition: {}",
                ip.protocol == 0x06 && ip.source_ip_addr == dest_ip
            );
            if ip.protocol == 0x06 && ip.source_ip_addr == dest_ip {
                let synack = TcpHeader::parse(buf[20..].to_vec());
                debug!(?buf, ?synack.control_flags, ?synack.source_port, ?synack.dest_port);
                if synack.control_flags == SYNACK {
                    debug!("recv {:?}", &buf[20..]);
                    return synack;
                }
            }
        }
    }
}

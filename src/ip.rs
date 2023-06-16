#[derive(Clone)]
pub struct IpHeader {
    version_and_header_length: u8,
    service_type: u8,
    pub total_packet_length: [u8; 2],
    packet_identification: [u8; 2],
    flags: [u8; 2],
    ttl: u8,
    pub protocol: u8,
    pub check_sum: [u8; 2],
    pub source_ip_addr: [u8; 4],
    pub dst_ip_addr: [u8; 4],
}

pub enum IpProtocol {
    Ip,
    Tcp,
    Udp,
}

impl IpHeader {
    pub fn new(source_ip: [u8; 4], dst_ip: [u8; 4], protocol: IpProtocol) -> Self {
        Self {
            version_and_header_length: 0x45,
            service_type: 0x00,
            total_packet_length: [0x00, 0x00],
            packet_identification: [0x00, 0x00],
            flags: [0x40, 0x00],
            ttl: 0x40,
            check_sum: [0x00, 0x00],
            source_ip_addr: source_ip,
            dst_ip_addr: dst_ip,
            protocol: match protocol {
                IpProtocol::Ip => 0x01,
                IpProtocol::Tcp => 0x06,
                IpProtocol::Udp => 0x11,
            },
        }
    }

    pub fn to_byte_array(&self) -> Vec<u8> {
        let mut byte = vec![];
        byte.push(self.version_and_header_length);
        byte.push(self.service_type);
        byte.append(&mut self.total_packet_length.to_vec());
        byte.append(&mut self.packet_identification.to_vec());
        byte.append(&mut self.flags.to_vec());
        byte.push(self.ttl);
        byte.push(self.protocol);
        byte.append(&mut self.check_sum.clone().to_vec());
        byte.append(&mut self.source_ip_addr.to_vec());
        byte.append(&mut self.dst_ip_addr.to_vec());
        byte
    }

    pub fn parse(buf: Vec<u8>) -> Self {
        Self {
            version_and_header_length: buf[0],
            service_type: buf[1],
            total_packet_length: [buf[2], buf[3]],
            packet_identification: [buf[4], buf[5]],
            flags: [buf[6], buf[7]],
            ttl: buf[8],
            check_sum: [buf[9], buf[10]],
            source_ip_addr: [buf[12], buf[13], buf[14], buf[15]],
            dst_ip_addr: [buf[16], buf[17], buf[18], buf[19]],
            protocol: buf[9],
        }
    }
}

#[derive(Clone)]
pub struct IpHeader {
    version_and_header_lenght: Vec<u8>,
    service_type: Vec<u8>,
    pub total_packet_length: [u8; 2],
    packet_identification: Vec<u8>,
    flags: Vec<u8>,
    ttl: Vec<u8>,
    protocol: Vec<u8>,
    pub check_sum: [u8; 2],
    pub source_ip_addr: Vec<u8>,
    pub dst_ip_addr: Vec<u8>,
}

pub enum IpProtocol {
    Ip,
    Tcp,
    Udp,
}

impl IpHeader {
    pub fn new(source_ip: Vec<u8>, dst_ip: Vec<u8>, protocol: IpProtocol) -> Self {
        Self {
            version_and_header_lenght: vec![0x45],
            service_type: vec![0x00],
            total_packet_length: [0x00, 0x00],
            packet_identification: vec![0x00, 0x00],
            flags: vec![0x40, 0x00],
            ttl: vec![0x40],
            check_sum: [0x00, 0x00],
            source_ip_addr: source_ip,
            dst_ip_addr: dst_ip,
            protocol: match protocol {
                IpProtocol::Ip => vec![0x01],
                IpProtocol::Tcp => vec![0x06],
                IpProtocol::Udp => vec![0x11],
            },
        }
    }

    pub fn to_byte_array(&self) -> Vec<u8> {
        let mut byte = vec![];
        byte.append(&mut self.version_and_header_lenght.clone());
        byte.append(&mut self.service_type.clone());
        byte.append(&mut self.total_packet_length.clone().to_vec());
        byte.append(&mut self.packet_identification.clone());
        byte.append(&mut self.flags.clone());
        byte.append(&mut self.ttl.clone());
        byte.append(&mut self.protocol.clone());
        byte.append(&mut self.check_sum.clone().to_vec());
        byte.append(&mut self.source_ip_addr.clone());
        byte.append(&mut self.dst_ip_addr.clone());
        byte
    }
}

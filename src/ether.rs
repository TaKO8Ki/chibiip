pub struct EthernetFrame {
    dst_mac_addr: Vec<u8>,
    source_mac_addr: Vec<u8>,
    r#type: Vec<u8>,
}

pub enum EthType {
    Ipv4,
    Arp,
}

const IPV4: &[u8] = &[0x08, 0x00];
const ARP: &[u8] = &[0x08, 0x06];

impl EthernetFrame {
    pub fn new(dst_mac_addr: Vec<u8>, source_mac_addr: Vec<u8>, eth_type: EthType) -> Self {
        let ty = match eth_type {
            EthType::Ipv4 => IPV4,
            EthType::Arp => ARP,
        };
        EthernetFrame {
            dst_mac_addr,
            source_mac_addr,
            r#type: ty.to_vec(),
        }
    }

    pub fn to_byte_array(&self) -> Vec<u8> {
        let mut byte = vec![];
        byte.append(&mut self.dst_mac_addr.clone());
        byte.append(&mut self.source_mac_addr.clone());
        byte.append(&mut self.r#type.clone());
        byte
    }
}

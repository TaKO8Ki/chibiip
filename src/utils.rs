use nix::ifaddrs::getifaddrs;
use tracing::debug;

pub fn sum_byte_arr(arr: Vec<u8>) -> usize {
    let mut sum = 0;
    for i in arr.chunks(2) {
        let [a, b] = i else {
            panic!("Invalid byte array");
        };
        sum += ((*a as usize) << 8) | *b as usize;
    }
    sum
}

pub fn checksum(sum: usize) -> [u8; 2] {
    let checksum = (sum - ((sum >> 16) << 16) + (sum >> 16)) ^ 0xffff;
    (checksum as u16).to_be_bytes()
}

pub fn iptobyte(ip: &str) -> Vec<u8> {
    let mut ipbyte = vec![];
    for v in ip.split('.') {
        let i = v.parse::<usize>().unwrap();
        ipbyte.push(i as u8)
    }
    ipbyte
}

pub fn get_local_ip_addr(
    name: Option<&str>,
) -> Result<(Option<[u8; 6]>, Option<u32>, Option<usize>), Box<dyn std::error::Error>> {
    let ifiter = getifaddrs()?;
    let mut ip_addr = None;
    let mut mac_addr = None;
    let mut index = None;
    for interface in ifiter {
        debug!(?interface.interface_name);
        if let Some(storage) = interface.address {
            if let Some(link_addr) = storage.as_link_addr() {
                debug!(?link_addr);
                debug!("addr {:?}", link_addr.addr());
                index = Some(link_addr.ifindex());
                if let Some(bytes) = link_addr.addr() {
                    if let Some(name) = name {
                        debug!(?interface.interface_name, ?name);
                        if interface.interface_name == name {
                            mac_addr = Some(bytes);
                        }
                    } else if bytes.iter().any(|&x| x != 0) {
                        mac_addr = Some(bytes);
                    }
                }
            }
            if let Some(socket_addr) = storage.as_sockaddr_in() {
                debug!(?socket_addr);
                if let Some(name) = name {
                    if interface.interface_name == name {
                        ip_addr = Some(socket_addr.ip());
                    }
                }
            }
        }
    }
    debug!(?mac_addr, ?ip_addr);
    Ok((mac_addr, ip_addr, index))
}

#[cfg(test)]
mod tests {
    use super::checksum;

    #[test]
    fn test_checksum() {
        assert_eq!(checksum(0x1f7dd), [8, 33]);
    }
}

use nix::ifaddrs::getifaddrs;
use tracing::debug;

pub struct NetworkInterface {
    pub mac_addr: [u8; 6],
    pub ip_addr: u32,
    pub ifindex: usize,
}

pub fn get_local_ip_addr(
    name: Option<&str>,
) -> Result<Option<NetworkInterface>, Box<dyn std::error::Error>> {
    let ifiter = getifaddrs()?;
    let mut ip_addr = None;
    let mut mac_addr = None;
    let mut ifindex = None;
    for interface in ifiter {
        debug!(?interface.interface_name);
        if let Some(name) = name {
            debug!(?interface.interface_name, ?name);
            if interface.interface_name == name {
                if let Some(storage) = interface.address {
                    if let Some(link_addr) = storage.as_link_addr() {
                        debug!(?link_addr);
                        debug!("addr {:?}", link_addr.addr());
                        ifindex = Some(link_addr.ifindex());
                        if let Some(bytes) = link_addr.addr() {
                            mac_addr = Some(bytes);
                        }
                    }
                    if let Some(socket_addr) = storage.as_sockaddr_in() {
                        debug!(?socket_addr);
                        ip_addr = Some(socket_addr.ip());
                    }
                }
            }
        }
    }
    debug!(?mac_addr, ?ip_addr);
    match (mac_addr, ip_addr, ifindex) {
        (Some(mac_addr), Some(ip_addr), Some(ifindex)) => Ok(Some(NetworkInterface {
            mac_addr,
            ip_addr,
            ifindex,
        })),
        _ => Ok(None),
    }
}

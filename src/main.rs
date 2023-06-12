mod arp;
mod ether;
mod icmp;
mod ip;
mod net;
mod socket;
mod tcp;
mod udp;
mod utils;

fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();

    match args[1].as_str() {
        "arp" => arp::send_arp(&args[2], &args[3]),
        "udp" => udp::send_udp(&args[2], &args[3]),
        "icmp" => icmp::send_icmp(&args[2], &args[3]),
        "tcp" => tcp::TcpIp::synack_finack(),
        _ => (),
    }
}

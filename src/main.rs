mod arp;
mod ether;
mod icmp;
mod ip;
mod net;
mod socket;
mod utils;

fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();

    icmp::send_icmp(&args[1], &args[2]);
}

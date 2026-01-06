// src/main.rs
mod tap;
mod engine;

use aether::ethernet::{EthernetFrame, MacAddress, EtherType};
use aether::ipv4::{Ipv4Packet, IpProtocol};
use aether::tcp::{TcpHeader, TcpFlags, TcpState, TcpConnection};
use aether::dhcp::{DhcpPacket, DhcpMessageType, DHCP_CLIENT_PORT, DHCP_SERVER_PORT};
use aether::{arp, icmp, ipv4, tcp, utils, http, udp, dns, dhcp};

use tap::TapDevice;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Instant, Duration};
use byteorder::{ByteOrder, NetworkEndian};
use std::thread;

// --- Configuration ---
pub const LOG_ENABLED: bool = false;
pub const STACK_MAC: MacAddress = MacAddress([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
pub const BATCH_SIZE: usize = 128;
pub const MTU: usize = 1514;
pub const GC_INTERVAL: u64 = 1;
pub const TCP_TIMEOUT: u64 = 10;
const FORCE_MULTI_THREADED: bool = false;

macro_rules! log {
    ($($arg:tt)*) => {
        if crate::LOG_ENABLED {
            println!("{}", format_args!($($arg)*));
        }
    }
}
pub(crate) use log;

#[derive(Clone, Copy)]
pub struct Packet {
    pub len: usize,
    pub data: [u8; MTU],
}

impl Packet {
    pub fn new() -> Self {
        Self { len: 0, data: [0u8; MTU] }
    }
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut p = Self::new();
        p.len = slice.len();
        p.data[..slice.len()].copy_from_slice(slice);
        p
    }
}

pub struct ActiveConnection {
    pub conn: TcpConnection,
    pub last_seen: Instant,
    pub remote_mac: MacAddress,
}

pub fn process_packet(
    my_ip: Ipv4Addr,
    raw_data: &[u8],
    connections: &mut HashMap<(Ipv4Addr, u16, u16), ActiveConnection>,
                      out_buf: &mut [u8; MTU]
) -> usize {
    if let Some(frame) = EthernetFrame::new(raw_data) {
        match frame.ether_type() {
            EtherType::ARP => {
                if let Some(arp_pkt) = arp::ArpPacket::new(frame.payload()) {
                    if arp_pkt.operation() == arp::ArpOp::Request && arp_pkt.target_ip() == my_ip {
                        EthernetFrame::write_header(&mut out_buf[0..14], frame.source(), STACK_MAC, EtherType::ARP);
                        arp::ArpPacket::write_reply(&mut out_buf[14..42], STACK_MAC, my_ip, arp_pkt.sender_mac(), arp_pkt.sender_ip());
                        return 42;
                    }
                }
            }
            EtherType::IPv4 => {
                if let Some(ip_pkt) = Ipv4Packet::new(frame.payload()) {
                    if ip_pkt.dest_ip() == my_ip {
                        match ip_pkt.protocol() {
                            IpProtocol::ICMP => {
                                if let Some(icmp_pkt) = icmp::IcmpPacket::new(ip_pkt.payload()) {
                                    if icmp_pkt.icmp_type() == icmp::IcmpType::EchoRequest {
                                        let len = 42 + icmp_pkt.payload().len();
                                        EthernetFrame::write_header(&mut out_buf[0..14], frame.source(), STACK_MAC, EtherType::IPv4);
                                        ipv4::Ipv4Packet::write_header(&mut out_buf[14..34], my_ip, ip_pkt.source_ip(), IpProtocol::ICMP, 8 + icmp_pkt.payload().len());
                                        icmp::IcmpPacket::write_echo_reply(&mut out_buf[34..], NetworkEndian::read_u16(&icmp_pkt.data[4..6]), NetworkEndian::read_u16(&icmp_pkt.data[6..8]), icmp_pkt.payload());
                                        return len;
                                    }
                                }
                            }
                            IpProtocol::TCP => {
                                if let Some(tcp_hdr) = TcpHeader::new(ip_pkt.payload()) {
                                    let key = (ip_pkt.source_ip(), tcp_hdr.src_port(), tcp_hdr.dest_port());
                                    let flags = tcp_hdr.flags();

                                    if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK == 0 {
                                        log!("[TCP] SYN -> Cookie: {}:{}", ip_pkt.source_ip(), tcp_hdr.src_port());
                                        let cookie = utils::generate_syn_cookie(ip_pkt.source_ip(), tcp_hdr.src_port(), my_ip, tcp_hdr.dest_port(), tcp_hdr.seq_num());
                                        EthernetFrame::write_header(&mut out_buf[0..14], frame.source(), STACK_MAC, EtherType::IPv4);
                                        ipv4::Ipv4Packet::write_header(&mut out_buf[14..34], my_ip, ip_pkt.source_ip(), IpProtocol::TCP, 20);
                                        tcp::TcpHeader::write_header(&mut out_buf[34..], tcp_hdr.dest_port(), tcp_hdr.src_port(), cookie, tcp_hdr.seq_num() + 1, TcpFlags::SYN | TcpFlags::ACK, my_ip, ip_pkt.source_ip(), 0);
                                        return 54;
                                    }

                                    let mut conn_exists = connections.contains_key(&key);
                                    if !conn_exists && (flags & TcpFlags::ACK != 0) {
                                        let received_cookie = tcp_hdr.ack_num().wrapping_sub(1);
                                        let expected_cookie = utils::generate_syn_cookie(ip_pkt.source_ip(), tcp_hdr.src_port(), my_ip, tcp_hdr.dest_port(), tcp_hdr.seq_num().wrapping_sub(1));
                                        if received_cookie == expected_cookie {
                                            log!("[TCP] NEW Connection: {}:{}", ip_pkt.source_ip(), tcp_hdr.src_port());
                                            connections.insert(key, ActiveConnection {
                                                conn: TcpConnection { state: TcpState::Established, local_seq: tcp_hdr.ack_num(), remote_seq: tcp_hdr.seq_num() },
                                                               last_seen: Instant::now(),
                                                               remote_mac: frame.source(),
                                            });
                                            conn_exists = true;
                                        }
                                    }

                                    if conn_exists {
                                        let mut should_remove = false;
                                        let mut resp_len = 0;
                                        let active_conn = connections.get_mut(&key).unwrap();
                                        active_conn.last_seen = Instant::now();
                                        let conn = &mut active_conn.conn;
                                        let payload = tcp_hdr.payload();
                                        let incoming_seq = tcp_hdr.seq_num();

                                        if !payload.is_empty() {
                                            if incoming_seq == conn.remote_seq {
                                                conn.remote_seq = incoming_seq.wrapping_add(payload.len() as u32);
                                                if let Some(http_resp) = http::handle_request(payload) {
                                                    log!("[HTTP] Request from {}:{}", ip_pkt.source_ip(), tcp_hdr.src_port());
                                                    let resp_bytes = http_resp.as_bytes();
                                                    resp_len = 54 + resp_bytes.len();
                                                    EthernetFrame::write_header(&mut out_buf[0..14], frame.source(), STACK_MAC, EtherType::IPv4);
                                                    ipv4::Ipv4Packet::write_header(&mut out_buf[14..34], my_ip, ip_pkt.source_ip(), IpProtocol::TCP, 20 + resp_bytes.len());
                                                    out_buf[54..54+resp_bytes.len()].copy_from_slice(resp_bytes);
                                                    tcp::TcpHeader::write_header(&mut out_buf[34..], tcp_hdr.dest_port(), tcp_hdr.src_port(), conn.local_seq, conn.remote_seq, TcpFlags::PSH | TcpFlags::ACK | TcpFlags::FIN, my_ip, ip_pkt.source_ip(), resp_bytes.len());
                                                    conn.local_seq += resp_bytes.len() as u32 + 1;
                                                    should_remove = true;
                                                } else {
                                                    let prefix = b"Aether Echo: ";
                                                    let suffix = b"> ";
                                                    let echo_len = prefix.len() + payload.len() + suffix.len();
                                                    resp_len = 54 + echo_len;
                                                    EthernetFrame::write_header(&mut out_buf[0..14], frame.source(), STACK_MAC, EtherType::IPv4);
                                                    ipv4::Ipv4Packet::write_header(&mut out_buf[14..34], my_ip, ip_pkt.source_ip(), IpProtocol::TCP, 20 + echo_len);
                                                    out_buf[54..54+prefix.len()].copy_from_slice(prefix);
                                                    out_buf[54+prefix.len()..54+prefix.len()+payload.len()].copy_from_slice(payload);
                                                    out_buf[54+prefix.len()+payload.len()..54+echo_len].copy_from_slice(suffix);
                                                    tcp::TcpHeader::write_header(&mut out_buf[34..], tcp_hdr.dest_port(), tcp_hdr.src_port(), conn.local_seq, conn.remote_seq, TcpFlags::PSH | TcpFlags::ACK, my_ip, ip_pkt.source_ip(), echo_len);
                                                    conn.local_seq += echo_len as u32;
                                                }
                                            }
                                        }

                                        if flags & TcpFlags::FIN != 0 {
                                            log!("[TCP] Closed: {}:{}", ip_pkt.source_ip(), tcp_hdr.src_port());
                                            conn.remote_seq = conn.remote_seq.wrapping_add(1);
                                            EthernetFrame::write_header(&mut out_buf[0..14], frame.source(), STACK_MAC, EtherType::IPv4);
                                            ipv4::Ipv4Packet::write_header(&mut out_buf[14..34], my_ip, ip_pkt.source_ip(), IpProtocol::TCP, 20);
                                            tcp::TcpHeader::write_header(&mut out_buf[34..], tcp_hdr.dest_port(), tcp_hdr.src_port(), conn.local_seq, conn.remote_seq, TcpFlags::FIN | TcpFlags::ACK, my_ip, ip_pkt.source_ip(), 0);
                                            resp_len = 54;
                                            should_remove = true;
                                        }

                                        if should_remove { connections.remove(&key); }
                                        return resp_len;
                                    }
                                }
                            }
                            IpProtocol::UDP => {
                                if let Some(udp_hdr) = udp::UdpHeader::new(ip_pkt.payload()) {
                                    if udp_hdr.dest_port() != 68 {
                                        if let Some(msg) = dns::parse_response(udp_hdr.payload()) {
                                            log!("[DNS] {}", msg);
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
    }
    0
}

fn main() -> std::io::Result<()> {
    let mut tap = TapDevice::new("aether0").expect("Failed to init TAP");
    tap.set_non_blocking(true).expect("Failed to set Non-Blocking");

    let mut temp_tx_buf = [0u8; MTU];
    let mut rx_buf = [0u8; MTU];
    let mut my_ip = Ipv4Addr::new(0, 0, 0, 0);
    let transaction_id = 0x12345678;
    let mut dhcp_state = DhcpMessageType::Discover;
    let start_time = Instant::now();

    log!("[SYSTEM] Booting Aether Stack...");

    loop {
        if start_time.elapsed() > Duration::from_secs(5) {
            log!("[DHCP] Timeout. Falling back to static IP (192.168.1.2).");
            my_ip = Ipv4Addr::new(192, 168, 1, 2);
            break;
        }

        let dhcp_len = match dhcp_state {
            DhcpMessageType::Discover => dhcp::DhcpPacket::build_packet(&mut temp_tx_buf[42..], 1, transaction_id, STACK_MAC, DhcpMessageType::Discover, None),
            _ => 0,
        };

        if dhcp_len > 0 {
            let payload = temp_tx_buf[42..42+dhcp_len].to_vec();
            udp::UdpHeader::write_header(&mut temp_tx_buf[34..], DHCP_CLIENT_PORT, DHCP_SERVER_PORT, Ipv4Addr::new(0,0,0,0), Ipv4Addr::new(255,255,255,255), &payload);
            ipv4::Ipv4Packet::write_header(&mut temp_tx_buf[14..34], Ipv4Addr::new(0,0,0,0), Ipv4Addr::new(255,255,255,255), IpProtocol::UDP, 8 + dhcp_len);
            EthernetFrame::write_header(&mut temp_tx_buf[0..14], MacAddress::BROADCAST, STACK_MAC, EtherType::IPv4);
            let _ = tap.write(&temp_tx_buf[..42+dhcp_len]);
        }
        thread::sleep(Duration::from_millis(50));

        if let Ok(n) = tap.read(&mut rx_buf) {
            if let Some(frame) = EthernetFrame::new(&rx_buf[..n]) {
                if let Some(ip) = Ipv4Packet::new(frame.payload()) {
                    if let Some(udp_hdr) = udp::UdpHeader::new(ip.payload()) {
                        if udp_hdr.src_port() == DHCP_SERVER_PORT {
                            if let Some(dhcp_pkt) = DhcpPacket::new(udp_hdr.payload()) {
                                if dhcp_pkt.xid() == transaction_id {
                                    if dhcp_pkt.message_type() == DhcpMessageType::Ack {
                                        my_ip = dhcp_pkt.your_ip();
                                        log!("[DHCP] ACK. Assigned IP: {}", my_ip);
                                        break;
                                    }
                                    if dhcp_pkt.message_type() == DhcpMessageType::Offer {
                                        let offered = dhcp_pkt.your_ip();
                                        log!("[DHCP] Offer received: {}", offered);
                                        let len = dhcp::DhcpPacket::build_packet(&mut temp_tx_buf[42..], 1, transaction_id, STACK_MAC, DhcpMessageType::Request, Some(offered));
                                        let req_copy = temp_tx_buf[42..42+len].to_vec();
                                        udp::UdpHeader::write_header(&mut temp_tx_buf[34..], DHCP_CLIENT_PORT, DHCP_SERVER_PORT, Ipv4Addr::new(0,0,0,0), Ipv4Addr::new(255,255,255,255), &req_copy);
                                        ipv4::Ipv4Packet::write_header(&mut temp_tx_buf[14..34], Ipv4Addr::new(0,0,0,0), Ipv4Addr::new(255,255,255,255), IpProtocol::UDP, 8 + len);
                                        EthernetFrame::write_header(&mut temp_tx_buf[0..14], MacAddress::BROADCAST, STACK_MAC, EtherType::IPv4);
                                        let _ = tap.write(&temp_tx_buf[..42+len]);
                                        dhcp_state = DhcpMessageType::Request;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let cores = thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    if FORCE_MULTI_THREADED || cores > 2 {
        engine::run_multi_threaded(tap, my_ip, cores)
    } else {
        engine::run_single_threaded(tap, my_ip)
    }
}

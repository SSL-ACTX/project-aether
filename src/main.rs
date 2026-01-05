// src/main.rs
mod tap;

use aether::ethernet::{EthernetFrame, MacAddress, EtherType};
use aether::ipv4::{Ipv4Packet, IpProtocol};
use aether::tcp::{TcpHeader, TcpFlags, TcpState, TcpConnection};
use aether::udp::UdpHeader;
use aether::dhcp::{DhcpPacket, DhcpMessageType, DHCP_CLIENT_PORT, DHCP_SERVER_PORT};
use aether::{arp, icmp, ipv4, tcp, utils, http, udp, dns, dhcp};

use tap::TapDevice;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Instant, Duration};
use byteorder::{ByteOrder, NetworkEndian};
use std::sync::mpsc::{self, Sender, Receiver, TryRecvError};
use std::thread;
use std::hint;

// --- Configuration ---
const LOG_ENABLED: bool = false;
const STACK_MAC: MacAddress = MacAddress([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
const BATCH_SIZE: usize = 128;
const MTU: usize = 1514;
const GC_INTERVAL: u64 = 1;
const TCP_TIMEOUT: u64 = 10;

macro_rules! log {
    ($($arg:tt)*) => {
        if LOG_ENABLED {
            println!("{}", format_args!($($arg)*));
        }
    }
}

// --- Shared Data Structures ---

#[derive(Clone, Copy)]
struct Packet {
    len: usize,
    data: [u8; MTU],
}

impl Packet {
    fn new() -> Self {
        Self { len: 0, data: [0u8; MTU] }
    }

    fn from_slice(slice: &[u8]) -> Self {
        let mut p = Self::new();
        p.len = slice.len();
        p.data[..slice.len()].copy_from_slice(slice);
        p
    }
}

struct ActiveConnection {
    conn: TcpConnection,
    last_seen: Instant,
    remote_mac: MacAddress,
}

// --- Logic Implementation ---

/// Central packet processing logic used by both engines to ensure consistency.
fn process_packet(
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
                        // Silent ARP replies to avoid log spam
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
                                        // log!("[ICMP] Ping from {}", ip_pkt.source_ip()); // Optional: Uncomment for Ping logs
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

                                    // 1. SYN Cookies (Stateless Handshake)
                                    if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK == 0 {
                                        // log!("[TCP] SYN -> Cookie: {}:{}", ip_pkt.source_ip(), tcp_hdr.src_port());
                                        let cookie = utils::generate_syn_cookie(ip_pkt.source_ip(), tcp_hdr.src_port(), my_ip, tcp_hdr.dest_port(), tcp_hdr.seq_num());
                                        EthernetFrame::write_header(&mut out_buf[0..14], frame.source(), STACK_MAC, EtherType::IPv4);
                                        ipv4::Ipv4Packet::write_header(&mut out_buf[14..34], my_ip, ip_pkt.source_ip(), IpProtocol::TCP, 20);
                                        tcp::TcpHeader::write_header(&mut out_buf[34..], tcp_hdr.dest_port(), tcp_hdr.src_port(), cookie, tcp_hdr.seq_num() + 1, TcpFlags::SYN | TcpFlags::ACK, my_ip, ip_pkt.source_ip(), 0);
                                        return 54;
                                    }

                                    // 2. Connection Logic
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

                                                // Application: HTTP
                                                if let Some(http_resp) = http::handle_request(payload) {
                                                    // log!("[HTTP] Request from {}:{}", ip_pkt.source_ip(), tcp_hdr.src_port());
                                                    let resp_bytes = http_resp.as_bytes();
                                                    resp_len = 54 + resp_bytes.len();
                                                    EthernetFrame::write_header(&mut out_buf[0..14], frame.source(), STACK_MAC, EtherType::IPv4);
                                                    ipv4::Ipv4Packet::write_header(&mut out_buf[14..34], my_ip, ip_pkt.source_ip(), IpProtocol::TCP, 20 + resp_bytes.len());
                                                    out_buf[54..54+resp_bytes.len()].copy_from_slice(resp_bytes);
                                                    tcp::TcpHeader::write_header(&mut out_buf[34..], tcp_hdr.dest_port(), tcp_hdr.src_port(), conn.local_seq, conn.remote_seq, TcpFlags::PSH | TcpFlags::ACK | TcpFlags::FIN, my_ip, ip_pkt.source_ip(), resp_bytes.len());
                                                    conn.local_seq += resp_bytes.len() as u32 + 1;
                                                    should_remove = true;
                                                } else {
                                                    // Application: Echo
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
                                            } else if incoming_seq < conn.remote_seq {
                                                // ACK Duplicate
                                                EthernetFrame::write_header(&mut out_buf[0..14], frame.source(), STACK_MAC, EtherType::IPv4);
                                                ipv4::Ipv4Packet::write_header(&mut out_buf[14..34], my_ip, ip_pkt.source_ip(), IpProtocol::TCP, 20);
                                                tcp::TcpHeader::write_header(&mut out_buf[34..], tcp_hdr.dest_port(), tcp_hdr.src_port(), conn.local_seq, conn.remote_seq, TcpFlags::ACK, my_ip, ip_pkt.source_ip(), 0);
                                                resp_len = 54;
                                            }
                                        }

                                        if flags & TcpFlags::FIN != 0 {
                                            if incoming_seq == conn.remote_seq || incoming_seq == conn.remote_seq.wrapping_sub(payload.len() as u32) {
                                                log!("[TCP] Closed: {}:{}", ip_pkt.source_ip(), tcp_hdr.src_port());
                                                conn.remote_seq = conn.remote_seq.wrapping_add(1);
                                                EthernetFrame::write_header(&mut out_buf[0..14], frame.source(), STACK_MAC, EtherType::IPv4);
                                                ipv4::Ipv4Packet::write_header(&mut out_buf[14..34], my_ip, ip_pkt.source_ip(), IpProtocol::TCP, 20);
                                                tcp::TcpHeader::write_header(&mut out_buf[34..], tcp_hdr.dest_port(), tcp_hdr.src_port(), conn.local_seq, conn.remote_seq, TcpFlags::FIN | TcpFlags::ACK, my_ip, ip_pkt.source_ip(), 0);
                                                resp_len = 54;
                                                should_remove = true;
                                            }
                                        }

                                        if should_remove {
                                            connections.remove(&key);
                                        }
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

// --- Mode 1: Single-Threaded Engine (Low Spec) ---
fn run_single_threaded(mut tap: TapDevice, my_ip: Ipv4Addr) -> std::io::Result<()> {
    log!("[ENGINE] Mode: SINGLE-THREADED (Optimized for Low Latency)");

    let mut rx_batch: [[u8; MTU]; BATCH_SIZE] = [[0u8; MTU]; BATCH_SIZE];
    let mut connections: HashMap<(Ipv4Addr, u16, u16), ActiveConnection> = HashMap::with_capacity(1024);
    let mut temp_tx_buf = [0u8; MTU];
    let mut tx_queue: Vec<Packet> = vec![Packet::new(); BATCH_SIZE];

    let mut idle_cycles: u32 = 0;
    let mut last_gc = Instant::now();

    loop {
        let mut packets_processed = 0;
        let mut tx_count = 0;

        // 1. Batch Read
        for i in 0..BATCH_SIZE {
            match tap.read(&mut rx_batch[i]) {
                Ok(n) => {
                    let len = process_packet(my_ip, &rx_batch[i][..n], &mut connections, &mut temp_tx_buf);
                    if len > 0 {
                        tx_queue[tx_count].len = len;
                        tx_queue[tx_count].data[..len].copy_from_slice(&temp_tx_buf[..len]);
                        tx_count += 1;
                    }
                    packets_processed += 1;
                },
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }

        // 2. Batch Write
        if tx_count > 0 {
            for i in 0..tx_count {
                let pkt = &tx_queue[i];
                let _ = tap.write(&pkt.data[..pkt.len]);
            }
        }

        // 3. Adaptive Backoff
        if packets_processed > 0 {
            idle_cycles = 0;
        } else {
            idle_cycles += 1;
            if idle_cycles < 100 { hint::spin_loop(); }
            else if idle_cycles < 1000 { thread::yield_now(); }
            else { thread::sleep(Duration::from_micros(100)); }
        }

        // 4. GC
        if last_gc.elapsed() > Duration::from_secs(GC_INTERVAL) {
            connections.retain(|_, v| v.last_seen.elapsed() < Duration::from_secs(TCP_TIMEOUT));
            last_gc = Instant::now();
        }
    }
}

// --- Mode 2: Multi-Threaded Engine (High Spec) ---
fn run_multi_threaded(mut tap: TapDevice, my_ip: Ipv4Addr, num_workers: usize) -> std::io::Result<()> {
    log!("[ENGINE] Mode: MULTI-THREADED (Workers: {})", num_workers);

    let (tx_collector, rx_collector) = mpsc::channel::<Packet>();
    let mut worker_senders = Vec::with_capacity(num_workers);

    // Spawn Workers
    for i in 0..num_workers {
        let (tx_dispatch, rx_dispatch) = mpsc::channel::<Packet>();
        worker_senders.push(tx_dispatch);
        let tx_out = tx_collector.clone();

        thread::spawn(move || {
            let mut connections = HashMap::with_capacity(4096);
            let mut out_buf = [0u8; MTU];
            let mut last_gc = Instant::now();

            log!("[Worker {}] Ready.", i);

            loop {
                match rx_dispatch.recv() {
                    Ok(pkt) => {
                        let len = process_packet(my_ip, &pkt.data[..pkt.len], &mut connections, &mut out_buf);
                        if len > 0 {
                            let mut resp = Packet::new();
                            resp.len = len;
                            resp.data[..len].copy_from_slice(&out_buf[..len]);
                            let _ = tx_out.send(resp);
                        }

                        if last_gc.elapsed() > Duration::from_secs(GC_INTERVAL) {
                            connections.retain(|_, v| v.last_seen.elapsed() < Duration::from_secs(TCP_TIMEOUT));
                            last_gc = Instant::now();
                        }
                    },
                    Err(_) => break,
                }
            }
            log!("[Worker {}] Shutdown.", i);
        });
    }
    drop(tx_collector);

    let mut rx_batch: [[u8; MTU]; BATCH_SIZE] = [[0u8; MTU]; BATCH_SIZE];
    let mut idle_cycles: u32 = 0;

    // Main I/O Pump
    loop {
        let mut packets_processed = 0;

        // 1. Burst Read & Dispatch
        for i in 0..BATCH_SIZE {
            match tap.read(&mut rx_batch[i]) {
                Ok(n) => {
                    let pkt_data = &rx_batch[i][..n];
                    let mut worker_id = 0;

                    // Hash Logic
                    if let Some(frame) = EthernetFrame::new(pkt_data) {
                        if frame.ether_type() == EtherType::IPv4 {
                            if let Some(ip) = Ipv4Packet::new(frame.payload()) {
                                let src = ip.source_ip().octets();
                                let mut hash: usize = (src[3] as usize) << 8 | (src[2] as usize);
                                if ip.protocol() == IpProtocol::TCP {
                                    if ip.payload().len() >= 2 {
                                        let port = NetworkEndian::read_u16(&ip.payload()[0..2]);
                                        hash ^= port as usize;
                                    }
                                }
                                worker_id = hash % num_workers;
                            }
                        }
                    }

                    let _ = worker_senders[worker_id].send(Packet::from_slice(pkt_data));
                    packets_processed += 1;
                },
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }

        // 2. Write Responses
        loop {
            match rx_collector.try_recv() {
                Ok(resp) => {
                    let _ = tap.write(&resp.data[..resp.len]);
                    packets_processed += 1;
                },
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return Ok(()),
            }
        }

        // 3. Adaptive Backoff
        if packets_processed > 0 {
            idle_cycles = 0;
        } else {
            idle_cycles += 1;
            if idle_cycles < 100 { hint::spin_loop(); }
            else if idle_cycles < 1000 { thread::yield_now(); }
            else { thread::sleep(Duration::from_micros(100)); }
        }
    }
}

// --- Entry Point ---
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

    // --- DHCP Sequence (Blocking) ---
    loop {
        if start_time.elapsed() > Duration::from_secs(5) {
            log!("[DHCP] Timeout. Falling back to static IP (192.168.1.2).");
            my_ip = Ipv4Addr::new(192, 168, 1, 2);
            break;
        }

        // Send DHCP
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

        // Read DHCP
        if let Ok(n) = tap.read(&mut rx_buf) {
            let raw = &rx_buf[..n];
            if let Some(frame) = EthernetFrame::new(raw) {
                if frame.ether_type() == EtherType::IPv4 {
                    if let Some(ip) = Ipv4Packet::new(frame.payload()) {
                        if ip.protocol() == IpProtocol::UDP {
                            if let Some(udp_hdr) = UdpHeader::new(ip.payload()) {
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
        }
    }

    log!("[SYSTEM] Stack Bound to: {}", my_ip);

    // --- Hardware Detection & Launch ---
    let cores = thread::available_parallelism().map(|n| n.get()).unwrap_or(1);

    if cores <= 2 {
        log!("[INIT] CPU Cores: {} (Low-Spec Detected).", cores);
        run_single_threaded(tap, my_ip)
    } else {
        log!("[INIT] CPU Cores: {} (High-Spec Detected).", cores);
        run_multi_threaded(tap, my_ip, cores)
    }
}

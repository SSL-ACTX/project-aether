<div align="center">

![Aether Banner](https://capsule-render.vercel.app/api?type=waving&color=0:121212,100:00ff&height=220&section=header&text=Project%20Aether&fontSize=80&fontColor=FFFFFF&animation=fadeIn&fontAlignY=35&desc=Hybrid%20Kernel-Bypass%20TCP/IP%20Stack&descSize=20&descAlignY=55)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge&logo=open-source-initiative)](https://opensource.org/licenses/MIT)
[![Language](https://img.shields.io/badge/Rust-Latest-orange.svg?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux_TAP-lightgrey.svg?style=for-the-badge&logo=linux)]()
[![Performance](https://img.shields.io/badge/Perf-3.1k_CPS-success.svg?style=for-the-badge&logo=speedtest)]()
[![Status](https://img.shields.io/badge/Status-Archived%20(Success)-success.svg?style=for-the-badge&logo=github)]()

</div>

---

## ⚡ Overview

**Project Aether** is a high-performance, user-space TCP/IP stack written from scratch in Rust. It bypasses the standard Linux kernel networking stack (`netfilter`, `conntrack`, routing tables) to communicate directly with a **TAP interface** via raw Ethernet frames.

Designed to scale from legacy hardware to modern servers, Aether utilizes a **Hybrid Engine** that automatically switches between a low-overhead single-threaded loop and a sharded multi-threaded dispatcher based on CPU topology.


### 🚀 Performance Benchmark
<div align="center">

Running on a single-core **Intel Celeron 900 (2.2GHz, 2009)**:

| Metric | Result | Notes |
| :--- | :--- | :--- |
| **Throughput** | **3,109 Connections/Sec** | +43% vs initial prototype |
| **Latency** | < 1ms (Local TAP) | Adaptive Backoff |
| **Concurrency** | 100/100 Success | 100 Concurrent Threads |
| **Memory** | Zero-Allocation Hot Path | `no_std` compatible logic |

</div>

---

## 🏗 Architecture

Aether abandons generic async runtimes for a custom, purpose-built event loop.

### 1. Hybrid Engine (Auto-Scaling)
At startup, Aether detects the available CPU cores:
* **Legacy Mode (≤ 2 Cores):** Runs a **Single-Threaded** zero-copy loop. Eliminates context switching and synchronization overhead for maximum efficiency on constrained hardware.
* **Turbo Mode (> 2 Cores):** Activates a **Sharded Dispatcher**. Spawns worker threads equal to the core count and distributes connections via `Hash(SrcIP, SrcPort)` sharding.

### 2. Adaptive Backoff
To prevent 100% CPU usage during idle times (a common issue in spin-loops), the main loop implements a 3-stage state machine:
1.  **Spin:** Nanosecond-level polling under high load.
2.  **Yield:** Relinquishes CPU time slice during moderate traffic.
3.  **Sleep:** Micro-sleep (50µs) during idle periods to drop CPU usage to ~1%.

### 3. "Burst" Processing
* **Batch I/O:** Reads up to **128 packets** per syscall using non-blocking I/O.
* **Zero-Copy Parsing:** Packets are parsed in-place using slice references. No heap allocations occur during the TCP handshake.

---

## 🛠 Features Implemented

* **L2 Data Link:** Raw Ethernet frame parsing & ARP (Request/Reply).
* **L3 Network:** IPv4 header validation & Checksum offloading.
* **L3 ICMP:** Echo Request/Reply (Ping).
* **L4 TCP:**
    * Full 3-Way Handshake (SYN, SYN-ACK, ACK).
    * **Security:** Cryptographic SYN Cookies (Stateless flood protection).
    * **Flow:** Sequence Number Synchronization & FIN/RST teardown.
* **L7 Application:**
    * **HTTP/1.1:** Static content server.
    * **DHCP:** Dynamic IP negotiation (Discover/Offer/Request/Ack).
    * **DNS:** Packet parsing and logging stub.

---

## 📦 Installation & Usage

### Prerequisites
* Linux (Root privileges required for TAP creation).
* Rust (Cargo).

### Quick Start
Use the automated setup script to build the optimized binary and configure the interface.

```bash
# 1. Clone and Setup
git clone https://github.com/SSL-ACTX/project-aether
chmod +x setup.sh

# 2. Launch
./setup.sh

```
> [!NOTE]
> *`setup.sh` defaults to the debug binary. Edit `BINARY` in the script to point to `./target/release/aether` for maximum speed.*

### Verification tools

```bash
# Ping the stack
ping 192.168.1.2

# Test HTTP Server
curl http://192.168.1.2/

# Run the Full Verification Suite
python3 test_stack.py --ip 192.168.1.2

# Run the Stress Benchmark
python3 benchmark.py --ip 192.168.1.2 --threads 100

```

---

## ⚠️ Engineering Trade-offs

**"Speed over Safety"**

To achieve maximum throughput on legacy hardware, this implementation makes specific reliability trade-offs:

1. **No Retransmission Queue:** Aether does not buffer outgoing packets or implement Retransmission Timeouts (RTO). Reliability relies on the client's TCP stack to resend lost segments.
2. **Reactive Integrity:** Duplicate packets are detected and ACK'd immediately, but the stack does not actively probe for unacknowledged data.
3. **Fixed Window:** Flow control is static; congestion control (Slow Start, Congestion Avoidance) is omitted to reduce CPU cycles per connection.

> [!IMPORTANT]
> **This stack is purpose-built for high-speed, low-latency environments where packet loss is negligible (e.g., virtualization, local IPC, specialized appliances).**

---

<div align="center">

**Built with 🦀 and ☕ by [Seuriin](https://github.com/SSL-ACTX)**

</div>

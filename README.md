# Computer Networks Lab & RFC Protocol Suite (Pure Java, JDK 11+)

A comprehensive suite of **RFC-compliant protocol engines**, **system design implementations**, and **interactive live dashboards** built in pure Java (Zero external dependencies, JDK 11+).

---

## Repository Structure & Modules

| Module | Protocol & RFCs | Ports | Description |
|:---|:---|:---|:---|
| **[DHCP](./DHCP)** | RFC 2131, RFC 2132 | UDP **6700** (LB), **6701-6703** (Cluster)<br/>HTTP **8080** (Dashboard) | Distributed & Load-Balanced DHCP Server Cluster with Consistent Hashing, Active-Active Gossip Lease Sync, and Rate Limiting. |
| **[Telnet](./Telnet)** | RFC 854, RFC 855, RFC 1143 | TCP **2323** (Server), **2324** (Wire Tap)<br/>TCP **9923** (TLS), **9924** (TLS Tap)<br/>HTTP **8081** (Dashboard) | Telnet Remote-Management Lab with NVT codec, Q-method option negotiation, Cisco IOS VTY CLI, sniffer, and brute-force guard. |
| **[ARP](./ARP)** | RFC 826, RFC 5227, RFC 1027 | HTTP **8082** (Dashboard & Wire Sniffer) | Address Resolution Protocol (ARP), L2 Switch CAM Learning, Address Conflict Detection (ACD), Proxy ARP, MITM Poisoning, and Dynamic ARP Inspection (DAI). |

---

## 1. ARP: Address Resolution Protocol & L2 Security Lab (`./ARP`)

### Features
- **RFC 826 Binary Engine**: 28-byte ARP header encoding/decoding and Ethernet II framing with auto-padding.
- **Cache State Machine**: `INCOMPLETE`, `REACHABLE`, `STALE`, `STATIC`, and `POISONED` states with real-time TTL countdowns.
- **Packet Buffer Queue**: Buffers outbound IP packets during cache misses and flushes them upon resolution.
- **RFC 5227 ACD & GARP**: Gratuitous ARP announcements and ARP Probes (`SPA = 0.0.0.0`) for duplicate IP detection.
- **RFC 1027 Proxy ARP**: Router transparently resolves remote subnet IPs (`10.0.0.0/24`) with its gateway MAC.
- **L2 Switch CAM Table**: Dynamic source MAC learning and intelligent unicast forwarding vs broadcast flooding.
- **Security & Dynamic ARP Inspection (DAI)**: Mitigates Man-In-The-Middle (MITM) cache poisoning by validating ARP frames against the DHCP Snooping database.
- **Live Web Dashboard & Wireshark Sniffer**: Runs on **http://localhost:8082**.

```powershell
cd ARP
.\run.bat           # Start lab + dashboard
.\run.bat --verify  # Run 30+ automated checks
```

---

## 2. DHCP: Distributed & Load-Balanced Server Cluster (`./DHCP`)

### Features
- **Full RFC 2131 DORA Handshake**: `DHCPDISCOVER`, `DHCPOFFER`, `DHCPREQUEST`, `DHCPACK`/`DHCPNAK`, `DHCPRELEASE`, `DHCPINFORM`, and `DHCPDECLINE`.
- **L4 UDP Load Balancer & Relay Agent (`giaddr`)**: Consistent Hashing with 32 virtual nodes per physical server, Round-Robin, and Least-Loaded routing.
- **Active-Active Peer Gossip Replication**: UDP gossip sync keeps all 3 server nodes synchronized.
- **Token-Bucket Rate Limiter**: Defends against DHCP starvation floods.
- **Live Web Dashboard & Chaos Panel**: Runs on **http://localhost:8080**.

```powershell
cd DHCP
.\run.bat           # Compile and start 3-node cluster + LB + dashboard
```

---

## 3. Telnet: Remote-Management Lab (`./Telnet`)

### Features
- **RFC 854 NVT Codec**: State machine handling control characters, CR NUL / CR LF, and IAC escaping.
- **RFC 1143 Q-Method Option Negotiation**: ECHO, SGA, STATUS, TIMING-MARK, TTYPE, NAWS, TSPEED.
- **Cisco IOS-style Command Shell**: Privilege levels, enable password, configuration modes, command history, and auto-completion.
- **Plaintext vs TLS Sniffer (Wire Tap)**: Demonstrates why Telnet was replaced by SSH.
- **Live Lecture-Slide Dashboard**: Runs on **http://localhost:8081**.

```powershell
cd Telnet
.\run.bat           # Start server, wire tap, and dashboard
.\run.bat --verify  # Run 35 automated checks
```

---

## System Requirements
- **JDK 11+** (Pure standard library, zero third-party dependencies).
- Windows, macOS, or Linux.

# RFC 826 Address Resolution Protocol (ARP) & L2 Security Lab

A complete **RFC 826 Address Resolution Protocol (ARP)** implementation and **L2 Network Security Lab** built in pure Java (Zero external dependencies, JDK 11+).

The lab simulates an IEEE 802.3 Ethernet Local Area Network (LAN) complete with an **8-Port L2 Learning Switch (CAM Table)**, **End Hosts (Alice, Bob, Charlie)**, a **Cisco Default Gateway Router with RFC 1027 Proxy ARP**, a **Kali Rogue Attacker demonstrating Man-In-The-Middle (MITM) ARP Cache Poisoning**, and an enterprise **Dynamic ARP Inspection (DAI)** defense engine integrated with DHCP Snooping.

---

## 1. Quick Start

```powershell
run.bat              REM compile + start everything, then open http://localhost:8082
run.bat --verify     REM run automated RFC 826 / 5227 / 1027 test suite (30+ checks)
```

### Port Allocation:
| Port | What |
|:---|:---|
| HTTP **8082** | Interactive Real-Time Web Dashboard & Wireshark-Style Wire Sniffer |
| HTTP **8080** | Sibling DHCP Module (DHCP Server Cluster & Lease DB) |
| HTTP **8081** | Sibling Telnet Remote-Management Lab (IOS VTY Router CLI) |

---

## 2. Core Protocol Features

### A. Full RFC 826 Address Resolution Protocol
- **28-byte Binary ARP Header**:
  - `HTYPE` (Hardware Type = 1 for Ethernet)
  - `PTYPE` (Protocol Type = `0x0800` for IPv4)
  - `HLEN` = 6 (MAC address length)
  - `PLEN` = 4 (IPv4 address length)
  - `OPER` = 1 (`ARP Request`), 2 (`ARP Reply`), 3 (`RARP Request`), 4 (`RARP Reply`), 8 (`InARP Request`), 9 (`InARP Reply`)
  - `SHA` (Sender Hardware Address, 6 bytes)
  - `SPA` (Sender Protocol Address, 4 bytes)
  - `THA` (Target Hardware Address, 6 bytes - all zeros in Request)
  - `TPA` (Target Protocol Address, 4 bytes)
- **Ethernet II Frame Encapsulation**:
  - Destination MAC (6 bytes, Broadcast `FF:FF:FF:FF:FF:FF` or Unicast)
  - Source MAC (6 bytes)
  - EtherType (`0x0806` for ARP, `0x0800` for IPv4)
  - Automatic padding up to the 46-byte minimum payload (60 bytes minimum on the wire).

### B. ARP Cache Management & State Machine
- Dynamic entries with real-time **TTL countdown timers** and automatic aging reaper.
- State transitions:
  - `INCOMPLETE`: Outbound packet queued while waiting for ARP Reply.
  - `REACHABLE`: Confirmed mapping; timer ticking down.
  - `STALE`: Aged entry awaiting re-verification.
  - `STATIC`: Manually configured VIP, permanent and immune to spoofing.
  - `POISONED`: Flagged when compromised by rogue unsolicited replies.
- **Outbound Packet Queueing (RFC 826 requirement)**: When an application pings an IP without a cached MAC, the IP packet is buffered, the ARP Request is broadcast, and the buffered packet is transmitted upon receiving the ARP Reply!

### C. RFC 5227 Address Conflict Detection (ACD) & Gratuitous ARP (GARP)
- **Gratuitous ARP Announcement (`SPA == TPA == myIp`)**: Broadcast upon link bringup or IP reconfiguration to update switch CAM tables and neighbor caches.
- **ARP Probe (`SPA == 0.0.0.0`, `TPA == candidateIp`)**: Probes candidate IP before assignment without polluting neighbor ARP caches; detects duplicate IP collisions immediately.

### D. RFC 1027 Proxy ARP
- Router transparently answers ARP requests on behalf of remote subnets (`10.0.0.0/24`) using its own Gateway MAC (`00:1A:2B:00:01:01`), allowing cross-subnet communication without client default-gateway configuration.

---

## 3. Network Architecture & Security Features

```
+-------------------------------------------------------------------------+
|                  VLAN 1: 192.168.1.0/24 (Ethernet LAN)                  |
|                                                                         |
|  [Port 1] Host-A (Alice)        192.168.1.10   AA:AA:AA:11:11:11        |
|  [Port 2] Host-B (Bob)          192.168.1.20   BB:BB:BB:22:22:22        |
|  [Port 3] Host-C (Charlie)      192.168.1.30   CC:CC:CC:33:33:33        |
|  [Port 4] Gateway-Router        192.168.1.1    00:1A:2B:00:01:01        |
|  [Port 5] Kali-Attacker         192.168.1.66   66:66:66:66:66:66        |
|                                                                         |
|                          +-------------------+                          |
|                          |    8-Port Switch  |                          |
|                          |    - CAM Learning |                          |
|                          |    - DAI Engine   |                          |
|                          +-------------------+                          |
+-------------------------------------------------------------------------+
```

1. **8-Port L2 Ethernet Switch**:
   - **CAM (Content Addressable Memory) / MAC Table**: Dynamically learns incoming source MACs per port; performs intelligent unicast forwarding or broadcast flooding.
2. **Man-In-The-Middle (MITM) ARP Cache Poisoning**:
   - Rogue node sends forged unsolicited ARP replies to Host-A (claiming Gateway IP is at Attacker MAC) and to Gateway (claiming Host-A is at Attacker MAC).
   - Attacker transparently intercepts packets, logs plaintext payloads, and forwards frames to the genuine destination.
3. **Dynamic ARP Inspection (DAI)**:
   - Cisco/IEEE enterprise switch defense: Intercepts all ARP packets on untrusted switch ports.
   - Validates Ethernet Source MAC against ARP `SHA`.
   - Validates ARP `SHA` and `SPA` against the **DHCP Snooping Database** (which automatically imports leases from `../DHCP/data/leases_node*.db`!).
   - Drops unauthorized ARP packets, increments drop counters, and logs security alerts.

---

## 4. Live Interactive Web Dashboard (`http://localhost:8082`)

The zero-dependency embedded web server provides:
1. **Interactive Topology Visualizer**: Real-time view of all nodes, switch ports, and packet flow.
2. **Real-Time Host ARP Tables**: Live TTL countdown bars for every IP-to-MAC mapping.
3. **Switch CAM Table**: Displays learned port mappings with age timers.
4. **Wireshark-Style Wire Sniffer**: Inspects all captured Ethernet & ARP frames with binary hex breakdown.
5. **MITM Interception Log**: Displays traffic intercepted during simulated attacks.
6. **One-Click Scenarios**: Send Ping, Gratuitous ARP, ARP Probe, Proxy ARP, MITM Poisoning, and Toggle DAI.

---

## 5. Course & Assignment Mapping

| Course Topic | Implementation in this Lab |
|:---|:---|
| **RFC 826 Protocol Specification** | Binary 28-byte encoder/decoder (`ArpPacket.java`, `EthernetFrame.java`) |
| **L2 Switching & MAC Learning** | CAM learning table, unicast forwarding, broadcast flooding (`EthernetSwitch.java`) |
| **Address Conflict Detection (RFC 5227)** | ARP Probe with `SPA = 0.0.0.0` and GARP announcements (`HostNode.java`) |
| **Proxy ARP (RFC 1027)** | Gateway router answering for remote subnets (`RouterNode.java`) |
| **ARP Poisoning & MITM Attacks** | Bidirectional cache poisoning and packet interception (`AttackerNode.java`) |
| **Dynamic ARP Inspection (DAI)** | L2 hardware security dropping unauthorized ARP frames (`DynamicArpInspection.java`) |
| **Cross-Module Link (DHCP)** | Reads `../DHCP/data/leases_node*.db` to populate DHCP Snooping table |
| **Cross-Module Link (Telnet)** | Corresponds to the router's `show arp` table in the Telnet lab |

---

## 6. Directory Layout

```
ARP/
├── README.md
├── PROJECT_GUIDE_AND_VISUALIZATION.md
├── run.bat
├── src/arp/
│   ├── Main.java                        (CLI entry point & demo coordinator)
│   ├── Verify.java                      (Automated end-to-end test suite)
│   ├── core/
│   │   ├── Hub.java                     (Telemetry, packet sniffer & logger)
│   │   ├── Json.java                    (Zero-dependency JSON builder)
│   │   └── Ring.java                    (Thread-safe circular buffer)
│   ├── model/
│   │   ├── MacAddress.java              (48-bit IEEE MAC address representation)
│   │   ├── IpAddress.java               (32-bit IPv4 address representation)
│   │   ├── ArpCacheEntry.java           (Cache entry with states & TTL timer)
│   │   ├── ArpTable.java                (Thread-safe ARP table & packet queue)
│   │   └── SwitchCamEntry.java          (Switch CAM entry with port & age)
│   ├── protocol/
│   │   ├── ArpOperation.java            (Opcodes: Request, Reply, RARP, InARP)
│   │   ├── ArpPacket.java               (RFC 826 binary serializer & parser)
│   │   └── EthernetFrame.java           (Ethernet II frame encoder & decoder)
│   ├── network/
│   │   ├── NetworkInterface.java        (Virtual NIC connected to switch port)
│   │   ├── HostNode.java                (Host TCP/IP + ARP stack & ping)
│   │   ├── RouterNode.java              (Default gateway with Proxy ARP)
│   │   ├── AttackerNode.java            (MITM poisoner & packet interceptor)
│   │   └── EthernetSwitch.java          (8-port switch with CAM & DAI)
│   ├── security/
│   │   ├── DhcpSnoopingTable.java       (Trusted IP-MAC binding database)
│   │   └── DynamicArpInspection.java    (DAI validation and drop engine)
│   └── dashboard/
│       └── DashboardServer.java         (HTTP server on port 8082)
└── web/
    └── dashboard.html                   (Interactive web UI & wire sniffer)
```

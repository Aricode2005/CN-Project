# RFC 826 Address Resolution Protocol (ARP) & L2 Security Lab

A complete **RFC 826 Address Resolution Protocol (ARP)** implementation and **Enterprise Layer 2 Network Security Lab** built in pure Java (Zero external dependencies, JDK 11+).

The lab simulates an IEEE 802.3 Ethernet Local Area Network (LAN) complete with an **8-Port Managed L2 Switch (CAM Table & 802.1Q VLANs)**, **End Hosts (Alice, Bob, Charlie)**, a **Cisco Default Gateway Router with RFC 1027 Proxy ARP and RFC 903 RARP Server**, a **Kali Rogue Attacker demonstrating MITM ARP Poisoning, macof CAM flooding, and DoS storms**, an enterprise **Dynamic ARP Inspection (DAI)** defense engine with **Rate Limiting**, **Cisco Switchport Port-Security (`errdisable`)**, **Host-Side Arpwatch Anti-Spoofing heuristics**, and **live Wireshark PCAP binary export**.

---

## 1. Quick Start

```powershell
run.bat                  REM compile + start lab + dashboard at http://localhost:8082
run.bat --verify         REM run automated test suite (50+ checks across RFC specs)
python interop_test.py   REM (with server running) test HTTP, Cisco CLI, PCAP & defenses
```

### Port Allocation:
| Port | What |
|:---|:---|
| HTTP **8082** | Interactive Real-Time Web Dashboard, Cisco CLI & Wire Sniffer |
| HTTP **8080** | Sibling DHCP Module (DHCP Server Cluster & Lease DB) |
| HTTP **8081** | Sibling Telnet Remote-Management Lab (IOS VTY Router CLI) |

---

## 2. Core Protocol Features

### A. Full RFC 826 Address Resolution Protocol (ARP)
- **28-byte Binary ARP Header**:
  - `HTYPE` (Hardware Type = 1 for Ethernet)
  - `PTYPE` (Protocol Type = `0x0800` for IPv4)
  - `HLEN` = 6 (MAC address length)
  - `PLEN` = 4 (IPv4 address length)
  - `OPER` = 1 (`ARP Request`), 2 (`ARP Reply`), 3 (`RARP Request`), 4 (`RARP Reply`)
  - `SHA` (Sender Hardware Address, 6 bytes)
  - `SPA` (Sender Protocol Address, 4 bytes)
  - `THA` (Target Hardware Address, 6 bytes - all zeros in Request)
  - `TPA` (Target Protocol Address, 4 bytes)
- **Ethernet II Frame Encapsulation**:
  - Destination MAC (6 bytes, Broadcast `FF:FF:FF:FF:FF:FF` or Unicast)
  - Source MAC (6 bytes)
  - EtherType (`0x0806` for ARP, `0x8035` for RARP, `0x0800` for IPv4)
  - Automatic zero-padding up to 60 bytes minimum on the wire.

### B. RFC 903 Reverse Address Resolution Protocol (RARP) Engine
- **Diskless Client Bootstrapping**: A diskless workstation knows only its MAC address and broadcasts a RARP Request (`SHA = myMac, SPA = 0.0.0.0, THA = myMac, TPA = 0.0.0.0`).
- **RARP Server (RouterNode)**: Matches the client MAC against a static MAC-to-IP lease database and replies with a unicast RARP Reply assigning the host's IP address.

### C. RFC 5227 Address Conflict Detection (ACD) State Machine
- Full standard state machine: `IDLE`, `PROBING`, `ANNOUNCING`, `CONFIGURED`, `DEFENDING`, `CONFLICTED`.
- **ARP Probe (`SPA == 0.0.0.0`, `TPA == candidateIp`)**: Probes candidate IP before assignment without polluting neighbor ARP caches; detects duplicate IP collisions immediately.
- **Gratuitous ARP Announcement (`SPA == TPA == myIp`)**: Broadcast upon link bringup or IP reconfiguration to update switch CAM tables and neighbor caches.
- **Active RFC 5227 §2.4 Defense**: When a conflict arrives on an active interface, the defending host transmits a **Defensive Gratuitous ARP**. If a second conflicting announcement arrives within 10s (`DEFEND_INTERVAL`), the host yields (`CONFLICTED`) to avoid split-brain network disruption.

### D. IEEE 802.1Q Virtual LAN (VLAN) Tagging & Isolation
- **4-Byte 802.1Q Header (`Dot1qHeader.java`)**: `TPID = 0x8100`, Priority (PCP 3-bits), Drop Eligible (DEI 1-bit), VLAN Identifier (VID 12-bits).
- **VLAN Segmentation**: Configures switch access ports into separate broadcast domains (e.g. VLAN 10 Sales, VLAN 20 Engineering). ARP broadcasts are strictly confined within their VLAN, completely preventing cross-VLAN ARP spoofing!

### E. RFC 1027 Proxy ARP
- Router transparently answers ARP requests on behalf of remote subnets (`10.0.0.0/24`) using its own Gateway MAC (`00:1A:2B:00:01:01`), allowing cross-subnet communication without client default-gateway configuration.

---

## 3. Enterprise L2 Security Architecture

```
+-----------------------------------------------------------------------------------+
|               VLAN 10: 192.168.1.0/24            |   VLAN 20: 192.168.1.0/24      |
|  [Port 1] Host-A (Alice)      192.168.1.10       |  [Port 3] Host-C (Charlie)     |
|           AA:AA:AA:11:11:11                      |           CC:CC:CC:33:33:33    |
|  [Port 2] Host-B (Bob)        192.168.1.20       |                                |
|           BB:BB:BB:22:22:22                      |                                |
|  [Port 4] Gateway-Router      192.168.1.1        |  [Port 5] Kali-Attacker        |
|           00:1A:2B:00:01:01  (TRUSTED)           |           66:66:66:66:66:66    |
|                                                  |                                |
|               +-----------------------------------------------------+             |
|               |              8-Port Managed L2 Switch               |             |
|               |  - CAM MAC Learning Table                           |             |
|               |  - IEEE 802.1Q VLAN Broadcast Isolation             |             |
|               |  - Cisco Switchport Port-Security (Err-Disable)     |             |
|               |  - Dynamic ARP Inspection (DAI) & Rate Limiting     |             |
|               +-----------------------------------------------------+             |
+-----------------------------------------------------------------------------------+
```

1. **Cisco Switchport Port-Security (`PortSecurity.java`)**:
   - Limits maximum allowed MAC addresses per port (e.g. max 1 MAC per access port).
   - Violation actions: `PROTECT` (silent drop), `RESTRICT` (drop + count violations), `SHUTDOWN` (transitions port into `ERR_DISABLE` state, taking the link completely offline).
   - Sticky MAC learning: automatically remembers legitimate station MAC.
   - Completely neutralizes `macof` / CAM table exhaustion flooding attacks!

2. **Dynamic ARP Inspection (DAI) & Rate Limiting (`DynamicArpInspection.java`)**:
   - Intercepts all ARP packets on untrusted switch ports.
   - Validates `SPA` and `SHA` against the **DHCP Snooping Database** (imported from `../DHCP/data/leases_node*.db`).
   - **Cisco Validation Checks**:
     - `validate src-mac`: checks Ethernet Frame Source MAC == ARP SHA.
     - `validate dst-mac`: checks Ethernet Frame Destination MAC == ARP THA (in unicast replies).
     - `validate ip`: drops invalid/banned IP ranges (`0.0.0.0` in replies, broadcast `255.255.255.255`, multicast `224.0.0.0/4`, loopback `127.0.0.0/8`).
   - **ARP Rate Limiting (DoS Storm Defense)**: Monitors packets per second per untrusted port (default: 15 pps). Shuts down bursting attacker ports to `ERR_DISABLE`.

3. **Host-Side Arpwatch & Anti-Spoofing Heuristics (`HostArpDefender.java`)**:
   - Monitors incoming ARP replies locally on end hosts.
   - Detects **MAC Flip-Flops**: when a known valid IP abruptly flips to a different MAC address without prior expiration or probing.
   - `STRICT` mode: Rejects unsolicited flip-flops to safeguard local caches even on unmanaged switches!

4. **Wireshark PCAP Binary Export Engine (`PcapExporter.java`)**:
   - Zero-dependency generator producing standard libpcap 2.4 binary format (`0xa1b2c3d4`).
   - Download the live simulation trace anytime via the web dashboard or `http://localhost:8082/api/export/pcap` and open it directly in Wireshark!

5. **Cisco IOS Diagnostic Console**:
   - Integrated CLI command runner supporting:
     - `show mac address-table`
     - `show vlan brief`
     - `show ip arp inspection`
     - `show port-security`
     - `show interfaces status`
     - `clear mac address-table`

---

## 4. Live Interactive Web Dashboard (`http://localhost:8082`)

The zero-dependency embedded web server provides:
1. **Interactive Topology Visualizer**: Displays nodes, ports, live VLAN badges (VLAN 1, 10, 20), ACD states, and link status.
2. **Real-Time Host ARP Tables**: Live TTL countdown bars for every IP-to-MAC mapping, with Arpwatch Flip-Flop monitors and Strict mode toggles.
3. **Switch CAM Table**: Displays learned port and VLAN mappings with age timers.
4. **Cisco IOS Diagnostic Console**: Interactive command prompt to run `show ...` commands in real time.
5. **Wireshark-Style Wire Sniffer**: Inspects all captured Ethernet & ARP frames with binary hex breakdown.
6. **One-Click Scenarios**:
   - Cold Cache Ping & Packet Queuing
   - Gratuitous ARP Announcement
   - RFC 903 Diskless RARP Boot (Host-C)
   - RFC 5227 ACD Full Workflow
   - RFC 1027 Proxy ARP across Subnets
   - 802.1Q VLAN Broadcast Domain Isolation
   - MITM ARP Cache Poisoning Attack
   - Cisco Port-Security vs macof CAM Flood
   - DAI Rate Limiting DoS Storm -> Err-Disable
   - Reset Err-Disabled Ports
   - Export Wireshark PCAP

---

## 5. Course & Assignment Mapping

| Course Topic | Implementation in this Lab |
|:---|:---|
| **RFC 826 Protocol Specification** | Binary 28-byte encoder/decoder (`ArpPacket.java`, `EthernetFrame.java`) |
| **RFC 903 Reverse ARP (RARP)** | Diskless client bootstrapping and static RARP lease server (`RouterNode.java`) |
| **Address Conflict Detection (RFC 5227)** | Full ACD state machine (Probing, Announcing, Defending, Conflicted) (`HostNode.java`) |
| **Proxy ARP (RFC 1027)** | Gateway router answering for remote subnets (`RouterNode.java`) |
| **IEEE 802.1Q Virtual LANs (VLANs)** | 4-byte 802.1Q tag header and switch broadcast domain isolation (`Dot1qHeader.java`) |
| **Cisco Switchport Port-Security** | Max MAC limiting, Sticky MACs, and `ERR_DISABLE` shutdown (`PortSecurity.java`) |
| **Dynamic ARP Inspection (DAI)** | L2 hardware security dropping unauthorized ARP frames (`DynamicArpInspection.java`) |
| **DAI Rate Limiting & DoS Storms** | Packet-per-second limiting per untrusted port (`ArpRateLimiter.java`) |
| **Host-Side Arpwatch / Anti-Spoofing** | Passive MAC flip-flop detection and strict mode rejection (`HostArpDefender.java`) |
| **Packet Trace Analysis** | Standard binary libpcap 2.4 generation (`PcapExporter.java`) |
| **Cross-Module Link (DHCP)** | Reads `../DHCP/data/leases_node*.db` to populate DHCP Snooping table |
| **Cross-Module Link (Telnet)** | Corresponds to the router's `show arp` table in the Telnet lab |

---

## 6. Directory Layout

```
ARP/
├── README.md                                (Comprehensive guide & feature reference)
├── PROJECT_GUIDE_AND_VISUALIZATION.md       (Theoretical guide, sequence diagrams & viva Q&A)
├── run.bat                                  (Build and run script)
├── interop_test.py                          (Python automated integration test suite)
├── src/arp/
│   ├── Main.java                            (CLI coordinator & interactive scenario runner)
│   ├── Verify.java                          (Automated verification suite: 50+ checks)
│   ├── core/
│   │   ├── Hub.java                         (Central telemetry, wire sniffer & logger)
│   │   ├── Json.java                        (Zero-dependency JSON builder)
│   │   ├── Ring.java                        (Thread-safe circular buffer)
│   │   └── PcapExporter.java                (Standard Wireshark .pcap binary generator)
│   ├── model/
│   │   ├── MacAddress.java                  (48-bit IEEE MAC address representation)
│   │   ├── IpAddress.java                   (32-bit IPv4 address representation)
│   │   ├── AcdState.java                    (RFC 5227 ACD state machine enum)
│   │   ├── ArpCacheEntry.java               (Cache entry with states & TTL timer)
│   │   ├── ArpTable.java                    (Thread-safe ARP table & packet queue)
│   │   └── SwitchCamEntry.java              (Switch CAM entry with port, VLAN & age)
│   ├── protocol/
│   │   ├── ArpOperation.java                (Opcodes: Request, Reply, RARP, InARP)
│   │   ├── ArpPacket.java                   (RFC 826 / 5227 / 903 binary serializer & parser)
│   │   ├── EthernetFrame.java               (Ethernet II & 802.1Q frame encoder & decoder)
│   │   └── Dot1qHeader.java                 (IEEE 802.1Q 4-byte VLAN tag header)
│   ├── network/
│   │   ├── NetworkInterface.java            (Virtual NIC connected to switch port)
│   │   ├── HostNode.java                    (Host ARP stack, ping, ACD & RARP client)
│   │   ├── RouterNode.java                  (Default gateway with Proxy ARP & RARP server)
│   │   ├── AttackerNode.java                (MITM poisoner, macof CAM flooder & DoS storm)
│   │   └── EthernetSwitch.java              (8-port switch with CAM, 802.1Q, Port-Sec & Cisco CLI)
│   ├── security/
│   │   ├── DhcpSnoopingTable.java           (Trusted IP-MAC binding database)
│   │   ├── DynamicArpInspection.java        (DAI validation and drop engine)
│   │   ├── ArpRateLimiter.java              (DAI DoS storm rate limiter & errdisable)
│   │   ├── PortSecurity.java                (Cisco switchport port-security simulator)
│   │   └── HostArpDefender.java             (Host-side Arpwatch & MAC flip-flop detector)
│   └── dashboard/
│       └── DashboardServer.java             (HTTP server, PCAP streaming & Cisco CLI REST API)
└── web/
    └── dashboard.html                       (Interactive real-time web UI, Cisco CLI & sniffer)
```

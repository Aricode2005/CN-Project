# RFC 826 ARP Protocol & L2 Security Architecture Guide

## Complete Theoretical Reference, Protocol Implementation & Live Demonstration Guide

---

## Table of Contents
1. [Project Overview & Architectural Scope](#1-project-overview--architectural-scope)
2. [Protocol Formats & Binary Encodings](#2-protocol-formats--binary-encodings)
   - [2.1 RFC 826 ARP / RARP Packet Layout](#21-rfc-826-arp--rarp-packet-layout)
   - [2.2 Ethernet II Frame Encapsulation](#22-ethernet-ii-frame-encapsulation)
   - [2.3 IEEE 802.1Q VLAN Tag Header (4 Octets)](#23-ieee-8021q-vlan-tag-header-4-octets)
   - [2.4 Wireshark libpcap 2.4 Binary Format](#24-wireshark-libpcap-24-binary-format)
3. [System Architecture & Network Topology](#3-system-architecture--network-topology)
4. [Detailed Protocol Workflows & Sequence Diagrams](#4-detailed-protocol-workflows--sequence-diagrams)
   - [4.1 Standard Address Resolution (Cold Cache)](#41-standard-address-resolution-cold-cache)
   - [4.2 RFC 5227 Address Conflict Detection (ACD) & Gratuitous ARP](#42-rfc-5227-address-conflict-detection-acd--gratuitous-arp)
   - [4.3 RFC 5227 §2.4 Active Defense & Conflict Yielding](#43-rfc-5227-24-active-defense--conflict-yielding)
   - [4.4 RFC 903 Reverse ARP (RARP) Diskless Workstation Boot](#44-rfc-903-reverse-arp-rarp-diskless-workstation-boot)
   - [4.5 RFC 1027 Proxy ARP Across Subnets](#45-rfc-1027-proxy-arp-across-subnets)
   - [4.6 IEEE 802.1Q VLAN Broadcast Domain Isolation](#46-ieee-8021q-vlan-broadcast-domain-isolation)
   - [4.7 MITM ARP Cache Poisoning Attack](#47-mitm-arp-cache-poisoning-attack)
   - [4.8 Cisco Switchport Port-Security vs macof CAM Overflow](#48-cisco-switchport-port-security-vs-macof-cam-overflow)
   - [4.9 Dynamic ARP Inspection (DAI) & Rate Limiting DoS Defense](#49-dynamic-arp-inspection-dai--rate-limiting-dos-defense)
   - [4.10 Host-Side Arpwatch & MAC Flip-Flop Detection](#410-host-side-arpwatch--mac-flip-flop-detection)
5. [Step-by-Step Live Demonstration Script (For Presentation / Viva)](#5-step-by-step-live-demonstration-script-for-presentation--viva)
6. [Viva & Technical Examination Questions](#6-viva--technical-examination-questions)

---

## 1. Project Overview & Architectural Scope

In an IP-over-Ethernet network, communication at Layer 3 (Network Layer) uses 32-bit logical IPv4 addresses, while communication at Layer 2 (Data Link Layer) requires 48-bit physical MAC addresses. The **Address Resolution Protocol (ARP)**, formalized in **RFC 826**, dynamically resolves a target IP address to its corresponding MAC address on the local broadcast domain.

Because standard ARP is **stateless and unauthenticated**, it is susceptible to serious vulnerabilities:
- **ARP Spoofing / Cache Poisoning**: An attacker transmits forged ARP replies claiming ownership of the default gateway's IP, intercepting or modifying traffic (Man-In-The-Middle).
- **IP Address Collisions**: Two hosts inadvertently configured with identical IP addresses cause network disruption.
- **CAM Table Overflow (macof)**: Flooding the switch with thousands of randomized MAC addresses exhausts switch memory, causing it to fail open and act as a hub.
- **ARP Storm DoS**: Flooding switches with high packet-per-second ARP bursts exhausts switch CPU and buffers.

This project delivers a **pure Java (zero-dependency, JDK 11+) production-grade simulation** of the entire Layer 2 ARP ecosystem:
1. **RFC 826 binary packet encoding/decoding**.
2. **RFC 903 Reverse ARP (RARP)** diskless workstation bootstrap client and server.
3. **IEEE 802.3 / Ethernet II framing** with auto-padding and **IEEE 802.1Q VLAN Tagging**.
4. **ARP cache state machine** with live aging timers, pending packet buffers, and static VIP pinning.
5. **RFC 5227 Address Conflict Detection (ACD)** state machine (`PROBING`, `ANNOUNCING`, `DEFENDING`, `CONFLICTED`).
6. **RFC 1027 Proxy ARP** for cross-subnet reachability.
7. **8-Port Managed L2 Switch** with CAM learning and IEEE 802.1Q VLAN broadcast domain isolation.
8. **Cisco Switchport Port-Security** with sticky MAC learning and `ERR_DISABLE` auto-shutdown.
9. **Dynamic ARP Inspection (DAI)** with DHCP Snooping integration, Cisco packet validation (`src-mac`, `dst-mac`, `ip`), and **ARP Rate Limiting**.
10. **Host-Side Arpwatch / Anti-Spoofing** with unsolicited MAC flip-flop detection and strict mode.
11. **Wireshark PCAP Binary Export Engine** (`/api/export/pcap`) producing standard libpcap 2.4 files.
12. **Cisco IOS Diagnostic CLI** (`show mac address-table`, `show vlan brief`, `show ip arp inspection`, `show port-security`).

---

## 2. Protocol Formats & Binary Encodings

### 2.1 RFC 826 ARP / RARP Packet Layout (28 Octets)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Hardware Type (1)      |     Protocol Type (0x0800)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  HW Len (6)   | Proto Len (4) |        Operation (1, 2, 3, 4) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Sender Hardware Address (SHA: bytes 0-3)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  SHA (bytes 4-5)              |  Sender IP (SPA: bytes 0-1)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  SPA (bytes 2-3)              |  Target Hardware (THA: 0-1)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Target Hardware Address (THA: bytes 2-5)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Target Protocol Address (TPA: bytes 0-3)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 2.2 Ethernet II Frame Encapsulation

```
+-------------------+-------------------+-------------------+--------------------+
|  Dest MAC (6 B)   |  Src MAC (6 B)    | EtherType (2 B)   |  Payload (46-1500) |
|  FF:FF:FF:FF:FF:FF|  AA:AA:AA:11:11:11| 0x0806 (ARP)      |  28B ARP + 18B Pad |
+-------------------+-------------------+-------------------+--------------------+
```
*(Total minimum wire length = 60 bytes excluding 4-byte CRC).*

### 2.3 IEEE 802.1Q VLAN Tag Header (4 Octets)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          TPID (0x8100)        | PCP (3b)|D(1b)|  VID (12 bits)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 2.4 Wireshark libpcap 2.4 Binary Format

- **24-byte Global Header**: `Magic: 0xA1B2C3D4`, `v2.4`, `Snaplen: 65535`, `LinkType: 1 (LINKTYPE_ETHERNET)`.
- **16-byte Packet Header**: `ts_sec`, `ts_usec`, `incl_len`, `orig_len` followed immediately by wire Ethernet bytes.

---

## 3. System Architecture & Network Topology

```mermaid
flowchart TB
    subgraph LAN["Managed Campus Ethernet Switch (Switch-1)"]
        direction TB
        subgraph V10["VLAN 10: Sales (192.168.1.0/24)"]
            H1["Host-A (Alice)<br/>IP: 192.168.1.10<br/>MAC: AA:AA:AA:11:11:11<br/>Port 1"]
            H2["Host-B (Bob)<br/>IP: 192.168.1.20<br/>MAC: BB:BB:BB:22:22:22<br/>Port 2"]
            R1["Gateway-Router (Cisco)<br/>IP: 192.168.1.1<br/>MAC: 00:1A:2B:00:01:01<br/>Port 4 (TRUSTED)"]
        end

        subgraph V20["VLAN 20: Engineering (192.168.1.0/24)"]
            H3["Host-C (Charlie)<br/>IP: 192.168.1.30 (Diskless RARP)<br/>MAC: CC:CC:CC:33:33:33<br/>Port 3"]
            AT["Kali Rogue Attacker<br/>IP: 192.168.1.66<br/>MAC: 66:66:66:66:66:66<br/>Port 5 (Port-Security / UNTRUSTED)"]
        end

        SW["8-Port Managed L2 Switch<br/>- IEEE 802.1Q VLAN Filtering<br/>- Cisco Port-Security (Err-Disable)<br/>- Dynamic ARP Inspection Engine<br/>- DAI Rate Limiting (15 pps)"]
    end

    subgraph Remote["Remote Subnet (Layer 3)"]
        REM["Remote Host<br/>10.0.0.5"]
    end

    H1 <-->|Port 1| SW
    H2 <-->|Port 2| SW
    H3 <-->|Port 3| SW
    R1 <-->|Port 4| SW
    AT <-->|Port 5| SW
    R1 -.->|Proxy ARP Routing| REM
```

---

## 4. Detailed Protocol Workflows & Sequence Diagrams

### 4.1 Standard Address Resolution (Cold Cache)

```mermaid
sequenceDiagram
    autonumber
    participant A as Host-A (192.168.1.10)
    participant SW as 8-Port L2 Switch
    participant B as Host-B (192.168.1.20)

    Note over A: Ping triggered to 192.168.1.20.<br/>ARP Cache MISS -> State=INCOMPLETE.<br/>Packet queued in buffer.
    A->>SW: Ethernet Frame (Broadcast FF:FF:FF:FF:FF:FF)<br/>ARP Request: "Who has 192.168.1.20? Tell 192.168.1.10"
    Note over SW: Switch learns Port 1 -> AA:AA:AA:11:11:11 in CAM.<br/>Floods broadcast to Ports on same VLAN.
    SW->>B: ARP Request received
    Note over B: Target IP matches my IP!<br/>Learns A in ARP Table (192.168.1.10 -> AA:AA:AA:11:11:11).
    B->>SW: Ethernet Frame (Unicast to AA:AA:AA:11:11:11)<br/>ARP Reply: "192.168.1.20 is at BB:BB:BB:22:22:22"
    Note over SW: Switch learns Port 2 -> BB:BB:BB:22:22:22 in CAM.<br/>Dest MAC known in CAM -> Forward ONLY to Port 1!
    SW->>A: ARP Reply delivered
    Note over A: ARP Entry updated: REACHABLE (TTL=30s).<br/>Queued ping packet drained & transmitted!
    A->>SW: Ethernet Frame (Unicast IPv4)<br/>PING: Host-A -> Host-B
    SW->>B: PING delivered directly
```

---

### 4.2 RFC 5227 Address Conflict Detection (ACD) & Gratuitous ARP

```mermaid
sequenceDiagram
    autonumber
    participant Node as Host-B (192.168.1.20)
    participant SW as L2 Switch
    participant LAN as All Network Hosts

    Note over Node: Case 1: Interface Bringup<br/>Broadcasts Gratuitous ARP (GARP)
    Node->>SW: ARP Request (SPA = 192.168.1.20, TPA = 192.168.1.20, Dst = FF:FF:FF:FF:FF:FF)
    SW->>LAN: Floods GARP
    Note over LAN: All neighbors update their ARP caches.<br/>Switch refreshes CAM port mapping immediately!

    Note over Node: Case 2: Address Conflict Detection (ACD)<br/>Node sends ARP Probe (SPA = 0.0.0.0)
    Node->>SW: ARP Probe (SPA = 0.0.0.0, TPA = Candidate IP)
    SW->>LAN: Floods ARP Probe
    Note over LAN: If another host holds Candidate IP,<br/>it responds with ARP Reply -> CONFLICT ALARM!
```

---

### 4.3 RFC 5227 §2.4 Active Defense & Conflict Yielding

```mermaid
sequenceDiagram
    autonumber
    participant Legitimate as Legitimate Host-B (192.168.1.20)
    participant SW as L2 Switch
    participant Rogue as Rogue Node (Intruder)

    Note over Legitimate: State: CONFIGURED (IP 192.168.1.20 is active)
    Rogue->>SW: Broadcast ARP Claiming 192.168.1.20 (Rogue MAC)
    SW->>Legitimate: Frame delivered
    Note over Legitimate: CONFLICT DETECTED while configured!<br/>State transitions to DEFENDING.<br/>Transmits Defensive GARP to re-assert ownership!
    Legitimate->>SW: Defensive GARP (SPA = 192.168.1.20, SHA = BB:BB:BB:22:22:22)
    SW->>Rogue: Network caches re-anchored to legitimate host

    Note over Rogue: Rogue re-transmits conflicting claim within 10s window!
    Rogue->>SW: Second Conflicting ARP
    SW->>Legitimate: Delivered
    Note over Legitimate: Re-asserted conflict within 10s DEFEND_INTERVAL!<br/>Per RFC 5227 §2.4: Host YIELDS IP to avoid split-brain disruption.<br/>State transitions to CONFLICTED.
```

---

### 4.4 RFC 903 Reverse ARP (RARP) Diskless Workstation Boot

```mermaid
sequenceDiagram
    autonumber
    participant C as Diskless Host-C (CC:CC:CC:33:33:33)
    participant SW as L2 Switch
    participant R as Router / RARP Server (00:1A:2B:00:01:01)

    Note over C: Workstation boots with no local storage.<br/>Knows its own MAC, but has IP = 0.0.0.0.
    C->>SW: Broadcast RARP Request (Oper=3)<br/>"Who am I? What is the IP for CC:CC:CC:33:33:33?"
    SW->>R: Flooded to Gateway Router
    Note over R: Router checks static RARP lease table:<br/>CC:CC:CC:33:33:33 -> 192.168.1.30
    R->>SW: Unicast RARP Reply (Oper=4)<br/>"CC:CC:CC:33:33:33 is assigned IP 192.168.1.30"
    SW->>C: Delivered to Host-C
    Note over C: Host-C configures IP to 192.168.1.30!<br/>ACD State becomes CONFIGURED.<br/>Workstation boot completed.
```

---

### 4.5 RFC 1027 Proxy ARP Across Subnets

```mermaid
sequenceDiagram
    autonumber
    participant A as Host-A (192.168.1.10)
    participant SW as L2 Switch
    participant R as Router Gateway (192.168.1.1)

    Note over A: Ping to 10.0.0.5 without gateway config.
    A->>SW: ARP Request: "Who has 10.0.0.5? Tell 192.168.1.10"
    SW->>R: Forwarded to Gateway Port 4
    Note over R: Proxy ARP Enabled!<br/>10.0.0.5 is in router's remote route table.<br/>Router responds with ITS OWN MAC!
    R->>SW: ARP Reply: "10.0.0.5 is at 00:1A:2B:00:01:01"
    SW->>A: Unicast delivered to Host-A
    Note over A: Host-A caches: 10.0.0.5 -> 00:1A:2B:00:01:01.<br/>Transmits packets directly to Router MAC!
```

---

### 4.6 IEEE 802.1Q VLAN Broadcast Domain Isolation

```mermaid
sequenceDiagram
    autonumber
    participant A as Host-A (Port 1 - VLAN 10)
    participant SW as Managed Switch
    participant B as Host-B (Port 2 - VLAN 10)
    participant C as Host-C (Port 3 - VLAN 20)

    Note over A: Host-A broadcasts ARP Request on Port 1
    A->>SW: Broadcast Frame (VLAN 10)
    Note over SW: Switch identifies Port 1 is in VLAN 10.<br/>Floods ONLY to ports belonging to VLAN 10!
    SW->>B: Broadcast delivered to Port 2 (VLAN 10)
    Note over SW: Port 3 is in VLAN 20 (different broadcast domain).<br/>Frame is FILTERED at switch boundary!
    SW--x C: Host-C NEVER receives VLAN 10 broadcast!
```

---

### 4.7 MITM ARP Cache Poisoning Attack

```mermaid
sequenceDiagram
    autonumber
    participant A as Victim (Host-A)
    participant K as Kali Attacker (66:66:66:66:66:66)
    participant G as Gateway (192.168.1.1)

    Note over K: Launch Bidirectional ARP Poisoning (DAI OFF)
    K->>A: Unsolicited Forged ARP Reply: "192.168.1.1 is at 66:66:66:66:66:66"
    K->>G: Unsolicited Forged ARP Reply: "192.168.1.10 is at 66:66:66:66:66:66"
    Note over A: Host-A ARP Table POISONED!<br/>Gateway mapped to Attacker MAC.
    Note over G: Gateway ARP Table POISONED!<br/>Host-A mapped to Attacker MAC.

    Note over A: Host-A sends packet to Gateway
    A->>K: Ethernet Frame sent to 66:66:66:66:66:66!
    Note over K: Attacker intercepts & logs plaintext payload!
    K->>G: Attacker re-encapsulates & forwards to real Gateway
```

---

### 4.8 Cisco Switchport Port-Security vs macof CAM Overflow

```mermaid
sequenceDiagram
    autonumber
    participant K as Attacker (Port 5 - Port Security ON, Max MAC=1)
    participant SW as Managed Switch (Port Security Engine)
    participant CAM as Switch CAM Table

    Note over K: Attacker floods randomized source MACs (macof attack)
    K->>SW: Frame 1: Src MAC = 66:66:66:66:66:66
    Note over SW: First MAC learned as sticky secure MAC (1/1). Permitted.
    K->>SW: Frame 2: Src MAC = 00:AA:11:22:33:44 (Spoofed)
    Note over SW: MAC limit exceeded (2 > 1)!<br/>Violation Action = SHUTDOWN.<br/>Port 5 transitioned to ERR_DISABLE!
    SW--x CAM: Spoofed MAC rejected. CAM table preserved.
    Note over K: Attacker link is DOWN! All subsequent frames dropped.
```

---

### 4.9 Dynamic ARP Inspection (DAI) & Rate Limiting DoS Defense

```mermaid
sequenceDiagram
    autonumber
    participant K as Attacker (Port 5 - Untrusted)
    participant SW as Switch (DAI & Rate Limiter ON)
    participant DB as DHCP Snooping Database
    participant A as Victim (Host-A)

    Note over K: Case 1: Spoofed IP Binding
    K->>SW: Forged ARP Reply: "192.168.1.1 is at 66:66:66:66:66:66"
    SW->>DB: Check Binding for 192.168.1.1
    DB-->>SW: Valid Binding is 192.168.1.1 -> 00:1A:2B:00:01:01
    Note over SW: BINDING MISMATCH! Frame dropped. Security alert logged.
    SW--x A: Malicious packet NEVER reaches victim.

    Note over K: Case 2: ARP Storm DoS Flood (35 pps burst)
    K->>SW: Burst ARP frames exceeding 15 pps threshold
    Note over SW: Rate limit threshold exceeded!<br/>Port 5 transitioned to ERR_DISABLE (Rate Limiting).<br/>DoS storm mitigated immediately.
```

---

### 4.10 Host-Side Arpwatch & MAC Flip-Flop Detection

```mermaid
sequenceDiagram
    autonumber
    participant A as Host-A (Arpwatch Defender STRICT Mode)
    participant K as Attacker

    Note over A: Current Cache: 192.168.1.1 -> 00:1A:2B:00:01:01 (Gateway)
    K->>A: Forged ARP Reply: "192.168.1.1 is at 66:66:66:66:66:66"
    Note over A: Host Defender checks update:<br/>Existing MAC (00:1A:2B) != Incoming MAC (66:66:66)!<br/>MAC FLIP-FLOP ALARM triggered!<br/>Strict Mode: Update REJECTED locally.
    Note over A: Gateway mapping remains clean (00:1A:2B:00:01:01).
```

---

## 5. Step-by-Step Live Demonstration Script (For Presentation / Viva)

1. **Launch the Lab**:
   ```powershell
   .\run.bat
   ```
   Open **http://localhost:8082** in your browser.

2. **Step 1: Standard Cold Resolution Handshake**:
   - In the dashboard, click **"1. Ping Host-A &rarr; Host-B"**.
   - Show the terminal log: `ARP Cache MISS for 192.168.1.20. Queueing packet and broadcasting ARP Request.`
   - Point out in the sniffer: Frame #1 is Broadcast `FF:FF:FF:FF:FF:FF` (ARP Request), Frame #2 is Unicast `BB:BB:BB:22:22:22 -> AA:AA:AA:11:11:11` (ARP Reply), and Frame #3 is the delivered IP Ping segment.
   - Host-A ARP table shows `192.168.1.20` is now `REACHABLE` with an active TTL timer.

3. **Step 2: RFC 903 Diskless Workstation Boot (RARP)**:
   - Click **"4. RFC 903 Diskless RARP Boot"**.
   - Host-C broadcasts a RARP request (`OPER=3`) asking for its IP address.
   - The Gateway Router answers with RARP reply (`OPER=4`) assigning `192.168.1.30`.
   - Host-C dynamically configures its IP and enters `CONFIGURED` state!

4. **Step 3: RFC 5227 ACD Full State Machine**:
   - Click **"5. RFC 5227 ACD Full Workflow"**.
   - Watch Host-A transition from `PROBING` (`SPA = 0.0.0.0`) to `ANNOUNCING` (Gratuitous ARPs) to `CONFIGURED`.

5. **Step 4: IEEE 802.1Q VLAN Broadcast Isolation**:
   - Click **"7. 802.1Q VLAN Demo: Isolate Host-C in VLAN 20"**.
   - Notice the topology badges: Host-A & B are in VLAN 10 (Sales), Host-C is in VLAN 20 (Engineering).
   - Host-A pings Host-C: show the terminal log explaining that broadcast frames from VLAN 10 are strictly filtered at the switch boundary and never reach VLAN 20!

6. **Step 5: Cisco Switchport Port-Security Defense**:
   - Click **"9. Cisco Port-Security vs macof CAM Flood"**.
   - Attacker attempts to flood randomized MACs to exhaust switch memory.
   - Port-Security triggers violation (`SHUTDOWN`) and places Port 5 in `ERR_DISABLE` state!
   - In the Cisco CLI box, type `show port-security` and `show interfaces status` to prove the port is shut down.

7. **Step 6: DAI Rate Limiting DoS Defense**:
   - Click **"10. DAI Rate Limiter DoS Test"**.
   - Attacker launches a burst ARP storm: the switch rate limiter detects the flood exceeding 15 pps and shuts down the port.
   - Click **"Reset Err-Disabled Ports"** to demonstrate administrative recovery.

8. **Step 7: Wireshark PCAP Binary Export**:
   - Click **"Export Wireshark PCAP (.pcap)"** at the top right.
   - The browser downloads `arp_lab_capture.pcap`.
   - Open this file in Wireshark: show professors that every single simulated frame is a 100% compliant IEEE 802.3 Ethernet frame with 802.1Q tags and 28-byte ARP headers!

---

## 6. Viva & Technical Examination Questions

**Q1: What is the exact size of an RFC 826 ARP packet over Ethernet, and why does Wireshark display 60 bytes on the wire?**  
*Answer:* The logical ARP header for Ethernet/IPv4 is exactly 28 bytes. However, the IEEE 802.3 standard specifies a minimum Ethernet payload of 46 bytes. Therefore, the sender NIC pads the remaining 18 bytes with zeros. Adding the 14-byte Ethernet header (6 Dest + 6 Src + 2 EtherType) yields 60 bytes minimum frame length on the wire (64 bytes including the 4-byte FCS/CRC).

**Q2: What is the difference between ARP, RARP (RFC 903), and Inverse ARP (RFC 2390)?**  
*Answer:*
- **ARP**: Resolves a known IP address to an unknown MAC address on a local broadcast domain.
- **RARP**: Resolves a known MAC address to an unknown IP address, traditionally used by diskless workstations during network bootstrapping.
- **InARP**: Resolves a Layer 2 virtual circuit ID (such as a Frame Relay DLCI or ATM VPI/VCI) to a Layer 3 IP address.

**Q3: What are the states in the RFC 5227 Address Conflict Detection (ACD) state machine?**  
*Answer:*
1. `PROBING`: Host broadcasts ARP Probes with `SPA = 0.0.0.0` to detect whether candidate IP is in use.
2. `ANNOUNCING`: If clean, host broadcasts Gratuitous ARPs (`SPA == TPA == myIp`) to update neighbor caches.
3. `CONFIGURED`: The IP is bound and active on the interface.
4. `DEFENDING`: If an ongoing collision packet arrives, the host transmits a defensive GARP to re-assert ownership.
5. `CONFLICTED`: If repeated collisions arrive within 10s, the host yields the IP to prevent network partition.

**Q4: How does IEEE 802.1Q VLAN tagging prevent ARP Spoofing across different subnets?**  
*Answer:* Switches insert a 4-byte 802.1Q tag (`TPID = 0x8100`, 12-bit VID) into the Ethernet header. Switches maintain strict broadcast domain boundaries: an ARP broadcast from an untrusted port in VLAN 20 is only flooded to ports assigned to VLAN 20. It can never cross into VLAN 10 at Layer 2, making cross-VLAN ARP cache poisoning physically impossible without a compromised Layer 3 router.

**Q5: What is Cisco Switchport Port-Security and how does `errdisable` mitigate CAM table exhaustion (`macof`)?**  
*Answer:* Port-Security restricts the number of unique MAC addresses allowed to enter a physical access port (typically max 1). When an attack tool like `macof` attempts to overflow the switch CAM table by generating thousands of random source MACs, Port-Security detects that the MAC threshold is exceeded and executes the configured violation action (`SHUTDOWN`), immediately placing the port into `errdisable` (administrative down) state and protecting the switch CAM table.

**Q6: What is Dynamic ARP Inspection (DAI) Rate Limiting?**  
*Answer:* While standard DAI validates ARP packets against the DHCP Snooping database, evaluating cryptographic or database lookups in switch hardware CPU is resource-intensive. Attackers can flood high rates of ARP packets to cause CPU exhaustion (DoS ARP Storm). DAI rate limiting restricts untrusted ports to a maximum packet-per-second threshold (e.g. 15 pps), shutting down bursting ports into `errdisable` state upon violation.

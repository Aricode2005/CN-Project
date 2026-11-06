# RFC 826 ARP Protocol & L2 Security Architecture Guide

## Complete Theoretical Reference, Protocol Implementation & Live Demonstration Guide

---

## Table of Contents
1. [Project Overview & Architectural Scope](#1-project-overview--architectural-scope)
2. [Protocol Formats & Binary Encodings](#2-protocol-formats--binary-encodings)
3. [System Architecture & Network Topology](#3-system-architecture--network-topology)
4. [Detailed Protocol Workflows & Sequence Diagrams](#4-detailed-protocol-workflows--sequence-diagrams)
   - [4.1 Standard Address Resolution (Cold Cache)](#41-standard-address-resolution-cold-cache)
   - [4.2 RFC 5227 Address Conflict Detection & Gratuitous ARP](#42-rfc-5227-address-conflict-detection--gratuitous-arp)
   - [4.3 RFC 1027 Proxy ARP Across Subnets](#43-rfc-1027-proxy-arp-across-subnets)
   - [4.4 MITM ARP Cache Poisoning Attack](#44-mitm-arp-cache-poisoning-attack)
   - [4.5 Dynamic ARP Inspection (DAI) Hardware Defense](#45-dynamic-arp-inspection-dai-hardware-defense)
5. [Step-by-Step Live Demonstration Script (For Presentation / Viva)](#5-step-by-step-live-demonstration-script-for-presentation--viva)
6. [Viva & Technical Examination Questions](#6-viva--technical-examination-questions)

---

## 1. Project Overview & Architectural Scope

In an IP-over-Ethernet network, communication at Layer 3 (Network Layer) uses 32-bit logical IPv4 addresses, while communication at Layer 2 (Data Link Layer) requires 48-bit physical MAC addresses. The **Address Resolution Protocol (ARP)**, formalized in **RFC 826**, bridges this gap by dynamically resolving a target IP address to its corresponding MAC address on the local broadcast domain.

Because standard ARP is **stateless and unauthenticated**, it is susceptible to serious vulnerabilities:
- **ARP Spoofing / Cache Poisoning**: An attacker transmits forged ARP replies claiming ownership of the default gateway's IP, intercepting or modifying traffic (Man-In-The-Middle).
- **IP Address Collisions**: Two hosts inadvertently configured with identical IP addresses cause disruption.

This project delivers a **pure Java (zero-dependency, JDK 11+) production-grade simulation** of the entire ARP ecosystem:
1. **RFC 826 binary packet encoding/decoding**.
2. **IEEE 802.3 / Ethernet II framing** with auto-padding.
3. **ARP cache state machine** with live aging timers and static VIP pinning.
4. **Outbound packet buffer queue** during resolution.
5. **RFC 5227 Address Conflict Detection (ACD)** and **Gratuitous ARP (GARP)**.
6. **RFC 1027 Proxy ARP** for subnet isolation.
7. **8-Port L2 Learning Switch** with a CAM table.
8. **Dynamic ARP Inspection (DAI)** with DHCP Snooping integration.
9. **Interactive real-time web dashboard (`http://localhost:8082`)** and an automated verification suite.

---

## 2. Protocol Formats & Binary Encodings

### 2.1 RFC 826 ARP Packet Format (28 Octets)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Hardware Type (1)      |     Protocol Type (0x0800)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  HW Len (6)   | Proto Len (4) |        Operation (1 or 2)     |
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

---

## 3. System Architecture & Network Topology

```mermaid
flowchart TB
    subgraph LAN["VLAN 1: 192.168.1.0/24 Ethernet Broadcast Domain"]
        H1["Host-A (Alice)<br/>IP: 192.168.1.10<br/>MAC: AA:AA:AA:11:11:11<br/>Port 1"]
        H2["Host-B (Bob)<br/>IP: 192.168.1.20<br/>MAC: BB:BB:BB:22:22:22<br/>Port 2"]
        H3["Host-C (Charlie)<br/>IP: 192.168.1.30<br/>MAC: CC:CC:CC:33:33:33<br/>Port 3"]
        R1["Gateway-Router (Cisco)<br/>IP: 192.168.1.1<br/>MAC: 00:1A:2B:00:01:01<br/>Port 4 (TRUSTED)"]
        AT["Kali Rogue Attacker<br/>IP: 192.168.1.66<br/>MAC: 66:66:66:66:66:66<br/>Port 5 (UNTRUSTED)"]

        SW["8-Port L2 Switch<br/>- IEEE 802.1D CAM Table<br/>- Dynamic ARP Inspection Engine<br/>- DHCP Snooping DB"]
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
    Note over SW: Switch learns Port 1 -> AA:AA:AA:11:11:11 in CAM.<br/>Floods broadcast to Ports 2, 3, 4, 5.
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

### 4.2 RFC 5227 Address Conflict Detection & Gratuitous ARP

```mermaid
sequenceDiagram
    autonumber
    participant Node as Host-B (192.168.1.20)
    participant SW as L2 Switch
    participant LAN as All Network Hosts

    Note over Node: Case 1: IP Assignment / Interface Up<br/>Broadcasts Gratuitous ARP (GARP)
    Node->>SW: ARP Request (SPA = 192.168.1.20, TPA = 192.168.1.20, Dst = FF:FF:FF:FF:FF:FF)
    SW->>LAN: Floods GARP
    Note over LAN: All neighbors update their ARP caches.<br/>Switch refreshes CAM port mapping immediately!

    Note over Node: Case 2: Address Conflict Detection (ACD)<br/>Node sends ARP Probe (SPA = 0.0.0.0)
    Node->>SW: ARP Probe (SPA = 0.0.0.0, TPA = Candidate IP)
    SW->>LAN: Floods ARP Probe
    Note over LAN: If another host holds Candidate IP,<br/>it responds with ARP Reply -> CONFLICT ALARM!
```

---

### 4.3 RFC 1027 Proxy ARP Across Subnets

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

### 4.4 MITM ARP Cache Poisoning Attack

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

### 4.5 Dynamic ARP Inspection (DAI) Hardware Defense

```mermaid
sequenceDiagram
    autonumber
    participant K as Kali Attacker (Port 5 - Untrusted)
    participant SW as Switch (Dynamic ARP Inspection ON)
    participant DB as DHCP Snooping Database
    participant A as Victim (Host-A)

    K->>SW: Forged ARP Reply: "192.168.1.1 is at 66:66:66:66:66:66"
    Note over SW: Port 5 is UNTRUSTED!<br/>DAI Intercepts ARP Frame.
    SW->>DB: Check Binding for 192.168.1.1
    DB-->>SW: Valid Binding is 192.168.1.1 -> 00:1A:2B:00:01:01 (Port 4)
    Note over SW: BINDING MISMATCH DETECTED!<br/>Frame is DROPPED at L2 switch boundary.<br/>Security Alert logged!
    SW--x A: Malicious packet NEVER reaches victim.
    Note over A: Host-A ARP table remains pristine and secure.
```

---

## 5. Step-by-Step Live Demonstration Script (For Presentation / Viva)

1. **Launch the Lab**:
   ```powershell
   .\run.bat
   ```
   Open **http://localhost:8082** in your browser.

2. **Step 1: Standard Resolution Handshake**:
   - In the dashboard, click **"1. Ping Host-A &rarr; Host-B"**.
   - Show the terminal log: `ARP Cache MISS for 192.168.1.20. Queueing packet and broadcasting ARP Request.`
   - Point out the wire sniffer: Frame #1 is Broadcast `FF:FF:FF:FF:FF:FF` (ARP Request), Frame #2 is Unicast `BB:BB:BB:22:22:22 -> AA:AA:AA:11:11:11` (ARP Reply), and Frame #3 is the delivered IP Ping segment.
   - Point out the Host-A ARP table: `192.168.1.20` is now `REACHABLE` with an active 30s TTL timer.

3. **Step 2: Gratuitous ARP Announcement**:
   - Click **"3. Send Gratuitous ARP (Host-B)"**.
   - Show how `SPA == TPA == 192.168.1.20`, updating all neighbor caches immediately without request queries.

4. **Step 3: RFC 5227 Address Conflict Detection (ACD)**:
   - Click **"4. RFC 5227 ARP Probe"**.
   - Point out in the sniffer: `SPA = 0.0.0.0` (prevents cache corruption) probing `192.168.1.20`.
   - Host-A detects the existing IP and triggers an `IP CONFLICT ALARM`.

5. **Step 4: RFC 1027 Proxy ARP**:
   - Click **"5. RFC 1027 Proxy ARP (Ping Remote 10.0.0.5)"**.
   - Point out that Host-A requests `10.0.0.5`, and the Router answers with its own MAC `00:1A:2B:00:01:01`.

6. **Step 5: Attack & Defense**:
   - Click **"6. Launch MITM ARP Poisoning Attack"**.
   - Watch Host-A's ARP table turn RED (`POISONED`).
   - Notice the **"MITM Intercepted Traffic Log"** displaying sniffed payload text!
   - Now toggle **Dynamic ARP Inspection (DAI)** to **ON**.
   - Flush caches and trigger the attack again: DAI drops the malicious frames immediately, drop counter increments, and Host-A remains safe!

---

## 6. Viva & Technical Examination Questions

**Q1: What is the exact size of an RFC 826 ARP packet over Ethernet, and why does Wireshark display 60 bytes on the wire?**  
*Answer:* The logical ARP header for Ethernet/IPv4 is exactly 28 bytes. However, the IEEE 802.3 standard specifies a minimum Ethernet payload of 46 bytes. Therefore, the sender NIC pads the remaining 18 bytes with zeros. Adding the 14-byte Ethernet header (6 Dest + 6 Src + 2 EtherType) yields 60 bytes minimum frame length on the wire (64 bytes including the 4-byte FCS/CRC).

**Q2: What is the difference between an ARP Probe and a Gratuitous ARP Announcement (RFC 5227)?**  
*Answer:* An ARP Probe sets the Sender Protocol Address (`SPA`) to `0.0.0.0` to test if an IP is in use without poisoning any neighbor ARP caches if a conflict exists. A Gratuitous ARP sets `SPA == TPA == own IP` with a broadcast destination to actively refresh neighbor ARP caches and switch CAM tables upon interface bringup or IP changes.

**Q3: How does Dynamic ARP Inspection (DAI) prevent ARP Poisoning?**  
*Answer:* Switches classify ports into *Trusted* (e.g. gateway/uplink) and *Untrusted* (access ports). On untrusted ports, DAI intercepts all ARP packets and checks the Sender MAC (`SHA`) and Sender IP (`SPA`) against the DHCP Snooping database. If the IP-to-MAC mapping was not legally assigned by the DHCP server, the frame is dropped before reaching other hosts.

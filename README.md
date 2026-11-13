# Computer Networks Lab & RFC Protocol Suite (Pure Java, JDK 11+)

A comprehensive suite of **RFC-compliant protocol engines**, **system design implementations**, and **interactive live dashboards** built in pure Java (Zero external dependencies, JDK 11+).

The repository has two parts:

- **Main project: ARP + DHCP + Telnet.** These three protocols are our assigned project basket.
- **Extra features: Mail (SMTP · POP3 · IMAP4), DNS, and RARP + BOOTP.** Protocols from the syllabus that we built on top of the main project, each with its own servers, clients and dashboard.

---

## Repository Structure & Modules

### Main project (ARP · DHCP · Telnet)

The three modules also run **together as one campus LAN** in **[MainProject](./MainProject)**:
- DHCP leases feed the switch's DHCP-snooping table;
- an ARP conflict triggers a DHCPDECLINE;
- an ARP-poisoning attacker reads a Telnet password;
- the admin turns on Dynamic ARP Inspection from the router's Telnet CLI.

Run `MainProject\run.bat` and open http://localhost:8089 (18 end-to-end checks with `--verify`).

| Module | Protocol & RFCs | Ports | Description |
|:---|:---|:---|:---|
| **[ARP](./ARP)** | RFC 826, RFC 5227, RFC 1027 | HTTP **8082** (Dashboard & Wire Sniffer) | Address Resolution Protocol (ARP), L2 Switch CAM Learning, Address Conflict Detection (ACD), Proxy ARP, MITM Poisoning, and Dynamic ARP Inspection (DAI). |
| **[DHCP](./DHCP)** | RFC 2131, RFC 2132 | UDP **6700** (LB), **6701-6703** (Cluster)<br/>HTTP **8080** (Dashboard) | Distributed & Load-Balanced DHCP Server Cluster with Consistent Hashing, Active-Active Gossip Lease Sync, and Rate Limiting. |
| **[Telnet](./Telnet)** | RFC 854, RFC 855, RFC 1143 | TCP **2323** (Server), **2324** (Wire Tap)<br/>TCP **9923** (TLS), **9924** (TLS Tap)<br/>HTTP **8081** (Dashboard) | Telnet Remote-Management Lab with NVT codec, Q-method option negotiation, Cisco IOS VTY CLI, sniffer, and brute-force guard. |

### Extra features (additional protocols)

| Module | Protocol & RFCs | Ports | Description |
|:---|:---|:---|:---|
| **[Mail](./Mail)** | SMTP RFC 5321, POP3 RFC 1939, IMAP4rev1 RFC 3501 | SMTP **2525** / TLS **2465**<br/>POP3 **1110** / TLS **2995**<br/>IMAP **1143** / TLS **2993**<br/>HTTP **8083** (Dashboard) | Our own mail servers and clients (the clients also work with Gmail and Outlook), MIME, STARTTLS, and a visual POP3 vs IMAP comparison on two devices. |
| **[DNS](./DNS)** | RFC 1034, RFC 1035, RFC 2308 | Resolver **127.0.0.1:53** / **:5300**<br/>Lab servers **127.0.0.10–13** (:53 / :5300)<br/>HTTP **8084** (Dashboard) | A four-level naming hierarchy, both recursive and iterative resolution, a TTL cache, a byte-level packet view, and a cache-poisoning demo. |
| **[RARP-BOOTP](./RARP-BOOTP)** | RARP RFC 903, BOOTP RFC 951 / 1542 / 1497 | BOOTP UDP **1067** (server), **2067** (relay), **1068** (client)<br/>HTTP **8085** (Dashboard) | The two obsolete protocols that came before DHCP: RARP frames on a simulated Ethernet and BOOTP over real UDP with a relay agent, plus a step-by-step simulation (Forward button) and a recorded MP4. |
| **[FTP](./FTP)** | RFC 959, RFC 2428, RFC 3659, RFC 4217, RFC 2577 | Control TCP **2121** (+ **21**), active data from **2120**, passive **50000–50100**<br/>Wire tap **2122**<br/>HTTP **8086** (Dashboard) | Our own FTP server and client: two connections, active vs passive (with a client firewall that breaks active mode), ASCII vs binary, REST/ABOR resume, FTPS and a sniffer, bounce protection. |
| **[HTTP](./HTTP)** | RFC 9110, RFC 9111, RFC 9112, RFC 6265 | Origin **8800** (+ **80**), WAN emulator **8801**, caching proxy **3128**<br/>HTTP **8087** (Dashboard) | Our own HTTP/1.1 server, client and caching proxy: persistent vs non-persistent vs pipelined connections measured against the textbook formulas, conditional GET (304), cookies, ranges, chunked, 100-continue, gzip. |
| **[Routing](./Routing)** | RIPv2 RFC 2453, OSPFv2 RFC 2328, BGP-4 RFC 4271 | Routers **127.0.0.20–25**: RIP UDP **520**, BGP TCP **179**, OSPF-in-UDP **8900**<br/>HTTP **8088** (Dashboard) | Dijkstra and Bellman-Ford step by step, count to infinity with 2 and 3 routers (split horizon / poison reverse), and how OSPF and BGP (AS_PATH loop check) recover from the same failure. Wireshark decodes the packets. |

All dashboards use different ports (8080–8089), so every module can run at the same time. (MainProject starts ARP, DHCP and Telnet itself, so stop their separate labs first.)

---

# Main project

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
- **HA cluster with session resume**: routers R1–R3 behind a TCP load balancer (port 2330), UDP heartbeats, session state replicated between nodes; after a node dies, reconnect and type `resume`.
- **RADIUS AAA (RFC 2865 / 2866)**: our own RADIUS server and router client: central logins, privilege from the Access-Accept, fallback to local users, accounting of every command.
- **LINEMODE (RFC 1184) vs character mode vs Nagle (RFC 896)**: the same typing measured three ways: segments, wire bytes, echo delay.
- **Live Lecture-Slide Dashboard**: Runs on **http://localhost:8081**.

```powershell
cd Telnet
.\run.bat           # Start server, wire tap, and dashboard
.\run.bat --verify  # Run 59 automated checks
```

---

# Extra features

## 4. Mail: SMTP, POP3 & IMAP4 Servers and Clients (`./Mail`)

### Features
- **SMTP Server (RFC 5321)**: EHLO extensions, STARTTLS and implicit TLS, AUTH PLAIN/LOGIN, dot-stuffing, Received/Return-Path headers, relay protection (no open relay), and bounce messages (DSN).
- **POP3 Server (RFC 1939)**: AUTHORIZATION → TRANSACTION → UPDATE states, UIDL, TOP, DELE/RSET, maildrop locking, and STLS.
- **IMAP4rev1 Server (RFC 3501)**: folders, FETCH (ENVELOPE, BODYSTRUCTURE, partial bodies), STORE flags, server-side SEARCH, COPY/MOVE, APPEND, and **IDLE push** notifications.
- **Our Own Clients**: SMTP, POP3 and IMAP clients that talk to our servers and to real providers (Gmail, Outlook) over TLS.
- **MIME**: multipart attachments, base64, quoted-printable, and encoded non-English subjects.
- **POP3 vs IMAP Visual Comparison**: one mailbox, a phone and a laptop. POP3 in delete mode empties the server, while IMAP keeps both devices in sync.
- **Live Dashboard**: shows the full protocol conversation with reply codes explained, a MIME viewer and a raw command console. Runs on **http://localhost:8083**.

```powershell
cd Mail
.\run.bat               # Start SMTP/POP3/IMAP servers + dashboard
.\run.bat --verify      # Run 39 automated checks
python interop_test.py  # Python's smtplib/poplib/imaplib against our servers (20 checks)
```

---

## 5. DNS: Naming Hierarchy, Recursive & Iterative Resolution (`./DNS`)

### Features
- **Four-Level Naming Hierarchy**: real DNS servers for a lab root, `.edu`, `myuniv.edu` and `cse.myuniv.edu`, each on its own loopback address. The `cse.myuniv.edu` zone holds the Assignment 6 records.
- **RFC 1035 Wire Format**: message header and all four sections, name compression, and a byte-by-byte packet view.
- **Iterative Resolution**: the resolver asks the root, then the TLD, then the authoritative server, following referrals and glue.
- **Recursive Resolution**: one query to the root, which passes it down the chain and relays the answer back. Real root servers refuse this, and a switch on the dashboard shows why.
- **Resolver Cache**: TTL countdowns and caching of "no such name" answers (RFC 2308).
- **UDP and TCP**: answers larger than 512 bytes are truncated over UDP (TC=1) and retried over TCP.
- **Cache-Poisoning Demo**: a 2008-style resolver is poisoned by 65,536 forged replies, while a modern resolver rejects them all.
- **Works With Windows nslookup**: the resolver answers on the real DNS port 53.
- **Live Dashboard**: shows recursive and iterative resolution side by side, step by step. Runs on **http://localhost:8084**.

```powershell
cd DNS
.\run.bat               # Start the DNS hierarchy, resolver + dashboard
.\run.bat --verify      # Run 31 automated checks
python interop_test.py  # Windows nslookup + raw packets against our servers (13 checks)
nslookup www.cse.myuniv.edu 127.0.0.1
```

---

## 6. RARP & BOOTP: Before DHCP (`./RARP-BOOTP`)

### Features
- **RARP (RFC 903)**: real 60-byte RARP frames (EtherType 0x8035, opcodes 3/4) on a simulated Ethernet with two LANs and a router. It shows why RARP fails on the far side of a router.
- **BOOTP (RFC 951)**: the 300-byte message over real UDP. Replies carry the IP, boot server, boot file and RFC 1497 options (mask, router, DNS, host name).
- **Relay Agent (RFC 1542)**: the router forwards BOOTP requests across LANs using giaddr and hops.
- **Step-by-Step Simulation**: **Forward ▶** advances one frame or packet at a time, with captions, so nothing plays until you click. An optional Auto-play and a recorded MP4 (`docs/video`) are included.
- **Live Dashboard**: drawn as an engineering blueprint. Runs on **http://localhost:8085**.

```powershell
cd RARP-BOOTP
.\run.bat               # Start the RARP LAN, BOOTP server + relay, and dashboard
.\run.bat --verify      # Run 19 automated checks
python interop_test.py  # A Python BOOTP client against our server and relay (7 checks)
```

---

## 7. FTP: Two Connections, Active vs Passive (`./FTP`)

### Features
- **RFC 959 Server and Client**: USER/PASS, PWD/CWD, LIST/NLST, RETR/STOR, DELE/MKD/RMD, RNFR/RNTO, SIZE/MDTM, FEAT, with 3-digit reply codes explained.
- **Control and Data Connections**: a long-lived control connection, and a new data connection for each listing or file.
- **Active vs Passive**: PORT/EPRT (the server connects back from port 20) and PASV/EPSV (the client connects). A simulated client firewall makes active mode fail with **425** while passive mode works.
- **ASCII vs Binary**: TYPE A turns LF into CR LF on the wire and corrupts an image; TYPE I keeps it byte-identical.
- **Resume**: ABOR half-way (426 + 226), then REST + RETR continues where it stopped.
- **Security**: FTPS (AUTH TLS, PBSZ, PROT P); a wire tap that reads the password on plain FTP but only TLS records on FTPS; bounce-attack protection (RFC 2577); and a directory jail.
- **Live Dashboard**: drawn as a freight terminal. Runs on **http://localhost:8086**.

```powershell
cd FTP
.\run.bat               # Start the FTP server, wire tap + dashboard
.\run.bat --verify      # Run 32 automated checks
python interop_test.py  # Python ftplib (plain + FTPS) and Windows ftp.exe against our server (10 checks)
ftp 127.0.0.1           # the real Windows client
```

---

## 8. HTTP: Persistence, Caching and State (`./HTTP`)

### Features
- **HTTP/1.1 Origin Server (RFC 9110/9112)**: GET, HEAD, POST, PUT, DELETE, OPTIONS; keep-alive and `Connection: close`; HTTP/1.0 rules; virtual hosting with `Host`; status codes 100–505.
- **Four Ways to Fetch a Page**: a WAN emulator adds a real RTT, and one page plus 10 images is fetched non-persistent (11 TCP connections), with k parallel connections, persistent, and pipelined. Each is measured against the textbook formula (≈ 22, 6, 12 and 3 RTT).
- **Conditional GET**: ETag and Last-Modified, then If-None-Match, then **304 Not Modified**.
- **Caching Proxy (RFC 9111)**: MISS → HIT → stale → REVALIDATED, with Age, Via and X-Cache; `no-store` respected; CONNECT tunnels for HTTPS. It also works as your real browser's proxy.
- **State and Security**: cookies (login and a cart) and Basic authentication (base64 is not encryption).
- **Framing**: Content-Length, chunked transfer coding (responses and uploads), `Expect: 100-continue`, byte ranges (206/416), and gzip.
- **Live Dashboard**: a library reading room with request slips, stamped responses, a connection waterfall and a reserve shelf. Runs on **http://localhost:8087**.

```powershell
cd HTTP
.\run.bat               # Start the origin server, WAN link, proxy + dashboard
.\run.bat --verify      # Run 52 automated checks
python interop_test.py  # Python http.client / urllib + curl against our server and proxy (11 checks)
```

---

## 9. Routing: Dijkstra, Bellman-Ford, RIP, OSPF, BGP (`./Routing`)

### Features
- **Dijkstra (Link State)**: the textbook table (N', D(v), p(v)) step by step on the Kurose & Ross six-router network, the shortest-path tree, and the forwarding table.
- **Bellman-Ford (Distance Vector)**: every router's DV table, exchange by exchange, with each vector sent as a real **RIPv2** packet on UDP port 520.
- **Instability**: good news vs bad news (a y ⇄ z loop for 47 rounds), **count to infinity with 2 routers** (fixed by split horizon), and **with 3 routers** (which survives split horizon and poison reverse).
- **The Fix, Twice**: **OSPF** floods new Router-LSAs (sequence numbers, the two-way check, Dijkstra) and recovers in 2 rounds. **BGP** (path vector over TCP port 179) rejects any AS_PATH that contains its own AS and recovers in 3 rounds.
- **Real Packets**: RIPv2, OSPFv2 LS Update (with correct checksums) and BGP-4 messages on real sockets. **Wireshark decodes them**; a sample capture is included.
- **Live Dashboard**: a railway signal box with track maps, split-flap routing boards, a cost-per-round chart and a packet inspector. Runs on **http://localhost:8088**.

```powershell
cd Routing
.\run.bat               # Start the dashboard
.\run.bat --verify      # Run 30 automated checks
python interop_test.py  # An independent Python decoder checks our RIP, OSPF and BGP bytes (15 checks)
```

---

## System Requirements
- **JDK 11+** (Pure standard library, zero third-party dependencies).
- Windows, macOS, or Linux.
- Python 3 is optional. It is used only by the `interop_test.py` scripts.

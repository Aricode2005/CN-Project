# Distributed & Load-Balanced DHCP Server System in Java

A complete **RFC 2131 DHCP Server Cluster** built in pure Java (Zero external dependencies, JDK 11+) incorporating modern **System Design & Distributed Systems** concepts.

---

## 1. Primary Features (Core RFC 2131 DHCP Protocol)
- **Full 4-Way DORA Handshake**:
  1. `DHCPDISCOVER`: Client broadcasts discovery packet.
  2. `DHCPOFFER`: Server offers an available IP from the pool along with Subnet Mask, Default Gateway, DNS Server, Domain Name, and Lease Time.
  3. `DHCPREQUEST`: Client requests the offered IP address.
  4. `DHCPACK` / `DHCPNAK`: Server commits the lease (`DHCPACK`) or rejects conflicting requests (`DHCPNAK`).
- **Additional RFC Message Types**:
  - `DHCPRELEASE`: Immediately returns an active IP lease to the pool.
  - `DHCPINFORM`: Supplies network configuration options (DNS, Router, Domain) to static clients.
  - `DHCPDECLINE`: Marks an IP as conflicted when a client detects an ARP collision.
- **Binary RFC 2131 Packet Serializer/Parser**:
  - Encodes and decodes the 236-byte BOOTP header, 4-byte Magic Cookie (`99.130.83.99`), and TLV (Type-Length-Value) DHCP Options (`1`, `3`, `6`, `12`, `15`, `50`, `51`, `53`, `54`, `56`, `255`).
- **Dynamic IP Pool, Static VIP Reservations & Expiration Reaper**:
  - Allocates dynamic leases from `192.168.10.10` – `192.168.10.150`.
  - Supports static MAC-to-IP VIP reservations (e.g., `00:1A:2B:3C:4D:01` $\rightarrow$ `192.168.10.5`).
  - Background **Lease Expiration Reaper** automatically reclaims expired leases.

---

## 2. System Design & Distributed Systems Features
1. **L4 UDP Load Balancer & DHCP Relay Agent (`giaddr`)**:
   - Listens on UDP Port `6700`, stamps the `giaddr` (`192.168.10.254`) field, and routes packets across the 3 backend DHCP Server nodes (`6701`, `6702`, `6703`).
   - Supports 3 live-switchable routing algorithms:
     - **Consistent Hashing with Virtual Nodes** (32 virtual nodes per physical server, hashing client MAC `chaddr` onto a 32-bit ring so DORA sessions stay sticky to the same node with minimal disruption on failover).
     - **Round-Robin**.
     - **Least-Loaded**.
2. **Active-Active Peer State Replication (UDP Gossip Sync)**:
   - Every lease offer, commit, decline, or release is asynchronously replicated to peer nodes over UDP so any surviving node can renew or inspect leases if the original node crashes.
3. **Heartbeat Health Checking & Automatic Failover**:
   - Load Balancer sends periodic `CLUSTER_HEALTH_PING` probes to backend nodes (`6701`, `6702`, `6703`).
   - If a node misses heartbeats, it is automatically evicted from the Consistent Hash Ring and re-added upon recovery.
4. **Token-Bucket Rate Limiter (DHCP Starvation Protection)**:
   - Dual-layer (Global + Per-MAC) Token Bucket rate limiter at the Load Balancer edge drops malicious `DHCPDISCOVER` floods before they can exhaust the IP pool.
5. **Disk Persistence (`data/leases_node*.db`)**:
   - Persists active leases to disk so server restarts preserve IP bindings.
6. **Live Web Dashboard (`http://localhost:8080`)**:
   - Real-time visualization of node health, load balancing metrics, replicated leases, packet logs, and one-click Chaos Engineering controls.

---

## 3. How to Compile & Run

### Option A: Using `run.bat` (Windows CMD / PowerShell)
```powershell
.\run.bat
```

### Option B: Manual `javac` & `java` Commands
```powershell
mkdir out -ErrorAction SilentlyContinue
javac -d out src/dhcp/protocol/*.java src/dhcp/model/*.java src/dhcp/cluster/*.java src/dhcp/lb/*.java src/dhcp/client/*.java src/dhcp/dashboard/*.java src/dhcp/Main.java
java -cp out dhcp.Main
```

### Option C: Run Automated End-to-End Verification Suite
```powershell
.\run.bat --verify
```

Once running, open **http://localhost:8080** in your browser to use the interactive System Design & Chaos Dashboard, or use the interactive terminal menu!

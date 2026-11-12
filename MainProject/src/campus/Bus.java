package campus;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

import arp.model.ArpCacheEntry;
import arp.model.IpAddress;
import arp.model.MacAddress;
import arp.model.SwitchCamEntry;
import arp.network.AttackerNode;
import arp.network.EthernetSwitch;
import arp.network.HostNode;
import arp.network.NetworkInterface;
import arp.network.RouterNode;
import arp.protocol.EthernetFrame;
import arp.security.DhcpSnoopingTable;
import arp.security.DynamicArpInspection;
import dhcp.client.DhcpClientSimulator;
import dhcp.cluster.DhcpServerNode;
import dhcp.lb.DhcpLoadBalancer;
import dhcp.model.LeaseRecord;
import telnet.server.CampusHooks;

/**
 * The integration bus: one campus LAN (192.168.1.0/24) built from the three main-project modules,
 * using only their public APIs. Nothing in ARP/ or DHCP/ is modified.
 *
 *   DHCP → ARP     every ACTIVE lease becomes a DHCP-snooping binding on the switch, so Dynamic ARP Inspection uses it live
 *   DHCP → ARP     a client that completes DORA is plugged into the simulated switch as a new host
 *   ARP  → DHCP    an RFC 5227 probe that finds the address in use triggers a real DHCPDECLINE
 *   Telnet → ARP   every chunk of the real Telnet TCP session is also sent as a frame across the simulated LAN,
 *                  addressed to whatever MAC the sender's ARP cache holds: so ARP poisoning really decides who sees it
 *   Telnet → both  the router CLI shows live DHCP bindings / ARP / MAC tables and switches DAI on and off
 */
public final class Bus implements CampusHooks {

    public static final String SUBNET = "192.168.1.", GATEWAY = "192.168.1.1";
    public static final String ADMIN_MAC = "3C:52:82:AD:00:01", ADMIN_NAME = "admin-laptop";
    public static final int ADMIN_PORT = 6, LB_PORT = 6700, DHCP_HTTP = 8080;
    private static final int[] NODE_PORTS = { 6701, 6702, 6703 };

    // ------------------------------------------------------------------ one shared timeline
    public static final class Ev {
        public final long seq, t; public final String module, text;
        Ev(long seq, String module, String text) { this.seq = seq; this.t = System.currentTimeMillis(); this.module = module; this.text = text; }
        String json() { return Json.obj("seq", seq, "t", t, "module", module, "text", text); }
    }
    private final List<Ev> timeline = Collections.synchronizedList(new ArrayList<>());
    private long evSeq;
    public volatile boolean quiet;
    private final SimpleDateFormat fmt = new SimpleDateFormat("HH:mm:ss.SSS");

    public void ev(String module, String text) {
        synchronized (timeline) { timeline.add(new Ev(++evSeq, module, text)); if (timeline.size() > 3000) timeline.remove(0); }
        if (!quiet) System.out.println(fmt.format(new Date()) + " [" + module + "] " + text);
    }
    public List<Ev> since(long seq) { List<Ev> l = new ArrayList<>(); synchronized (timeline) { for (Ev e : timeline) if (e.seq > seq) l.add(e); } return l; }

    // ------------------------------------------------------------------ DHCP (real UDP cluster)
    public List<DhcpServerNode> nodes; public DhcpLoadBalancer lb; public DhcpClientSimulator sim;
    private dhcp.dashboard.DashboardServer dhcpDash;
    private final List<String> dhcpLogs = Collections.synchronizedList(new ArrayList<>());
    private final File dhcpData;

    // ------------------------------------------------------------------ ARP (simulated layer-2 LAN)
    public final DhcpSnoopingTable snooping = new DhcpSnoopingTable();
    public final DynamicArpInspection dai = new DynamicArpInspection(snooping);
    public final EthernetSwitch sw = new EthernetSwitch("CSE-Switch", dai);
    public final HostNode hostA, hostB, hostC; public final RouterNode router; public final AttackerNode attacker;
    public final List<HostNode> hosts = new CopyOnWriteArrayList<>();
    public volatile HostNode admin; public volatile String adminIp;
    private final Set<String> bound = new HashSet<>();
    private final Map<String, DhcpSnoopingTable.Binding> displaced = new java.util.HashMap<>();   // binding a lease replaced, restored if the lease is declined
    public volatile long sniffEpoch = System.currentTimeMillis();
    public volatile String lastTranscript = "";
    public final Recorder rec = new Recorder(ADMIN_MAC, ADMIN_NAME);

    public Bus(File dataDir) throws Exception {
        dhcpData = new File(dataDir, "dhcp"); dhcpData.mkdirs();
        arp.core.Hub.I.quiet = true;
        arp.core.Hub.I.onLog(line -> ev("ARP", line.replaceFirst("^\\S+ ", "")));

        NetworkInterface nicA = nic("AA:AA:AA:11:11:11", "192.168.1.10"), nicB = nic("BB:BB:BB:22:22:22", "192.168.1.20"), nicC = nic("CC:CC:CC:33:33:33", "192.168.1.30");
        NetworkInterface nicR = nic("00:1A:2B:00:01:01", GATEWAY), nicK = nic("66:66:66:66:66:66", "192.168.1.66");
        sw.connect(1, nicA); sw.connect(2, nicB); sw.connect(3, nicC); sw.connect(4, nicR); sw.connect(5, nicK);
        dai.setPortTrusted(4, true);                         // the router uplink is trusted; access ports are not
        dai.setEnabled(false);                               // a switch out of the box: no inspection
        snooping.addBinding(nicA.getIp(), nicA.getMac(), 1, "Host-A (static)");
        snooping.addBinding(nicB.getIp(), nicB.getMac(), 2, "Host-B (static)");
        snooping.addBinding(nicC.getIp(), nicC.getMac(), 3, "Host-C (static)");
        snooping.addBinding(nicR.getIp(), nicR.getMac(), 4, "JU-Main-R");
        snooping.addBinding(nicK.getIp(), nicK.getMac(), 5, "Kali-Attacker");
        hostA = new HostNode("Host-A", nicA); hostB = new HostNode("Host-B", nicB); hostC = new HostNode("Host-C", nicC);
        router = new RouterNode("JU-Main-R", nicR); attacker = new AttackerNode("Kali-Attacker", nicK);
        hosts.addAll(Arrays.asList(hostA, hostB, hostC));
        for (HostNode h : Arrays.asList(hostA, hostB, hostC, router)) h.setAcdState(arp.model.AcdState.CONFIGURED);   // statically configured: they defend their addresses (RFC 5227 §2.4)

        startDhcp();
        Thread t = new Thread(this::leaseLoop, "campus-lease-sync"); t.setDaemon(true); t.start();
    }

    private static NetworkInterface nic(String mac, String ip) { return new NetworkInterface("eth0", MacAddress.parse(mac), ip == null ? IpAddress.ANY : IpAddress.parse(ip), null, null); }

    private void startDhcp() throws Exception {
        Consumer<String> logger = msg -> { dhcpLogs.add(msg); if (dhcpLogs.size() > 200) dhcpLogs.remove(0); ev("DHCP", msg); rec.dhcpLog(msg, hashedNode()); };
        List<DhcpServerNode> ns = new ArrayList<>();
        for (int i = 0; i < 3; i++)
            ns.add(new DhcpServerNode("DHCP-Node-" + (i + 1), "10.0.0." + (i + 1), NODE_PORTS[i], SUBNET, GATEWAY, GATEWAY, new File(dhcpData, "leases_node" + (i + 1) + ".db"), logger));
        for (DhcpServerNode n : ns) { for (int p : NODE_PORTS) n.registerPeerPort(p); n.start(); }
        DhcpLoadBalancer l = new DhcpLoadBalancer(LB_PORT, logger);
        l.setDirectLanMode(false); l.setSubnetPrefix(SUBNET); l.setClusterNodes(ns);
        for (int p : NODE_PORTS) l.registerBackendNode("127.0.0.1", p);
        l.start();
        nodes = ns; lb = l; sim = new DhcpClientSimulator(LB_PORT, logger);
        dhcpDash = new dhcp.dashboard.DashboardServer(DHCP_HTTP, l, ns, sim, dhcpLogs);
        dhcpDash.start();
    }

    /** Which cluster node the load balancer's consistent hash sends the laptop to (1..3), or 0 if unknown. */
    int hashedNode() {
        try { Integer p = lb.getRouter().selectBackendPort(ADMIN_MAC); for (int i = 0; i < NODE_PORTS.length; i++) if (p != null && p == NODE_PORTS[i]) return i + 1; } catch (RuntimeException e) { }
        return 0;
    }

    private void stopDhcp() {
        try { dhcpDash.shutdown(); } catch (Exception ignored) { }
        try { lb.shutdown(); } catch (Exception ignored) { }
        for (DhcpServerNode n : nodes) try { n.shutdown(); } catch (Exception ignored) { }
    }

    public void shutdown() { stopDhcp(); }

    // ------------------------------------------------------------------ DHCP → ARP: leases become snooping bindings
    private void leaseLoop() {
        while (true) {
            try { syncLeases(); Thread.sleep(300); } catch (InterruptedException e) { return; } catch (Exception e) { /* cluster restarting */ }
        }
    }

    public synchronized void syncLeases() {
        for (DhcpServerNode n : nodes) for (LeaseRecord r : n.getLeaseManager().getAllLeases()) {
            String key = r.getIpAddress() + "|" + r.getMacAddress().toUpperCase();
            if (r.getState() == LeaseRecord.State.DECLINED && bound.removeIf(k -> k.startsWith(r.getIpAddress() + "|"))) {   // snooping drops the binding on DHCPDECLINE (DHCP rewrites the MAC as CONFLICT-…)
                DhcpSnoopingTable.Binding old = displaced.remove(r.getIpAddress());
                if (old != null) snooping.addBinding(old.ip, old.mac, old.port, old.hostname);
                ev("BUS", "DHCP → ARP: lease " + r.getIpAddress() + " was declined; its snooping binding is removed" + (old != null ? " and " + old.hostname + "'s binding restored" : ""));
                continue;
            }
            if (r.getState() != LeaseRecord.State.ACTIVE) continue;
            if (!bound.add(key)) continue;
            int port = r.getMacAddress().equalsIgnoreCase(ADMIN_MAC) ? ADMIN_PORT : 0;
            IpAddress lip = IpAddress.parse(r.getIpAddress());
            DhcpSnoopingTable.Binding prev = snooping.getBinding(lip);
            if (prev != null && !prev.mac.equals(MacAddress.parse(r.getMacAddress()))) displaced.put(r.getIpAddress(), prev);
            snooping.addBinding(lip, MacAddress.parse(r.getMacAddress()), port, r.getHostname());
            ev("BUS", "DHCP → ARP: lease " + r.getIpAddress() + " ↔ " + r.getMacAddress().toUpperCase() + " (" + r.getHostname() + ") added to the switch's DHCP-snooping table");
        }
    }

    /** All leases, one row per IP (ACTIVE wins, then the most recently updated). */
    public List<LeaseRecord> leases() {
        Map<String, LeaseRecord> best = new TreeMap<>((x, y) -> Integer.compare(lastOctet(x), lastOctet(y)));
        for (DhcpServerNode n : nodes) for (LeaseRecord r : n.getLeaseManager().getAllLeases()) {
            LeaseRecord o = best.get(r.getIpAddress());
            if (o == null || (r.getState() == LeaseRecord.State.ACTIVE && o.getState() != LeaseRecord.State.ACTIVE)
                || (r.getState() == o.getState() && r.getLastUpdatedEpochMs() > o.getLastUpdatedEpochMs())) best.put(r.getIpAddress(), r);
        }
        return new ArrayList<>(best.values());
    }
    private static int lastOctet(String ip) { try { return Integer.parseInt(ip.substring(ip.lastIndexOf('.') + 1)); } catch (Exception e) { return 0; } }

    // ------------------------------------------------------------------ the laptop that boots
    /** A real DORA exchange with the cluster (UDP). Returns the leased address, or null. */
    public String dora() { return sim.runSingleClientDora(ADMIN_MAC, ADMIN_NAME); }

    /** Plug the laptop into switch port 6 (first call), then run the RFC 5227 probe for the leased address on the LAN. */
    public boolean probe(String ip) {
        if (admin == null) {
            NetworkInterface n = nic(ADMIN_MAC, null);
            sw.connect(ADMIN_PORT, n);
            admin = new HostNode(ADMIN_NAME, n);
            hosts.add(admin);
            ev("BUS", "DHCP → ARP: " + ADMIN_NAME + " (" + ADMIN_MAC + ") is plugged into switch port " + ADMIN_PORT);
        }
        admin.resetDuplicateIpFlag();
        boolean clean = admin.performAcd(IpAddress.parse(ip));
        if (clean && admin.isDuplicateIpDetected()) {
            // the address's owner answered the laptop's announcement with a defensive gratuitous ARP (RFC 5227 §2.4)
            clean = false;
            admin.getNic().setIp(IpAddress.ANY);
            admin.setAcdState(arp.model.AcdState.CONFLICTED);
            ev("BUS", "ARP: " + ip + " is already in use (its owner defended it): " + ADMIN_NAME + " gives the address up");
        }
        if (clean) adminIp = ip;
        return clean;
    }

    /** ARP → DHCP: the probe found the address in use, so the client declines it (RFC 2131 §3.1 step 5). */
    public void decline(String ip) {
        ev("BUS", "ARP → DHCP: the probe found " + ip + " already in use → DHCPDECLINE");
        sim.sendDecline(ADMIN_MAC, ip);
    }

    public boolean poisoned() {
        HostNode a = admin; if (a == null) return false;
        MacAddress m = a.getArpTable().lookupMac(IpAddress.parse(GATEWAY));
        return m != null && m.equals(attacker.getNic().getMac());
    }

    public void poison() {
        attacker.setMitmTargets(IpAddress.parse(adminIp), MacAddress.parse(ADMIN_MAC), router.getNic().getIp(), router.getNic().getMac());
        attacker.launchArpPoisoning();
    }

    // ------------------------------------------------------------------ Telnet → ARP: session bytes cross the simulated LAN
    /** Called by the LAN relay for every chunk of the real TCP session between the laptop and the router. */
    public void telnetBytes(boolean toRouter, byte[] b, int n, boolean tls) {
        HostNode a = admin; String ip = adminIp;
        if (a == null || ip == null) return;
        String text = tls ? "TLS record, " + n + " bytes (encrypted)" : printable(b, n);
        if (text.isEmpty()) text = "(Telnet option negotiation: IAC commands only)";
        if (text.length() > 160) text = text.substring(0, 160) + "…";
        String payload = "TELNET " + (toRouter ? ip + " > " + GATEWAY + ":23" : GATEWAY + ":23 > " + ip) + " | " + text;
        HostNode from = toRouter ? a : router;
        IpAddress dst = toRouter ? router.getNic().getIp() : IpAddress.parse(ip);
        MacAddress mac = from.getArpTable().lookupMac(dst);
        if (mac == null) { from.sendArpRequest(dst); mac = from.getArpTable().lookupMac(dst); }
        if (mac == null) return;
        int toPort = mac.equals(attacker.getNic().getMac()) ? 5 : toRouter ? 4 : ADMIN_PORT;
        rec.telnet(toRouter, b, n, tls, toPort, ip);
        from.getNic().send(new EthernetFrame(mac, from.getNic().getMac(), EthernetFrame.ETHERTYPE_IPV4, payload.getBytes(StandardCharsets.UTF_8)));
    }

    /** Telnet data bytes as text: IAC command sequences are skipped, CR becomes ⏎. */
    static String printable(byte[] b, int n) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < n; i++) {
            int c = b[i] & 0xff;
            if (c == 255) {                                             // IAC
                if (i + 1 >= n) break;
                int cmd = b[i + 1] & 0xff;
                if (cmd >= 251 && cmd <= 254) i += 2;                   // WILL / WONT / DO / DONT + option
                else if (cmd == 250) { while (i + 1 < n && !((b[i] & 0xff) == 255 && (b[i + 1] & 0xff) == 240)) i++; i++; }   // SB … IAC SE
                else i += 1;
            } else if (c == '\r') s.append('⏎');
            else if (c >= 0x20 && c < 0x7f) s.append((char) c);
        }
        return s.toString();
    }

    /** What the attacker captured from the laptop → router direction since the last reset, straight from the ARP module's intercept log. */
    public String sniffed() {
        StringBuilder s = new StringBuilder();
        for (arp.core.Hub.InterceptedData d : arp.core.Hub.I.intercepted.snapshot()) {
            if (d.timestampMs < sniffEpoch || d.payloadPreview == null) continue;
            int i = d.payloadPreview.indexOf(" > " + GATEWAY + ":23 | ");
            if (i < 0 || !d.payloadPreview.startsWith("TELNET ")) continue;
            s.append(d.payloadPreview.substring(d.payloadPreview.indexOf(" | ") + 3).replace("⏎", "\n"));
            if (s.length() > 0 && s.charAt(s.length() - 1) != '\n' && d.payloadPreview.contains("TLS record")) s.append('\n');
        }
        return s.toString();
    }

    // ------------------------------------------------------------------ reset for a new run of the story
    public synchronized void reset() throws Exception {
        attacker.stopMitm(); dai.setEnabled(false); dai.clearStats();
        if (admin != null) { sw.disconnect(ADMIN_PORT); hosts.remove(admin); admin = null; adminIp = null; }
        for (HostNode h : hosts) h.getArpTable().clearDynamic();
        router.getArpTable().clearDynamic(); attacker.getArpTable().clearDynamic(); sw.clearCamTable();
        stopDhcp();                                           // a fresh cluster with an empty lease database
        Thread.sleep(300);
        File[] old = dhcpData.listFiles(); if (old != null) for (File f : old) f.delete();
        bound.clear(); displaced.clear();
        startDhcp();
        sniffEpoch = System.currentTimeMillis(); lastTranscript = "";
        ev("BUS", "— network reset: fresh DHCP cluster, ARP caches flushed, inspection off —");
    }

    // ------------------------------------------------------------------ Telnet → both: the router's CLI
    @Override public String showDhcpBinding() {
        StringBuilder b = new StringBuilder("Bindings from all DHCP cluster nodes:\n");
        b.append(String.format("%-16s %-19s %-20s %-9s %-13s %s%n", "IP address", "Hardware address", "Hostname", "State", "Server", "Lease expires in"));
        for (LeaseRecord r : leases())
            b.append(String.format("%-16s %-19s %-20s %-9s %-13s %s%n", r.getIpAddress(), r.getMacAddress().toUpperCase(), r.getHostname(), r.getState(), r.getAllocatedByNode(),
                r.isStaticReservation() ? "infinite (reserved)" : r.getRemainingSeconds() + " s"));
        return b.toString();
    }

    @Override public String showIpArp() {
        StringBuilder b = new StringBuilder(String.format("%-10s %-16s %-10s %-19s %-11s %s%n", "Protocol", "Address", "Age (s)", "Hardware Addr", "State", "Interface"));
        b.append(String.format("%-10s %-16s %-10s %-19s %-11s %s%n", "Internet", GATEWAY, "-", router.getNic().getMac(), "(self)", "FastEthernet0/0"));
        for (ArpCacheEntry e : router.getArpTable().getEntries())
            b.append(String.format("%-10s %-16s %-10s %-19s %-11s %s%n", "Internet", e.getIp(), e.getAgeSeconds(), e.getMac(), e.getState(), "FastEthernet0/0"));
        HostNode a = admin;
        if (a != null) {
            b.append("\nARP cache of ").append(ADMIN_NAME).append(" (").append(adminIp).append("):\n");
            for (ArpCacheEntry e : a.getArpTable().getEntries())
                b.append(String.format("  %-16s %-19s %s%s%n", e.getIp(), e.getMac(), e.getState(), e.getMac() != null && e.getMac().equals(attacker.getNic().getMac()) && !e.getIp().equals(attacker.getNic().getIp()) ? "   <-- this is the attacker's MAC" : ""));
        }
        return b.toString();
    }

    @Override public String showMacTable() {
        StringBuilder b = new StringBuilder("          Mac Address Table (" + "CSE-Switch" + ")\n-------------------------------------------\nVlan    Mac Address          Type        Ports\n");
        for (SwitchCamEntry e : sw.getCamEntries())
            b.append(String.format("%-7d %-20s %-11s Fa0/%d%n", 1, e.getMac(), e.isStatic() ? "STATIC" : "DYNAMIC", e.getPort()));
        return b.toString();
    }

    @Override public String showArpInspection() {
        StringBuilder b = new StringBuilder();
        b.append("Dynamic ARP Inspection on VLAN 1: ").append(dai.isEnabled() ? "Enabled" : "Disabled").append('\n');
        b.append("Trusted ports: Fa0/4 (router uplink)   Untrusted: all access ports\n");
        b.append("DHCP-snooping bindings: ").append(snooping.getBindings().size()).append("   (static hosts + live DHCP leases)\n");
        b.append("ARP packets inspected: ").append(dai.getInspectedCount()).append("   forwarded: ").append(dai.getPassedCount()).append("   DROPPED: ").append(dai.getDroppedCount()).append('\n');
        List<DynamicArpInspection.Violation> v = dai.getRecentViolations();
        for (DynamicArpInspection.Violation x : v.subList(Math.max(0, v.size() - 4), v.size()))
            b.append("  drop on Fa0/").append(x.port).append(": ").append(x.reason).append("  (claimed ").append(x.arpSpa).append(" is at ").append(x.arpSha).append(")\n");
        return b.toString();
    }

    @Override public String setArpInspection(boolean on) {
        syncLeases();
        dai.setEnabled(on);
        ev("BUS", "Telnet → ARP: the admin " + (on ? "ENABLED" : "disabled") + " Dynamic ARP Inspection from the router CLI");
        return on ? "Dynamic ARP Inspection enabled on VLAN 1. ARP packets on untrusted ports are now checked against " + snooping.getBindings().size() + " DHCP-snooping bindings."
                  : "Dynamic ARP Inspection disabled on VLAN 1.";
    }

    @Override public String clearArpCache() {
        for (HostNode h : hosts) h.getArpTable().clearDynamic();
        router.getArpTable().clearDynamic();
        ev("BUS", "Telnet → ARP: dynamic ARP entries flushed on every host and on the router");
        return "ARP cache cleared.";
    }
}

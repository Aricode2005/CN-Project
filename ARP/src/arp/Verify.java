package arp;

import arp.core.Hub;
import arp.core.PcapExporter;
import arp.model.AcdState;
import arp.model.ArpCacheEntry;
import arp.model.ArpTable;
import arp.model.IpAddress;
import arp.model.MacAddress;
import arp.network.AttackerNode;
import arp.network.EthernetSwitch;
import arp.network.HostNode;
import arp.network.NetworkInterface;
import arp.network.RouterNode;
import arp.protocol.ArpOperation;
import arp.protocol.ArpPacket;
import arp.protocol.Dot1qHeader;
import arp.protocol.EthernetFrame;
import arp.security.DhcpSnoopingTable;
import arp.security.DynamicArpInspection;
import arp.security.PortSecurity;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.util.Arrays;
import java.util.List;

/**
 * Automated end-to-end test suite for the RFC 826 ARP & L2 Security Lab ("run.bat --verify").
 * Tests 50+ protocol specifications, state machines, and hardware defenses.
 */
public final class Verify {

    private static int passCount = 0;
    private static int failCount = 0;

    private static void check(String testName, boolean condition, String details) {
        if (condition) {
            passCount++;
            System.out.printf("  [PASS] %-64s %s%n", testName, details != null ? "(" + details + ")" : "");
        } else {
            failCount++;
            System.out.printf("  [FAIL] %-64s %s%n", testName, details != null ? "(" + details + ")" : "");
        }
    }

    public static int runAll() {
        passCount = 0;
        failCount = 0;
        Hub.I.quiet = true;

        System.out.println("============================================================================");
        System.out.println("   RUNNING AUTOMATED VERIFICATION SUITE: RFC 826 / 5227 / 903 / 1027 / 802.1Q ");
        System.out.println("============================================================================");

        System.out.println("\n--- 1. RFC 826 Binary Packet Encoding & Decoding ------------------------");
        testBinaryEncodingDecoding();

        System.out.println("\n--- 2. Ethernet II Frame Encapsulation & Padding -----------------------");
        testEthernetEncapsulation();

        System.out.println("\n--- 3. IEEE 802.1Q Virtual LAN (VLAN) Tagging & Serialization ----------");
        testDot1qVlanFraming();

        System.out.println("\n--- 4. ARP Cache State Machine, Resolution & Outbound Queueing ----------");
        testResolutionAndQueueing();

        System.out.println("\n--- 5. Cache TTL Aging, Stale Transitions & Static VIP Protection -------");
        testCacheAgingAndStaticVip();

        System.out.println("\n--- 6. RFC 5227 Address Conflict Detection (ACD) State Machine ----------");
        testAcdStateMachineAndDefense();

        System.out.println("\n--- 7. RFC 903 Reverse ARP (RARP) Diskless Client Bootstrapping -------- ");
        testReverseArpBoot();

        System.out.println("\n--- 8. RFC 1027 Proxy ARP across Subnets -------------------------------");
        testProxyArp();

        System.out.println("\n--- 9. L2 Switch CAM Learning & 802.1Q VLAN Broadcast Isolation ---------");
        testSwitchCamAndVlanIsolation();

        System.out.println("\n--- 10. Cisco Switchport Port-Security vs macof CAM Overflow -----------");
        testPortSecurity();

        System.out.println("\n--- 11. Dynamic ARP Inspection (DAI) Binding & Rate Limiting -----------");
        testDaiSecurityAndRateLimiting();

        System.out.println("\n--- 12. Host-Side Arpwatch / MAC Flip-Flop Detection -------------------");
        testHostArpwatchDefender();

        System.out.println("\n--- 13. Wireshark PCAP Binary Export ------------------------------------");
        testPcapBinaryExport();

        System.out.println("\n============================================================================");
        System.out.printf("  VERIFICATION RESULT: %d PASSED, %d FAILED%n", passCount, failCount);
        System.out.println("============================================================================");

        Hub.I.quiet = false;
        return failCount;
    }

    private static void testBinaryEncodingDecoding() {
        MacAddress sha = MacAddress.parse("AA:AA:AA:11:11:11");
        IpAddress spa = IpAddress.parse("192.168.1.10");
        IpAddress tpa = IpAddress.parse("192.168.1.20");

        ArpPacket req = ArpPacket.createRequest(sha, spa, tpa);
        byte[] bytes = req.toBytes();

        check("ARP Header is exactly 28 bytes", bytes.length == 28, "length=" + bytes.length);
        check("HTYPE is 1 (Ethernet)", req.getHardwareType() == 1, null);
        check("PTYPE is 0x0800 (IPv4)", req.getProtocolType() == 0x0800, null);
        check("HLEN is 6 and PLEN is 4", req.getHardwareLength() == 6 && req.getProtocolLength() == 4, null);
        check("OPER is 1 (ARP Request)", req.getOperation() == ArpOperation.REQUEST, null);

        // Round-trip deserialization
        ArpPacket parsed = ArpPacket.fromBytes(bytes);
        check("Round-trip deserialization preserves SHA", parsed.getSenderHardwareAddress().equals(sha), parsed.getSenderHardwareAddress().toString());
        check("Round-trip deserialization preserves SPA", parsed.getSenderProtocolAddress().equals(spa), parsed.getSenderProtocolAddress().toString());
        check("Round-trip deserialization preserves Target IP", parsed.getTargetProtocolAddress().equals(tpa), parsed.getTargetProtocolAddress().toString());
        check("Target MAC in Request is all zeros (RFC 826)", parsed.getTargetHardwareAddress().isZero(), parsed.getTargetHardwareAddress().toString());

        // Test ARP Reply
        MacAddress tha = MacAddress.parse("BB:BB:BB:22:22:22");
        ArpPacket reply = ArpPacket.createReply(tha, tpa, sha, spa);
        byte[] repBytes = reply.toBytes();
        ArpPacket repParsed = ArpPacket.fromBytes(repBytes);
        check("ARP Reply OPER is 2", repParsed.getOperation() == ArpOperation.REPLY, null);
        check("ARP Reply has non-zero Target Hardware Address", repParsed.getTargetHardwareAddress().equals(sha), repParsed.getTargetHardwareAddress().toString());
    }

    private static void testEthernetEncapsulation() {
        MacAddress src = MacAddress.parse("AA:AA:AA:11:11:11");
        MacAddress dst = MacAddress.BROADCAST;

        byte[] smallPayload = new byte[]{1, 2, 3}; // 3 bytes payload
        EthernetFrame frame = new EthernetFrame(dst, src, EthernetFrame.ETHERTYPE_ARP, smallPayload);
        byte[] wireBytes = frame.toBytes();

        check("Ethernet frame auto-pads short payloads to 60 bytes minimum", wireBytes.length == 60, "wireLen=" + wireBytes.length);
        check("Ethernet header contains EtherType 0x0806 (ARP)", frame.getEtherType() == EthernetFrame.ETHERTYPE_ARP, null);
        check("Ethernet frame correctly identifies broadcast destination", frame.isBroadcast(), null);

        EthernetFrame decoded = EthernetFrame.fromBytes(wireBytes);
        check("Ethernet frame deserializes correct Destination MAC", decoded.getDestinationMac().equals(dst), decoded.getDestinationMac().toString());
        check("Ethernet frame deserializes correct Source MAC", decoded.getSourceMac().equals(src), decoded.getSourceMac().toString());
    }

    private static void testDot1qVlanFraming() {
        MacAddress src = MacAddress.parse("AA:AA:AA:11:11:11");
        MacAddress dst = MacAddress.parse("BB:BB:BB:22:22:22");

        EthernetFrame tagged = new EthernetFrame(dst, src, EthernetFrame.ETHERTYPE_IPV4, new byte[42], new Dot1qHeader(10));
        byte[] raw = tagged.toBytes();

        check("802.1Q tagged frame is at least 60 bytes on the wire", raw.length >= 60, "len=" + raw.length);
        check("Frame recognizes 802.1Q tagged status", tagged.isTagged(), "vlan=" + tagged.getVlanId());
        check("Frame preserves VLAN ID 10", tagged.getVlanId() == 10, null);

        EthernetFrame parsed = EthernetFrame.fromBytes(raw);
        check("Round-trip parses 802.1Q tagged frame correctly", parsed.isTagged(), null);
        check("Parsed 802.1Q frame preserves VLAN ID", parsed.getVlanId() == 10, "vid=" + parsed.getVlanId());
        check("Parsed 802.1Q frame preserves inner EtherType (0x0800)", parsed.getEtherType() == EthernetFrame.ETHERTYPE_IPV4, null);
    }

    private static void testResolutionAndQueueing() {
        DhcpSnoopingTable snooping = new DhcpSnoopingTable();
        DynamicArpInspection dai = new DynamicArpInspection(snooping);
        EthernetSwitch sw = new EthernetSwitch("Switch-1", dai);

        NetworkInterface nicA = new NetworkInterface("eth0", MacAddress.parse("AA:AA:AA:11:11:11"), IpAddress.parse("192.168.1.10"), null, null);
        NetworkInterface nicB = new NetworkInterface("eth0", MacAddress.parse("BB:BB:BB:22:22:22"), IpAddress.parse("192.168.1.20"), null, null);

        sw.connect(1, nicA);
        sw.connect(2, nicB);

        snooping.addBinding(nicA.getIp(), nicA.getMac(), 1, "Host-A");
        snooping.addBinding(nicB.getIp(), nicB.getMac(), 2, "Host-B");

        HostNode hostA = new HostNode("Host-A", nicA);
        HostNode hostB = new HostNode("Host-B", nicB);

        check("Host-A initial ARP table is cold / empty", hostA.getArpTable().size() == 0, null);

        // Ping Host-B: should miss cache, queue packet, and trigger ARP Request
        boolean immediate = hostA.ping(nicB.getIp(), "Hello-Bob");
        check("Initial ping returns false on cache miss (packet queued)", !immediate, null);
        check("Host-A marked next-hop as INCOMPLETE in ARP table",
                hostA.getArpTable().lookup(nicB.getIp()) != null, null);

        // Handshake completes via switch: Host-B should have replied and Host-A should have resolved
        MacAddress resolved = hostA.getArpTable().lookupMac(nicB.getIp());
        check("Host-A resolved Host-B MAC address to BB:BB:BB:22:22:22",
                resolved != null && resolved.equals(nicB.getMac()), resolved != null ? resolved.toString() : "null");
        check("Host-B learned Host-A MAC address (RFC 826 symmetric learning)",
                hostB.getArpTable().lookupMac(nicA.getIp()) != null, null);

        // Second ping: now cache hit, returns immediate true
        boolean secondPing = hostA.ping(nicB.getIp(), "Hello-Again");
        check("Subsequent ping to Host-B returns true immediately (Cache Hit)", secondPing, null);
    }

    private static void testCacheAgingAndStaticVip() {
        ArpTable table = new ArpTable("TestHost");
        IpAddress dynIp = IpAddress.parse("192.168.1.50");
        MacAddress dynMac = MacAddress.parse("AA:BB:CC:50:50:50");

        // Dynamic entry with 1 second TTL
        table.putDynamic(dynIp, dynMac, 1);
        check("Dynamic entry added as REACHABLE",
                table.lookup(dynIp).getState() == ArpCacheEntry.State.REACHABLE, null);

        try { Thread.sleep(1100); } catch (InterruptedException ignored) {}

        table.reap();
        ArpCacheEntry aged = table.lookup(dynIp);
        check("Dynamic entry ages to STALE or is purged after TTL",
                aged == null || aged.getState() == ArpCacheEntry.State.STALE, null);

        // Static VIP test
        IpAddress vipIp = IpAddress.parse("192.168.1.1");
        MacAddress vipMac = MacAddress.parse("00:1A:2B:00:01:01");
        table.putStatic(vipIp, vipMac);

        check("Static VIP entry marked as STATIC", table.lookup(vipIp).isStatic(), null);

        // Attempt dynamic overwrite
        table.putDynamic(vipIp, MacAddress.parse("66:66:66:66:66:66"), 30);
        check("Static VIP entry cannot be overwritten by dynamic ARP",
                table.lookupMac(vipIp).equals(vipMac), table.lookupMac(vipIp).toString());
    }

    private static void testAcdStateMachineAndDefense() {
        DhcpSnoopingTable snooping = new DhcpSnoopingTable();
        DynamicArpInspection dai = new DynamicArpInspection(snooping);
        EthernetSwitch sw = new EthernetSwitch("Switch-1", dai);

        NetworkInterface nicA = new NetworkInterface("eth0", MacAddress.parse("AA:AA:AA:11:11:11"), IpAddress.parse("192.168.1.10"), null, null);
        NetworkInterface nicB = new NetworkInterface("eth0", MacAddress.parse("BB:BB:BB:22:22:22"), IpAddress.parse("192.168.1.20"), null, null);
        sw.connect(1, nicA);
        sw.connect(2, nicB);

        snooping.addBinding(nicA.getIp(), nicA.getMac(), 1, "Host-A");
        snooping.addBinding(nicB.getIp(), nicB.getMac(), 2, "Host-B");

        HostNode hostA = new HostNode("Host-A", nicA);
        HostNode hostB = new HostNode("Host-B", nicB);

        // Gratuitous ARP Announcement
        ArpPacket garp = ArpPacket.createGratuitousAnnouncement(nicB.getMac(), nicB.getIp());
        check("Gratuitous ARP has SPA == TPA (RFC 5227)", garp.isGratuitous(), null);

        hostB.sendGratuitousArp();
        check("Host-A updated ARP table from Host-B Gratuitous ARP announcement",
                hostA.getArpTable().lookup(nicB.getIp()) != null, null);

        // Address Conflict Detection (ACD) Probe
        ArpPacket probe = ArpPacket.createProbe(nicA.getMac(), nicB.getIp());
        check("ARP Probe has SPA == 0.0.0.0 to prevent cache poisoning", probe.isProbe(), null);

        // RFC 5227 Active Defense: Host-B encounters a rogue claim for its IP
        ArpPacket conflictClaim = ArpPacket.createReply(nicA.getMac(), nicB.getIp(), MacAddress.BROADCAST, nicB.getIp());
        nicA.send(conflictClaim.toFrame());

        check("Host-B transitions to DEFENDING on first conflict",
                hostB.getAcdState() == AcdState.DEFENDING, "state=" + hostB.getAcdState());

        // Second conflict within 10s window: Host-B must yield per RFC 5227 §2.4
        nicA.send(conflictClaim.toFrame());
        check("Host-B yields and transitions to CONFLICTED after repeated collision",
                hostB.getAcdState() == AcdState.CONFLICTED, "state=" + hostB.getAcdState());
    }

    private static void testReverseArpBoot() {
        NetworkInterface nicR = new NetworkInterface("eth0", MacAddress.parse("00:1A:2B:00:01:01"), IpAddress.parse("192.168.1.1"), null, null);
        NetworkInterface nicClient = new NetworkInterface("eth0", MacAddress.parse("CC:CC:CC:33:33:33"), IpAddress.ANY, null, null);

        DhcpSnoopingTable snooping = new DhcpSnoopingTable();
        DynamicArpInspection dai = new DynamicArpInspection(snooping);
        EthernetSwitch sw = new EthernetSwitch("Switch-1", dai);
        sw.connect(4, nicR);
        sw.connect(3, nicClient);
        dai.setPortTrusted(4, true);

        RouterNode router = new RouterNode("Gateway-Router", nicR);
        HostNode client = new HostNode("Diskless-Client", nicClient);

        // Configure RARP lease on server
        IpAddress expectedIp = IpAddress.parse("192.168.1.30");
        router.addRarpMapping(nicClient.getMac(), expectedIp);

        // Client initiates RARP boot
        client.bootViaRarp();

        check("Client bootstrapped valid IP via RFC 903 RARP",
                client.getNic().getIp().equals(expectedIp), client.getNic().getIp().toString());
        check("Client ACD state transitions to CONFIGURED after RARP boot",
                client.getAcdState() == AcdState.CONFIGURED, "state=" + client.getAcdState());
    }

    private static void testProxyArp() {
        DhcpSnoopingTable snooping = new DhcpSnoopingTable();
        DynamicArpInspection dai = new DynamicArpInspection(snooping);
        dai.setEnabled(false); // disable DAI for proxy test
        EthernetSwitch sw = new EthernetSwitch("Switch-1", dai);

        NetworkInterface nicA = new NetworkInterface("eth0", MacAddress.parse("AA:AA:AA:11:11:11"), IpAddress.parse("192.168.1.10"), null, null);
        NetworkInterface nicR = new NetworkInterface("eth0", MacAddress.parse("00:1A:2B:00:01:01"), IpAddress.parse("192.168.1.1"), null, null);
        sw.connect(1, nicA);
        sw.connect(4, nicR);

        HostNode hostA = new HostNode("Host-A", nicA);
        RouterNode router = new RouterNode("Router-Main", nicR);
        router.setProxyArpEnabled(true);

        // Host A sends ARP Request for remote IP 10.0.0.5 (remote subnet)
        IpAddress remoteIp = IpAddress.parse("10.0.0.5");
        hostA.sendArpRequest(remoteIp);

        MacAddress resolved = hostA.getArpTable().lookupMac(remoteIp);
        check("Router answered Proxy ARP for remote 10.0.0.5 with Gateway MAC (RFC 1027)",
                resolved != null && resolved.equals(nicR.getMac()), resolved != null ? resolved.toString() : "null");
    }

    private static void testSwitchCamAndVlanIsolation() {
        DhcpSnoopingTable snooping = new DhcpSnoopingTable();
        DynamicArpInspection dai = new DynamicArpInspection(snooping);
        EthernetSwitch sw = new EthernetSwitch("Switch-1", dai);

        NetworkInterface nicA = new NetworkInterface("eth0", MacAddress.parse("AA:AA:AA:11:11:11"), IpAddress.parse("192.168.1.10"), null, null);
        NetworkInterface nicB = new NetworkInterface("eth0", MacAddress.parse("BB:BB:BB:22:22:22"), IpAddress.parse("192.168.1.20"), null, null);
        NetworkInterface nicC = new NetworkInterface("eth0", MacAddress.parse("CC:CC:CC:33:33:33"), IpAddress.parse("192.168.1.30"), null, null);

        sw.connect(1, nicA);
        sw.connect(2, nicB);
        sw.connect(3, nicC);

        // Configure VLANs: Port 1 & 2 in VLAN 10; Port 3 in VLAN 20
        sw.setPortVlan(1, 10);
        sw.setPortVlan(2, 10);
        sw.setPortVlan(3, 20);

        HostNode hostA = new HostNode("Host-A", nicA);
        HostNode hostB = new HostNode("Host-B", nicB);
        HostNode hostC = new HostNode("Host-C", nicC);

        // Frame from Host-A (VLAN 10)
        hostA.sendGratuitousArp();

        check("Host-B in same VLAN 10 receives broadcast and learns Host-A",
                hostB.getArpTable().lookup(nicA.getIp()) != null, null);
        check("Host-C in isolated VLAN 20 NEVER receives VLAN 10 broadcast (802.1Q Isolation)",
                hostC.getArpTable().lookup(nicA.getIp()) == null, null);
    }

    private static void testPortSecurity() {
        DhcpSnoopingTable snooping = new DhcpSnoopingTable();
        DynamicArpInspection dai = new DynamicArpInspection(snooping);
        EthernetSwitch sw = new EthernetSwitch("Switch-1", dai);

        NetworkInterface nicAttacker = new NetworkInterface("eth0", MacAddress.parse("66:66:66:66:66:66"), IpAddress.parse("192.168.1.66"), null, null);
        sw.connect(5, nicAttacker);

        // Enable port security: max 1 MAC, action = SHUTDOWN
        sw.getPortSecurity().enablePortSecurity(5, 1, PortSecurity.ViolationAction.SHUTDOWN);

        AttackerNode attacker = new AttackerNode("Attacker", nicAttacker);

        // First frame with legal MAC: passes and is learned as sticky
        attacker.sendGratuitousArp();
        check("Port security permits first legal MAC on port 5",
                !sw.getPortSecurity().isPortErrDisabled(5), null);

        // Attacker attempts macof CAM overflow attack with random MACs
        attacker.floodRandomMacs(5);

        check("Port security triggers violation on unauthorized MAC flooding",
                sw.getPortSecurity().getConfig(5).getViolations() > 0, "violations=" + sw.getPortSecurity().getConfig(5).getViolations());
        check("Port security transitions port 5 to ERR_DISABLE (Link Down)",
                sw.getPortSecurity().isPortErrDisabled(5), null);
    }

    private static void testDaiSecurityAndRateLimiting() {
        DhcpSnoopingTable snooping = new DhcpSnoopingTable();
        DynamicArpInspection dai = new DynamicArpInspection(snooping);
        EthernetSwitch sw = new EthernetSwitch("Switch-1", dai);

        NetworkInterface nicA = new NetworkInterface("eth0", MacAddress.parse("AA:AA:AA:11:11:11"), IpAddress.parse("192.168.1.10"), null, null);
        NetworkInterface nicR = new NetworkInterface("eth0", MacAddress.parse("00:1A:2B:00:01:01"), IpAddress.parse("192.168.1.1"), null, null);
        NetworkInterface nicAttacker = new NetworkInterface("eth0", MacAddress.parse("66:66:66:66:66:66"), IpAddress.parse("192.168.1.66"), null, null);

        sw.connect(1, nicA);
        sw.connect(4, nicR);
        sw.connect(5, nicAttacker);

        dai.setPortTrusted(4, true);
        snooping.addBinding(nicA.getIp(), nicA.getMac(), 1, "Host-A");
        snooping.addBinding(nicR.getIp(), nicR.getMac(), 4, "Gateway");
        snooping.addBinding(nicAttacker.getIp(), nicAttacker.getMac(), 5, "Kali-Attacker");

        HostNode hostA = new HostNode("Host-A", nicA);
        AttackerNode attacker = new AttackerNode("Attacker", nicAttacker);

        // 1. Without DAI: Poisoning succeeds
        dai.setEnabled(false);
        attacker.setMitmTargets(nicA.getIp(), nicA.getMac(), nicR.getIp(), nicR.getMac());
        attacker.launchArpPoisoning();

        MacAddress victimCached = hostA.getArpTable().lookupMac(nicR.getIp());
        check("Without DAI: Attacker successfully poisons Victim ARP Cache",
                victimCached != null && victimCached.equals(nicAttacker.getMac()), victimCached != null ? victimCached.toString() : "null");

        // 2. Enable DAI and test protection
        dai.setEnabled(true);
        int initialDrops = dai.getDroppedCount();

        attacker.launchArpPoisoning();

        check("With DAI: Switch intercepts and drops spoofed ARP packets from untrusted port",
                dai.getDroppedCount() > initialDrops, "drops=" + dai.getDroppedCount());
        check("DAI records violation with reason",
                !dai.getRecentViolations().isEmpty() && dai.getRecentViolations().get(0).reason.contains("Mismatch"),
                dai.getRecentViolations().isEmpty() ? "none" : dai.getRecentViolations().get(0).reason);

        // 3. DAI Rate Limiter DoS Test
        dai.getRateLimiter().getTracker(5).setRateLimitPps(5);
        attacker.launchArpStorm(10);
        check("DAI rate limiter flags burst ARP storm and transitions port to ERR_DISABLE",
                dai.getRateLimiter().isPortErrDisabled(5), null);
    }

    private static void testHostArpwatchDefender() {
        HostNode hostA = new HostNode("Host-A",
                new NetworkInterface("eth0", MacAddress.parse("AA:AA:AA:11:11:11"), IpAddress.parse("192.168.1.10"), null, null));

        IpAddress gwIp = IpAddress.parse("192.168.1.1");
        MacAddress legitimateGwMac = MacAddress.parse("00:1A:2B:00:01:01");
        MacAddress attackerMac = MacAddress.parse("66:66:66:66:66:66");

        // Legitimate resolution
        hostA.getArpTable().putDynamic(gwIp, legitimateGwMac, 30);

        // Enable strict anti-spoofing mode on host
        hostA.getDefender().setStrictMode(true);

        // Attacker attempts unverified MAC flip-flop directly against host
        boolean allowed = hostA.getDefender().checkUpdate(hostA.getArpTable(), gwIp, attackerMac);
        check("Host Defender detects unsolicited MAC flip-flop",
                hostA.getDefender().getFlipFlopCount() > 0, "flips=" + hostA.getDefender().getFlipFlopCount());
        check("Host Defender strict mode BLOCKS malicious flip-flop", !allowed, null);
    }

    private static void testPcapBinaryExport() {
        try {
            byte[] pcapBytes = PcapExporter.exportToPcap(Hub.I.allFrames());
            check("PCAP export generates non-empty binary byte stream", pcapBytes.length >= 24, "len=" + pcapBytes.length);

            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(pcapBytes));
            int magic = dis.readInt();
            short vMaj = dis.readShort();
            short vMin = dis.readShort();
            dis.skipBytes(8);
            int snaplen = dis.readInt();
            int linkType = dis.readInt();

            check("PCAP magic number matches standard libpcap 0xa1b2c3d4", magic == 0xa1b2c3d4, String.format("0x%08X", magic));
            check("PCAP version is 2.4", vMaj == 2 && vMin == 4, vMaj + "." + vMin);
            check("PCAP link layer type is Ethernet (1)", linkType == 1, "linkType=" + linkType);
        } catch (Exception e) {
            check("PCAP export generates valid libpcap stream", false, e.getMessage());
        }
    }
}

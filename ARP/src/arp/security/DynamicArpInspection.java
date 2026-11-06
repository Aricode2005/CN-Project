package arp.security;

import arp.core.Json;
import arp.model.IpAddress;
import arp.model.MacAddress;
import arp.protocol.ArpPacket;
import arp.protocol.EthernetFrame;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Dynamic ARP Inspection (DAI) Engine.
 *
 * An enterprise L2 security feature (IEEE / Cisco standard) that intercepts and validates
 * ARP packets on untrusted switch ports against the DHCP Snooping database to prevent
 * ARP Poisoning / Spoofing and Man-In-The-Middle attacks.
 */
public final class DynamicArpInspection {

    public static final class Violation {
        public final long timestampMs;
        public final int port;
        public final String reason;
        public final MacAddress ethSrcMac;
        public final MacAddress arpSha;
        public final IpAddress arpSpa;

        public Violation(int port, String reason, MacAddress ethSrcMac, MacAddress arpSha, IpAddress arpSpa) {
            this.timestampMs = System.currentTimeMillis();
            this.port = port;
            this.reason = reason;
            this.ethSrcMac = ethSrcMac;
            this.arpSha = arpSha;
            this.arpSpa = arpSpa;
        }

        public String json() {
            return Json.obj(
                    "t", timestampMs,
                    "port", port,
                    "reason", reason,
                    "ethSrcMac", ethSrcMac.toString(),
                    "arpSha", arpSha.toString(),
                    "arpSpa", arpSpa.toString()
            );
        }
    }

    private volatile boolean enabled = true;
    private final DhcpSnoopingTable snoopingTable;
    private final Set<Integer> trustedPorts = Collections.synchronizedSet(new HashSet<>());

    private final AtomicInteger inspectedCount = new AtomicInteger();
    private final AtomicInteger passedCount = new AtomicInteger();
    private final AtomicInteger droppedCount = new AtomicInteger();
    private final List<Violation> recentViolations = Collections.synchronizedList(new ArrayList<>());

    public DynamicArpInspection(DhcpSnoopingTable snoopingTable) {
        this.snoopingTable = snoopingTable;
    }

    public void setPortTrusted(int port, boolean trusted) {
        if (trusted) trustedPorts.add(port);
        else trustedPorts.remove(port);
    }

    public boolean isPortTrusted(int port) {
        return trustedPorts.contains(port);
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Inspects an incoming Ethernet ARP frame on a specific switch port.
     *
     * @param port Ingress switch port
     * @param frame Raw Ethernet frame containing ARP payload
     * @return true if packet is authentic and permitted; false if packet is malicious and dropped
     */
    public boolean inspect(int port, EthernetFrame frame) {
        if (!enabled) {
            return true;
        }

        inspectedCount.incrementAndGet();

        // 1. Trusted ports (e.g. Gateway uplink) bypass DAI inspection
        if (isPortTrusted(port)) {
            passedCount.incrementAndGet();
            return true;
        }

        if (!frame.isArp()) {
            passedCount.incrementAndGet();
            return true;
        }

        ArpPacket arp;
        try {
            arp = ArpPacket.fromBytes(frame.getPayload());
        } catch (Exception e) {
            recordViolation(port, "Malformed ARP Packet payload", frame.getSourceMac(), MacAddress.ZERO, IpAddress.ANY);
            droppedCount.incrementAndGet();
            return false;
        }

        // 2. Rule: Ethernet Source MAC must match ARP Sender Hardware Address (SHA)
        if (!frame.getSourceMac().equals(arp.getSenderHardwareAddress())) {
            recordViolation(port, "Ethernet Source MAC != ARP SHA (MAC spoofing attempt)",
                    frame.getSourceMac(), arp.getSenderHardwareAddress(), arp.getSenderProtocolAddress());
            droppedCount.incrementAndGet();
            return false;
        }

        // 3. Rule: ARP Probe exception (SPA == 0.0.0.0 is permitted for RFC 5227 ACD)
        if (arp.isProbe()) {
            passedCount.incrementAndGet();
            return true;
        }

        // 4. Rule: Sender IP and MAC must match DHCP Snooping Binding Table
        IpAddress spa = arp.getSenderProtocolAddress();
        MacAddress sha = arp.getSenderHardwareAddress();

        if (!snoopingTable.isValid(spa, sha)) {
            recordViolation(port, String.format("DAI Binding Mismatch: %s is NOT owned by %s", spa, sha),
                    frame.getSourceMac(), sha, spa);
            droppedCount.incrementAndGet();
            return false;
        }

        passedCount.incrementAndGet();
        return true;
    }

    private void recordViolation(int port, String reason, MacAddress ethSrc, MacAddress sha, IpAddress spa) {
        Violation v = new Violation(port, reason, ethSrc, sha, spa);
        synchronized (recentViolations) {
            recentViolations.add(0, v);
            if (recentViolations.size() > 50) {
                recentViolations.remove(recentViolations.size() - 1);
            }
        }
    }

    public int getInspectedCount() { return inspectedCount.get(); }
    public int getPassedCount() { return passedCount.get(); }
    public int getDroppedCount() { return droppedCount.get(); }

    public List<Violation> getRecentViolations() {
        synchronized (recentViolations) {
            return new ArrayList<>(recentViolations);
        }
    }

    public String json() {
        List<String> vJsons = new ArrayList<>();
        for (Violation v : getRecentViolations()) {
            vJsons.add(v.json());
        }
        return Json.obj(
                "enabled", enabled,
                "inspected", inspectedCount.get(),
                "passed", passedCount.get(),
                "dropped", droppedCount.get(),
                "trustedPorts", Json.arr(new ArrayList<>(trustedPorts)),
                "violations", Json.arr(vJsons)
        );
    }
}

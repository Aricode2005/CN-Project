package arp.security;

import arp.core.Json;
import arp.model.IpAddress;
import arp.model.MacAddress;
import arp.protocol.ArpOperation;
import arp.protocol.ArpPacket;
import arp.protocol.EthernetFrame;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Enterprise Dynamic ARP Inspection (DAI) Engine.
 *
 * Implements Cisco / IEEE enterprise switch security:
 * 1. DHCP Snooping binding table validation
 * 2. ARP Rate Limiting (DoS prevention)
 * 3. Validation checks:
 *    - validate src-mac: frame source MAC must match ARP SHA
 *    - validate dst-mac: frame destination MAC must match ARP THA in unicast replies
 *    - validate ip: validates against invalid/banned IP ranges (0.0.0.0 in reply, broadcast, multicast, loopback)
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
    private final ArpRateLimiter rateLimiter = new ArpRateLimiter();

    // Additional validation flags (Cisco "ip arp inspection validate ...")
    private volatile boolean validateSrcMac = true;
    private volatile boolean validateDstMac = true;
    private volatile boolean validateIp = true;

    private final AtomicInteger inspectedCount = new AtomicInteger();
    private final AtomicInteger passedCount = new AtomicInteger();
    private final AtomicInteger droppedCount = new AtomicInteger();
    private final AtomicInteger rateLimitDropCount = new AtomicInteger();
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

    public ArpRateLimiter getRateLimiter() {
        return rateLimiter;
    }

    public boolean isValidateSrcMac() { return validateSrcMac; }
    public void setValidateSrcMac(boolean v) { this.validateSrcMac = v; }
    public boolean isValidateDstMac() { return validateDstMac; }
    public void setValidateDstMac(boolean v) { this.validateDstMac = v; }
    public boolean isValidateIp() { return validateIp; }
    public void setValidateIp(boolean v) { this.validateIp = v; }

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

        // 2. ARP Rate Limiting Check (DoS / Storm Prevention)
        if (!rateLimiter.check(port)) {
            rateLimitDropCount.incrementAndGet();
            droppedCount.incrementAndGet();
            recordViolation(port, "DAI Rate Limit Exceeded (ARP Storm DoS detected)", frame.getSourceMac(), MacAddress.ZERO, IpAddress.ANY);
            return false;
        }

        ArpPacket arp;
        try {
            arp = ArpPacket.fromBytes(frame.getPayload());
        } catch (Exception e) {
            recordViolation(port, "Malformed ARP Packet payload", frame.getSourceMac(), MacAddress.ZERO, IpAddress.ANY);
            droppedCount.incrementAndGet();
            return false;
        }

        // 3. Cisco Validation Check: Source MAC vs ARP SHA
        if (validateSrcMac && !frame.getSourceMac().equals(arp.getSenderHardwareAddress())) {
            recordViolation(port, "validate src-mac FAILED: Ethernet Src MAC != ARP SHA",
                    frame.getSourceMac(), arp.getSenderHardwareAddress(), arp.getSenderProtocolAddress());
            droppedCount.incrementAndGet();
            return false;
        }

        // 4. Cisco Validation Check: Destination MAC vs ARP THA (in unicast replies)
        if (validateDstMac && arp.getOperation() == ArpOperation.REPLY && !frame.getDestinationMac().isBroadcast()) {
            if (!frame.getDestinationMac().equals(arp.getTargetHardwareAddress())) {
                recordViolation(port, "validate dst-mac FAILED: Ethernet Dst MAC != ARP THA",
                        frame.getSourceMac(), arp.getSenderHardwareAddress(), arp.getSenderProtocolAddress());
                droppedCount.incrementAndGet();
                return false;
            }
        }

        // 5. Cisco Validation Check: Invalid IP Addresses
        if (validateIp) {
            IpAddress spa = arp.getSenderProtocolAddress();
            int spaInt = spa.toInt();

            // Broadcast IP 255.255.255.255
            if (spa.isBroadcast()) {
                recordViolation(port, "validate ip FAILED: Broadcast SPA 255.255.255.255 invalid",
                        frame.getSourceMac(), arp.getSenderHardwareAddress(), spa);
                droppedCount.incrementAndGet();
                return false;
            }
            // Multicast IP range 224.0.0.0/4 (0xE0000000 to 0xEFFFFFFF)
            if ((spaInt & 0xF0000000) == 0xE0000000) {
                recordViolation(port, "validate ip FAILED: Multicast SPA invalid for ARP: " + spa,
                        frame.getSourceMac(), arp.getSenderHardwareAddress(), spa);
                droppedCount.incrementAndGet();
                return false;
            }
            // Loopback IP range 127.0.0.0/8 (0x7F000000)
            if ((spaInt & 0xFF000000) == 0x7F000000) {
                recordViolation(port, "validate ip FAILED: Loopback SPA invalid for ARP: " + spa,
                        frame.getSourceMac(), arp.getSenderHardwareAddress(), spa);
                droppedCount.incrementAndGet();
                return false;
            }
            // 0.0.0.0 in ARP Reply is invalid
            if (spa.isAny() && arp.getOperation() == ArpOperation.REPLY) {
                recordViolation(port, "validate ip FAILED: 0.0.0.0 invalid as SPA in ARP Reply",
                        frame.getSourceMac(), arp.getSenderHardwareAddress(), spa);
                droppedCount.incrementAndGet();
                return false;
            }
        }

        // 6. RFC 5227 ACD Probe exception (SPA == 0.0.0.0 in REQUEST is authentic probe)
        if (arp.isProbe()) {
            passedCount.incrementAndGet();
            return true;
        }

        // 7. Core DAI Rule: Sender IP and MAC must match DHCP Snooping Binding Table
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
    public int getRateLimitDropCount() { return rateLimitDropCount.get(); }

    public void clearStats() {
        inspectedCount.set(0);
        passedCount.set(0);
        droppedCount.set(0);
        rateLimitDropCount.set(0);
        recentViolations.clear();
    }

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
                "rateLimitDrops", rateLimitDropCount.get(),
                "validateSrcMac", validateSrcMac,
                "validateDstMac", validateDstMac,
                "validateIp", validateIp,
                "trustedPorts", Json.arr(new ArrayList<>(trustedPorts)),
                "rateLimiter", Json.raw(rateLimiter.json()),
                "violations", Json.arr(vJsons)
        );
    }
}

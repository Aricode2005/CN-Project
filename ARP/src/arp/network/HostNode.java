package arp.network;

import arp.core.Hub;
import arp.core.Json;
import arp.model.AcdState;
import arp.model.ArpCacheEntry;
import arp.model.ArpTable;
import arp.model.IpAddress;
import arp.model.MacAddress;
import arp.protocol.ArpOperation;
import arp.protocol.ArpPacket;
import arp.protocol.EthernetFrame;
import arp.security.HostArpDefender;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Enterprise Host Network Node (e.g. Alice, Bob, Charlie).
 *
 * Implements:
 * - RFC 826 Address Resolution Protocol (ARP) Request / Reply
 * - Outbound packet queueing during INCOMPLETE state
 * - RFC 5227 Address Conflict Detection (ACD) State Machine (Probing, Announcing, Defending, Conflicted)
 * - RFC 903 Reverse Address Resolution Protocol (RARP) Client Bootstrapping
 * - Host-Side Arpwatch / MAC Flip-Flop Detection & Strict Anti-Spoofing Mode
 */
public class HostNode {

    private final String hostname;
    private final NetworkInterface nic;
    private final ArpTable arpTable;
    private final HostArpDefender defender;
    private volatile AcdState acdState = AcdState.CONFIGURED;
    private volatile long lastDefendTimestampMs = 0;
    private volatile boolean duplicateIpDetected = false;
    private volatile String lastPingStatus = "Idle";

    public HostNode(String hostname, NetworkInterface nic) {
        this.hostname = hostname;
        this.nic = nic;
        this.arpTable = new ArpTable(hostname);
        this.defender = new HostArpDefender(hostname);
        this.nic.setFrameReceiver(this::onReceiveFrame);
    }

    public String getHostname() { return hostname; }
    public NetworkInterface getNic() { return nic; }
    public ArpTable getArpTable() { return arpTable; }
    public HostArpDefender getDefender() { return defender; }
    public AcdState getAcdState() { return acdState; }
    public void setAcdState(AcdState state) { this.acdState = state; }
    public boolean isDuplicateIpDetected() { return duplicateIpDetected; }
    public void resetDuplicateIpFlag() { this.duplicateIpDetected = false; }
    public String getLastPingStatus() { return lastPingStatus; }

    /**
     * Sends an IP packet (simulated ICMP Echo Request) to destinationIp.
     * Follows standard OS network stack logic:
     * 1. Subnet check to determine Next-Hop IP (direct or Gateway).
     * 2. ARP Cache lookup.
     * 3. If cache hit -> transmit immediately.
     * 4. If cache miss -> mark INCOMPLETE, queue packet, and broadcast ARP Request.
     */
    public boolean ping(IpAddress destinationIp, String payloadText) {
        if (acdState == AcdState.CONFLICTED) {
            Hub.I.log(String.format("[%s] CANNOT SEND: Host IP is in CONFLICTED state (yielded per RFC 5227)!", hostname));
            this.lastPingStatus = "Failed: Interface in CONFLICTED state";
            return false;
        }

        IpAddress nextHop = nic.getIp().isInSameSubnet(destinationIp, nic.getNetmask())
                ? destinationIp
                : nic.getGateway();

        byte[] payload = ("PING:" + hostname + "->" + destinationIp + ":" + (payloadText != null ? payloadText : "DATA"))
                .getBytes(StandardCharsets.UTF_8);

        MacAddress nextHopMac = arpTable.lookupMac(nextHop);

        if (nextHopMac != null) {
            // Cache Hit: Transmit Ethernet frame directly
            EthernetFrame frame = new EthernetFrame(nextHopMac, nic.getMac(), EthernetFrame.ETHERTYPE_IPV4, payload);
            Hub.I.log(String.format("[%s] ARP Cache HIT for %s (%s). Sending IP packet directly.",
                    hostname, nextHop, nextHopMac));
            nic.send(frame);
            this.lastPingStatus = "Sent direct to " + nextHop + " via " + nextHopMac;
            return true;
        } else {
            // Cache Miss: Queue packet and send ARP Request
            Hub.I.log(String.format("[%s] ARP Cache MISS for %s. Queueing packet and broadcasting ARP Request.",
                    hostname, nextHop));
            arpTable.markIncomplete(nextHop, 10);
            EthernetFrame pendingFrame = new EthernetFrame(MacAddress.ZERO, nic.getMac(), EthernetFrame.ETHERTYPE_IPV4, payload);
            arpTable.queuePendingPacket(nextHop, pendingFrame);

            sendArpRequest(nextHop);
            this.lastPingStatus = "ARP Request broadcasted for " + nextHop;
            return false;
        }
    }

    public void sendArpRequest(IpAddress targetIp) {
        ArpPacket req = ArpPacket.createRequest(nic.getMac(), nic.getIp(), targetIp);
        EthernetFrame frame = req.toFrame();
        Hub.I.log(String.format("[%s] Broadcasting: %s", hostname, req.toDetailedString()));
        nic.send(frame);
    }

    public void sendGratuitousArp() {
        ArpPacket garp = ArpPacket.createGratuitousAnnouncement(nic.getMac(), nic.getIp());
        EthernetFrame frame = garp.toFrame();
        Hub.I.log(String.format("[%s] Broadcasting GARP Announcement: %s", hostname, garp.toDetailedString()));
        nic.send(frame);
    }

    /**
     * Executes RFC 5227 Address Conflict Detection (ACD) workflow:
     * 1. State -> PROBING: broadcasts ARP Probe with SPA = 0.0.0.0
     * 2. If conflict detected -> state becomes CONFLICTED
     * 3. If clean -> state becomes ANNOUNCING, broadcasts GARP, then CONFIGURED
     */
    public boolean performAcd(IpAddress candidateIp) {
        Hub.I.log(String.format("[%s] Starting RFC 5227 ACD for candidate IP %s...", hostname, candidateIp));
        this.acdState = AcdState.PROBING;
        this.duplicateIpDetected = false;

        // Broadcast ARP Probe
        sendArpProbe(candidateIp);

        // Check if an immediate conflict was flagged
        if (this.duplicateIpDetected || this.acdState == AcdState.CONFLICTED) {
            this.acdState = AcdState.CONFLICTED;
            Hub.I.log(String.format("[%s] ACD FAILED: %s is already in use on the LAN! Declining IP.", hostname, candidateIp));
            return false;
        }

        // Clean probe -> Announcing
        this.acdState = AcdState.ANNOUNCING;
        nic.setIp(candidateIp);
        sendGratuitousArp();

        this.acdState = AcdState.CONFIGURED;
        Hub.I.log(String.format("[%s] ACD SUCCESS: Candidate IP %s confirmed clean and configured.", hostname, candidateIp));
        return true;
    }

    public void sendArpProbe(IpAddress candidateIp) {
        ArpPacket probe = ArpPacket.createProbe(nic.getMac(), candidateIp);
        EthernetFrame frame = probe.toFrame();
        Hub.I.log(String.format("[%s] Broadcasting RFC 5227 ARP Probe for %s (SPA=0.0.0.0)", hostname, candidateIp));
        nic.send(frame);
    }

    /**
     * Initiates RFC 903 Reverse ARP (RARP) diskless boot request.
     */
    public void bootViaRarp() {
        Hub.I.log(String.format("[%s] Bootstrapping via RFC 903 RARP (Diskless Client Boot)...", hostname));
        nic.setIp(IpAddress.ANY);
        this.acdState = AcdState.IDLE;
        ArpPacket rarpReq = ArpPacket.createRarpRequest(nic.getMac());
        nic.send(rarpReq.toFrame());
    }

    protected void onReceiveFrame(EthernetFrame frame) {
        // Discard frames not addressed to our MAC, unless broadcast/multicast
        if (!frame.getDestinationMac().isBroadcast()
                && !frame.getDestinationMac().isMulticast()
                && !frame.getDestinationMac().equals(nic.getMac())) {
            return;
        }

        if (frame.isArp() || frame.isRarp()) {
            handleArpPacket(frame);
        } else if (frame.isIpv4()) {
            handleIpv4Packet(frame);
        }
    }

    private void handleArpPacket(EthernetFrame frame) {
        ArpPacket arp;
        try {
            arp = ArpPacket.fromBytes(frame.getPayload());
        } catch (Exception e) {
            return;
        }

        // 1. Handle RFC 903 RARP Reply
        if (arp.isRarpReply()) {
            if (arp.getTargetHardwareAddress().equals(nic.getMac())) {
                IpAddress assignedIp = arp.getTargetProtocolAddress();
                nic.setIp(assignedIp);
                this.acdState = AcdState.CONFIGURED;
                Hub.I.log(String.format("[%s] RARP SUCCESS! Boot Server %s assigned IP %s to MAC %s",
                        hostname, arp.getSenderHardwareAddress(), assignedIp, nic.getMac()));
                return;
            }
        }

        IpAddress senderIp = arp.getSenderProtocolAddress();
        MacAddress senderMac = arp.getSenderHardwareAddress();
        IpAddress targetIp = arp.getTargetProtocolAddress();

        // 2. RFC 5227 Duplicate IP Detection & Defense State Machine
        if (!senderIp.isAny() && senderIp.equals(nic.getIp()) && !senderMac.equals(nic.getMac())) {
            this.duplicateIpDetected = true;

            if (acdState == AcdState.PROBING) {
                // Conflict during probing phase: yield immediately
                this.acdState = AcdState.CONFLICTED;
                Hub.I.log(String.format("[ALARM] RFC 5227 CONFLICT during PROBING on %s! Candidate IP %s claimed by %s",
                        hostname, nic.getIp(), senderMac));
                return;
            } else if (acdState == AcdState.CONFIGURED || acdState == AcdState.DEFENDING) {
                long now = System.currentTimeMillis();
                if (acdState == AcdState.DEFENDING && (now - lastDefendTimestampMs) < 10000) {
                    // Second conflict within 10s: must yield per RFC 5227 §2.4
                    this.acdState = AcdState.CONFLICTED;
                    Hub.I.log(String.format("[ALARM] RFC 5227 DEFENSE FAILED on %s! Re-asserted conflict within 10s by %s. YIELDING IP %s!",
                            hostname, senderMac, nic.getIp()));
                    return;
                } else {
                    // First conflict: defend by sending Defensive Gratuitous ARP
                    this.acdState = AcdState.DEFENDING;
                    this.lastDefendTimestampMs = now;
                    Hub.I.log(String.format("[DEFENSE] RFC 5227 DEFENSE TRIGGERED on %s! Transmitting Defensive GARP for %s against intruder %s",
                            hostname, nic.getIp(), senderMac));
                    ArpPacket defGarp = ArpPacket.createDefensiveGarp(nic.getMac(), nic.getIp());
                    nic.send(defGarp.toFrame());
                    return;
                }
            }
        }

        // 3. Host-Side Arpwatch / Anti-Spoofing Defender Check
        boolean amITarget = targetIp.equals(nic.getIp());
        boolean hasExisting = arpTable.lookup(senderIp) != null;

        if (!senderIp.isAny() && (amITarget || hasExisting)) {
            boolean allowUpdate = defender.checkUpdate(arpTable, senderIp, senderMac);
            if (allowUpdate) {
                arpTable.putDynamic(senderIp, senderMac, 30);
            }
        }

        // 4. Process Request
        if (arp.getOperation() == ArpOperation.REQUEST) {
            if (amITarget && !arp.isProbe() && acdState != AcdState.CONFLICTED) {
                // We are the requested target: Send Unicast ARP Reply
                ArpPacket reply = ArpPacket.createReply(nic.getMac(), nic.getIp(), senderMac, senderIp);
                EthernetFrame replyFrame = new EthernetFrame(senderMac, nic.getMac(), EthernetFrame.ETHERTYPE_ARP, reply.toBytes());
                Hub.I.log(String.format("[%s] Sending Unicast ARP Reply to %s: %s is at %s",
                        hostname, senderIp, nic.getIp(), nic.getMac()));
                nic.send(replyFrame);
            }
        }

        // 5. Drain queued packets if this reply resolved a pending next-hop
        List<EthernetFrame> queued = arpTable.drainPendingPackets(senderIp);
        if (!queued.isEmpty()) {
            Hub.I.log(String.format("[%s] Draining %d queued packets for resolved target %s (%s)",
                    hostname, queued.size(), senderIp, senderMac));
            for (EthernetFrame qf : queued) {
                EthernetFrame resolvedFrame = new EthernetFrame(senderMac, nic.getMac(), qf.getEtherType(), qf.getPayload());
                nic.send(resolvedFrame);
            }
        }
    }

    private void handleIpv4Packet(EthernetFrame frame) {
        String msg = new String(frame.getPayload(), StandardCharsets.UTF_8);
        if (msg.startsWith("PING:")) {
            Hub.I.log(String.format("[%s] Received ICMP Echo Request: %s. Sending Echo Reply.", hostname, msg));
            byte[] replyPayload = ("PONG:" + hostname + "->" + frame.getSourceMac()).getBytes(StandardCharsets.UTF_8);
            EthernetFrame replyFrame = new EthernetFrame(frame.getSourceMac(), nic.getMac(), EthernetFrame.ETHERTYPE_IPV4, replyPayload);
            nic.send(replyFrame);
            this.lastPingStatus = "Received and replied to ping from " + frame.getSourceMac();
        } else if (msg.startsWith("PONG:")) {
            Hub.I.log(String.format("[%s] Received ICMP Echo Reply: %s", hostname, msg));
            this.lastPingStatus = "Ping succeeded: " + msg;
        }
    }

    public String json() {
        return Json.obj(
                "hostname", hostname,
                "ip", nic.getIp().toString(),
                "mac", nic.getMac().toString(),
                "vendor", nic.getMac().getVendor(),
                "port", nic.getConnectedPort(),
                "conflict", duplicateIpDetected,
                "acdState", acdState.name(),
                "acdStateLabel", acdState.getLabel(),
                "pingStatus", lastPingStatus,
                "defender", Json.raw(defender.json()),
                "arpTable", Json.raw(arpTable.json())
        );
    }
}

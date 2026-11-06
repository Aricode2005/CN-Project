package arp.network;

import arp.core.Hub;
import arp.core.Json;
import arp.model.ArpCacheEntry;
import arp.model.ArpTable;
import arp.model.IpAddress;
import arp.model.MacAddress;
import arp.protocol.ArpOperation;
import arp.protocol.ArpPacket;
import arp.protocol.EthernetFrame;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * A standard networked host computer (e.g. Alice, Bob, Charlie) with an RFC 826 ARP stack.
 */
public class HostNode {

    private final String hostname;
    private final NetworkInterface nic;
    private final ArpTable arpTable;
    private volatile boolean duplicateIpDetected;
    private volatile String lastPingStatus = "Idle";

    public HostNode(String hostname, NetworkInterface nic) {
        this.hostname = hostname;
        this.nic = nic;
        this.arpTable = new ArpTable(hostname);
        this.nic.setFrameReceiver(this::onReceiveFrame);
    }

    public String getHostname() { return hostname; }
    public NetworkInterface getNic() { return nic; }
    public ArpTable getArpTable() { return arpTable; }
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

    public void sendArpProbe(IpAddress candidateIp) {
        ArpPacket probe = ArpPacket.createProbe(nic.getMac(), candidateIp);
        EthernetFrame frame = probe.toFrame();
        Hub.I.log(String.format("[%s] Broadcasting RFC 5227 ARP Probe for %s (SPA=0.0.0.0)", hostname, candidateIp));
        nic.send(frame);
    }

    protected void onReceiveFrame(EthernetFrame frame) {
        // Discard frames not addressed to our MAC, unless broadcast/multicast
        if (!frame.getDestinationMac().isBroadcast()
                && !frame.getDestinationMac().isMulticast()
                && !frame.getDestinationMac().equals(nic.getMac())) {
            return;
        }

        if (frame.isArp()) {
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

        IpAddress senderIp = arp.getSenderProtocolAddress();
        MacAddress senderMac = arp.getSenderHardwareAddress();
        IpAddress targetIp = arp.getTargetProtocolAddress();

        // 1. Duplicate IP Detection (RFC 5227)
        if (!senderIp.isAny() && senderIp.equals(nic.getIp()) && !senderMac.equals(nic.getMac())) {
            this.duplicateIpDetected = true;
            Hub.I.log(String.format("[ALARM] IP CONFLICT DETECTED on %s! %s also claimed by rogue MAC %s",
                    hostname, nic.getIp(), senderMac));
            return;
        }

        // 2. RFC 826 Table Update Rule:
        // If sender IP is already in our cache OR if we are the target IP, update the mapping
        boolean amITarget = targetIp.equals(nic.getIp());
        boolean hasExisting = arpTable.lookup(senderIp) != null;

        if (!senderIp.isAny() && (amITarget || hasExisting)) {
            arpTable.putDynamic(senderIp, senderMac, 30);
        }

        // 3. Process Request
        if (arp.getOperation() == ArpOperation.REQUEST) {
            if (amITarget && !arp.isProbe()) {
                // We are the requested target: Send Unicast ARP Reply
                ArpPacket reply = ArpPacket.createReply(nic.getMac(), nic.getIp(), senderMac, senderIp);
                EthernetFrame replyFrame = new EthernetFrame(senderMac, nic.getMac(), EthernetFrame.ETHERTYPE_ARP, reply.toBytes());
                Hub.I.log(String.format("[%s] Sending Unicast ARP Reply to %s: %s is at %s",
                        hostname, senderIp, nic.getIp(), nic.getMac()));
                nic.send(replyFrame);
            }
        }

        // 4. Drain queued packets if this reply resolved a pending next-hop
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
            // Send Echo Reply
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
                "pingStatus", lastPingStatus,
                "arpTable", Json.raw(arpTable.json())
        );
    }
}

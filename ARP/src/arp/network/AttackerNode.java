package arp.network;

import arp.core.Hub;
import arp.core.Json;
import arp.model.IpAddress;
import arp.model.MacAddress;
import arp.protocol.ArpOperation;
import arp.protocol.ArpPacket;
import arp.protocol.EthernetFrame;

import java.nio.charset.StandardCharsets;
import java.util.Random;

/**
 * Rogue Attacker Node (Kali Linux) demonstrating:
 * - Unsolicited Bidirectional ARP Cache Poisoning (MITM)
 * - Broadcast Forged Gratuitous ARP (LAN-wide poisoning)
 * - MAC Table Overflow Flooding (macof CAM exhaustion)
 * - High-Rate ARP Storm (DoS testing for DAI Rate Limiting & Err-Disable)
 * - Transparent Layer 2 Packet Interception & Forwarding
 */
public final class AttackerNode extends HostNode {

    private volatile boolean mitmActive = false;
    private volatile IpAddress targetVictimIp;
    private volatile MacAddress targetVictimMac;
    private volatile IpAddress targetGatewayIp;
    private volatile MacAddress targetGatewayMac;

    public AttackerNode(String hostname, NetworkInterface nic) {
        super(hostname, nic);
    }

    public boolean isMitmActive() {
        return mitmActive;
    }

    public void setMitmTargets(IpAddress victimIp, MacAddress victimMac, IpAddress gatewayIp, MacAddress gatewayMac) {
        this.targetVictimIp = victimIp;
        this.targetVictimMac = victimMac;
        this.targetGatewayIp = gatewayIp;
        this.targetGatewayMac = gatewayMac;
    }

    /**
     * Executes bidirectional ARP Cache Poisoning:
     * 1. Poison Victim: Gateway IP (192.168.1.1) -> Attacker MAC
     * 2. Poison Gateway: Victim IP (192.168.1.10) -> Attacker MAC
     */
    public void launchArpPoisoning() {
        if (targetVictimIp == null || targetGatewayIp == null) {
            Hub.I.log("[ATTACKER] Cannot launch attack: Targets not configured");
            return;
        }

        this.mitmActive = true;
        Hub.I.log(String.format("[ATTACKER] LAUNCHING ARP CACHE POISONING ATTACK against %s and %s!",
                targetVictimIp, targetGatewayIp));

        // 1. Send forged ARP reply to victim claiming to be Gateway
        ArpPacket poisonVictim = new ArpPacket(
                ArpPacket.HTYPE_ETHERNET, ArpPacket.PTYPE_IPV4, ArpPacket.HLEN_ETHERNET, ArpPacket.PLEN_IPV4,
                ArpOperation.REPLY,
                getNic().getMac(), targetGatewayIp,
                targetVictimMac, targetVictimIp
        );
        EthernetFrame frame1 = new EthernetFrame(targetVictimMac, getNic().getMac(), EthernetFrame.ETHERTYPE_ARP, poisonVictim.toBytes());
        getNic().send(frame1);

        // 2. Send forged ARP reply to gateway claiming to be Victim
        ArpPacket poisonGateway = new ArpPacket(
                ArpPacket.HTYPE_ETHERNET, ArpPacket.PTYPE_IPV4, ArpPacket.HLEN_ETHERNET, ArpPacket.PLEN_IPV4,
                ArpOperation.REPLY,
                getNic().getMac(), targetVictimIp,
                targetGatewayMac, targetGatewayIp
        );
        EthernetFrame frame2 = new EthernetFrame(targetGatewayMac, getNic().getMac(), EthernetFrame.ETHERTYPE_ARP, poisonGateway.toBytes());
        getNic().send(frame2);
    }

    /**
     * Broadcasts a forged Gratuitous ARP announcement to poison all hosts on the LAN.
     */
    public void broadcastForgedGarp(IpAddress victimIp) {
        Hub.I.log(String.format("[ATTACKER] Broadcasting malicious GARP: %s is at %s", victimIp, getNic().getMac()));
        ArpPacket forgedGarp = new ArpPacket(
                ArpPacket.HTYPE_ETHERNET, ArpPacket.PTYPE_IPV4, ArpPacket.HLEN_ETHERNET, ArpPacket.PLEN_IPV4,
                ArpOperation.REQUEST,
                getNic().getMac(), victimIp,
                MacAddress.BROADCAST, victimIp
        );
        EthernetFrame frame = new EthernetFrame(MacAddress.BROADCAST, getNic().getMac(), EthernetFrame.ETHERTYPE_ARP, forgedGarp.toBytes());
        getNic().send(frame);
    }

    /**
     * Floods the switch with randomized MAC addresses to overflow CAM table (macof simulation).
     */
    public int floodRandomMacs(int count) {
        Hub.I.log(String.format("[ATTACKER] Flooding switch with %d random MAC addresses (macof CAM Overflow)", count));
        Random r = new Random();
        byte[] macBytes = new byte[6];
        for (int i = 0; i < count; i++) {
            r.nextBytes(macBytes);
            macBytes[0] = (byte) (macBytes[0] & 0xFE); // ensure unicast
            MacAddress spoofed = new MacAddress(macBytes);
            EthernetFrame frame = new EthernetFrame(MacAddress.BROADCAST, spoofed, EthernetFrame.ETHERTYPE_ARP, new byte[46]);
            getNic().send(frame);
        }
        return count;
    }

    /**
     * Launches a high-rate ARP storm to test DAI Rate Limiting DoS defenses.
     */
    public int launchArpStorm(int count) {
        Hub.I.log(String.format("[ATTACKER] Launching ARP Storm DoS (%d burst packets) to test DAI Rate Limiting...", count));
        for (int i = 0; i < count; i++) {
            ArpPacket req = ArpPacket.createRequest(getNic().getMac(), getNic().getIp(), IpAddress.parse("192.168.1." + (100 + (i % 50))));
            getNic().send(req.toFrame());
        }
        return count;
    }

    public void stopMitm() {
        this.mitmActive = false;
        Hub.I.log("[ATTACKER] MITM Poisoning deactivated.");
    }

    @Override
    protected void onReceiveFrame(EthernetFrame frame) {
        // If MITM is active and we receive an IPv4 packet addressed to our MAC that originated from
        // the victim or gateway, intercept and forward it!
        if (mitmActive && frame.isIpv4() && frame.getDestinationMac().equals(getNic().getMac())) {
            String payloadStr = new String(frame.getPayload(), StandardCharsets.UTF_8);

            if (frame.getSourceMac().equals(targetVictimMac)) {
                // Intercepted from Victim destined for Gateway
                Hub.I.log(String.format("[MITM SNIFFED] Intercepted from Victim (%s): %s", targetVictimMac, payloadStr));
                Hub.I.logIntercepted("Victim (" + targetVictimIp + ")", "Gateway (" + targetGatewayIp + ")", payloadStr);

                // Forward to actual gateway
                EthernetFrame forwarded = new EthernetFrame(targetGatewayMac, getNic().getMac(), frame.getEtherType(), frame.getPayload());
                getNic().send(forwarded);
                return;
            } else if (frame.getSourceMac().equals(targetGatewayMac)) {
                // Intercepted from Gateway destined for Victim
                Hub.I.log(String.format("[MITM SNIFFED] Intercepted from Gateway (%s): %s", targetGatewayMac, payloadStr));
                Hub.I.logIntercepted("Gateway (" + targetGatewayIp + ")", "Victim (" + targetVictimIp + ")", payloadStr);

                // Forward to actual victim
                EthernetFrame forwarded = new EthernetFrame(targetVictimMac, getNic().getMac(), frame.getEtherType(), frame.getPayload());
                getNic().send(forwarded);
                return;
            }
        }

        super.onReceiveFrame(frame);
    }

    @Override
    public String json() {
        return Json.obj(
                "hostname", getHostname(),
                "ip", getNic().getIp().toString(),
                "mac", getNic().getMac().toString(),
                "vendor", getNic().getMac().getVendor(),
                "port", getNic().getConnectedPort(),
                "mitmActive", mitmActive,
                "victimIp", targetVictimIp != null ? targetVictimIp.toString() : "",
                "gatewayIp", targetGatewayIp != null ? targetGatewayIp.toString() : "",
                "arpTable", Json.raw(getArpTable().json())
        );
    }
}

package arp.network;

import arp.core.Hub;
import arp.core.Json;
import arp.model.IpAddress;
import arp.model.MacAddress;
import arp.protocol.ArpOperation;
import arp.protocol.ArpPacket;
import arp.protocol.EthernetFrame;

import java.nio.charset.StandardCharsets;

/**
 * Enterprise Router / Default Gateway implementing RFC 1027 Proxy ARP.
 */
public final class RouterNode extends HostNode {

    private volatile boolean proxyArpEnabled = true;
    private final IpAddress remoteSubnet = IpAddress.parse("10.0.0.0");
    private final IpAddress remoteNetmask = IpAddress.parse("255.255.255.0");

    public RouterNode(String hostname, NetworkInterface nic) {
        super(hostname, nic);
    }

    public boolean isProxyArpEnabled() {
        return proxyArpEnabled;
    }

    public void setProxyArpEnabled(boolean enabled) {
        this.proxyArpEnabled = enabled;
    }

    @Override
    protected void onReceiveFrame(EthernetFrame frame) {
        if (frame.isArp()) {
            handleRouterArp(frame);
        } else {
            super.onReceiveFrame(frame);
        }
    }

    private void handleRouterArp(EthernetFrame frame) {
        ArpPacket arp;
        try {
            arp = ArpPacket.fromBytes(frame.getPayload());
        } catch (Exception e) {
            return;
        }

        IpAddress targetIp = arp.getTargetProtocolAddress();
        IpAddress senderIp = arp.getSenderProtocolAddress();
        MacAddress senderMac = arp.getSenderHardwareAddress();

        // 1. Standard Router ARP behavior for its own Gateway IP (192.168.1.1)
        if (targetIp.equals(getNic().getIp())) {
            super.onReceiveFrame(frame);
            return;
        }

        // 2. RFC 1027 Proxy ARP:
        // If Proxy ARP is enabled and the requested target is in our routable remote subnet (10.0.0.0/24)
        if (proxyArpEnabled && arp.getOperation() == ArpOperation.REQUEST && !senderIp.isAny()) {
            if (targetIp.isInSameSubnet(remoteSubnet, remoteNetmask)) {
                Hub.I.log(String.format("[%s] PROXY ARP TRIGGERED! Answering on behalf of remote host %s with Gateway MAC %s",
                        getHostname(), targetIp, getNic().getMac()));

                // Construct Proxy ARP reply: sender says targetIp is at router's MAC
                ArpPacket proxyReply = ArpPacket.createReply(getNic().getMac(), targetIp, senderMac, senderIp);
                EthernetFrame replyFrame = new EthernetFrame(senderMac, getNic().getMac(), EthernetFrame.ETHERTYPE_ARP, proxyReply.toBytes());
                getNic().send(replyFrame);
                return;
            }
        }

        // Let base class update its cache if relevant
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
                "proxyArpEnabled", proxyArpEnabled,
                "remoteSubnet", remoteSubnet.toString() + "/24",
                "arpTable", Json.raw(getArpTable().json())
        );
    }
}

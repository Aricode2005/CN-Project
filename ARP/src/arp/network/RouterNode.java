package arp.network;

import arp.core.Hub;
import arp.core.Json;
import arp.model.IpAddress;
import arp.model.MacAddress;
import arp.protocol.ArpOperation;
import arp.protocol.ArpPacket;
import arp.protocol.EthernetFrame;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Enterprise Router / Default Gateway implementing:
 * - RFC 1027 Proxy ARP for remote routed subnets (10.0.0.0/24)
 * - RFC 903 Reverse ARP (RARP) Bootstrap Server for diskless clients
 */
public final class RouterNode extends HostNode {

    private volatile boolean proxyArpEnabled = true;
    private volatile boolean rarpServerEnabled = true;
    private final IpAddress remoteSubnet = IpAddress.parse("10.0.0.0");
    private final IpAddress remoteNetmask = IpAddress.parse("255.255.255.0");
    private final Map<MacAddress, IpAddress> rarpDatabase = new ConcurrentHashMap<>();

    public RouterNode(String hostname, NetworkInterface nic) {
        super(hostname, nic);
    }

    public boolean isProxyArpEnabled() {
        return proxyArpEnabled;
    }

    public void setProxyArpEnabled(boolean enabled) {
        this.proxyArpEnabled = enabled;
    }

    public boolean isRarpServerEnabled() {
        return rarpServerEnabled;
    }

    public void setRarpServerEnabled(boolean enabled) {
        this.rarpServerEnabled = enabled;
    }

    public void addRarpMapping(MacAddress mac, IpAddress ip) {
        rarpDatabase.put(mac, ip);
    }

    public Map<MacAddress, IpAddress> getRarpDatabase() {
        return Collections.unmodifiableMap(rarpDatabase);
    }

    @Override
    protected void onReceiveFrame(EthernetFrame frame) {
        if (frame.isArp() || frame.isRarp()) {
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

        // 1. Handle RFC 903 RARP Request as Bootstrap Server
        if (rarpServerEnabled && arp.isRarpRequest()) {
            MacAddress clientMac = arp.getSenderHardwareAddress();
            IpAddress assignedIp = rarpDatabase.get(clientMac);
            if (assignedIp != null) {
                Hub.I.log(String.format("[%s RARP SERVER] Answering RARP Request for MAC %s -> Assigning IP %s",
                        getHostname(), clientMac, assignedIp));

                ArpPacket rarpReply = ArpPacket.createRarpReply(getNic().getMac(), getNic().getIp(), clientMac, assignedIp);
                EthernetFrame replyFrame = new EthernetFrame(clientMac, getNic().getMac(), EthernetFrame.ETHERTYPE_RARP, rarpReply.toBytes());
                getNic().send(replyFrame);
                return;
            } else {
                Hub.I.log(String.format("[%s RARP SERVER] No static RARP lease configured for client MAC %s (Ignored)",
                        getHostname(), clientMac));
                return;
            }
        }

        IpAddress targetIp = arp.getTargetProtocolAddress();
        IpAddress senderIp = arp.getSenderProtocolAddress();
        MacAddress senderMac = arp.getSenderHardwareAddress();

        // 2. Standard Router ARP behavior for its own Gateway IP (192.168.1.1)
        if (targetIp.equals(getNic().getIp())) {
            super.onReceiveFrame(frame);
            return;
        }

        // 3. RFC 1027 Proxy ARP:
        // If Proxy ARP is enabled and the requested target is in our routable remote subnet (10.0.0.0/24)
        if (proxyArpEnabled && arp.getOperation() == ArpOperation.REQUEST && !senderIp.isAny()) {
            if (targetIp.isInSameSubnet(remoteSubnet, remoteNetmask)) {
                Hub.I.log(String.format("[%s] PROXY ARP TRIGGERED! Answering on behalf of remote host %s with Gateway MAC %s",
                        getHostname(), targetIp, getNic().getMac()));

                // Construct Proxy ARP reply: router claims remote targetIp is at router's MAC
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
        List<String> rarpJsons = new ArrayList<>();
        for (var entry : rarpDatabase.entrySet()) {
            rarpJsons.add(Json.obj("mac", entry.getKey().toString(), "ip", entry.getValue().toString()));
        }

        return Json.obj(
                "hostname", getHostname(),
                "ip", getNic().getIp().toString(),
                "mac", getNic().getMac().toString(),
                "vendor", getNic().getMac().getVendor(),
                "port", getNic().getConnectedPort(),
                "proxyArpEnabled", proxyArpEnabled,
                "rarpServerEnabled", rarpServerEnabled,
                "remoteSubnet", remoteSubnet.toString() + "/24",
                "rarpDatabase", Json.arr(rarpJsons),
                "arpTable", Json.raw(getArpTable().json())
        );
    }
}

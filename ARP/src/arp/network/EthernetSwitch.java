package arp.network;

import arp.core.Hub;
import arp.core.Json;
import arp.model.MacAddress;
import arp.model.SwitchCamEntry;
import arp.protocol.EthernetFrame;
import arp.security.DynamicArpInspection;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 8-Port L2 Ethernet Switch Simulator.
 *
 * Implements:
 * - IEEE 802.1D MAC Address Learning (CAM Table)
 * - Intelligent Unicast Forwarding vs Broadcast Flooding
 * - Dynamic ARP Inspection (DAI) Enforcement
 * - Real-time Frame Telemetry for Web Sniffer
 */
public final class EthernetSwitch {

    private final String name;
    private final Map<Integer, NetworkInterface> ports = new ConcurrentHashMap<>();
    private final Map<MacAddress, SwitchCamEntry> camTable = new ConcurrentHashMap<>();
    private final DynamicArpInspection dai;

    public EthernetSwitch(String name, DynamicArpInspection dai) {
        this.name = name;
        this.dai = dai;
    }

    public void connect(int port, NetworkInterface nic) {
        ports.put(port, nic);
        nic.attach(this, port);
    }

    public void disconnect(int port) {
        NetworkInterface nic = ports.remove(port);
        if (nic != null) {
            camTable.entrySet().removeIf(e -> e.getValue().getPort() == port);
        }
    }

    public synchronized void handleIncomingFrame(int ingressPort, EthernetFrame frame) {
        // 1. MAC Learning: Update CAM table with the source MAC of the arriving frame
        MacAddress srcMac = frame.getSourceMac();
        if (!srcMac.isBroadcast() && !srcMac.isMulticast() && !srcMac.isZero()) {
            SwitchCamEntry existing = camTable.get(srcMac);
            if (existing != null) {
                existing.refresh(ingressPort);
            } else {
                camTable.put(srcMac, SwitchCamEntry.dynamicEntry(srcMac, ingressPort, 60));
            }
        }

        // 2. Dynamic ARP Inspection (DAI) security check
        boolean allowed = true;
        if (frame.isArp() && dai != null) {
            allowed = dai.inspect(ingressPort, frame);
        }

        // 3. Log to central telemetry hub for dashboard packet sniffer
        Hub.I.captureFrame(ingressPort, frame, !allowed);

        if (!allowed) {
            Hub.I.log(String.format("[SWITCH %s] DAI BLOCKED spoofed ARP frame on Port %d from %s",
                    name, ingressPort, srcMac));
            return; // Dropped at L2 edge
        }

        // 4. Forwarding Decision
        MacAddress dstMac = frame.getDestinationMac();

        if (dstMac.isBroadcast() || dstMac.isMulticast()) {
            // Broadcast / Multicast: Flood to all ports except ingress
            flood(ingressPort, frame);
        } else {
            // Unicast: Check CAM table
            SwitchCamEntry destEntry = camTable.get(dstMac);
            if (destEntry != null && !destEntry.isExpired()) {
                int egressPort = destEntry.getPort();
                if (egressPort != ingressPort) {
                    forwardToPort(egressPort, frame);
                }
            } else {
                // Unknown Unicast: Flood to learn destination port
                flood(ingressPort, frame);
            }
        }
    }

    private void forwardToPort(int egressPort, EthernetFrame frame) {
        NetworkInterface nic = ports.get(egressPort);
        if (nic != null) {
            nic.receive(frame);
        }
    }

    private void flood(int ingressPort, EthernetFrame frame) {
        for (Map.Entry<Integer, NetworkInterface> entry : ports.entrySet()) {
            if (entry.getKey() != ingressPort) {
                entry.getValue().receive(frame);
            }
        }
    }

    public void reapCamTable() {
        camTable.entrySet().removeIf(e -> e.getValue().isExpired());
    }

    public void clearCamTable() {
        camTable.clear();
    }

    public List<SwitchCamEntry> getCamEntries() {
        List<SwitchCamEntry> list = new ArrayList<>(camTable.values());
        Collections.sort(list, (a, b) -> Integer.compare(a.getPort(), b.getPort()));
        return list;
    }

    public DynamicArpInspection getDai() {
        return dai;
    }

    public String getName() {
        return name;
    }

    public Map<Integer, NetworkInterface> getPorts() {
        return ports;
    }

    public String json() {
        List<String> camJsons = new ArrayList<>();
        for (SwitchCamEntry e : getCamEntries()) {
            camJsons.add(e.json());
        }
        return Json.obj(
                "name", name,
                "cam", Json.arr(camJsons),
                "dai", dai != null ? Json.raw(dai.json()) : null
        );
    }
}

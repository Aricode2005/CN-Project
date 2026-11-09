package arp.network;

import arp.core.Hub;
import arp.core.Json;
import arp.model.MacAddress;
import arp.model.SwitchCamEntry;
import arp.protocol.EthernetFrame;
import arp.security.DynamicArpInspection;
import arp.security.PortSecurity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Enterprise 8-Port L2 Managed Ethernet Switch Simulator.
 *
 * Implements:
 * - IEEE 802.1D MAC Address Learning (CAM Table)
 * - IEEE 802.1Q Virtual LAN (VLAN) Segmentation & Broadcast Isolation
 * - Cisco Switchport Port-Security (MAC limiting & Err-Disable shutdown)
 * - Dynamic ARP Inspection (DAI) Enforcement & Rate Limiting
 * - Cisco IOS Command-Line Diagnostic Engine (show mac address-table, show vlan, etc.)
 */
public final class EthernetSwitch {

    private final String name;
    private final Map<Integer, NetworkInterface> ports = new ConcurrentHashMap<>();
    private final Map<Integer, Integer> portVlans = new ConcurrentHashMap<>(); // Port -> VLAN ID (default 1)
    private final Map<MacAddress, SwitchCamEntry> camTable = new ConcurrentHashMap<>();
    private final DynamicArpInspection dai;
    private final PortSecurity portSecurity = new PortSecurity();

    public EthernetSwitch(String name, DynamicArpInspection dai) {
        this.name = name;
        this.dai = dai;
    }

    public void connect(int port, NetworkInterface nic) {
        ports.put(port, nic);
        portVlans.putIfAbsent(port, 1); // default to VLAN 1
        nic.attach(this, port);
    }

    public void disconnect(int port) {
        NetworkInterface nic = ports.remove(port);
        portVlans.remove(port);
        if (nic != null) {
            camTable.entrySet().removeIf(e -> e.getValue().getPort() == port);
        }
    }

    public void setPortVlan(int port, int vlanId) {
        if (vlanId < 1 || vlanId > 4094) {
            throw new IllegalArgumentException("VLAN ID must be in range 1-4094");
        }
        portVlans.put(port, vlanId);
        Hub.I.log(String.format("[SWITCH %s] Port %d assigned to VLAN %d", name, port, vlanId));
    }

    public int getPortVlan(int port) {
        return portVlans.getOrDefault(port, 1);
    }

    public PortSecurity getPortSecurity() {
        return portSecurity;
    }

    public synchronized void handleIncomingFrame(int ingressPort, EthernetFrame frame) {
        // 0. Physical / Link-layer check: Is the port in ERR_DISABLE state?
        if (portSecurity.isPortErrDisabled(ingressPort)) {
            Hub.I.log(String.format("[SWITCH %s] Port %d is in ERR_DISABLE (Port-Security) - frame dropped!", name, ingressPort));
            return;
        }
        if (dai != null && dai.getRateLimiter().isPortErrDisabled(ingressPort)) {
            Hub.I.log(String.format("[SWITCH %s] Port %d is in ERR_DISABLE (DAI Rate-Limit) - frame dropped!", name, ingressPort));
            return;
        }

        // 1. Port Security Check (Limits MACs per port; defends against macof CAM overflow)
        MacAddress srcMac = frame.getSourceMac();
        boolean portSecOk = portSecurity.check(ingressPort, srcMac);
        if (!portSecOk) {
            Hub.I.captureFrame(ingressPort, frame, true);
            return; // Dropped by hardware port security
        }

        // Determine VLAN for this frame (from 802.1Q tag or ingress access port VLAN)
        int frameVlan = frame.isTagged() ? frame.getVlanId() : getPortVlan(ingressPort);

        // 2. MAC Learning: Update CAM table with the source MAC and ingress port
        if (!srcMac.isBroadcast() && !srcMac.isMulticast() && !srcMac.isZero()) {
            SwitchCamEntry existing = camTable.get(srcMac);
            if (existing != null) {
                existing.refresh(ingressPort);
            } else {
                camTable.put(srcMac, SwitchCamEntry.dynamicEntry(srcMac, ingressPort, 60));
            }
        }

        // 3. Dynamic ARP Inspection (DAI) security check
        boolean allowed = true;
        if (frame.isArp() && dai != null) {
            allowed = dai.inspect(ingressPort, frame);
        }

        // 4. Log to central telemetry hub for dashboard packet sniffer
        Hub.I.captureFrame(ingressPort, frame, !allowed);

        if (!allowed) {
            Hub.I.log(String.format("[SWITCH %s] DAI BLOCKED spoofed ARP frame on Port %d from %s",
                    name, ingressPort, srcMac));
            return; // Dropped at L2 edge
        }

        // 5. Forwarding Decision with IEEE 802.1Q VLAN Isolation
        MacAddress dstMac = frame.getDestinationMac();

        if (dstMac.isBroadcast() || dstMac.isMulticast()) {
            // Broadcast / Multicast: Flood ONLY to ports in the SAME VLAN!
            floodVlan(ingressPort, frameVlan, frame);
        } else {
            // Unicast: Check CAM table
            SwitchCamEntry destEntry = camTable.get(dstMac);
            if (destEntry != null && !destEntry.isExpired()) {
                int egressPort = destEntry.getPort();
                int egressVlan = getPortVlan(egressPort);

                // VLAN check: Egress port must belong to the same VLAN as the frame!
                if (egressVlan == frameVlan && egressPort != ingressPort) {
                    forwardToPort(egressPort, frame);
                } else if (egressVlan != frameVlan) {
                    Hub.I.log(String.format("[SWITCH %s] VLAN ISOLATION: Frame from Port %d (VLAN %d) to %s blocked on Port %d (VLAN %d)",
                            name, ingressPort, frameVlan, dstMac, egressPort, egressVlan));
                }
            } else {
                // Unknown Unicast: Flood within the same VLAN
                floodVlan(ingressPort, frameVlan, frame);
            }
        }
    }

    private void forwardToPort(int egressPort, EthernetFrame frame) {
        NetworkInterface nic = ports.get(egressPort);
        if (nic != null) {
            nic.receive(frame);
        }
    }

    private void floodVlan(int ingressPort, int vlanId, EthernetFrame frame) {
        for (Map.Entry<Integer, NetworkInterface> entry : ports.entrySet()) {
            int portNum = entry.getKey();
            if (portNum != ingressPort) {
                int portVlan = getPortVlan(portNum);
                // Strict 802.1Q VLAN boundary: only deliver to ports in the same broadcast domain
                if (portVlan == vlanId) {
                    entry.getValue().receive(frame);
                }
            }
        }
    }

    public void reapCamTable() {
        camTable.entrySet().removeIf(e -> e.getValue().isExpired());
    }

    public void clearCamTable() {
        camTable.clear();
    }

    public void resetAllErrDisabled() {
        for (int p : ports.keySet()) {
            portSecurity.resetPort(p);
            if (dai != null) dai.getRateLimiter().resetPort(p);
        }
        Hub.I.log("[SWITCH] All err-disabled ports have been reset and restored.");
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

    public Map<Integer, Integer> getPortVlans() {
        return Collections.unmodifiableMap(portVlans);
    }

    /**
     * Executes Cisco IOS diagnostic CLI commands.
     */
    public String executeCiscoCommand(String cmd) {
        if (cmd == null) return "% Incomplete command";
        cmd = cmd.trim().toLowerCase();

        if (cmd.equals("show mac address-table") || cmd.equals("show mac-address-table")) {
            StringBuilder sb = new StringBuilder();
            sb.append("          Mac Address Table\n");
            sb.append("-------------------------------------------\n");
            sb.append("Vlan    Mac Address       Type        Ports\n");
            sb.append("----    -----------       --------    -----\n");
            for (SwitchCamEntry e : getCamEntries()) {
                sb.append(String.format("%-7d %-17s %-11s Fa0/%d\n",
                        getPortVlan(e.getPort()), e.getMac(), e.isStatic() ? "STATIC" : "DYNAMIC", e.getPort()));
            }
            sb.append("Total Mac Addresses for this criterion: ").append(camTable.size()).append("\n");
            return sb.toString();
        }

        if (cmd.startsWith("show vlan") || cmd.equals("show vlan brief")) {
            StringBuilder sb = new StringBuilder();
            sb.append("VLAN Name                             Status    Ports\n");
            sb.append("---- -------------------------------- --------- -------------------------------\n");
            Map<Integer, List<Integer>> vlanMap = new ConcurrentHashMap<>();
            for (var entry : portVlans.entrySet()) {
                vlanMap.computeIfAbsent(entry.getValue(), k -> new ArrayList<>()).add(entry.getKey());
            }
            for (var entry : vlanMap.entrySet()) {
                int vid = entry.getKey();
                String name = (vid == 1) ? "default" : (vid == 10) ? "Engineering" : (vid == 20) ? "Finance" : "VLAN" + vid;
                StringBuilder portList = new StringBuilder();
                for (int p : entry.getValue()) {
                    if (portList.length() > 0) portList.append(", ");
                    portList.append("Fa0/").append(p);
                }
                sb.append(String.format("%-4d %-32s %-9s %s\n", vid, name, "active", portList));
            }
            return sb.toString();
        }

        if (cmd.startsWith("show ip arp inspection")) {
            if (dai == null) return "% Dynamic ARP inspection not configured";
            StringBuilder sb = new StringBuilder();
            sb.append("Source Mac Validation      : ").append(dai.isValidateSrcMac() ? "Enabled" : "Disabled").append("\n");
            sb.append("Destination Mac Validation : ").append(dai.isValidateDstMac() ? "Enabled" : "Disabled").append("\n");
            sb.append("IP Address Validation      : ").append(dai.isValidateIp() ? "Enabled" : "Disabled").append("\n");
            sb.append("\n Vlan  Configuration  Operation  Rate (pps)\n");
            sb.append(" ----  -------------  ---------  ----------\n");
            sb.append("    1  Enabled        Running    15\n\n");
            sb.append(" Vlan  Permitted  Dropped  Rate-Limit Drops\n");
            sb.append(" ----  ---------  -------  ----------------\n");
            sb.append(String.format("    1  %-10d %-8d %-16d\n", dai.getPassedCount(), dai.getDroppedCount(), dai.getRateLimitDropCount()));
            return sb.toString();
        }

        if (cmd.startsWith("show port-security")) {
            StringBuilder sb = new StringBuilder();
            sb.append("Secure Port  MaxSecureAddr  CurrentAddr  SecurityViolation  Security Action\n");
            sb.append("-----------  -------------  -----------  -----------------  ---------------\n");
            for (PortSecurity.PortConfig cfg : portSecurity.getAllConfigs()) {
                String act = cfg.getAction().name();
                String status = cfg.isErrDisabled() ? "Shutdown(err-disable)" : act;
                sb.append(String.format("Fa0/%-7d  %-13d  %-11d  %-17d  %s\n",
                        cfg.getPort(), cfg.getMaxMacs(), cfg.getSecureMacs().size(), cfg.getViolations(), status));
            }
            return sb.toString();
        }

        if (cmd.equals("show interfaces status")) {
            StringBuilder sb = new StringBuilder();
            sb.append("Port      Name               Status       Vlan       Duplex  Speed Type\n");
            sb.append("--------- ------------------ ------------ ---------- ------  ----- ----\n");
            for (var entry : ports.entrySet()) {
                int p = entry.getKey();
                boolean errDis = portSecurity.isPortErrDisabled(p) || (dai != null && dai.getRateLimiter().isPortErrDisabled(p));
                String status = errDis ? "err-disabled" : "connected";
                int vlan = getPortVlan(p);
                sb.append(String.format("Fa0/%-5d %-18s %-12s %-10d a-full  a-100 10/100BaseTX\n",
                        p, entry.getValue().getName(), status, vlan));
            }
            return sb.toString();
        }

        if (cmd.equals("clear mac address-table") || cmd.equals("clear mac-address-table")) {
            clearCamTable();
            return "CAM table cleared.";
        }

        return "% Invalid command: " + cmd;
    }

    public String json() {
        List<String> camJsons = new ArrayList<>();
        for (SwitchCamEntry e : getCamEntries()) {
            camJsons.add(e.json());
        }

        List<String> vlanJsons = new ArrayList<>();
        for (Map.Entry<Integer, Integer> e : portVlans.entrySet()) {
            vlanJsons.add(Json.obj("port", e.getKey(), "vlan", e.getValue()));
        }

        return Json.obj(
                "name", name,
                "cam", Json.arr(camJsons),
                "portVlans", Json.arr(vlanJsons),
                "portSecurity", Json.raw(portSecurity.json()),
                "dai", dai != null ? Json.raw(dai.json()) : null
        );
    }
}

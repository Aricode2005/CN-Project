package arp;

import arp.core.Hub;
import arp.dashboard.DashboardServer;
import arp.model.IpAddress;
import arp.model.MacAddress;
import arp.network.AttackerNode;
import arp.network.EthernetSwitch;
import arp.network.HostNode;
import arp.network.NetworkInterface;
import arp.network.RouterNode;
import arp.security.DhcpSnoopingTable;
import arp.security.DynamicArpInspection;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Main Entry Point for the RFC 826 ARP Protocol Simulation & Security Lab.
 *
 * Topology:
 * - Center:  8-Port L2 Switch (CAM Learning + Dynamic ARP Inspection)
 * - Port 1:  Host-A (192.168.1.10, AA:AA:AA:11:11:11)
 * - Port 2:  Host-B (192.168.1.20, BB:BB:BB:22:22:22)
 * - Port 3:  Host-C (192.168.1.30, CC:CC:CC:33:33:33)
 * - Port 4:  Gateway / Router (192.168.1.1, 00:1A:2B:00:01:01 - Cisco 2911)
 * - Port 5:  Attacker Node (192.168.1.66, 66:66:66:66:66:66 - Kali Linux)
 * - Port 8082: Real-time Web Dashboard & Sniffer (http://localhost:8082)
 *
 * Usage:
 *   run.bat              compile + start lab + dashboard + interactive console
 *   run.bat --verify     run automated RFC 826 verification test suite
 */
public final class Main {

    public static final int HTTP_PORT = 8082;

    public static void main(String[] args) throws Exception {
        List<String> argList = Arrays.asList(args);
        if (argList.contains("--verify")) {
            int failed = Verify.runAll();
            System.exit(failed == 0 ? 0 : 1);
        }

        System.out.println("==============================================================================");
        System.out.println("   RFC 826 ADDRESS RESOLUTION PROTOCOL (ARP) & L2 SECURITY LAB               ");
        System.out.println("   RFC 826 (ARP) | RFC 5227 (ACD & GARP) | RFC 1027 (Proxy ARP) | IEEE 802.1D ");
        System.out.println("==============================================================================");

        // 1. Initialize DHCP Snooping Database & Dynamic ARP Inspection (DAI)
        DhcpSnoopingTable snooping = new DhcpSnoopingTable();
        File dhcpData = new File("../DHCP/data");
        int imported = snooping.importFromDhcpDataDir(dhcpData);
        if (imported > 0) {
            Hub.I.log("[DHCP SNOOPING] Successfully imported " + imported + " active leases from ../DHCP/data");
        }

        DynamicArpInspection dai = new DynamicArpInspection(snooping);
        EthernetSwitch ethSwitch = new EthernetSwitch("Switch-1", dai);

        // 2. Instantiate Network Interfaces & Virtual Nodes
        NetworkInterface nicA = new NetworkInterface("eth0", MacAddress.parse("AA:AA:AA:11:11:11"), IpAddress.parse("192.168.1.10"), null, null);
        NetworkInterface nicB = new NetworkInterface("eth0", MacAddress.parse("BB:BB:BB:22:22:22"), IpAddress.parse("192.168.1.20"), null, null);
        NetworkInterface nicC = new NetworkInterface("eth0", MacAddress.parse("CC:CC:CC:33:33:33"), IpAddress.parse("192.168.1.30"), null, null);
        NetworkInterface nicR = new NetworkInterface("eth0", MacAddress.parse("00:1A:2B:00:01:01"), IpAddress.parse("192.168.1.1"), null, null);
        NetworkInterface nicAttacker = new NetworkInterface("eth0", MacAddress.parse("66:66:66:66:66:66"), IpAddress.parse("192.168.1.66"), null, null);

        // Connect nodes to switch ports
        ethSwitch.connect(1, nicA);
        ethSwitch.connect(2, nicB);
        ethSwitch.connect(3, nicC);
        ethSwitch.connect(4, nicR);
        ethSwitch.connect(5, nicAttacker);

        // Port 4 (Gateway uplink) is trusted for DAI; host and attacker ports are untrusted
        dai.setPortTrusted(4, true);

        // Register valid bindings in DHCP Snooping Database
        snooping.addBinding(nicA.getIp(), nicA.getMac(), 1, "Host-A");
        snooping.addBinding(nicB.getIp(), nicB.getMac(), 2, "Host-B");
        snooping.addBinding(nicC.getIp(), nicC.getMac(), 3, "Host-C");
        snooping.addBinding(nicR.getIp(), nicR.getMac(), 4, "Gateway-Router");
        snooping.addBinding(nicAttacker.getIp(), nicAttacker.getMac(), 5, "Kali-Attacker");

        HostNode hostA = new HostNode("Host-A", nicA);
        HostNode hostB = new HostNode("Host-B", nicB);
        HostNode hostC = new HostNode("Host-C", nicC);
        RouterNode router = new RouterNode("Gateway-Router", nicR);
        AttackerNode attacker = new AttackerNode("Kali-Attacker", nicAttacker);
        attacker.setMitmTargets(nicA.getIp(), nicA.getMac(), nicR.getIp(), nicR.getMac());

        List<HostNode> hosts = Arrays.asList(hostA, hostB, hostC);

        // 3. Start Web Dashboard on port 8082
        File webDir = new File("web");
        DashboardServer dashboard = new DashboardServer(HTTP_PORT, ethSwitch, hosts, router, attacker, webDir);
        dashboard.start();

        System.out.println("  Web Dashboard ..... http://localhost:" + HTTP_PORT);
        System.out.println("  DHCP Link ......... http://localhost:8080 (if running)");
        System.out.println("  Telnet Link ....... http://localhost:8081 (if running)");
        System.out.println();

        // 4. Run Initial Live Demonstration Scenarios
        runInitialDemonstration(hostA, hostB, router, attacker, ethSwitch, dai);

        // 5. Interactive CLI Menu Loop
        printCliMenu();
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = in.readLine()) != null) {
            line = line.trim();
            if ("q".equalsIgnoreCase(line) || "exit".equalsIgnoreCase(line)) break;
            handleCommand(line, hostA, hostB, hostC, router, attacker, ethSwitch, dai);
            printCliMenu();
        }

        dashboard.stop();
        System.out.println("ARP Lab shut down successfully.");
        System.exit(0);
    }

    private static void runInitialDemonstration(
            HostNode hostA,
            HostNode hostB,
            RouterNode router,
            AttackerNode attacker,
            EthernetSwitch ethSwitch,
            DynamicArpInspection dai) throws InterruptedException {

        System.out.println("--- [SCENARIO 1] Standard RFC 826 Address Resolution (Host-A -> Host-B) ---");
        hostA.ping(hostB.getNic().getIp(), "Hello-Bob");
        Thread.sleep(400);

        System.out.println("\n--- [SCENARIO 2] RFC 5227 Gratuitous ARP Announcement (Host-B) ---");
        hostB.sendGratuitousArp();
        Thread.sleep(400);

        System.out.println("\n--- [SCENARIO 3] RFC 1027 Proxy ARP across Subnets (Host-A -> Remote 10.0.0.5) ---");
        dai.setEnabled(false); // disable temporarily for proxy demo
        hostA.ping(IpAddress.parse("10.0.0.5"), "Packet-to-Remote-Subnet");
        Thread.sleep(400);

        System.out.println("\n--- [SCENARIO 4] Security: MITM ARP Cache Poisoning Attack ---");
        attacker.launchArpPoisoning();
        Thread.sleep(400);
        System.out.println("  Host-A ARP Table after Poisoning:");
        System.out.println("  " + hostA.getArpTable().lookup(router.getNic().getIp()));

        System.out.println("\n--- [SCENARIO 5] Dynamic ARP Inspection (DAI) Protection Activated ---");
        dai.setEnabled(true);
        // Flush poisoned caches
        hostA.getArpTable().clearDynamic();
        router.getArpTable().clearDynamic();
        // Attacker attempts to poison again
        attacker.launchArpPoisoning();
        Thread.sleep(400);
        System.out.printf("  DAI Status: Passed=%d, Dropped Spoofed Packets=%d%n",
                dai.getPassedCount(), dai.getDroppedCount());
        System.out.println();
    }

    private static void printCliMenu() {
        System.out.println("==============================================================================");
        System.out.println("  LIVE DASHBOARD: http://localhost:" + HTTP_PORT);
        System.out.println("  COMMANDS:");
        System.out.println("   [1] Ping: Host-A -> Host-B (192.168.1.20)");
        System.out.println("   [2] Ping: Host-A -> Gateway Router (192.168.1.1)");
        System.out.println("   [3] Send Gratuitous ARP (Host-B announcement)");
        System.out.println("   [4] Send RFC 5227 ARP Probe (ACD Duplicate IP check)");
        System.out.println("   [5] Ping Remote Subnet (RFC 1027 Proxy ARP demo: 10.0.0.5)");
        System.out.println("   [6] Launch MITM ARP Poisoning Attack");
        System.out.println("   [7] Stop MITM Attack");
        System.out.println("   [8] Toggle Dynamic ARP Inspection (DAI)");
        System.out.println("   [9] Display All ARP Tables & Switch CAM");
        System.out.println("   [0] Flush All Caches & CAM Table");
        System.out.println("   [q] Quit");
        System.out.print("  Enter choice > ");
    }

    private static void handleCommand(
            String cmd,
            HostNode hostA,
            HostNode hostB,
            HostNode hostC,
            RouterNode router,
            AttackerNode attacker,
            EthernetSwitch ethSwitch,
            DynamicArpInspection dai) {

        switch (cmd) {
            case "1":
                hostA.ping(hostB.getNic().getIp(), "CLI-Ping-Payload");
                break;
            case "2":
                hostA.ping(router.getNic().getIp(), "Gateway-Ping-Payload");
                break;
            case "3":
                hostB.sendGratuitousArp();
                break;
            case "4":
                hostA.sendArpProbe(hostB.getNic().getIp());
                break;
            case "5":
                hostA.ping(IpAddress.parse("10.0.0.5"), "Proxy-ARP-Payload");
                break;
            case "6":
                attacker.launchArpPoisoning();
                break;
            case "7":
                attacker.stopMitm();
                break;
            case "8":
                boolean newState = !dai.isEnabled();
                dai.setEnabled(newState);
                System.out.println("  Dynamic ARP Inspection (DAI) is now: " + (newState ? "ENABLED" : "DISABLED"));
                break;
            case "9":
                printAllTables(hostA, hostB, hostC, router, attacker, ethSwitch);
                break;
            case "0":
                hostA.getArpTable().clearDynamic();
                hostB.getArpTable().clearDynamic();
                hostC.getArpTable().clearDynamic();
                router.getArpTable().clearDynamic();
                attacker.getArpTable().clearDynamic();
                ethSwitch.clearCamTable();
                System.out.println("  All dynamic ARP entries and switch CAM table flushed.");
                break;
            default:
                System.out.println("  Unknown command: " + cmd);
        }
    }

    private static void printAllTables(
            HostNode hostA,
            HostNode hostB,
            HostNode hostC,
            RouterNode router,
            AttackerNode attacker,
            EthernetSwitch ethSwitch) {

        System.out.println("\n--- [SWITCH CAM TABLE] ---");
        for (var e : ethSwitch.getCamEntries()) System.out.println("  " + e);

        List<HostNode> all = Arrays.asList(hostA, hostB, hostC, router, attacker);
        for (HostNode n : all) {
            System.out.println("\n--- [" + n.getHostname() + " ARP CACHE (" + n.getNic().getIp() + ")] ---");
            if (n.getArpTable().getEntries().isEmpty()) {
                System.out.println("  (empty)");
            } else {
                for (var e : n.getArpTable().getEntries()) System.out.println("  " + e);
            }
        }
        System.out.println();
    }
}

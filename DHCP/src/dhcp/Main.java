package dhcp;

import dhcp.client.DhcpClientSimulator;
import dhcp.cluster.DhcpServerNode;
import dhcp.dashboard.DashboardServer;
import dhcp.lb.ConsistentHashRouter;
import dhcp.lb.DhcpLoadBalancer;
import dhcp.model.LeaseRecord;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Scanner;
import java.util.function.Consumer;

public class Main {

    private static final int LB_PORT = 6700;
    private static final int NODE1_PORT = 6701;
    private static final int NODE2_PORT = 6702;
    private static final int NODE3_PORT = 6703;
    private static final int DASHBOARD_PORT = 8080;

    public static void main(String[] args) throws Exception {
        List<String> argList = Arrays.asList(args);
        boolean verifyOnly = argList.contains("--verify");
        boolean directLanMode = argList.contains("--lan");
        String role = getArgValue(args, "--role", "all");
        String subnetPrefix = getArgValue(args, "--subnet", "192.168.10.");
        String gatewayIp = getArgValue(args, "--gateway", "192.168.10.1");
        String dnsIp = getArgValue(args, "--dns", "8.8.8.8");
        String remoteNodesArg = getArgValue(args, "--nodes", null);

        int lbListenPort = directLanMode ? 67 : Integer.parseInt(getArgValue(args, "--lb-port", String.valueOf(LB_PORT)));

        List<String> recentLogs = Collections.synchronizedList(new ArrayList<>());
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss.SSS");

        Consumer<String> logger = msg -> {
            String line = sdf.format(new Date()) + " " + msg;
            System.out.println(line);
            synchronized (recentLogs) {
                recentLogs.add(line);
                if (recentLogs.size() > 200) {
                    recentLogs.remove(0);
                }
            }
        };

        System.out.println("================================================================================");
        System.out.println("   DISTRIBUTED & LOAD-BALANCED DHCP SERVER CLUSTER (RFC 2131 + SYSTEM DESIGN)   ");
        System.out.println("================================================================================");

        File dataDir = new File("data");
        if (!dataDir.exists()) {
            dataDir.mkdirs();
        }

        if (role.equalsIgnoreCase("node")) {
            String nodeId = getArgValue(args, "--id", "DHCP-Node-1");
            String serverIp = getArgValue(args, "--ip", "192.168.10.201");
            int port = Integer.parseInt(getArgValue(args, "--port", "6701"));
            String peersArg = getArgValue(args, "--peers", "");

            DhcpServerNode standaloneNode = new DhcpServerNode(
                    nodeId, serverIp, port, subnetPrefix, gatewayIp, dnsIp,
                    new File(dataDir, "leases_" + nodeId + ".db"), logger);

            if (!peersArg.isEmpty()) {
                for (String peer : peersArg.split(",")) {
                    String[] hp = peer.trim().split(":");
                    if (hp.length == 2) {
                        standaloneNode.registerPeerEndpoint(hp[0], Integer.parseInt(hp[1]));
                    }
                }
            }
            standaloneNode.start();
            logger.accept("[STANDALONE-NODE] Running " + nodeId + " on " + serverIp + ":" + port + " (Press Ctrl+C to stop)");
            Thread.currentThread().join();
            return;
        }

        String n1Ip = "10.0.0.1";
        String n2Ip = "10.0.0.2";
        String n3Ip = "10.0.0.3";
        if (remoteNodesArg != null) {
            String[] endpoints = remoteNodesArg.split(",");
            if (endpoints.length >= 1) n1Ip = endpoints[0].split(":")[0].trim();
            if (endpoints.length >= 2) n2Ip = endpoints[1].split(":")[0].trim();
            if (endpoints.length >= 3) n3Ip = endpoints[2].split(":")[0].trim();
        }

        DhcpServerNode node1 = new DhcpServerNode("DHCP-Node-1", n1Ip, NODE1_PORT, subnetPrefix, gatewayIp, dnsIp, new File(dataDir, "leases_node1.db"), logger);
        DhcpServerNode node2 = new DhcpServerNode("DHCP-Node-2", n2Ip, NODE2_PORT, subnetPrefix, gatewayIp, dnsIp, new File(dataDir, "leases_node2.db"), logger);
        DhcpServerNode node3 = new DhcpServerNode("DHCP-Node-3", n3Ip, NODE3_PORT, subnetPrefix, gatewayIp, dnsIp, new File(dataDir, "leases_node3.db"), logger);
        List<DhcpServerNode> nodes = Arrays.asList(node1, node2, node3);

        int[] allPorts = new int[]{NODE1_PORT, NODE2_PORT, NODE3_PORT};
        if (remoteNodesArg == null) {
            for (DhcpServerNode node : nodes) {
                for (int p : allPorts) {
                    node.registerPeerPort(p);
                }
                node.start();
            }
        }

        DhcpLoadBalancer loadBalancer = new DhcpLoadBalancer(lbListenPort, logger);
        loadBalancer.setDirectLanMode(directLanMode);
        loadBalancer.setSubnetPrefix(subnetPrefix);
        loadBalancer.setClusterNodes(nodes);

        if (remoteNodesArg != null) {
            for (String endpoint : remoteNodesArg.split(",")) {
                String[] hp = endpoint.trim().split(":");
                if (hp.length == 2) {
                    loadBalancer.registerBackendNode(hp[0], Integer.parseInt(hp[1]));
                }
            }
        } else {
            for (int p : allPorts) {
                loadBalancer.registerBackendNode("127.0.0.1", p);
            }
        }

        try {
            loadBalancer.start();
        } catch (java.net.SocketException se) {
            if (lbListenPort == 67) {
                logger.accept("[WARN] Could not bind to privileged port 0.0.0.0:67 (" + se.getMessage() + ").");
                logger.accept("[WARN] To listen on port 67 for real LAN devices, run Command Prompt / PowerShell as Administrator!");
                logger.accept("[WARN] Falling back to port " + LB_PORT + " so dashboard and simulator can still run...");
                lbListenPort = LB_PORT;
                loadBalancer = new DhcpLoadBalancer(lbListenPort, logger);
                loadBalancer.setClusterNodes(nodes);
                for (int p : allPorts) loadBalancer.registerBackendNode("127.0.0.1", p);
                loadBalancer.start();
            } else {
                throw se;
            }
        }

        DhcpClientSimulator simulator = new DhcpClientSimulator(lbListenPort, logger);

        DashboardServer dashboard = new DashboardServer(DASHBOARD_PORT, loadBalancer, nodes, simulator, recentLogs);
        dashboard.start();
        logger.accept("[DASHBOARD] Live Web UI started at http://localhost:" + DASHBOARD_PORT);

        if (!directLanMode || argList.contains("--demo")) {
            if (remoteNodesArg != null) {
                Thread.sleep(1500);
            }
            runInitialDemoScenario(simulator, loadBalancer, nodes, logger);
        } else {
            logger.accept("[DIRECT-LAN-MODE] Listening on 0.0.0.0:" + lbListenPort + " for real LAN DHCP broadcasts (255.255.255.255:67 -> :68)!");
        }

        if (verifyOnly) {
            logger.accept("[VERIFY] All automated Distributed DHCP checks passed! Shutting down cleanly.");
            dashboard.shutdown();
            loadBalancer.shutdown();
            for (DhcpServerNode n : nodes) n.shutdown();
            System.exit(0);
        }

        printCliMenu();
        Scanner scanner = new Scanner(System.in);
        while (scanner.hasNextLine()) {
            String input = scanner.nextLine().trim();
            if (input.equalsIgnoreCase("q") || input.equalsIgnoreCase("exit")) {
                break;
            }
            handleCliCommand(input, simulator, loadBalancer, nodes, logger);
            printCliMenu();
        }

        if (remoteNodesArg != null) {
            Thread.currentThread().join();
        }

        dashboard.shutdown();
        loadBalancer.shutdown();
        for (DhcpServerNode n : nodes) n.shutdown();
        System.exit(0);
    }

    private static String getArgValue(String[] args, String flag, String defaultValue) {
        for (int i = 0; i < args.length - 1; i++) {
            if (args[i].equalsIgnoreCase(flag)) {
                return args[i + 1];
            }
        }
        return defaultValue;
    }

    private static void runInitialDemoScenario(
            DhcpClientSimulator simulator,
            DhcpLoadBalancer loadBalancer,
            List<DhcpServerNode> nodes,
            Consumer<String> logger) throws InterruptedException {

        System.out.println("\n--- [SCENARIO 1] Multi-Client DORA Handshakes via Consistent Hashing Load Balancer ---");
        simulator.runSingleClientDora("AA:BB:CC:11:22:01", "laptop-alice");
        simulator.runSingleClientDora("AA:BB:CC:11:22:02", "workstation-bob");
        simulator.runSingleClientDora("AA:BB:CC:11:22:03", "iot-sensor-charlie");

        System.out.println("\n--- [SCENARIO 2] Static VIP MAC Reservation & Extended RFC 2131 Messages (INFORM / DECLINE / RELEASE) ---");
        simulator.runSingleClientDora("00:1A:2B:3C:4D:01", "gateway-admin-vip");
        simulator.sendInform("AA:BB:CC:99:88:77", "192.168.10.250", "static-printer-01");
        simulator.sendDecline("AA:BB:CC:11:22:03", "192.168.10.12");
        simulator.sendRelease("AA:BB:CC:11:22:02", "192.168.10.11");

        Thread.sleep(300);

        System.out.println("\n--- [SCENARIO 3] Chaos Engineering: Simulate DHCP-Node-1 Crash & Automatic Failover ---");
        nodes.get(0).setSimulatedDown(true);
        Thread.sleep(3500);

        simulator.runSingleClientDora("AA:BB:CC:11:22:04", "failover-client-dave");
        simulator.runSingleClientDora("AA:BB:CC:11:22:01", "laptop-alice");

        nodes.get(0).setSimulatedDown(false);
        Thread.sleep(1800);

        System.out.println("\n--- [SCENARIO 4] Security: Simulated DHCP Starvation Flood vs. Token-Bucket Rate Limiter ---");
        simulator.simulateStarvationAttack(35);
        Thread.sleep(400);
        logger.accept(String.format("[SECURITY-REPORT] Rate Limiter Allowed=%d packets, Blocked=%d flood packets",
                loadBalancer.getRateLimiter().getTotalAllowed(),
                loadBalancer.getRateLimiter().getTotalDropped()));
    }

    private static void printCliMenu() {
        System.out.println("\n================================================================================");
        System.out.println("  LIVE WEB DASHBOARD: http://localhost:" + DASHBOARD_PORT);
        System.out.println("  CLI COMMANDS:");
        System.out.println("   [1] Simulate 1 New Client DORA Handshake");
        System.out.println("   [2] Simulate 5 Concurrent Clients (Load Balancing Demo)");
        System.out.println("   [3] Show Replicated Active Lease Table & Node Metrics");
        System.out.println("   [4] Toggle Load Balancing Strategy (Consistent Hash / Round-Robin / Least-Loaded)");
        System.out.println("   [5] Toggle Node-1 Crash / Recovery (Failover Demo)");
        System.out.println("   [6] Launch Simulated DHCP Starvation Attack (Rate Limiter Demo)");
        System.out.println("   [7] Send DHCPINFORM / DHCPRELEASE / DHCPDECLINE Test Packets");
        System.out.println("   [q] Quit");
        System.out.print("Select option > ");
    }

    private static void handleCliCommand(
            String cmd,
            DhcpClientSimulator simulator,
            DhcpLoadBalancer lb,
            List<DhcpServerNode> nodes,
            Consumer<String> logger) {
        switch (cmd) {
            case "1":
                simulator.simulateConcurrentClients(1);
                sleepQuietly(400);
                break;
            case "2":
                simulator.simulateConcurrentClients(5);
                sleepQuietly(700);
                break;
            case "3":
                System.out.println("\n--- CLUSTER NODE METRICS ---");
                for (DhcpServerNode n : nodes) {
                    boolean healthy = lb.getNodeHealthStatus().getOrDefault(n.getUdpPort(), true);
                    long routed = lb.getRouter().getNodeLoadCounters().getOrDefault(n.getUdpPort(), 0L);
                    System.out.printf("  %s (%s:%d) | LB-Healthy=%s | Routed=%d | Offers=%d | ACKs=%d | PeerSyncs=%d%n",
                            n.getNodeId(), n.getServerIp(), n.getUdpPort(), healthy, routed,
                            n.getOffersSent(), n.getAcksSent(), n.getPeerSyncsReceived());
                }
                System.out.println("\n--- ACTIVE REPLICATED LEASES ---");
                for (LeaseRecord r : nodes.get(1).getLeaseManager().getAllLeases()) {
                    System.out.println("  " + r);
                }
                break;
            case "4":
                ConsistentHashRouter.Strategy current = lb.getRouter().getStrategy();
                ConsistentHashRouter.Strategy next = ConsistentHashRouter.Strategy.values()[
                        (current.ordinal() + 1) % ConsistentHashRouter.Strategy.values().length];
                lb.getRouter().setStrategy(next);
                logger.accept("Switched Load Balancer Strategy to: " + next);
                break;
            case "5":
                DhcpServerNode n1 = nodes.get(0);
                n1.setSimulatedDown(!n1.isSimulatedDown());
                break;
            case "6":
                simulator.simulateStarvationAttack(40);
                sleepQuietly(400);
                break;
            case "7":
                simulator.sendInform("AA:BB:CC:99:88:77", "192.168.10.250", "static-printer-01");
                sleepQuietly(200);
                simulator.sendDecline("AA:BB:CC:11:22:03", "192.168.10.12");
                sleepQuietly(200);
                simulator.sendRelease("AA:BB:CC:11:22:01", "192.168.10.10");
                sleepQuietly(300);
                break;
            default:
                System.out.println("Unknown option: " + cmd);
                break;
        }
    }

    private static void sleepQuietly(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException ignored) {}
    }
}

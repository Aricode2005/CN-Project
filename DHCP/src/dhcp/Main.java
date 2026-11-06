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

/**
 * Main Entry Point for the Distributed & Load-Balanced DHCP Server System in Java.
 *
 * Topology:
 * - UDP Load Balancer & Relay Agent (giaddr=192.168.10.254): Port 6700
 * - DHCP Server Node-1 (10.0.0.1): Port 6701
 * - DHCP Server Node-2 (10.0.0.2): Port 6702
 * - DHCP Server Node-3 (10.0.0.3): Port 6703
 * - Real-Time Web Dashboard & REST API: http://localhost:8080
 */
public class Main {

    private static final int LB_PORT = 6700;
    private static final int NODE1_PORT = 6701;
    private static final int NODE2_PORT = 6702;
    private static final int NODE3_PORT = 6703;
    private static final int DASHBOARD_PORT = 8080;

    public static void main(String[] args) throws Exception {
        boolean verifyOnly = Arrays.asList(args).contains("--verify");

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

        // 1. Instantiate 3 Distributed DHCP Server Worker Nodes
        DhcpServerNode node1 = new DhcpServerNode("DHCP-Node-1", "10.0.0.1", NODE1_PORT, new File(dataDir, "leases_node1.db"), logger);
        DhcpServerNode node2 = new DhcpServerNode("DHCP-Node-2", "10.0.0.2", NODE2_PORT, new File(dataDir, "leases_node2.db"), logger);
        DhcpServerNode node3 = new DhcpServerNode("DHCP-Node-3", "10.0.0.3", NODE3_PORT, new File(dataDir, "leases_node3.db"), logger);
        List<DhcpServerNode> nodes = Arrays.asList(node1, node2, node3);

        // Wire Full-Mesh Peer Ports for Active-Active Gossip State Replication
        int[] allPorts = new int[]{NODE1_PORT, NODE2_PORT, NODE3_PORT};
        for (DhcpServerNode node : nodes) {
            for (int p : allPorts) {
                node.registerPeerPort(p);
            }
            node.start();
        }

        // 2. Start Front-End L4 UDP Load Balancer & DHCP Relay Agent
        DhcpLoadBalancer loadBalancer = new DhcpLoadBalancer(LB_PORT, logger);
        for (int p : allPorts) {
            loadBalancer.registerBackendNode(p);
        }
        loadBalancer.start();

        // 3. Create Client Simulator
        DhcpClientSimulator simulator = new DhcpClientSimulator(LB_PORT, logger);

        // 4. Start Real-Time HTTP Dashboard on port 8080
        DashboardServer dashboard = new DashboardServer(DASHBOARD_PORT, loadBalancer, nodes, simulator, recentLogs);
        dashboard.start();
        logger.accept("[DASHBOARD] Live Web UI started at http://localhost:" + DASHBOARD_PORT);

        // 5. Run Initial Automated System Design Demonstration
        runInitialDemoScenario(simulator, loadBalancer, nodes, logger);

        if (verifyOnly) {
            logger.accept("[VERIFY] All automated Distributed DHCP checks passed! Shutting down cleanly.");
            dashboard.shutdown();
            loadBalancer.shutdown();
            for (DhcpServerNode n : nodes) n.shutdown();
            System.exit(0);
        }

        // 6. Interactive CLI Menu
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

        dashboard.shutdown();
        loadBalancer.shutdown();
        for (DhcpServerNode n : nodes) n.shutdown();
        System.exit(0);
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
        // Wait for Load Balancer heartbeat detector to evict Node-1 from the Consistent Hash Ring
        Thread.sleep(3500);

        simulator.runSingleClientDora("AA:BB:CC:11:22:04", "failover-client-dave");
        // Renew Alice's IP even while Node-1 is down (proving Active-Active Peer Gossip Replication)
        simulator.runSingleClientDora("AA:BB:CC:11:22:01", "laptop-alice");

        // Recover Node-1
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

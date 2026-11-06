package dhcp.lb;

import dhcp.protocol.DhcpMessageType;
import dhcp.protocol.DhcpPacket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * L4 UDP Load Balancer & RFC 2131 DHCP Relay Agent (giaddr).
 *
 * Responsibilities:
 * - Listens on front-end UDP port (6700) for DHCP Client packets
 * - Enforces Token-Bucket Rate Limiting to block DHCP Starvation floods
 * - Stamps giaddr (Gateway Relay IP) and client return port option
 * - Routes requests to healthy backend DHCP Server nodes via Consistent Hashing (or Round-Robin / Least-Loaded)
 * - Performs continuous Heartbeat Health Checks (PING/PONG) and automatic failover
 */
public class DhcpLoadBalancer {

    private final int listenPort;
    private final String relayAgentIp = "192.168.10.254";
    private final ConsistentHashRouter router;
    private final RateLimiter rateLimiter;

    private final List<Integer> allRegisteredBackendPorts = new CopyOnWriteArrayList<>();
    private final Map<Integer, Long> lastPongTimestamp = new ConcurrentHashMap<>();
    private final Map<Integer, Boolean> nodeHealthStatus = new ConcurrentHashMap<>();

    private DatagramSocket socket;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicInteger healthPingXid = new AtomicInteger(90000);
    private final Consumer<String> eventLogger;

    private final ScheduledExecutorService healthCheckExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "LB-HealthChecker");
        t.setDaemon(true);
        return t;
    });

    public DhcpLoadBalancer(int listenPort, Consumer<String> eventLogger) {
        this.listenPort = listenPort;
        this.eventLogger = eventLogger;
        this.router = new ConsistentHashRouter(32); // 32 virtual nodes per server on consistent hash ring
        // Allow up to 8 burst packets per MAC (4/sec refill), and 25 global burst packets (15/sec refill)
        this.rateLimiter = new RateLimiter(8.0, 4.0, 25.0, 15.0);
    }

    public void registerBackendNode(int backendPort) {
        allRegisteredBackendPorts.add(backendPort);
        lastPongTimestamp.put(backendPort, System.currentTimeMillis());
        nodeHealthStatus.put(backendPort, true);
        router.addNode(backendPort);
    }

    public void start() throws SocketException {
        if (running.getAndSet(true)) return;
        socket = new DatagramSocket(listenPort);

        Thread listenerThread = new Thread(this::listenLoop, "LB-UDP-Listener");
        listenerThread.setDaemon(true);
        listenerThread.start();

        // Run heartbeat health check every 700 milliseconds
        healthCheckExecutor.scheduleAtFixedRate(this::runHealthChecks, 500, 700, TimeUnit.MILLISECONDS);
        log("Started on UDP port " + listenPort + " [Relay giaddr=" + relayAgentIp + ", Strategy=" + router.getStrategy() + "]");
    }

    private void listenLoop() {
        byte[] buf = new byte[1500];
        while (running.get()) {
            try {
                DatagramPacket raw = new DatagramPacket(buf, buf.length);
                socket.receive(raw);

                DhcpPacket packet = DhcpPacket.fromBytes(raw.getData(), raw.getLength());
                DhcpMessageType type = packet.getMessageType();
                if (type == null) continue;

                // 1. Handle Health Check PONG from backend DHCP Node
                if (type == DhcpMessageType.CLUSTER_HEALTH_PONG) {
                    int backendPort = raw.getPort();
                    lastPongTimestamp.put(backendPort, System.currentTimeMillis());
                    Boolean wasHealthy = nodeHealthStatus.put(backendPort, true);
                    if (wasHealthy != null && !wasHealthy) {
                        router.addNode(backendPort);
                        log("HEALTH RECOVERED: Backend port " + backendPort + " rejoined the Consistent Hash Ring!");
                    }
                    continue;
                }

                // 2. If BOOTREQUEST from Client -> Rate limit, inject giaddr, route to Backend Node
                if (packet.getOp() == DhcpPacket.BOOTREQUEST) {
                    String clientMac = packet.getChaddr();
                    if (!rateLimiter.allowRequest(clientMac)) {
                        log("RATE LIMIT DROP: Blocked packet from MAC " + clientMac + " (DHCP Starvation Protection)");
                        continue;
                    }

                    Integer targetBackendPort = router.selectBackendPort(clientMac);
                    if (targetBackendPort == null) {
                        log("CRITICAL: No healthy DHCP backend nodes available!");
                        continue;
                    }

                    // Populate Relay Agent IP (giaddr), increment hops, and record client port
                    packet.setGiaddr(relayAgentIp);
                    packet.setHops((byte) (packet.getHops() + 1));
                    if (packet.getOptionInt(DhcpPacket.OPT_CLIENT_PORT) == null) {
                        packet.setOptionInt(DhcpPacket.OPT_CLIENT_PORT, raw.getPort());
                    }

                    byte[] outBytes = packet.toBytes();
                    DatagramPacket forward = new DatagramPacket(
                            outBytes, outBytes.length, InetAddress.getByName("127.0.0.1"), targetBackendPort);
                    socket.send(forward);
                }
                // 3. If BOOTREPLY from Backend Node -> Forward back to Client port
                else if (packet.getOp() == DhcpPacket.BOOTREPLY) {
                    Integer clientPort = packet.getOptionInt(DhcpPacket.OPT_CLIENT_PORT);
                    if (clientPort != null) {
                        byte[] outBytes = packet.toBytes();
                        DatagramPacket toClient = new DatagramPacket(
                                outBytes, outBytes.length, InetAddress.getByName("127.0.0.1"), clientPort);
                        socket.send(toClient);
                    }
                }
            } catch (IOException e) {
                if (running.get()) {
                    log("LB Socket error: " + e.getMessage());
                }
            } catch (Exception ignored) {
            }
        }
    }

    private void runHealthChecks() {
        long now = System.currentTimeMillis();
        for (int backendPort : allRegisteredBackendPorts) {
            // Check if node timed out (> 1.8 seconds since last PONG)
            long lastSeen = lastPongTimestamp.getOrDefault(backendPort, 0L);
            if (now - lastSeen > 1800L) {
                Boolean wasHealthy = nodeHealthStatus.put(backendPort, false);
                if (wasHealthy == null || wasHealthy) {
                    router.removeNode(backendPort);
                    log("FAILOVER TRIGGERED: Backend port " + backendPort + " missed heartbeats! Evicted from Hash Ring.");
                }
            }

            // Send fresh CLUSTER_HEALTH_PING
            try {
                DhcpPacket ping = new DhcpPacket();
                ping.setOp(DhcpPacket.BOOTREQUEST);
                ping.setXid(healthPingXid.incrementAndGet());
                ping.setMessageType(DhcpMessageType.CLUSTER_HEALTH_PING);
                byte[] bytes = ping.toBytes();
                DatagramPacket dp = new DatagramPacket(
                        bytes, bytes.length, InetAddress.getByName("127.0.0.1"), backendPort);
                socket.send(dp);
            } catch (IOException ignored) {
            }
        }
    }

    private void log(String msg) {
        if (eventLogger != null) {
            eventLogger.accept("[LOAD-BALANCER] " + msg);
        }
    }

    public ConsistentHashRouter getRouter() { return router; }
    public RateLimiter getRateLimiter() { return rateLimiter; }
    public Map<Integer, Boolean> getNodeHealthStatus() { return nodeHealthStatus; }
    public int getListenPort() { return listenPort; }

    public void shutdown() {
        running.set(false);
        healthCheckExecutor.shutdownNow();
        if (socket != null && !socket.isClosed()) {
            socket.close();
        }
    }
}

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

public class DhcpLoadBalancer {

    private final int listenPort;
    private final String relayAgentIp = "192.168.10.254";
    private final ConsistentHashRouter router;
    private final RateLimiter rateLimiter;

    private final List<Integer> allRegisteredBackendPorts = new CopyOnWriteArrayList<>();
    private final Map<Integer, String> backendHostByPort = new ConcurrentHashMap<>();
    private final Map<Integer, Long> lastPongTimestamp = new ConcurrentHashMap<>();
    private final Map<Integer, Boolean> nodeHealthStatus = new ConcurrentHashMap<>();

    private DatagramSocket socket;
    private DatagramSocket lanInterfaceSocket;
    private boolean directLanMode = false;
    private String lanServerIp = "192.168.1.41";
    private String subnetPrefix = "192.168.1.";
    private List<dhcp.cluster.DhcpServerNode> clusterNodes;
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
        this.directLanMode = (listenPort == 67);
        this.eventLogger = eventLogger;
        this.router = new ConsistentHashRouter(32);
        this.rateLimiter = new RateLimiter(20.0, 10.0, 30.0, 15.0);
    }

    public void setClusterNodes(List<dhcp.cluster.DhcpServerNode> clusterNodes) {
        this.clusterNodes = clusterNodes;
    }

    public void setDirectLanMode(boolean directLanMode) {
        this.directLanMode = directLanMode;
    }

    public void setSubnetPrefix(String subnetPrefix) {
        this.subnetPrefix = subnetPrefix.endsWith(".") ? subnetPrefix : subnetPrefix + ".";
        detectLanServerIp();
    }

    private void detectLanServerIp() {
        try {
            java.util.Enumeration<java.net.NetworkInterface> interfaces = java.net.NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                java.net.NetworkInterface nif = interfaces.nextElement();
                if (!nif.isUp() || nif.isLoopback()) continue;
                java.util.Enumeration<InetAddress> addrs = nif.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress addr = addrs.nextElement();
                    String ip = addr.getHostAddress();
                    if (ip != null && ip.startsWith(subnetPrefix)) {
                        this.lanServerIp = ip;
                        return;
                    }
                }
            }
        } catch (Exception ignored) {
        }
    }

    public void registerBackendNode(int backendPort) {
        registerBackendNode("127.0.0.1", backendPort);
    }

    public void registerBackendNode(String backendHost, int backendPort) {
        allRegisteredBackendPorts.add(backendPort);
        backendHostByPort.put(backendPort, backendHost);
        lastPongTimestamp.put(backendPort, System.currentTimeMillis());
        nodeHealthStatus.put(backendPort, true);
        router.addNode(backendPort);
    }

    public void start() throws SocketException {
        if (running.getAndSet(true)) return;
        detectLanServerIp();

        socket = new DatagramSocket(null);
        socket.setReuseAddress(true);
        socket.setBroadcast(true);
        socket.bind(new java.net.InetSocketAddress("0.0.0.0", listenPort));

        if (directLanMode) {
            try {
                lanInterfaceSocket = new DatagramSocket(new java.net.InetSocketAddress(lanServerIp, 0));
                lanInterfaceSocket.setBroadcast(true);
                log("Bound dedicated Wi-Fi broadcast sender to LAN IP " + lanServerIp);
            } catch (Exception e) {
                log("Note: Could not bind dedicated sender to " + lanServerIp + " (" + e.getMessage() + "), using default socket.");
            }
        }

        Thread listenerThread = new Thread(this::listenLoop, "LB-UDP-Listener");
        listenerThread.setDaemon(true);
        listenerThread.start();

        healthCheckExecutor.scheduleAtFixedRate(this::runHealthChecks, 500, 700, TimeUnit.MILLISECONDS);
        log("Started on 0.0.0.0:" + listenPort + " [DirectLANBroadcast=" + directLanMode
                + ", LAN-Server-IP=" + lanServerIp + ", Strategy=" + router.getStrategy() + "]");
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

                if (type == DhcpMessageType.CLUSTER_HEALTH_PONG) {
                    int backendPort = raw.getPort();
                    lastPongTimestamp.put(backendPort, System.currentTimeMillis());
                    Boolean wasHealthy = nodeHealthStatus.put(backendPort, true);
                    if (wasHealthy != null && !wasHealthy) {
                        router.addNode(backendPort);
                        log("HEALTH RECOVERED: Backend " + backendHostByPort.getOrDefault(backendPort, "127.0.0.1")
                                + ":" + backendPort + " rejoined the Consistent Hash Ring!");
                    }
                    continue;
                }

                if (type == DhcpMessageType.CLUSTER_PEER_SYNC) {
                    String payload = packet.getOptionString(DhcpPacket.OPT_SYNC_PAYLOAD);
                    if (payload != null && clusterNodes != null) {
                        dhcp.model.LeaseRecord synced = dhcp.model.LeaseRecord.deserialize(payload);
                        for (dhcp.cluster.DhcpServerNode n : clusterNodes) {
                            n.getLeaseManager().applyPeerSync(synced);
                            if (n.getUdpPort() != raw.getPort()) {
                                n.recordRemotePeerSync();
                            }
                        }
                    }
                    continue;
                }

                if (packet.getOp() == DhcpPacket.BOOTREQUEST) {
                    String clientMac = packet.getChaddr();
                    if (raw.getPort() == 68) {
                        log("LAN PACKET IN -> Received " + type + " from MAC " + clientMac
                                + " (src=" + raw.getAddress().getHostAddress() + ":" + raw.getPort() + ")");
                    }

                    if (!rateLimiter.allowRequest(clientMac)) {
                        log("RATE LIMIT DROP: Blocked packet from MAC " + clientMac + " (DHCP Starvation Protection)");
                        continue;
                    }

                    Integer targetBackendPort = router.selectBackendPort(clientMac);
                    if (targetBackendPort == null) {
                        log("CRITICAL: No healthy DHCP backend nodes available!");
                        continue;
                    }

                    packet.setGiaddr(relayAgentIp);
                    packet.setHops((byte) (packet.getHops() + 1));
                    if (packet.getOptionInt(DhcpPacket.OPT_CLIENT_PORT) == null) {
                        packet.setOptionInt(DhcpPacket.OPT_CLIENT_PORT, raw.getPort());
                    }

                    String targetHost = backendHostByPort.getOrDefault(targetBackendPort, "127.0.0.1");
                    byte[] outBytes = packet.toBytes();
                    DatagramPacket forward = new DatagramPacket(
                            outBytes, outBytes.length, InetAddress.getByName(targetHost), targetBackendPort);
                    socket.send(forward);
                } else if (packet.getOp() == DhcpPacket.BOOTREPLY) {
                    if (clusterNodes != null) {
                        for (dhcp.cluster.DhcpServerNode n : clusterNodes) {
                            if (n.getUdpPort() == raw.getPort() && !n.getServerIp().startsWith("10.0.0.")) {
                                if (type == DhcpMessageType.DHCPOFFER) n.recordRemoteOffer();
                                else if (type == DhcpMessageType.DHCPACK) n.recordRemoteAck();
                            }
                        }
                    }
                    Integer clientPort = packet.getOptionInt(DhcpPacket.OPT_CLIENT_PORT);
                    int destPort = (clientPort != null) ? clientPort : 68;

                    if (destPort == 68 || directLanMode && (clientPort == null || clientPort == 68)) {
                        packet.removeOption(DhcpPacket.OPT_CLIENT_PORT);
                        packet.setGiaddr("0.0.0.0");
                        packet.setSiaddr(lanServerIp);
                        packet.setOptionIp(DhcpPacket.OPT_SERVER_ID, lanServerIp);

                        byte[] outBytes = packet.toBytes();
                        DatagramSocket outSock = (lanInterfaceSocket != null) ? lanInterfaceSocket : socket;

                        boolean broadcastFlag = (packet.getFlags() & 0x8000) != 0;
                        String ciaddr = packet.getCiaddr();
                        boolean isNak = (packet.getMessageType() == DhcpMessageType.DHCPNAK);

                        if (!isNak && !broadcastFlag && ciaddr != null && !ciaddr.equals("0.0.0.0")) {
                            DatagramPacket toUnicastClient = new DatagramPacket(
                                     outBytes, outBytes.length, InetAddress.getByName(ciaddr), 68);
                            outSock.send(toUnicastClient);
                            log("LAN UNICAST REPLY -> Sent " + packet.getMessageType() + " (yiaddr=" + packet.getYiaddr()
                                    + ") to " + ciaddr + ":68 for MAC " + packet.getChaddr());
                        } else {
                            String subnetBroadcast = subnetPrefix + "255";
                            DatagramPacket toSubnetBcast = new DatagramPacket(
                                    outBytes, outBytes.length, InetAddress.getByName(subnetBroadcast), 68);
                            outSock.send(toSubnetBcast);

                            DatagramPacket toGlobalBcast = new DatagramPacket(
                                    outBytes, outBytes.length, InetAddress.getByName("255.255.255.255"), 68);
                            outSock.send(toGlobalBcast);
                            log("LAN BROADCAST REPLY -> Sent " + packet.getMessageType() + " (yiaddr=" + packet.getYiaddr()
                                    + ", ServerID=" + lanServerIp + ") to " + subnetBroadcast + ":68 & 255.255.255.255:68 for MAC " + packet.getChaddr());
                        }
                    } else if (clientPort != null) {
                        byte[] outBytes = packet.toBytes();
                        DatagramPacket toSimClient = new DatagramPacket(
                                outBytes, outBytes.length, InetAddress.getByName("127.0.0.1"), clientPort);
                        socket.send(toSimClient);
                    }
                }
            } catch (IOException e) {
                if (running.get()) {
                    log("LB Socket error: " + e.getMessage());
                }
            } catch (Exception e) {
                log("LB Packet parse warning: " + e.getMessage());
            }
        }
    }

    private void runHealthChecks() {
        long now = System.currentTimeMillis();
        for (int backendPort : allRegisteredBackendPorts) {
            String host = backendHostByPort.getOrDefault(backendPort, "127.0.0.1");
            long lastSeen = lastPongTimestamp.getOrDefault(backendPort, 0L);
            if (now - lastSeen > 1800L) {
                Boolean wasHealthy = nodeHealthStatus.put(backendPort, false);
                if (wasHealthy == null || wasHealthy) {
                    router.removeNode(backendPort);
                    log("FAILOVER TRIGGERED: Backend " + host + ":" + backendPort + " missed heartbeats! Evicted from Hash Ring.");
                }
            }

            try {
                DhcpPacket ping = new DhcpPacket();
                ping.setOp(DhcpPacket.BOOTREQUEST);
                ping.setXid(healthPingXid.incrementAndGet());
                ping.setMessageType(DhcpMessageType.CLUSTER_HEALTH_PING);
                byte[] bytes = ping.toBytes();
                DatagramPacket dp = new DatagramPacket(
                        bytes, bytes.length, InetAddress.getByName(host), backendPort);
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

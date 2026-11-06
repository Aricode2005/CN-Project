package dhcp.cluster;

import dhcp.model.LeaseRecord;
import dhcp.protocol.DhcpMessageType;
import dhcp.protocol.DhcpPacket;

import java.io.File;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * A Distributed DHCP Server Worker Node.
 * - Listens on a dedicated UDP port (e.g. 6701, 6702, 6703)
 * - Processes full RFC 2131 DORA + RELEASE + INFORM + DECLINE packets
 * - Participates in Active-Active Peer State Replication (Gossip over UDP)
 * - Responds to Load Balancer Heartbeat Health Pings
 * - Supports simulated node crash / recovery (Chaos Engineering)
 */
public class DhcpServerNode {

    private final String nodeId;
    private final String serverIp;
    private final int udpPort;
    private final LeaseManager leaseManager;
    private final List<Integer> peerPorts = new CopyOnWriteArrayList<>();

    private final String subnetMask = "255.255.255.0";
    private final String routerGateway = "192.168.10.1";
    private final String dnsServer = "8.8.8.8";
    private final String domainName = "corp.distributed.local";

    private DatagramSocket socket;
    private final AtomicBoolean running = new AtomicBoolean(false);
    // Simulated crash flag for Chaos / Failover testing
    private final AtomicBoolean simulatedDown = new AtomicBoolean(false);

    private final ExecutorService workerPool;
    private final AtomicLong packetsProcessed = new AtomicLong(0);
    private final AtomicLong offersSent = new AtomicLong(0);
    private final AtomicLong acksSent = new AtomicLong(0);
    private final AtomicLong naksSent = new AtomicLong(0);
    private final AtomicLong peerSyncsReceived = new AtomicLong(0);

    private Consumer<String> eventLogger;

    public DhcpServerNode(String nodeId, String serverIp, int udpPort, File persistenceFile, Consumer<String> eventLogger) {
        this.nodeId = nodeId;
        this.serverIp = serverIp;
        this.udpPort = udpPort;
        this.eventLogger = eventLogger;
        this.leaseManager = new LeaseManager("192.168.10.", 10, 150, 120, persistenceFile);
        this.workerPool = Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, nodeId + "-Worker");
            t.setDaemon(true);
            return t;
        });
    }

    public void registerPeerPort(int peerPort) {
        if (peerPort != this.udpPort && !peerPorts.contains(peerPort)) {
            peerPorts.add(peerPort);
        }
    }

    public void start() throws SocketException {
        if (running.getAndSet(true)) return;
        socket = new DatagramSocket(udpPort);
        Thread listenerThread = new Thread(this::listenLoop, nodeId + "-UDP-Listener");
        listenerThread.setDaemon(true);
        listenerThread.start();
        log("Started on UDP port " + udpPort + " (Server ID: " + serverIp + ")");
    }

    private void listenLoop() {
        byte[] buf = new byte[1500];
        while (running.get()) {
            try {
                DatagramPacket rawPacket = new DatagramPacket(buf, buf.length);
                socket.receive(rawPacket);

                // If node is in simulated crash mode, drop all traffic (including health pings)
                if (simulatedDown.get()) {
                    continue;
                }

                byte[] copy = new byte[rawPacket.getLength()];
                System.arraycopy(rawPacket.getData(), rawPacket.getOffset(), copy, 0, rawPacket.getLength());
                InetAddress senderAddr = rawPacket.getAddress();
                int senderPort = rawPacket.getPort();

                workerPool.submit(() -> handlePacket(copy, senderAddr, senderPort));
            } catch (IOException e) {
                if (running.get()) {
                    log("Socket error: " + e.getMessage());
                }
            }
        }
    }

    private void handlePacket(byte[] data, InetAddress senderAddr, int senderPort) {
        try {
            DhcpPacket request = DhcpPacket.fromBytes(data, data.length);
            DhcpMessageType type = request.getMessageType();
            if (type == null) return;

            // 1. Handle Load Balancer Health Check Ping
            if (type == DhcpMessageType.CLUSTER_HEALTH_PING) {
                DhcpPacket pong = new DhcpPacket();
                pong.setOp(DhcpPacket.BOOTREPLY);
                pong.setXid(request.getXid());
                pong.setMessageType(DhcpMessageType.CLUSTER_HEALTH_PONG);
                pong.setOptionIp(DhcpPacket.OPT_SERVER_ID, serverIp);
                sendUdp(pong, senderAddr, senderPort);
                return;
            }

            // 2. Handle Peer Gossip Replication Sync
            if (type == DhcpMessageType.CLUSTER_PEER_SYNC) {
                String payload = request.getOptionString(DhcpPacket.OPT_SYNC_PAYLOAD);
                if (payload != null) {
                    LeaseRecord syncedRecord = LeaseRecord.deserialize(payload);
                    leaseManager.applyPeerSync(syncedRecord);
                    peerSyncsReceived.incrementAndGet();
                }
                return;
            }

            packetsProcessed.incrementAndGet();
            String clientMac = request.getChaddr();
            String hostname = request.getOptionString(DhcpPacket.OPT_HOSTNAME);
            String requestedIp = request.getOptionIp(DhcpPacket.OPT_REQUESTED_IP);

            switch (type) {
                case DHCPDISCOVER: {
                    LeaseRecord offer = leaseManager.offerLease(clientMac, hostname, requestedIp, nodeId);
                    if (offer != null) {
                        DhcpPacket reply = buildBaseReply(request, DhcpMessageType.DHCPOFFER, offer.getIpAddress());
                        offersSent.incrementAndGet();
                        replicateToPeers(offer);
                        log("DHCPOFFER -> " + offer.getIpAddress() + " for MAC " + clientMac + " (giaddr=" + request.getGiaddr() + ")");
                        sendUdp(reply, senderAddr, senderPort);
                    } else {
                        log("WARN: IP Pool Exhausted! Cannot offer IP to " + clientMac);
                    }
                    break;
                }

                case DHCPREQUEST: {
                    String targetIp = requestedIp != null ? requestedIp : request.getCiaddr();
                    LeaseRecord active = leaseManager.commitLease(
                            clientMac, targetIp, hostname, nodeId, leaseManager.getDefaultLeaseSeconds());
                    if (active != null) {
                        DhcpPacket ack = buildBaseReply(request, DhcpMessageType.DHCPACK, active.getIpAddress());
                        acksSent.incrementAndGet();
                        replicateToPeers(active);
                        log("DHCPACK   -> " + active.getIpAddress() + " bound to MAC " + clientMac + " (Lease " + leaseManager.getDefaultLeaseSeconds() + "s)");
                        sendUdp(ack, senderAddr, senderPort);
                    } else {
                        DhcpPacket nak = buildBaseReply(request, DhcpMessageType.DHCPNAK, "0.0.0.0");
                        nak.setOptionString(DhcpPacket.OPT_MESSAGE, "Requested IP conflict or invalid lease");
                        naksSent.incrementAndGet();
                        log("DHCPNAK   -> Rejected request from MAC " + clientMac + " for IP " + targetIp);
                        sendUdp(nak, senderAddr, senderPort);
                    }
                    break;
                }

                case DHCPRELEASE: {
                    boolean released = leaseManager.releaseLease(clientMac, nodeId);
                    if (released) {
                        LeaseRecord expiredEvent = new LeaseRecord(
                                request.getCiaddr(), clientMac, hostname,
                                LeaseRecord.State.EXPIRED, nodeId, 0L, false);
                        replicateToPeers(expiredEvent);
                        log("DHCPRELEASE -> Reclaimed IP " + request.getCiaddr() + " from MAC " + clientMac);
                    }
                    break;
                }

                case DHCPINFORM: {
                    DhcpPacket ack = buildBaseReply(request, DhcpMessageType.DHCPACK, request.getCiaddr());
                    acksSent.incrementAndGet();
                    log("DHCPINFORM -> Sent network options (DNS/Gateway) to " + clientMac);
                    sendUdp(ack, senderAddr, senderPort);
                    break;
                }

                case DHCPDECLINE: {
                    LeaseRecord declined = leaseManager.declineLease(clientMac, requestedIp, nodeId);
                    if (declined != null) {
                        replicateToPeers(declined);
                        log("DHCPDECLINE -> Marked IP " + requestedIp + " as DECLINED (ARP Conflict reported by " + clientMac + ")");
                    }
                    break;
                }

                default:
                    break;
            }
        } catch (Exception e) {
            log("Error handling packet: " + e.getMessage());
        }
    }

    private DhcpPacket buildBaseReply(DhcpPacket req, DhcpMessageType replyType, String assignedIp) {
        DhcpPacket reply = new DhcpPacket();
        reply.setOp(DhcpPacket.BOOTREPLY);
        reply.setXid(req.getXid());
        reply.setFlags(req.getFlags());
        reply.setCiaddr(req.getCiaddr());
        reply.setYiaddr(assignedIp);
        reply.setSiaddr(serverIp);
        reply.setGiaddr(req.getGiaddr());
        reply.setChaddr(req.getChaddr());

        reply.setMessageType(replyType);
        reply.setOptionIp(DhcpPacket.OPT_SERVER_ID, serverIp);
        reply.setOptionIp(DhcpPacket.OPT_SUBNET_MASK, subnetMask);
        reply.setOptionIp(DhcpPacket.OPT_ROUTER, routerGateway);
        reply.setOptionIp(DhcpPacket.OPT_DNS_SERVER, dnsServer);
        reply.setOptionString(DhcpPacket.OPT_DOMAIN_NAME, domainName);
        reply.setOptionInt(DhcpPacket.OPT_LEASE_TIME, leaseManager.getDefaultLeaseSeconds());

        // Preserve client return port option if forwarded through the UDP Relay/Load Balancer
        Integer clientPort = req.getOptionInt(DhcpPacket.OPT_CLIENT_PORT);
        if (clientPort != null) {
            reply.setOptionInt(DhcpPacket.OPT_CLIENT_PORT, clientPort);
        }
        return reply;
    }

    /**
     * Asynchronously replicates lease state changes to all peer DHCP server nodes via UDP Gossip.
     */
    private void replicateToPeers(LeaseRecord record) {
        DhcpPacket syncPacket = new DhcpPacket();
        syncPacket.setOp(DhcpPacket.BOOTREQUEST);
        syncPacket.setXid((int) System.nanoTime());
        syncPacket.setMessageType(DhcpMessageType.CLUSTER_PEER_SYNC);
        syncPacket.setOptionString(DhcpPacket.OPT_SYNC_PAYLOAD, record.serialize());
        byte[] bytes = syncPacket.toBytes();

        for (int peerPort : peerPorts) {
            try {
                DatagramPacket dp = new DatagramPacket(bytes, bytes.length, InetAddress.getByName("127.0.0.1"), peerPort);
                socket.send(dp);
            } catch (IOException ignored) {
            }
        }
    }

    private void sendUdp(DhcpPacket packet, InetAddress addr, int port) {
        try {
            byte[] bytes = packet.toBytes();
            DatagramPacket dp = new DatagramPacket(bytes, bytes.length, addr, port);
            socket.send(dp);
        } catch (IOException e) {
            log("Failed to send UDP reply: " + e.getMessage());
        }
    }

    private void log(String msg) {
        String formatted = String.format("[%s] %s", nodeId, msg);
        if (eventLogger != null) {
            eventLogger.accept(formatted);
        }
    }

    public void setSimulatedDown(boolean down) {
        this.simulatedDown.set(down);
        log(down ? "CHAOS ALERT: Node simulated CRASH (offline)" : "RECOVERY: Node restored ONLINE");
    }

    public boolean isSimulatedDown() { return simulatedDown.get(); }
    public String getNodeId() { return nodeId; }
    public String getServerIp() { return serverIp; }
    public int getUdpPort() { return udpPort; }
    public LeaseManager getLeaseManager() { return leaseManager; }
    public long getPacketsProcessed() { return packetsProcessed.get(); }
    public long getOffersSent() { return offersSent.get(); }
    public long getAcksSent() { return acksSent.get(); }
    public long getNaksSent() { return naksSent.get(); }
    public long getPeerSyncsReceived() { return peerSyncsReceived.get(); }

    public void shutdown() {
        running.set(false);
        if (socket != null && !socket.isClosed()) {
            socket.close();
        }
        workerPool.shutdownNow();
        leaseManager.shutdown();
    }
}

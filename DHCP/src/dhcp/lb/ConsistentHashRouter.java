package dhcp.lb;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Distributed Systems Load Balancing Router for DHCP Traffic.
 * Supports 3 switchable algorithms:
 * 1. CONSISTENT_HASHING (Default): Hashes client MAC (chaddr) onto a 32-bit ring with Virtual Nodes
 *    so that all packets of a client's DORA handshake deterministically land on the same node,
 *    with minimal key remapping when a node crashes or recovers.
 * 2. ROUND_ROBIN: Cycles evenly across healthy nodes.
 * 3. LEAST_LOADED: Routes to the healthy node with the lowest active traffic counter.
 */
public class ConsistentHashRouter {

    public enum Strategy {
        CONSISTENT_HASHING,
        ROUND_ROBIN,
        LEAST_LOADED
    }

    private final int virtualNodesPerServer;
    private final TreeMap<Long, Integer> hashRing = new TreeMap<>();
    private final List<Integer> healthyBackendPorts = new ArrayList<>();
    private final Map<Integer, Long> nodeLoadCounters = new ConcurrentHashMap<>();
    private final AtomicInteger roundRobinIndex = new AtomicInteger(0);

    private volatile Strategy currentStrategy = Strategy.CONSISTENT_HASHING;

    public ConsistentHashRouter(int virtualNodesPerServer) {
        this.virtualNodesPerServer = virtualNodesPerServer;
    }

    public synchronized void addNode(int backendPort) {
        if (!healthyBackendPorts.contains(backendPort)) {
            healthyBackendPorts.add(backendPort);
            nodeLoadCounters.putIfAbsent(backendPort, 0L);
            for (int v = 0; v < virtualNodesPerServer; v++) {
                long hash = computeHash("NODE-" + backendPort + "-VN-" + v);
                hashRing.put(hash, backendPort);
            }
        }
    }

    public synchronized void removeNode(int backendPort) {
        if (healthyBackendPorts.remove(Integer.valueOf(backendPort))) {
            for (int v = 0; v < virtualNodesPerServer; v++) {
                long hash = computeHash("NODE-" + backendPort + "-VN-" + v);
                hashRing.remove(hash);
            }
        }
    }

    /**
     * Selects a healthy backend DHCP Server UDP port based on the active Load Balancing strategy.
     */
    public synchronized Integer selectBackendPort(String clientMac) {
        if (healthyBackendPorts.isEmpty()) {
            return null;
        }

        Integer chosenPort;
        switch (currentStrategy) {
            case ROUND_ROBIN: {
                int idx = Math.abs(roundRobinIndex.getAndIncrement()) % healthyBackendPorts.size();
                chosenPort = healthyBackendPorts.get(idx);
                break;
            }
            case LEAST_LOADED: {
                chosenPort = healthyBackendPorts.get(0);
                long minLoad = Long.MAX_VALUE;
                for (int port : healthyBackendPorts) {
                    long load = nodeLoadCounters.getOrDefault(port, 0L);
                    if (load < minLoad) {
                        minLoad = load;
                        chosenPort = port;
                    }
                }
                break;
            }
            case CONSISTENT_HASHING:
            default: {
                long hash = computeHash(clientMac.toUpperCase());
                Map.Entry<Long, Integer> entry = hashRing.ceilingEntry(hash);
                if (entry == null) {
                    entry = hashRing.firstEntry();
                }
                chosenPort = entry.getValue();
                break;
            }
        }

        nodeLoadCounters.merge(chosenPort, 1L, Long::sum);
        return chosenPort;
    }

    private long computeHash(String key) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(key.getBytes(StandardCharsets.UTF_8));
            return ((long) (digest[3] & 0xFF) << 24)
                    | ((long) (digest[2] & 0xFF) << 16)
                    | ((long) (digest[1] & 0xFF) << 8)
                    | ((long) (digest[0] & 0xFF));
        } catch (Exception e) {
            return key.hashCode() & 0xFFFFFFFFL;
        }
    }

    public Strategy getStrategy() { return currentStrategy; }
    public void setStrategy(Strategy strategy) { this.currentStrategy = strategy; }
    public synchronized List<Integer> getHealthyBackendPorts() { return new ArrayList<>(healthyBackendPorts); }
    public Map<Integer, Long> getNodeLoadCounters() { return nodeLoadCounters; }
}

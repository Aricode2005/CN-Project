package telnet.cluster;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import telnet.core.Hub;
import telnet.tap.WireTap;

/**
 * Layer-4 TCP load balancer in front of the cluster (one public port, three VTY servers behind it).
 *
 *  - Health: every node sends a UDP heartbeat every 400 ms; a node silent for 1.5 s is taken out of rotation.
 *  - Scheduling: least connections (default), round robin, or source-IP hash (the same client always lands on the same node).
 *  - Each client TCP connection is spliced to one node's TCP connection; when that node dies, the client sees the drop.
 */
final class Balancer {
    static final long HB_TIMEOUT_MS = 1500;

    final int port, healthPort;
    volatile String policy = "least";
    private final Cluster cluster;
    final Map<String, Long> lastHb = new ConcurrentHashMap<>();
    final Map<String, Boolean> healthy = new ConcurrentHashMap<>();
    final List<Conn> conns = new CopyOnWriteArrayList<>();
    private final AtomicInteger ids = new AtomicInteger(1000);
    private final AtomicInteger rr = new AtomicInteger();
    volatile long accepted, refused;

    static final class Conn { final int id; final String client; final Node node; final long since = System.currentTimeMillis(); Conn(int id, String client, Node node) { this.id = id; this.client = client; this.node = node; } }

    Balancer(Cluster cluster, int port, int healthPort) { this.cluster = cluster; this.port = port; this.healthPort = healthPort; }

    void start() throws IOException {
        DatagramSocket hs = new DatagramSocket(new InetSocketAddress(InetAddress.getLoopbackAddress(), healthPort));
        daemon("lb-health", () -> {
            byte[] b = new byte[512];
            while (true) {
                try {
                    DatagramPacket p = new DatagramPacket(b, b.length);
                    hs.receive(p);
                    String[] f = new String(p.getData(), 0, p.getLength(), StandardCharsets.UTF_8).split("\t");
                    if (f.length >= 2 && f[0].equals("HB")) lastHb.put(f[1], System.currentTimeMillis());
                } catch (IOException e) { return; }
            }
        });
        daemon("lb-monitor", () -> {                       // turn heartbeats into up/down decisions, and log every change
            while (true) {
                long now = System.currentTimeMillis();
                for (Node n : cluster.nodes) {
                    Long t = lastHb.get(n.name);
                    boolean ok = t != null && now - t < HB_TIMEOUT_MS;
                    Boolean was = healthy.put(n.name, ok);
                    if (was != null && was != ok)
                        cluster.event(ok ? "LB: heartbeat from " + n.name + " is back: " + n.name + " returns to the rotation"
                                : "LB: no heartbeat from " + n.name + " for " + HB_TIMEOUT_MS + " ms: " + n.name + " taken out of the rotation");
                }
                sleep(250);
            }
        });
        ServerSocket ss = new ServerSocket(port);
        daemon("lb-accept", () -> {
            while (!ss.isClosed()) {
                try { Socket c = ss.accept(); daemon("lb-conn", () -> handle(c)); } catch (IOException e) { return; }
            }
        });
        Hub.I.log("[CLUSTER] load balancer on TCP " + port + " (" + policy + "), heartbeats on UDP " + healthPort);
    }

    boolean isHealthy(Node n) { return Boolean.TRUE.equals(healthy.get(n.name)); }

    /** Pick a node for a new client, by the current policy, among the healthy ones. */
    Node pick(String clientIp) {
        List<Node> up = new ArrayList<>();
        for (Node n : cluster.nodes) if (isHealthy(n)) up.add(n);
        if (up.isEmpty()) return null;
        switch (policy) {
            case "rr": return up.get(Math.floorMod(rr.getAndIncrement(), up.size()));
            case "hash": {                                 // rendezvous (highest-random-weight) hashing: stable when nodes come and go
                Node best = null; long bestScore = Long.MIN_VALUE;
                for (Node n : up) { long sc = mix((clientIp + "|" + n.name).hashCode()); if (sc > bestScore) { bestScore = sc; best = n; } }
                return best;
            }
            default: {                                     // least connections
                Node best = null; int bestN = Integer.MAX_VALUE;
                for (Node n : up) { int k = count(n); if (k < bestN) { bestN = k; best = n; } }
                return best;
            }
        }
    }

    int count(Node n) { int k = 0; for (Conn c : conns) if (c.node == n) k++; return k; }

    private void handle(Socket c) {
        String client = c.getInetAddress().getHostAddress();
        Node n = pick(client);
        if (n == null) {
            refused++;
            try { c.getOutputStream().write("\r\n% HA cluster: no healthy node available. Try again in a moment.\r\n".getBytes(StandardCharsets.US_ASCII)); c.close(); } catch (IOException ignored) { }
            cluster.event("LB: refused " + client + ": no healthy node");
            return;
        }
        Socket up;
        try { up = new Socket("127.0.0.1", n.port); }
        catch (IOException e) { try { c.close(); } catch (IOException ignored) { } cluster.event("LB: " + n.name + " refused the connection: " + e.getMessage()); return; }
        try { c.setTcpNoDelay(true); up.setTcpNoDelay(true); } catch (IOException ignored) { }
        Conn conn = new Conn(ids.incrementAndGet(), client, n);
        conns.add(conn);
        accepted++;
        // let the VTY server (and the dashboard) know who is really behind 127.0.0.1:<port>
        Hub.I.tap(new Hub.TapConn(conn.id, client, up.getLocalPort(), false, "lb"));
        cluster.event("LB: " + client + " -> " + n.name + " (" + describePolicy() + ")");
        Runnable done = () -> { if (conns.remove(conn)) { try { c.close(); } catch (IOException ignored) { } try { up.close(); } catch (IOException ignored) { } } };
        // The balancer is a relay in the middle of a plaintext protocol: it sees every byte, exactly like the wire tap.
        // Decode it the same way, so the dashboard shows the NVT bytes and any password typed through the cluster.
        WireTap.Sniffer sn = new WireTap.Sniffer(conn.id, false);
        daemon("lb-up", () -> { pump(c, up, sn, true); done.run(); });
        pump(up, c, sn, false);
        done.run();
    }

    String describePolicy() { return "rr".equals(policy) ? "round robin" : "hash".equals(policy) ? "source-IP hash" : "least connections"; }

    private static void pump(Socket a, Socket b, WireTap.Sniffer sn, boolean c2s) {
        byte[] buf = new byte[8192];
        try { InputStream in = a.getInputStream(); OutputStream out = b.getOutputStream(); int n; while ((n = in.read(buf)) > 0) { out.write(buf, 0, n); out.flush(); sn.chunk(c2s, buf, n); } }
        catch (IOException ignored) { }
    }

    private static long mix(long x) { x ^= x >>> 33; x *= 0xff51afd7ed558ccdL; x ^= x >>> 33; x *= 0xc4ceb9fe1a85ec53L; return x ^ (x >>> 33); }
    private static void sleep(long ms) { try { Thread.sleep(ms); } catch (InterruptedException ignored) { } }
    private static void daemon(String name, Runnable r) { Thread t = new Thread(r, name); t.setDaemon(true); t.start(); }
}

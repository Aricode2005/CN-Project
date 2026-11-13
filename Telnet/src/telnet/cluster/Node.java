package telnet.cluster;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ServerSocketFactory;
import telnet.server.VtyPool;

/**
 * One router in the HA cluster: its own VTY server (TCP), a replication socket (UDP) that keeps a copy of
 * every session snapshot in the cluster, and a heartbeat it sends to the load balancer (UDP).
 */
final class Node {
    final String name;
    final int port, replPort;
    final VtyPool pool;
    final Map<String, Snapshot> store = new ConcurrentHashMap<>();
    private final Cluster cluster;
    private volatile DatagramSocket repl;
    volatile long replSent, replReceived;

    Node(Cluster cluster, String name, int port, int replPort, VtyPool pool) {
        this.cluster = cluster; this.name = name; this.port = port; this.replPort = replPort; this.pool = pool;
        pool.node = name;
    }

    boolean alive() { return pool.up; }

    void start() throws IOException {
        pool.listen(port, ServerSocketFactory.getDefault(), "telnet");
        openReplication();
    }

    private void openReplication() throws IOException {
        DatagramSocket s = new DatagramSocket(new InetSocketAddress(InetAddress.getLoopbackAddress(), replPort));
        repl = s;
        Thread t = new Thread(() -> {
            byte[] b = new byte[65000];
            while (!s.isClosed()) {
                try {
                    DatagramPacket p = new DatagramPacket(b, b.length);
                    s.receive(p);
                    replReceived++;
                    receive(new String(p.getData(), 0, p.getLength(), StandardCharsets.UTF_8), p.getPort());
                } catch (IOException e) { if (!s.isClosed()) cluster.event(name + ": replication receive error " + e.getMessage()); }
            }
        }, "repl-" + name);
        t.setDaemon(true);
        t.start();
    }

    private void receive(String msg, int fromPort) {
        if (msg.startsWith("SNAP\t")) {
            Snapshot x = Snapshot.decode(msg);
            if (x == null) return;
            Snapshot old = store.get(x.token);
            if (old == null || old.updated <= x.updated) store.put(x.token, x);       // last writer wins, by timestamp
        } else if (msg.startsWith("DEL\t")) {
            store.remove(msg.substring(4));
        } else if (msg.equals("SYNC?")) {                                            // a restarted peer asks for everything we have
            for (Snapshot x : store.values()) sendTo(fromPort, x.encode());
        }
    }

    /** Store locally and send to every other node. A crashed node sends nothing: it is dead. */
    void replicate(Snapshot x) {
        if (!alive()) return;
        store.put(x.token, x);
        for (Node n : cluster.nodes) if (n != this) sendTo(n.replPort, x.encode());
    }

    void replicateDelete(String token) {
        if (!alive()) return;
        store.remove(token);
        for (Node n : cluster.nodes) if (n != this) sendTo(n.replPort, "DEL\t" + token);
    }

    private void sendTo(int port, String msg) {
        DatagramSocket s = repl;
        if (s == null || s.isClosed()) return;
        byte[] b = msg.getBytes(StandardCharsets.UTF_8);
        try { s.send(new DatagramPacket(b, b.length, InetAddress.getLoopbackAddress(), port)); replSent++; } catch (IOException ignored) { }
    }

    /** Power cut: the VTY server and the replication socket disappear, and the node's memory is lost. */
    void crash() {
        pool.crash();
        DatagramSocket s = repl; repl = null;
        if (s != null) s.close();
        store.clear();
    }

    /** Power back on: listen again and pull the cluster's session state from the peers (anti-entropy). */
    void restart() throws IOException {
        pool.restart();
        openReplication();
        for (Node n : cluster.nodes) if (n != this && n.alive()) { sendTo(n.replPort, "SYNC?"); break; }
    }

    List<telnet.server.TelnetSession> sessions() { return pool.sessions(); }

    /** "I am alive", sent to the load balancer's health port every 400 ms (only while the node is up). */
    void heartbeat(int healthPort) { if (alive()) sendTo(healthPort, "HB\t" + name + "\t" + pool.sessions().size()); }
}

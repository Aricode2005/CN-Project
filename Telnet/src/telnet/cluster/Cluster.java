package telnet.cluster;

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import telnet.core.Hub;
import telnet.core.Json;
import telnet.server.DeviceConfig;
import telnet.server.Resumer;
import telnet.server.SessionEvents;
import telnet.server.TelnetSession;
import telnet.server.VtyPool;

/**
 * High-availability Telnet: three router nodes behind one load balancer, with session resume.
 *
 * <pre>
 *   client --TCP 2330--> Balancer --TCP--> R1 :2331   \
 *                         (least-conn,     R2 :2332    }  each node: VtyPool + replication socket (UDP 2341-2343)
 *                          rr, ip-hash)    R3 :2333   /   heartbeat to the balancer every 400 ms (UDP 2340)
 * </pre>
 *
 * A Telnet session is stateful TCP: if its node dies the connection is gone, and TCP cannot move to another machine.
 * What can move is the session's <i>state</i>. After every login and every command the node replicates a snapshot
 * (user, privilege, mode, history, last screen) to its peers. If the connection drops, the user reconnects to the
 * balancer, lands on a healthy node, and types {@code resume}: that node already holds the snapshot and continues
 * the session. This is the idea behind tmux/screen and SSH session managers, done across machines.
 */
public final class Cluster {

    public static final int LB_PORT = 2330, NODE_BASE = 2331, HEALTH_PORT = 2340, REPL_BASE = 2341;
    public static volatile Cluster I;

    final List<Node> nodes = new ArrayList<>();
    final Balancer lb;
    private final List<String> events = new ArrayList<>();
    private final SecureRandom rnd = new SecureRandom();
    private static final long DETACH_TTL_MS = 10 * 60_000;

    public Cluster(DeviceConfig cfg, File dhcpDir) {
        for (int i = 0; i < 3; i++) {
            VtyPool p = new VtyPool(cfg, dhcpDir);          // the three nodes serve the same management configuration
            Node n = new Node(this, "R" + (i + 1), NODE_BASE + i, REPL_BASE + i, p);
            p.events.add(new Watcher(n));
            p.resumer = (s, tok) -> resume(n, s, tok);
            nodes.add(n);
        }
        lb = new Balancer(this, LB_PORT, HEALTH_PORT);
        I = this;
    }

    public void start() throws IOException {
        for (Node n : nodes) n.start();
        lb.start();
        Thread hb = new Thread(() -> {
            while (true) {
                for (Node n : nodes) n.heartbeat(HEALTH_PORT);
                expire();
                try { Thread.sleep(400); } catch (InterruptedException e) { return; }
            }
        }, "cluster-heartbeat");
        hb.setDaemon(true);
        hb.start();
        event("cluster up: R1 :" + NODE_BASE + ", R2 :" + (NODE_BASE + 1) + ", R3 :" + (NODE_BASE + 2) + " behind the load balancer on :" + LB_PORT);
    }

    /** Every VTY pool of the cluster (for the RADIUS client to attach to). */
    public List<VtyPool> pools() { List<VtyPool> l = new ArrayList<>(); for (Node n : nodes) l.add(n.pool); return l; }

    // ================================================================== session life cycle on each node

    private final class Watcher implements SessionEvents {
        final Node n;
        Watcher(Node n) { this.n = n; }

        @Override public void loggedIn(TelnetSession s, boolean resumed) {
            if (!resumed) {
                s.token = newToken();
                s.print("% HA cluster node " + n.name + ". Session token " + s.token + ": if the connection drops, reconnect to port "
                        + LB_PORT + " and type  resume  at the Username: prompt.\n");
                event(n.name + ": " + s.user + " logged in from " + s.clientIp() + ", token " + s.token);
            }
            n.replicate(snapshot(n, s, Snapshot.ATTACHED));
        }

        @Override public void command(TelnetSession s, String line) { if (s.token != null) n.replicate(snapshot(n, s, Snapshot.ATTACHED)); }

        @Override public void closed(TelnetSession s, String why) {
            if (s.token == null) return;
            if (!n.alive()) return;                       // a crashed node cannot tell anyone anything
            boolean ended = why.equals("exit") || why.equals("logout") || why.equals("quit") || why.equals("Ctrl-D") || why.equals("exec-timeout");
            if (ended) { n.replicateDelete(s.token); event(n.name + ": " + s.user + " logged out (" + why + "): session " + s.token + " removed from all nodes"); return; }
            Snapshot x = snapshot(n, s, Snapshot.DETACHED);
            x.detachedAt = System.currentTimeMillis();
            n.replicate(x);
            event(n.name + ": connection of " + s.user + " lost (" + why + "): session " + s.token + " DETACHED, kept for 10 min");
        }
    }

    private Snapshot snapshot(Node n, TelnetSession s, String state) {
        Snapshot x = new Snapshot();
        x.token = s.token; x.node = n.name; x.state = state; x.user = s.user; x.priv = s.priv; x.client = s.clientIp();
        x.config = s.mode == TelnetSession.Mode.CONFIG;
        x.history.addAll(s.history);
        x.screen = s.screenTail();
        x.updated = System.currentTimeMillis();
        return x;
    }

    private String newToken() {
        String a = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < 8; i++) { if (i == 4) b.append('-'); b.append(a.charAt(rnd.nextInt(a.length()))); }
        return b.toString();
    }

    // ================================================================== resume

    /** A snapshot can be resumed if its connection was lost, or if the node holding it is no longer healthy. */
    private boolean resumable(Snapshot x, Node here) {
        if (Snapshot.DETACHED.equals(x.state)) return true;
        for (Node n : nodes) if (n.name.equals(x.node)) return !lb.isHealthy(n) || !n.alive();
        return true;
    }

    private String resume(Node n, TelnetSession s, String tok) {
        Snapshot pick = null;
        String ip = s.clientIp();
        for (Snapshot x : n.store.values()) {
            if (!resumable(x, n)) continue;
            boolean match = tok.isEmpty() ? ip.equals(x.client) : x.token.equalsIgnoreCase(tok);
            if (match && (pick == null || x.updated > pick.updated)) pick = x;
        }
        if (pick == null) {
            event(n.name + ": resume" + (tok.isEmpty() ? " from " + ip : " " + tok) + " failed: no detached session found in " + n.name + "'s replica");
            return tok.isEmpty() ? "No detached session from " + ip + " on this cluster. Log in normally, or type  resume TOKEN"
                    : "No detached session with token " + tok;
        }
        long ago = (System.currentTimeMillis() - (pick.detachedAt > 0 ? pick.detachedAt : pick.updated)) / 1000;
        String note = "Session " + pick.token + " RESUMED on node " + n.name + " (it was on " + pick.node + ", lost " + ago + " s ago). "
                + "Same user, privilege, mode and command history: press the Up arrow.";
        event(n.name + ": " + pick.user + " RESUMED session " + pick.token + " (was on " + pick.node + ", " + ago + " s ago)");
        s.restore(pick.user, pick.priv, pick.config, pick.history, pick.screen, pick.token, note);   // fires loggedIn(resumed) -> replicate ATTACHED on n
        return null;
    }

    private void expire() {
        long now = System.currentTimeMillis();
        for (Node n : nodes) n.store.values().removeIf(x -> Snapshot.DETACHED.equals(x.state) && now - x.detachedAt > DETACH_TTL_MS);
    }

    // ================================================================== control (dashboard)

    public String control(String op, String node, String policy) {
        if ("policy".equals(op)) {
            if (!policy.equals("least") && !policy.equals("rr") && !policy.equals("hash")) return Json.obj("error", "unknown policy");
            lb.policy = policy; event("LB: scheduling policy set to " + lb.describePolicy()); return "{\"ok\":true}";
        }
        Node n = null;
        for (Node x : nodes) if (x.name.equalsIgnoreCase(node)) n = x;
        if (n == null) return Json.obj("error", "no node " + node);
        try {
            if ("kill".equals(op)) { if (!n.alive()) return Json.obj("error", n.name + " is already down"); event(n.name + ": POWER CUT (killed from the dashboard)"); n.crash(); }
            else if ("revive".equals(op)) { if (n.alive()) return Json.obj("error", n.name + " is already up"); n.restart(); event(n.name + ": restarted; asked a peer for the cluster's session state (SYNC)"); }
            else return Json.obj("error", "unknown op");
        } catch (IOException e) { return Json.obj("error", e.getMessage()); }
        return "{\"ok\":true}";
    }

    /** On how many nodes a session snapshot is stored (for the tests). */
    public int replicaCount(String token) { int k = 0; for (Node n : nodes) if (n.store.containsKey(token)) k++; return k; }
    public boolean healthy(String node) { for (Node n : nodes) if (n.name.equals(node)) return lb.isHealthy(n) && n.alive(); return false; }

    synchronized void event(String s) {
        events.add(new SimpleDateFormat("HH:mm:ss.SSS").format(new Date()) + "  " + s);
        if (events.size() > 60) events.remove(0);
        Hub.I.log("[CLUSTER] " + s);
    }

    public String json() {
        long now = System.currentTimeMillis();
        List<String> ns = new ArrayList<>();
        Map<String, List<String>> where = new LinkedHashMap<>();
        Map<String, Snapshot> newest = new LinkedHashMap<>();
        for (Node n : nodes) {
            List<String> ss = new ArrayList<>();
            for (TelnetSession s : n.sessions())
                ss.add(Json.obj("id", s.id, "user", s.user.isEmpty() ? "(logging in)" : s.user, "client", s.clientIp(), "token", s.token, "mode", s.mode.name()));
            Long hb = lb.lastHb.get(n.name);
            ns.add(Json.obj("name", n.name, "port", n.port, "replPort", n.replPort, "alive", n.alive(), "healthy", lb.isHealthy(n),
                    "hbAge", hb == null ? -1 : now - hb, "lbConns", lb.count(n), "sessions", Json.raw(Json.arr(ss)),
                    "replicas", n.store.size(), "sent", n.replSent, "received", n.replReceived));
            for (Snapshot x : n.store.values()) {
                where.computeIfAbsent(x.token, k -> new ArrayList<>()).add(Json.str(n.name));
                Snapshot o = newest.get(x.token);
                if (o == null || o.updated < x.updated) newest.put(x.token, x);
            }
        }
        List<String> sn = new ArrayList<>();
        for (Snapshot x : newest.values())
            sn.add(Json.obj("token", x.token, "user", x.user, "client", x.client, "state", x.state, "node", x.node, "priv", x.priv, "config", x.config,
                    "commands", x.history.size(), "ago", ((now - (x.detachedAt > 0 ? x.detachedAt : x.updated)) / 1000), "on", Json.raw("[" + String.join(",", where.get(x.token)) + "]")));
        List<String> cs = new ArrayList<>();
        for (Balancer.Conn c : lb.conns) cs.add(Json.obj("id", c.id, "client", c.client, "node", c.node.name, "age", (now - c.since) / 1000));
        List<String> ev;
        synchronized (this) { ev = new ArrayList<>(); for (String e : events) ev.add(Json.str(e)); }
        return Json.obj("lbPort", LB_PORT, "healthPort", HEALTH_PORT, "policy", lb.policy, "policyName", lb.describePolicy(),
                "accepted", lb.accepted, "refused", lb.refused, "timeoutMs", Balancer.HB_TIMEOUT_MS,
                "nodes", Json.raw(Json.arr(ns)), "snapshots", Json.raw(Json.arr(sn)), "conns", Json.raw(Json.arr(cs)), "events", Json.raw(Json.arr(ev)));
    }

    static String lower(String s) { return s.toLowerCase(Locale.ROOT); }
}

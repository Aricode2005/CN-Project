package route.sim;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import route.core.Hub;
import route.core.Json;
import route.net.Wire;
import route.wire.Bgp;
import route.wire.Rip;

/**
 * Path-vector routing as BGP does it. Each router is its own autonomous system (A = AS 100, B = AS 200, …).
 * An announcement carries the whole AS_PATH, not just a number; a router that finds its OWN AS number in a received
 * path rejects it, because accepting it would create a loop. That single rule is why BGP never counts to infinity.
 *
 * Messages are real BGP-4 OPEN / UPDATE messages over real TCP sessions (port 179 on each router's loopback address).
 * Updates are incremental: a router only sends when what it would advertise to that neighbour has changed.
 */
public final class PathVector {

    public final Topo t; private final Wire wire; final int n; public final int origin;
    final List<Integer>[][] ribIn;            // ribIn[x][v] = path x accepted from v (null = none)
    final String[][] ribNote;                 // why: "rejected: loop", "withdrawn", …
    final List<Integer>[] best; final int[] via;
    final List<Integer>[][] sent;              // what x last advertised to v (null = nothing)
    public final List<String> rounds = new ArrayList<>();
    public int roundNo, messages;

    @SuppressWarnings("unchecked")
    public PathVector(Topo t, Wire wire, int origin) {
        this.t = t; this.wire = wire; this.n = t.n(); this.origin = origin;
        ribIn = new List[n][n]; ribNote = new String[n][n]; best = new List[n]; via = new int[n]; sent = new List[n][n];
        java.util.Arrays.fill(via, -1);
        best[origin] = new ArrayList<>();                         // the origin's own network: empty path
    }

    /** Opens a TCP session per link and exchanges OPEN + KEEPALIVE (the BGP handshake). */
    public void open() throws IOException {
        roundNo = 0;
        List<String> msgs = new ArrayList<>();
        for (int a = 0; a < n; a++) for (int b : t.neighbours(a)) if (a < b) {
            if (wire != null) wire.connect(a, b);
            for (int[] p : new int[][] { { a, b }, { b, a } }) {
                byte[] o = Bgp.open(t.as[p[0]], route.wire.Ospf.routerId(p[0]));
                byte[] got = wire != null ? wire.tcp(p[0], p[1], o) : o;
                msgs.add(Json.obj("from", p[0], "to", p[1], "type", "OPEN", "text", "OPEN: I am AS " + t.as[p[0]] + ", hold time 180 s", "hex", DistanceVector.hex(got), "bytes", got.length));
                byte[] k = Bgp.keepalive(); byte[] gk = wire != null ? wire.tcp(p[1], p[0], k) : k;
                msgs.add(Json.obj("from", p[1], "to", p[0], "type", "KEEPALIVE", "text", "KEEPALIVE: OPEN accepted, session Established", "hex", DistanceVector.hex(gk), "bytes", gk.length));
            }
        }
        snapshot("open", "A TCP connection to port 179 for every link, then OPEN + KEEPALIVE each way: every session is Established. AS " + t.as[origin] + " (" + t.names[origin] + ") owns 10.4.0.0/16.", msgs);
    }

    private List<Integer> advert(int x) {
        if (best[x] == null) return null;
        List<Integer> p = new ArrayList<>(); p.add(t.as[x]); p.addAll(best[x]); return p;
    }

    /** One round: every router sends an UPDATE to each neighbour whose advertisement changed; then everyone re-selects. */
    public boolean round() throws IOException {
        roundNo++;
        List<String> msgs = new ArrayList<>();
        List<Object[]> deliveries = new ArrayList<>();
        for (int x = 0; x < n; x++) for (int v : t.neighbours(x)) {
            List<Integer> adv = advert(x);
            if (Objects.equals(adv, sent[x][v])) continue;           // nothing new to say (null = nothing announced, so nothing to withdraw either)
            byte[] m = Bgp.update(adv, Rip.network(x));
            byte[] got = wire != null ? wire.tcp(x, v, m) : m;
            Bgp.Update u = Bgp.parseUpdate(got);
            sent[x][v] = adv;
            messages++;
            deliveries.add(new Object[] { x, v, u, got });
        }
        for (Object[] d : deliveries) {
            int x = (int) d[0], v = (int) d[1]; Bgp.Update u = (Bgp.Update) d[2]; byte[] got = (byte[]) d[3];
            String action;
            if (u.path == null) { ribIn[v][x] = null; ribNote[v][x] = "withdrawn"; action = t.names[v] + " removes the route it had from " + t.names[x]; }
            else if (u.path.contains(t.as[v])) { ribIn[v][x] = null; ribNote[v][x] = "rejected: loop (AS " + t.as[v] + " already in " + u.path + ")"; action = "LOOP: " + t.names[v] + " sees its own AS " + t.as[v] + " in the path → rejects it"; }
            else { ribIn[v][x] = u.path; ribNote[v][x] = null; action = t.names[v] + " stores path " + u.path; }
            msgs.add(Json.obj("from", x, "to", v, "type", u.path == null ? "WITHDRAW" : "UPDATE", "path", u.path == null ? null : Json.raw(u.path.toString()),
                "loop", u.path != null && u.path.contains(t.as[v]), "action", action, "hex", DistanceVector.hex(got), "bytes", got.length));
        }
        boolean changed = false;
        for (int x = 0; x < n; x++) if (x != origin) changed |= select(x);
        snapshot("update", deliveries.isEmpty() ? "No router has anything new to say: BGP has converged." : deliveries.size() + " UPDATE message" + (deliveries.size() == 1 ? "" : "s") + " this round.", msgs);
        return !deliveries.isEmpty() || changed;
    }

    /** Best path = shortest AS_PATH among accepted ones (ties: lowest neighbour). */
    boolean select(int x) {
        List<Integer> b = null; int bv = -1;
        for (int v = 0; v < n; v++) { List<Integer> p = ribIn[x][v]; if (p != null && (b == null || p.size() < b.size())) { b = p; bv = v; } }
        boolean ch = !Objects.equals(b, best[x]) || bv != via[x];
        best[x] = b; via[x] = bv;
        return ch;
    }

    public void linkEvent(int a, int b) {
        roundNo++;
        t.cost[a][b] = t.cost[b][a] = Topo.NONE;
        if (wire != null) wire.disconnect(a, b);
        ribIn[a][b] = ribIn[b][a] = null; ribNote[a][b] = ribNote[b][a] = "session down";
        sent[a][b] = sent[b][a] = null;
        if (a != origin) select(a); if (b != origin) select(b);
        Hub.I.event("BGP", "session " + t.names[a] + "–" + t.names[b] + " down");
        snapshot("event", "Link " + t.names[a] + "–" + t.names[b] + " fails: the TCP session closes, and both sides drop every route learned over it.", new ArrayList<>());
    }

    public int converge(int max) throws IOException { int r = 0; while (r < max && round()) r++; return r; }

    public void snapshot(String kind, String note, List<String> msgs) {
        List<String> routers = new ArrayList<>();
        for (int x = 0; x < n; x++) {
            List<String> rib = new ArrayList<>();
            for (int v : neighboursEver(x)) rib.add(Json.obj("from", v, "path", ribIn[x][v] == null ? null : Json.raw(ribIn[x][v].toString()), "note", ribNote[x][v]));
            routers.add(Json.obj("best", best[x] == null ? null : Json.raw(best[x].toString()), "via", via[x], "rib", Json.raw(Json.arr(rib)),
                "hops", best[x] == null ? null : best[x].size()));
        }
        rounds.add(Json.obj("round", roundNo, "kind", kind, "note", note, "msgs", Json.raw(Json.arr(msgs)), "routers", Json.raw(Json.arr(routers)), "loops", Json.raw(loops())));
    }

    private final java.util.Set<Long> everLinked = new java.util.HashSet<>();
    private List<Integer> neighboursEver(int x) {
        for (int v : t.neighbours(x)) everLinked.add(((long) x << 32) | v);
        List<Integer> l = new ArrayList<>(); for (int v = 0; v < n; v++) if (everLinked.contains(((long) x << 32) | v)) l.add(v);
        return l;
    }

    /** Forwarding loops right now (routers whose next hops point round in a circle). */
    private String loops() {
        for (int s = 0; s < n; s++) {
            List<Integer> seen = new ArrayList<>(); int x = s;
            while (x >= 0 && x != origin && !seen.contains(x)) { seen.add(x); x = via[x]; }
            if (x >= 0 && x != origin && seen.contains(x)) { List<Integer> c = new ArrayList<>(seen.subList(seen.indexOf(x), seen.size())); java.util.Collections.sort(c); return "[" + c + "]"; }
        }
        return "[]";
    }
}

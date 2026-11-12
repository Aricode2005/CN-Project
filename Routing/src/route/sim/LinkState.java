package route.sim;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import route.core.Hub;
import route.core.Json;
import route.net.Wire;
import route.wire.Ospf;

/**
 * Link-state routing as OSPF does it: every router floods a Router-LSA describing its own links;
 * every router keeps the same link-state database (LSDB) and runs Dijkstra on it.
 *
 * Flooding rule (RFC 2328 §13): an LSA with a higher sequence number than the stored copy is installed and sent on
 * to every neighbour except the one it came from; an equal or older copy is not forwarded.
 * A link is used by SPF only if BOTH end routers list it (the two-way check), so a failure reported by one side is enough.
 */
public final class LinkState {

    public final Topo t; private final Wire wire; final int n;
    final List<Map<Integer, Ospf.Lsa>> lsdb = new ArrayList<>();
    public final List<String> rounds = new ArrayList<>();
    public int roundNo, messages, watch;
    private List<int[]> pending = new ArrayList<>();          // {from, to, origin} LSAs to deliver next round

    public LinkState(Topo t, Wire wire, int watch) {
        this.t = t; this.wire = wire; this.n = t.n(); this.watch = watch;
        for (int i = 0; i < n; i++) lsdb.add(new HashMap<>());
        for (int o = 0; o < n; o++) { Ospf.Lsa l = originate(o, Ospf.INITIAL_SEQ); for (int i = 0; i < n; i++) lsdb.get(i).put(o, l); }
    }

    private Ospf.Lsa originate(int o, int seq) {
        List<int[]> ls = new ArrayList<>(); for (int v : t.neighbours(o)) ls.add(new int[] { v, t.cost[o][v] });
        return new Ospf.Lsa(o, seq, ls.toArray(new int[0][]));
    }

    /** The graph router r believes in, from its own LSDB (two-way check). */
    Topo view(int r) {
        Topo g = t.copy();
        for (int[] row : g.cost) java.util.Arrays.fill(row, Topo.NONE);
        Map<Integer, Ospf.Lsa> db = lsdb.get(r);
        for (Ospf.Lsa a : db.values()) for (int[] k : a.links) {
            Ospf.Lsa b = db.get(k[0]);
            if (b == null) continue;
            for (int[] back : b.links) if (back[0] == a.origin) { g.cost[a.origin][k[0]] = k[1]; }
        }
        for (int i = 0; i < n; i++) for (int j = 0; j < n; j++) if (g.cost[i][j] < Topo.NONE && g.cost[j][i] >= Topo.NONE) g.cost[i][j] = Topo.NONE;
        return g;
    }

    public void snapshot(String kind, String note, List<String> msgs) {
        List<String> routers = new ArrayList<>();
        for (int r = 0; r < n; r++) {
            Dijkstra d = new Dijkstra(view(r), r);
            List<String> db = new ArrayList<>();
            for (int o = 0; o < n; o++) { Ospf.Lsa l = lsdb.get(r).get(o); db.add(l == null ? "null" : Json.obj("origin", o, "seq", String.format("0x%08x", l.seq), "links", l.links.length)); }
            List<String> nx = new ArrayList<>(), ds = new ArrayList<>();
            for (int x = 0; x < n; x++) { nx.add(String.valueOf(x == r ? r : d.firstHop(x))); ds.add(d.dist[x] >= Topo.NONE ? "null" : String.valueOf(d.dist[x])); }
            routers.add(Json.obj("lsdb", Json.raw("[" + String.join(",", db) + "]"), "next", Json.raw("[" + String.join(",", nx) + "]"), "dist", Json.raw("[" + String.join(",", ds) + "]")));
        }
        rounds.add(Json.obj("round", roundNo, "kind", kind, "note", note, "msgs", Json.raw(Json.arr(msgs)), "routers", Json.raw(Json.arr(routers))));
    }

    public void linkEvent(int a, int b, int newCost) {
        roundNo++;
        String what = newCost >= Topo.NONE ? "fails" : "changes cost to " + newCost;
        t.cost[a][b] = t.cost[b][a] = newCost;
        for (int r : new int[] { a, b }) {
            Ospf.Lsa old = lsdb.get(r).get(r);
            Ospf.Lsa fresh = originate(r, old.seq + 1);
            lsdb.get(r).put(r, fresh);
            for (int v : t.neighbours(r)) pending.add(new int[] { r, v, r });
        }
        Hub.I.event("OSPF", "link " + t.names[a] + "–" + t.names[b] + " " + what + ": both ends originate a new Router-LSA");
        snapshot("event", "Link " + t.names[a] + "–" + t.names[b] + " " + what + ". " + t.names[a] + " and " + t.names[b] + " each build a new Router-LSA (sequence number + 1) listing only their working links, and start flooding it.", new ArrayList<>());
    }

    /** Deliver every pending LSA (real OSPF LS Update bytes over UDP). Returns false when flooding has finished. */
    public boolean round() throws IOException {
        if (pending.isEmpty()) return false;
        roundNo++;
        List<int[]> now = pending; pending = new ArrayList<>();
        List<String> msgs = new ArrayList<>();
        for (int[] m : now) {
            int from = m[0], to = m[1], origin = m[2];
            Ospf.Lsa l = lsdb.get(from).get(origin);
            byte[] bytes = Ospf.update(from, List.of(l));
            byte[] got = wire != null ? wire.udp(from, to, bytes, true) : bytes;
            Ospf.Lsa recv = Ospf.parse(got).get(0);
            messages++;
            Ospf.Lsa have = lsdb.get(to).get(origin);
            String action;
            if (have == null || recv.seq > have.seq) {
                lsdb.get(to).put(origin, recv);
                List<String> fw = new ArrayList<>();
                for (int v : t.neighbours(to)) if (v != from) { pending.add(new int[] { to, v, origin }); fw.add(t.names[v]); }
                action = "newer (seq " + String.format("0x%08x", recv.seq) + "): installed" + (fw.isEmpty() ? "" : ", flooded on to " + String.join(", ", fw));
            } else action = recv.seq == have.seq ? "same sequence number: already have it, not forwarded (just acknowledged)" : "older: discarded";
            msgs.add(Json.obj("from", from, "to", to, "origin", origin, "seq", String.format("0x%08x", recv.seq), "action", action, "installed", action.startsWith("newer"), "hex", DistanceVector.hex(got), "bytes", got.length));
        }
        snapshot("flood", pending.isEmpty() ? "Flooding is over: every router has the same LSDB, and each runs Dijkstra on it." : now.size() + " LS Update packet" + (now.size() == 1 ? "" : "s") + " delivered; " + pending.size() + " more to forward.", msgs);
        return true;
    }

    public int converge(int max) throws IOException { int r = 0; while (r < max && round()) r++; return r; }

    public String spf(int r) { return new Dijkstra(view(r), r).json(); }
}

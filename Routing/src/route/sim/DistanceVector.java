package route.sim;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import route.core.Hub;
import route.core.Json;
import route.net.Wire;
import route.wire.Rip;

/**
 * Distance-vector routing (the Bellman-Ford equation, as RIP uses it):
 *      D_x(y) = min over neighbours v of { c(x,v) + D_v(y) }
 * Synchronous rounds: in every round each router sends its whole vector to every neighbour as a real RIPv2
 * response over UDP, then every router recomputes from the vectors it received.
 *
 * Options:  infinity (16 for RIP)  ·  split horizon (don't tell v about routes that go through v)
 *           poison reverse (tell v those routes cost ∞ instead of staying silent)
 */
public final class DistanceVector {

    public final Topo t; public final int inf; public final boolean split, poison;
    private final Wire wire;
    final int n;
    final int[][] D, next;
    final int[][][] heard;             // heard[x][v][d] = D_v(d) as last advertised by neighbour v to x (inf = ∞ / not told)
    final boolean[][] knows;           // has x heard from v at all yet?
    public final List<String> rounds = new ArrayList<>();
    public int roundNo, messages;

    public DistanceVector(Topo t, int inf, boolean split, boolean poison, Wire wire) {
        this.t = t; this.inf = inf; this.split = split || poison; this.poison = poison; this.wire = wire;
        n = t.n(); D = new int[n][n]; next = new int[n][n]; heard = new int[n][n][n]; knows = new boolean[n][n];
        for (int x = 0; x < n; x++) for (int v = 0; v < n; v++) java.util.Arrays.fill(heard[x][v], inf);
        for (int x = 0; x < n; x++) for (int d = 0; d < n; d++) {
            if (d == x) { D[x][d] = 0; next[x][d] = x; }
            else if (t.up(x, d)) { D[x][d] = Math.min(inf, t.cost[x][d]); next[x][d] = d; }
            else { D[x][d] = inf; next[x][d] = -1; }
        }
    }

    public int dist(int x, int d) { return D[x][d]; }
    public int nextHop(int x, int d) { return next[x][d]; }

    /** Bellman-Ford update for router x. Returns the destinations whose cost or next hop changed. */
    List<Integer> recompute(int x) {
        List<Integer> changed = new ArrayList<>();
        for (int d = 0; d < n; d++) {
            if (d == x) continue;
            int best = inf, via = -1;
            for (int v : t.neighbours(x)) {
                int dv = d == v ? 0 : heard[x][v][d];
                int c = dv >= inf ? inf : Math.min(inf, t.cost[x][v] + dv);
                if (c < best || (c == best && c < inf && v == next[x][d] && via != next[x][d])) { best = c; via = v; }
            }
            if (best >= inf) { best = inf; via = -1; }
            if (best != D[x][d] || via != next[x][d]) { D[x][d] = best; next[x][d] = via; changed.add(d); }
        }
        return changed;
    }

    /** What x tells neighbour v (split horizon omits, poison reverse sends ∞ for routes whose next hop is v). */
    private List<Rip.Entry> advert(int x, int v, List<Integer> omitted, List<Integer> poisoned) {
        List<Rip.Entry> e = new ArrayList<>();
        for (int d = 0; d < n; d++) {
            if (d != x && next[x][d] == v && split) {
                if (poison) { e.add(new Rip.Entry(d, inf)); poisoned.add(d); } else omitted.add(d);
                continue;
            }
            e.add(new Rip.Entry(d, D[x][d]));
        }
        return e;
    }

    /** Record the starting state (round 0). */
    public void snapshot(String kind, String note, List<String> msgs, List<int[]> changed) {
        rounds.add(Json.obj("round", roundNo, "kind", kind, "note", note, "msgs", Json.raw(Json.arr(msgs)), "tables", Json.raw(tables()),
            "changed", Json.raw(pairs(changed)), "loops", Json.raw(loops())));
    }

    /** One synchronous exchange: every router sends its vector to every neighbour, then everybody recomputes. */
    public boolean round() throws IOException {
        roundNo++;
        List<String> msgs = new ArrayList<>();
        int[][][] incoming = new int[n][n][];
        for (int x = 0; x < n; x++) for (int v : t.neighbours(x)) {
            List<Integer> omitted = new ArrayList<>(), poisoned = new ArrayList<>();
            List<Rip.Entry> adv = advert(x, v, omitted, poisoned);
            byte[] bytes = Rip.response(adv);
            byte[] got = wire != null ? wire.udp(x, v, bytes, false) : bytes;          // real UDP datagram between the routers' sockets
            int[] vec = new int[n]; java.util.Arrays.fill(vec, inf);
            for (Rip.Entry e : Rip.parse(got)) if (e.dest >= 0 && e.dest < n) vec[e.dest] = Math.min(inf, e.metric);
            incoming[v][x] = vec;
            messages++;
            List<String> es = new ArrayList<>();
            for (Rip.Entry e : adv) es.add(Json.obj("d", e.dest, "m", e.metric >= inf ? null : e.metric, "poisoned", poisoned.contains(e.dest)));
            msgs.add(Json.obj("from", x, "to", v, "entries", Json.raw(Json.arr(es)), "omitted", Json.raw(omitted.toString()), "hex", hex(got), "bytes", got.length));
        }
        for (int v = 0; v < n; v++) for (int x = 0; x < n; x++) if (incoming[v][x] != null) { heard[v][x] = incoming[v][x]; knows[v][x] = true; }
        List<int[]> changed = new ArrayList<>();
        for (int x = 0; x < n; x++) for (int d : recompute(x)) changed.add(new int[] { x, d });
        snapshot("exchange", changed.isEmpty() ? "Every router sent its vector; nothing changed: converged." : changed.size() + " entr" + (changed.size() == 1 ? "y" : "ies") + " changed after this exchange.", msgs, changed);
        return !changed.isEmpty();
    }

    /** A link changes cost (or fails, newCost = NONE). The two end routers notice at once and recompute. */
    public void linkEvent(int a, int b, int newCost) {
        roundNo++;
        String what = newCost >= Topo.NONE ? "fails" : "changes cost " + t.cost[a][b] + " → " + newCost;
        t.cost[a][b] = t.cost[b][a] = newCost;
        if (newCost >= Topo.NONE) { java.util.Arrays.fill(heard[a][b], inf); java.util.Arrays.fill(heard[b][a], inf); knows[a][b] = knows[b][a] = false; }
        List<int[]> changed = new ArrayList<>();
        for (int x : new int[] { a, b }) for (int d : recompute(x)) changed.add(new int[] { x, d });
        Hub.I.event("DV", "link " + t.names[a] + "–" + t.names[b] + " " + what);
        snapshot("event", "Link " + t.names[a] + "–" + t.names[b] + " " + what + ". " + t.names[a] + " and " + t.names[b] + " notice immediately and recompute from what their neighbours last told them.", new ArrayList<>(), changed);
    }

    /** Rounds until nothing changes (or the limit). */
    public int converge(int max) throws IOException {
        int r = 0;
        while (r < max) { r++; if (!round()) break; }
        return r;
    }

    // ------------------------------------------------------------------ json
    private String tables() {
        List<String> out = new ArrayList<>();
        for (int x = 0; x < n; x++) {
            List<String> rows = new ArrayList<>();
            for (int v : t.neighbours(x)) rows.add(Json.obj("via", v, "known", knows[x][v], "vec", Json.raw(vec(heard[x][v], v))));
            out.add(Json.obj("dist", Json.raw(vec(D[x], -1)), "next", Json.raw(java.util.Arrays.toString(next[x])), "rows", Json.raw(Json.arr(rows))));
        }
        return Json.arr(out);
    }
    private String vec(int[] v, int self) {
        StringBuilder b = new StringBuilder("[");
        for (int i = 0; i < v.length; i++) { if (i > 0) b.append(','); b.append(i == self ? "0" : v[i] >= inf ? "null" : String.valueOf(v[i])); }
        return b.append(']').toString();
    }
    private static String pairs(List<int[]> l) { List<String> s = new ArrayList<>(); for (int[] p : l) s.add("[" + p[0] + "," + p[1] + "]"); return "[" + String.join(",", s) + "]"; }

    /** Routing loops in the current next-hop graph, per destination: [[dest, [routers in the cycle]], …]. */
    private String loops() {
        List<String> out = new ArrayList<>();
        for (int d = 0; d < n; d++) {
            for (int s = 0; s < n; s++) {
                List<Integer> seen = new ArrayList<>(); int x = s;
                while (x >= 0 && x != d && !seen.contains(x)) { seen.add(x); x = next[x][d]; }
                if (x >= 0 && x != d && seen.contains(x)) {
                    List<Integer> cyc = new ArrayList<>(seen.subList(seen.indexOf(x), seen.size()));
                    java.util.Collections.sort(cyc);
                    String j = "[" + d + "," + cyc + "]";
                    if (!out.contains(j)) out.add(j);
                }
            }
        }
        return "[" + String.join(",", out) + "]";
    }

    public static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format("%02x", x & 0xff)); return s.toString(); }
}

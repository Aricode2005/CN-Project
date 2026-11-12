package route.sim;

import java.util.ArrayList;
import java.util.List;
import route.core.Json;

/**
 * Dijkstra's shortest-path algorithm, the heart of every link-state protocol (OSPF, IS-IS).
 * Records the textbook table step by step: N' (the settled set), D(v) and p(v) for every router.
 * Ties are broken alphabetically (lowest router name first).
 */
public final class Dijkstra {

    public final int src; public final int[] dist, prev; public final List<String> steps = new ArrayList<>();
    private final Topo t;

    public Dijkstra(Topo t, int src) {
        this.t = t; this.src = src;
        int n = t.n();
        dist = new int[n]; prev = new int[n];
        boolean[] done = new boolean[n];
        List<Integer> order = new ArrayList<>();
        java.util.Arrays.fill(dist, Topo.NONE); java.util.Arrays.fill(prev, -1);
        // initialisation: N' = {src}, D(v) = c(src, v) for neighbours
        dist[src] = 0; done[src] = true; order.add(src);
        List<String> relaxed = new ArrayList<>();
        for (int v : t.neighbours(src)) { dist[v] = t.cost[src][v]; prev[v] = src; relaxed.add(Json.obj("v", v, "old", null, "new", dist[v], "via", src)); }
        steps.add(step(0, src, order, relaxed, "Initialisation: N' = {" + t.names[src] + "}. Every direct neighbour gets D(v) = c(" + t.names[src] + ",v); everything else is ∞."));
        for (int k = 1; k < n; k++) {
            int w = -1;
            for (int v = 0; v < n; v++) if (!done[v] && dist[v] < Topo.NONE && (w < 0 || dist[v] < dist[w])) w = v;
            if (w < 0) break;                                                     // the rest is unreachable
            done[w] = true; order.add(w);
            relaxed = new ArrayList<>();
            StringBuilder why = new StringBuilder("Pick the unsettled router with the smallest D: " + t.names[w] + " (D = " + dist[w] + "). Add it to N'. Then for each neighbour v of " + t.names[w] + " not in N': is D(" + t.names[w] + ") + c(" + t.names[w] + ",v) smaller than D(v)?");
            for (int v : t.neighbours(w)) {
                if (done[v]) continue;
                int alt = dist[w] + t.cost[w][v];
                if (alt < dist[v]) {
                    relaxed.add(Json.obj("v", v, "old", dist[v] >= Topo.NONE ? null : dist[v], "new", alt, "via", w));
                    dist[v] = alt; prev[v] = w;
                } else relaxed.add(Json.obj("v", v, "old", dist[v], "new", dist[v], "via", prev[v], "kept", true, "tried", alt));
            }
            steps.add(step(k, w, order, relaxed, why.toString()));
        }
    }

    private String step(int k, int added, List<Integer> order, List<String> relaxed, String why) {
        List<String> d = new ArrayList<>(), p = new ArrayList<>();
        for (int v = 0; v < t.n(); v++) { d.add(dist[v] >= Topo.NONE ? "null" : String.valueOf(dist[v])); p.add(String.valueOf(prev[v])); }
        return Json.obj("step", k, "added", added, "nPrime", Json.raw(order.toString()), "dist", Json.raw("[" + String.join(",", d) + "]"),
            "prev", Json.raw("[" + String.join(",", p) + "]"), "relaxed", Json.raw(Json.arr(relaxed)), "why", why);
    }

    /** First hop on the shortest path from src to d (what goes in the forwarding table). */
    public int firstHop(int d) {
        if (d == src || prev[d] < 0) return -1;
        int v = d; while (prev[v] != src) v = prev[v];
        return v;
    }

    public List<Integer> path(int d) {
        List<Integer> p = new ArrayList<>(); if (prev[d] < 0 && d != src) return p;
        for (int v = d; v >= 0; v = v == src ? -1 : prev[v]) p.add(0, v);
        return p;
    }

    public String json() {
        List<String> table = new ArrayList<>();
        for (int d = 0; d < t.n(); d++) if (d != src)
            table.add(Json.obj("dest", d, "cost", dist[d] >= Topo.NONE ? null : dist[d], "next", firstHop(d), "path", Json.raw(path(d).toString())));
        return Json.obj("source", src, "steps", Json.raw(Json.arr(steps)), "table", Json.raw(Json.arr(table)));
    }
}

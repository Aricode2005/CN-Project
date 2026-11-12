package route.sim;

import java.util.ArrayList;
import java.util.List;
import route.core.Json;

/** A small network: routers with drawing positions, and weighted links that can change cost or fail. */
public final class Topo {

    public static final int NONE = Integer.MAX_VALUE / 4;

    public final String id, title;
    public final String[] names;
    public final int[][] pos;
    public final int[][] cost;          // cost[a][b] = link cost, NONE if no (working) link
    public final int[] as;              // AS number per router (for the BGP view)

    public Topo(String id, String title, String[] names, int[][] pos) {
        this.id = id; this.title = title; this.names = names; this.pos = pos;
        int n = names.length; cost = new int[n][n]; as = new int[n];
        for (int[] r : cost) java.util.Arrays.fill(r, NONE);
        for (int i = 0; i < n; i++) as[i] = 100 * (i + 1);
    }

    public int n() { return names.length; }
    public int idx(String name) { for (int i = 0; i < names.length; i++) if (names[i].equals(name)) return i; throw new IllegalArgumentException("no router " + name); }
    public Topo link(String a, String b, int c) { int i = idx(a), j = idx(b); cost[i][j] = cost[j][i] = c; return this; }
    public boolean up(int a, int b) { return cost[a][b] < NONE; }
    public List<Integer> neighbours(int a) { List<Integer> l = new ArrayList<>(); for (int b = 0; b < n(); b++) if (b != a && up(a, b)) l.add(b); return l; }

    public Topo copy() {
        Topo t = new Topo(id, title, names.clone(), pos);
        for (int i = 0; i < n(); i++) t.cost[i] = cost[i].clone();
        System.arraycopy(as, 0, t.as, 0, as.length);
        return t;
    }

    public String json() {
        List<String> nodes = new ArrayList<>(), links = new ArrayList<>();
        for (int i = 0; i < n(); i++) nodes.add(Json.obj("name", names[i], "x", pos[i][0], "y", pos[i][1], "as", as[i], "net", route.wire.Rip.ip(route.wire.Rip.network(i)) + "/24"));
        for (int i = 0; i < n(); i++) for (int j = i + 1; j < n(); j++) if (up(i, j)) links.add(Json.obj("a", i, "b", j, "cost", cost[i][j]));
        return Json.obj("id", id, "title", title, "nodes", Json.raw(Json.arr(nodes)), "links", Json.raw(Json.arr(links)));
    }

    // ------------------------------------------------------------------ the lab networks
    /** The six-router network from Kurose & Ross (Figure 5.3): the standard Dijkstra example. */
    public static Topo six() {
        return new Topo("six", "Six routers (the textbook network)", new String[] { "u", "v", "w", "x", "y", "z" },
            new int[][] { { 70, 225 }, { 230, 110 }, { 430, 110 }, { 230, 345 }, { 430, 345 }, { 590, 225 } })
            .link("u", "v", 2).link("u", "x", 1).link("u", "w", 5).link("v", "x", 2).link("v", "w", 3)
            .link("x", "w", 3).link("x", "y", 1).link("w", "y", 1).link("w", "z", 5).link("y", "z", 2);
    }
    /** Kurose & Ross Figure 5.7: good news / bad news. */
    public static Topo three() {
        return new Topo("three", "Three routers (link-cost change)", new String[] { "x", "y", "z" }, new int[][] { { 110, 300 }, { 330, 80 }, { 550, 300 } })
            .link("x", "y", 4).link("y", "z", 1).link("x", "z", 50);
    }
    /** A – B – C in a line: the two-router count to infinity when B–C fails. */
    public static Topo line() {
        return new Topo("line", "Three routers in a line", new String[] { "A", "B", "C" }, new int[][] { { 100, 200 }, { 330, 200 }, { 560, 200 } })
            .link("A", "B", 1).link("B", "C", 1);
    }
    /** A, B, C in a triangle, D hanging off C: the case split horizon cannot save. */
    public static Topo triangle() {
        Topo t = new Topo("triangle", "Triangle + stub (A, B, C, D)", new String[] { "A", "B", "C", "D" }, new int[][] { { 110, 90 }, { 110, 320 }, { 360, 205 }, { 590, 205 } })
            .link("A", "B", 1).link("A", "C", 1).link("B", "C", 1).link("C", "D", 1);
        return t;
    }
    public static Topo byId(String id) {
        switch (id) { case "three": return three(); case "line": return line(); case "triangle": return triangle(); default: return six(); }
    }
}

package route.sim;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import route.core.Hub;
import route.core.Json;
import route.net.Wire;

/**
 * The lab's experiments. Each one opens fresh sockets for its routers, runs, and returns a full JSON trace
 * that the dashboard replays one step at a time with Forward ▶.
 */
public final class Scenarios {
    private Scenarios() { }

    public static final int GENERIC_INF = 999;          // "∞" for the textbook's generic distance vector (link costs above 15)
    private static final Object LOCK = new Object();
    public static volatile boolean lastRealRip, lastRealBgp;

    public static String run(String scn, Map<String, String> q) throws Exception {
        synchronized (LOCK) {
            switch (scn) {
                case "dijkstra": {
                    Topo t = Topo.six();
                    int src = t.idx(q.getOrDefault("src", "u"));
                    return Json.obj("scn", scn, "topo", Json.raw(t.json()), "dijkstra", Json.raw(new Dijkstra(t, src).json()));
                }
                case "bf": {
                    Topo t = Topo.six();
                    try (Wire w = wire(t.n(), false)) {
                        DistanceVector dv = new DistanceVector(t, GENERIC_INF, false, false, w);
                        dv.snapshot("start", "Time 0: each router knows only the cost of its own links. Neighbours' vectors are unknown (∞).", new ArrayList<>(), new ArrayList<>());
                        int r = dv.converge(30);
                        return dvJson(scn, t, dv, GENERIC_INF, -1, r, "Bellman-Ford from a cold start on the six-router network", w);
                    }
                }
                case "costchange": {
                    Topo t = Topo.three();
                    int nc = Integer.parseInt(q.getOrDefault("cost", "60"));
                    boolean poison = "1".equals(q.get("poison"));
                    try (Wire w = wire(t.n(), false)) {
                        DistanceVector dv = settled(t, GENERIC_INF, poison, poison, w);
                        dv.linkEvent(t.idx("x"), t.idx("y"), nc);
                        int r = dv.converge(120);
                        return dvJson(scn, t, dv, GENERIC_INF, t.idx("x"), r, "Link x–y: cost 4 → " + nc + (poison ? " (with poison reverse)" : ""), w);
                    }
                }
                case "count2": {
                    Topo t = Topo.line();
                    boolean split = "1".equals(q.get("split"));
                    try (Wire w = wire(t.n(), false)) {
                        DistanceVector dv = settled(t, 16, split, false, w);
                        dv.linkEvent(t.idx("B"), t.idx("C"), Topo.NONE);
                        int r = dv.converge(40);
                        return dvJson(scn, t, dv, 16, t.idx("C"), r, "RIP, link B–C fails" + (split ? " (split horizon on)" : ""), w);
                    }
                }
                case "count3": {
                    Topo t = Topo.triangle();
                    boolean split = !"0".equals(q.get("split")), poison = "1".equals(q.get("poison"));
                    try (Wire w = wire(t.n(), false)) {
                        DistanceVector dv = settled(t, 16, split, poison, w);
                        dv.linkEvent(t.idx("C"), t.idx("D"), Topo.NONE);
                        int r = dv.converge(40);
                        return dvJson(scn, t, dv, 16, t.idx("D"), r, "RIP, link C–D fails" + (poison ? " (split horizon + poison reverse)" : split ? " (split horizon)" : " (no split horizon)"), w);
                    }
                }
                case "ospf": {
                    Topo t = Topo.byId(q.getOrDefault("topo", "triangle"));
                    String[] l = q.getOrDefault("link", t.id.equals("six") ? "x-y" : "C-D").split("-");
                    int watch = t.idx(q.getOrDefault("watch", t.id.equals("six") ? "z" : "D"));
                    try (Wire w = wire(t.n(), false)) {
                        LinkState ls = new LinkState(t, w, watch);
                        ls.snapshot("start", "Before the failure: every router holds the same LSDB (one Router-LSA per router, sequence 0x80000001) and has run Dijkstra on it.", new ArrayList<>());
                        ls.linkEvent(t.idx(l[0]), t.idx(l[1]), Topo.NONE);
                        int r = ls.converge(20);
                        Hub.I.event("OSPF", "flooding finished in " + r + " rounds, " + ls.messages + " LS Update packets");
                        return Json.obj("scn", scn, "topo", Json.raw(t.json()), "watch", watch, "rounds", Json.raw(Json.arr(ls.rounds)), "messages", ls.messages, "converged", r,
                            "spf", Json.raw(ls.spf(0)), "wire", Json.raw(wireJson(w)), "title", "OSPF, link " + l[0] + "–" + l[1] + " fails");
                    }
                }
                case "bgp": {
                    Topo t = Topo.triangle();
                    try (Wire w = wire(t.n(), true)) {
                        PathVector pv = new PathVector(t, w, t.idx("D"));
                        pv.open();
                        int r1 = pv.converge(10);
                        int phase2 = pv.rounds.size();
                        pv.linkEvent(t.idx("C"), t.idx("D"));
                        int r2 = pv.converge(20);
                        Hub.I.event("BGP", "announcement converged in " + r1 + " rounds; after the failure, " + r2 + " rounds");
                        return Json.obj("scn", scn, "topo", Json.raw(t.json()), "watch", t.idx("D"), "rounds", Json.raw(Json.arr(pv.rounds)), "messages", pv.messages,
                            "converged1", r1, "converged2", r2, "failAt", phase2, "wire", Json.raw(wireJson(w)), "title", "BGP, link C–D fails");
                    }
                }
                default: throw new IllegalArgumentException("unknown scenario " + scn);
            }
        }
    }

    /** A DV network that has already converged; its trace starts at that settled state (round 0). */
    static DistanceVector settled(Topo t, int inf, boolean split, boolean poison, Wire w) throws Exception {
        DistanceVector dv = new DistanceVector(t, inf, split, poison, w);
        dv.converge(60);
        dv.rounds.clear(); dv.roundNo = 0; dv.messages = 0;
        dv.snapshot("start", "Before the change: the network has converged; every router has a correct table.", new ArrayList<>(), new ArrayList<>());
        return dv;
    }

    private static Wire wire(int n, boolean bgp) throws Exception {
        Wire w = new Wire(n, bgp);
        if (!bgp) lastRealRip = w.realRipPort; else lastRealBgp = w.realBgpPort;
        return w;
    }

    private static String wireJson(Wire w) {
        return Json.obj("datagrams", w.datagrams, "tcp", w.tcpMessages, "bytes", w.bytes, "rip520", w.realRipPort, "bgp179", w.realBgpPort);
    }

    private static String dvJson(String scn, Topo t, DistanceVector dv, int inf, int watch, int rounds, String title, Wire w) {
        return Json.obj("scn", scn, "topo", Json.raw(t.json()), "inf", inf, "watch", watch, "split", dv.split, "poison", dv.poison, "rounds", Json.raw(Json.arr(dv.rounds)),
            "messages", dv.messages, "converged", rounds, "title", title, "wire", Json.raw(wireJson(w)));
    }
}

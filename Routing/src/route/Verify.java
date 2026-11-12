package route;

import java.util.ArrayList;
import java.util.List;
import route.net.Wire;
import route.sim.Dijkstra;
import route.sim.DistanceVector;
import route.sim.LinkState;
import route.sim.PathVector;
import route.sim.Topo;
import route.wire.Bgp;
import route.wire.Ospf;
import route.wire.Rip;

/** Automated checks ("run.bat --verify"): the algorithms give the textbook answers, and the packets are well-formed. */
final class Verify {

    private static int pass, fail;
    private static void check(String name, boolean ok, String detail) {
        if (ok) pass++; else fail++;
        System.out.printf("  [%s] %-72s %s%n", ok ? "PASS" : "FAIL", name, detail == null ? "" : detail);
    }
    interface T { void run() throws Exception; }
    private static void test(String name, T t) { try { t.run(); } catch (Exception e) { e.printStackTrace(); check(name, false, e.getClass().getSimpleName() + ": " + e.getMessage()); } }

    static int run() {
        System.out.println("\n--- Dijkstra (link state) on the six-router network ------------------------------");
        test("dijkstra", () -> {
            Topo t = Topo.six(); Dijkstra d = new Dijkstra(t, t.idx("u"));
            int[] want = { 0, 2, 3, 1, 2, 4 };                // u v w x y z, Kurose & Ross Table 5.1
            check("D(v)=2, D(w)=3, D(x)=1, D(y)=2, D(z)=4 from u (the textbook table)", java.util.Arrays.equals(d.dist, want), java.util.Arrays.toString(d.dist));
            check("forwarding table of u: v via v, every other router via x", d.firstHop(t.idx("v")) == t.idx("v") && d.firstHop(t.idx("w")) == t.idx("x") && d.firstHop(t.idx("z")) == t.idx("x"), "");
            check("shortest path u → z is u x y z", d.path(t.idx("z")).toString().equals("[0, 3, 4, 5]"), d.path(t.idx("z")).toString());
            check("one step per router: N' grows from {u} to all six", d.steps.size() == 6, d.steps.size() + " steps");
        });

        System.out.println("\n--- Bellman-Ford (distance vector) ---------------------------------------------");
        test("bf", () -> {
            Topo t = Topo.six();
            try (Wire w = new Wire(t.n(), false)) {
                DistanceVector dv = new DistanceVector(t, 999, false, false, w);
                int r = dv.converge(30);
                boolean same = true;
                for (int s = 0; s < t.n(); s++) { Dijkstra d = new Dijkstra(t, s); for (int x = 0; x < t.n(); x++) if (dvDist(dv, s, x) != d.dist[x]) same = false; }
                check("cold start converges, and every distance equals Dijkstra's", same && r <= 6, r + " rounds");
                check("every vector crossed a real UDP socket as a RIPv2 response", w.datagrams == dv.messages && w.datagrams > 0, w.datagrams + " datagrams" + (w.realRipPort ? " on port 520" : " (port 520 busy: ephemeral ports)"));
            }
        });

        System.out.println("\n--- good news travels fast, bad news travels slowly ------------------------------");
        test("costchange", () -> {
            Topo t = Topo.three(); int x = t.idx("x"), y = t.idx("y"), z = t.idx("z");
            DistanceVector g = settledDv(t, 999, false, false);
            g.linkEvent(x, y, 1); int rg = g.converge(50);
            check("good news (x–y 4 → 1): converged in ≤ 3 rounds, D_y(x)=1, D_z(x)=2", rg <= 3 && dvDist(g, y, x) == 1 && dvDist(g, z, x) == 2, rg + " rounds");
            Topo t2 = Topo.three();
            DistanceVector b = settledDv(t2, 999, false, false);
            b.linkEvent(x, y, 60); int rb = b.converge(200);
            check("bad news (x–y 4 → 60): y and z bounce for dozens of rounds (≥ 40)", rb >= 40, rb + " rounds");
            check("… and finally settle on D_z(x)=50 (direct), D_y(x)=51 (via z)", dvDist(b, z, x) == 50 && dvDist(b, y, x) == 51, "");
            check("… with a y ↔ z routing loop along the way", anyLoop(b), "");
            Topo t3 = Topo.three();
            DistanceVector p = settledDv(t3, 999, true, true);
            p.linkEvent(x, y, 60); int rp = p.converge(200);
            check("poison reverse fixes this 3-router case: ≤ 3 rounds, no loop", rp <= 3 && !anyLoop(p) && dvDist(p, z, x) == 50, rp + " rounds");
        });

        System.out.println("\n--- count to infinity (RIP, ∞ = 16) ----------------------------------------------");
        test("count2", () -> {
            Topo t = Topo.line(); int a = t.idx("A"), b = t.idx("B"), c = t.idx("C");
            DistanceVector dv = settledDv(t, 16, false, false);
            dv.linkEvent(b, c, Topo.NONE); int r = dv.converge(40);
            check("two routers: A and B count up to 16 before giving C up", r >= 10 && dvDist(dv, a, c) == 16 && dvDist(dv, b, c) == 16, r + " rounds");
            check("… and point at each other (loop A ↔ B) while counting", anyLoop(dv), "");
            Topo t2 = Topo.line();
            DistanceVector sh = settledDv(t2, 16, true, false);
            sh.linkEvent(b, c, Topo.NONE); int r2 = sh.converge(40);
            check("split horizon: A never told B about C, so B gives up at once (≤ 2 rounds)", r2 <= 2 && !anyLoop(sh) && dvDist(sh, a, c) == 16, r2 + " rounds");
        });
        test("count3", () -> {
            Topo t = Topo.triangle(); int d = t.idx("D");
            DistanceVector dv = settledDv(t, 16, true, true);
            dv.linkEvent(t.idx("C"), d, Topo.NONE); int r = dv.converge(40);
            check("three routers: split horizon + poison reverse STILL count to 16", r >= 10 && dvDist(dv, t.idx("A"), d) == 16, r + " rounds");
            check("… a loop forms (A ⇄ B), then the stale route keeps circling A → B → C", anyLoop(dv), "");
        });

        System.out.println("\n--- the same failure with link state (OSPF) --------------------------------------");
        test("ospf", () -> {
            Topo t = Topo.triangle();
            try (Wire w = new Wire(t.n(), false)) {
                LinkState ls = new LinkState(t, w, t.idx("D"));
                ls.linkEvent(t.idx("C"), t.idx("D"), Topo.NONE);
                int r = ls.converge(20);
                check("flooding ends within 3 rounds", r <= 3, r + " rounds, " + ls.messages + " LS Updates");
                check("every LS Update passed the OSPF checksum and the LSA Fletcher checksum", w.datagrams == ls.messages, w.datagrams + " datagrams parsed");
                String spf = ls.spf(t.idx("A"));
                check("A's Dijkstra: D unreachable, B and C at cost 1, no counting", spf.contains("\"dest\":3,\"cost\":null") && spf.contains("\"dest\":1,\"cost\":1"), "");
            }
        });

        System.out.println("\n--- the same failure with path vector (BGP) --------------------------------------");
        test("bgp", () -> {
            Topo t = Topo.triangle();
            try (Wire w = new Wire(t.n(), true)) {
                PathVector pv = new PathVector(t, w, t.idx("D"));
                pv.open();
                int r1 = pv.converge(10);
                String s1 = pv.rounds.get(pv.rounds.size() - 1);
                check("announcement converges: A and B reach 10.4.0.0/16 via [300 400]", r1 <= 4 && s1.contains("\"best\":[300, 400]"), r1 + " rounds");
                pv.linkEvent(t.idx("C"), t.idx("D"));
                int r2 = pv.converge(20);
                String all = String.join("", pv.rounds);
                check("after C–D fails: converged in ≤ 4 rounds (RIP needed ~15)", r2 <= 4, r2 + " rounds");
                check("a router rejected a path because it saw its own AS in it", all.contains("\"loop\":true"), "");
                String last = pv.rounds.get(pv.rounds.size() - 1);
                check("finally nobody but D has a route: no counting, no stale loop", !last.contains("\"best\":[") || last.indexOf("\"best\":[") == last.indexOf("\"best\":[]"), "");
                check("BGP messages went over real TCP sessions", w.tcpMessages > 0, w.tcpMessages + " messages" + (w.realBgpPort ? " on port 179" : " (port 179 busy: ephemeral ports)"));
            }
        });

        System.out.println("\n--- packet formats ----------------------------------------------------------------");
        test("formats", () -> {
            byte[] r = Rip.response(List.of(new Rip.Entry(0, 1), new Rip.Entry(2, 16)));
            check("RIPv2 response: 4-byte header + 20 bytes per route, command 2, version 2", r.length == 44 && r[0] == 2 && r[1] == 2 && Rip.parse(r).get(1).metric == 16, r.length + " bytes");
            byte[] lsa = Ospf.lsa(new Ospf.Lsa(0, Ospf.INITIAL_SEQ, new int[][] { { 1, 1 }, { 2, 5 } }));
            check("Router-LSA: 20-byte header + 4 + 12 per link, Fletcher checksum verifies", lsa.length == 48 && Ospf.fletcherOk(lsa), String.format("checksum 0x%02x%02x", lsa[16] & 0xff, lsa[17] & 0xff));
            byte[] u = Ospf.update(0, List.of(new Ospf.Lsa(0, Ospf.INITIAL_SEQ, new int[][] { { 1, 1 } })));
            check("OSPF packet checksum (one's complement) verifies", Ospf.ipChecksum(u) == 0, "");
            byte[] up = Bgp.update(List.of(200, 300, 400), Rip.network(1));
            Bgp.Update pu = Bgp.parseUpdate(up);
            check("BGP UPDATE: 16 × 0xFF marker, type 2, AS_PATH round-trips", up[0] == (byte) 0xff && Bgp.type(up) == 2 && pu.path.equals(List.of(200, 300, 400)) && !pu.withdraw, up.length + " bytes");
            byte[] wd = Bgp.update(null, 0);
            check("BGP withdrawal: withdrawn-routes field, no attributes, 26 bytes", Bgp.parseUpdate(wd).withdraw && wd.length == 26, "");
            check("BGP OPEN is 29 bytes, KEEPALIVE 19", Bgp.open(100, 1).length == 29 && Bgp.keepalive().length == 19, "");
        });

        System.out.printf("%n  %d passed, %d failed%n", pass, fail);
        return fail;
    }

    static int dvDist(DistanceVector dv, int x, int d) { return dv.dist(x, d); }
    static boolean anyLoop(DistanceVector dv) { for (String r : dv.rounds) if (!r.contains("\"loops\":[]")) return true; return false; }
    static DistanceVector settledDv(Topo t, int inf, boolean split, boolean poison) throws Exception {
        DistanceVector dv = new DistanceVector(t, inf, split, poison, null);
        dv.converge(60); dv.rounds.clear(); dv.roundNo = 0;
        return dv;
    }
}

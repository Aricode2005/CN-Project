package route;

import java.io.File;
import java.util.Arrays;
import route.core.Hub;
import route.dashboard.DashboardServer;
import route.net.Wire;

/**
 * JU Routing Lab: Dijkstra / link state (OSPF), Bellman-Ford / distance vector (RIP) and path vector (BGP),
 * with the classic instability cases (count to infinity with 2 and 3 routers) and how BGP's AS_PATH avoids them.
 *
 *   routers   127.0.0.20 … 127.0.0.25   RIP on UDP 520, OSPF-in-UDP on 8900, BGP on TCP 179 (real ports when free)
 *   dashboard http://localhost:8088
 */
public final class Main {

    public static final int HTTP = 8088;

    public static void main(String[] args) throws Exception {
        boolean verify = Arrays.asList(args).contains("--verify");
        System.out.println("==============================================================================");
        System.out.println("   JU ROUTING LAB  -  Dijkstra · Bellman-Ford · RIP · OSPF · BGP                 ");
        System.out.println("==============================================================================");
        Hub.I.quiet = verify;
        if (verify) { int failed = Verify.run(); System.exit(failed == 0 ? 0 : 1); }
        boolean r520, b179;
        try (Wire w = new Wire(6, true)) { r520 = w.realRipPort; b179 = w.realBgpPort; }
        route.sim.Scenarios.lastRealRip = r520; route.sim.Scenarios.lastRealBgp = b179;
        DashboardServer dash = new DashboardServer(HTTP, new File("web"));
        dash.start();
        Hub.I.log("[DASHBOARD] http://localhost:" + HTTP);
        System.out.println();
        System.out.println("  Dashboard ...... http://localhost:" + HTTP);
        System.out.println("  Routers ........ 127.0.0.20 - 127.0.0.25   RIP UDP " + (r520 ? "520" : "(520 busy: ephemeral)") + " · BGP TCP " + (b179 ? "179" : "(179 busy: ephemeral)") + " · OSPF-in-UDP 8900");
        System.out.println("  Wireshark ...... capture on the loopback adapter, display filter:  rip || bgp");
        System.out.println("  Interop test ... python interop_test.py   (an independent Python decoder checks our RIP, OSPF and BGP bytes)");
        System.out.println("  Press Enter to stop.");
        System.in.read();
        dash.stop();
        System.exit(0);
    }
}

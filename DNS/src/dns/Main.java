package dns;

import java.io.File;
import java.util.Arrays;
import dns.core.Hub;
import dns.dashboard.DashboardServer;
import dns.server.Resolver;

/**
 * JU DNS Lab — our own authoritative servers (a 4-level naming tree), a recursive resolver,
 * a dig-style client, a cache-poisoning attacker and a live dashboard.
 *
 *   recursive resolver   127.0.0.1:5300  (and 127.0.0.1:53 when the port is free)
 *   lab root / edu / myuniv / cse   127.0.0.10 / .11 / .12 / .13 : 5300
 *   dashboard            http://localhost:8084     (DHCP 8080, Telnet 8081, ARP 8082, Mail 8083)
 */
public final class Main {

    public static final int HTTP = 8084;

    public static void main(String[] args) throws Exception {
        boolean verify = Arrays.asList(args).contains("--verify");
        System.out.println("==============================================================================");
        System.out.println("   JU DNS LAB  -  RFC 1034 / 1035 · iterative + recursive · cache · poisoning   ");
        System.out.println("==============================================================================");
        Hub.I.quiet = verify;
        Lab lab = new Lab().start();
        Resolver res = new Resolver();
        res.listen("127.0.0.1", Resolver.LAB_PORT);
        boolean on53 = false;
        try { res.listen("127.0.0.1", 53); on53 = true; } catch (Exception e) { Hub.I.log("[DNS] port 53 is busy: the resolver stays on 5300 only"); }

        DashboardServer dash = new DashboardServer(HTTP, lab, res, new File("web"));
        dash.start();
        Hub.I.log("[DASHBOARD] http://localhost:" + HTTP);

        if (verify) {
            int failed = Verify.run(lab, res, on53);
            dash.stop(); lab.stop(); res.stop();
            System.exit(failed == 0 ? 0 : 1);
        }
        System.out.println();
        System.out.println("  Dashboard ...... http://localhost:" + HTTP);
        System.out.println("  Try it ......... nslookup www.cse.myuniv.edu 127.0.0.1" + (on53 ? "" : "   (port 53 busy: add -port=5300)"));
        System.out.println("                   nslookup -type=MX cse.myuniv.edu 127.0.0.1");
        System.out.println("                   nslookup -norecurse www.cse.myuniv.edu 127.0.0.10   (iterative: the lab root only refers)");
        System.out.println("                   nslookup www.cse.myuniv.edu 127.0.0.10              (recursive: the root asks down the chain)");
        System.out.println("  Interop test ... python interop_test.py");
        System.out.println("  Press Enter to stop.");
        System.in.read();
        dash.stop(); lab.stop(); res.stop();
        System.exit(0);
    }
}

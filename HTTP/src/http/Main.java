package http;

import java.io.File;
import java.util.Arrays;
import http.core.Hub;
import http.dashboard.DashboardServer;
import http.link.Link;
import http.proxy.Proxy;
import http.server.Origin;
import http.server.Site;

/**
 * JU HTTP Lab: our own HTTP/1.1 origin server, client, WAN emulator and caching proxy.
 *
 *   origin    127.0.0.1:8800 (and :80 when free)    www.cse.myuniv.edu + intranet.cse.myuniv.edu (virtual hosts)
 *   WAN link  127.0.0.1:8801 → 8800                 adds RTT + bandwidth so connection strategies can be measured
 *   proxy     127.0.0.1:3128                        caching forward proxy (the classic Squid port)
 *   dashboard http://localhost:8087
 */
public final class Main {

    public static final int ORIGIN = 8800, LINK = 8801, PROXY = 3128, HTTP = 8087;

    public static void main(String[] args) throws Exception {
        boolean verify = Arrays.asList(args).contains("--verify");
        System.out.println("==============================================================================");
        System.out.println("   JU HTTP LAB  -  HTTP/1.1 (RFC 9110/9112) · persistent vs not · caching proxy   ");
        System.out.println("==============================================================================");
        Hub.I.quiet = verify;
        Site site = new Site();
        Origin origin = new Origin(site).listen(ORIGIN);
        boolean on80 = false;
        try { origin.listen(80); on80 = true; } catch (Exception e) { Hub.I.log("[ORIGIN] port 80 is busy: the server stays on " + ORIGIN + " only"); }
        Link link = new Link(ORIGIN).listen(LINK);
        Proxy proxy = new Proxy(LINK).listen(PROXY);
        DashboardServer dash = new DashboardServer(HTTP, ORIGIN, LINK, PROXY, on80, origin, link, proxy, new File("web"));
        dash.start();
        Hub.I.log("[DASHBOARD] http://localhost:" + HTTP);
        if (verify) {
            int failed = Verify.run(origin, link, proxy, on80);
            dash.stop(); proxy.stop(); link.stop(); origin.stop();
            System.exit(failed == 0 ? 0 : 1);
        }
        System.out.println();
        System.out.println("  Dashboard ...... http://localhost:" + HTTP);
        System.out.println("  Our web server . http://localhost:" + ORIGIN + "/" + (on80 ? "   and   http://localhost/" : "") + "   (open it in your browser)");
        System.out.println("  Caching proxy .. 127.0.0.1:" + PROXY + "   (set it as your browser's HTTP proxy, or: curl -x 127.0.0.1:" + PROXY + " http://" + Site.WWW + "/news.html)");
        System.out.println("  WAN emulator ... 127.0.0.1:" + LINK + " → " + ORIGIN + "   (RTT " + link.rttMs + " ms, " + link.kbps + " kbit/s)");
        System.out.println("  Users .......... alice/alice123  bob/bob123  subham/ju2026   (login page and /private/)");
        System.out.println("  Interop test ... python interop_test.py   (Python http.client/urllib + curl vs our server and proxy)");
        System.out.println("  Press Enter to stop.");
        System.in.read();
        dash.stop(); proxy.stop(); link.stop(); origin.stop();
        System.exit(0);
    }
}

package boot;

import java.io.File;
import java.util.Arrays;
import boot.bootp.Bootp;
import boot.core.Hub;
import boot.dashboard.DashboardServer;
import boot.rarp.Lan;

/**
 * JU Bootstrap Lab — how a diskless machine learned its IP address before DHCP.
 *
 *   RARP  (RFC 903, 1984)  layer 2, EtherType 0x8035: simulated Ethernet LAN with real frames
 *   BOOTP (RFC 951, 1985)  UDP: server 127.0.0.1:1067 (real 67), relay 2067, client 1068 (real 68)
 *   dashboard               http://localhost:8085   (DHCP 8080, Telnet 8081, ARP 8082, Mail 8083, DNS 8084)
 */
public final class Main {

    public static final int HTTP = 8085;

    public static void main(String[] args) throws Exception {
        boolean verify = Arrays.asList(args).contains("--verify");
        System.out.println("==============================================================================");
        System.out.println("   JU BOOTSTRAP LAB  -  RARP (RFC 903) · BOOTP (RFC 951 / 1542 / 1497)          ");
        System.out.println("==============================================================================");
        Hub.I.quiet = verify;
        Topology topo = new Topology();
        Lan lan = new Lan(topo);
        Bootp bootp = new Bootp(topo);
        bootp.start();
        DashboardServer dash = new DashboardServer(HTTP, topo, lan, bootp, new File("web"));
        dash.start();
        Hub.I.log("[DASHBOARD] http://localhost:" + HTTP);
        if (verify) {
            int failed = Verify.run(topo, lan, bootp);
            dash.stop(); bootp.stop();
            System.exit(failed == 0 ? 0 : 1);
        }
        System.out.println();
        System.out.println("  Dashboard ...... http://localhost:" + HTTP);
        System.out.println("  Interop test ... python interop_test.py   (a BOOTREQUEST built by hand in Python)");
        System.out.println("  Press Enter to stop.");
        System.in.read();
        dash.stop(); bootp.stop();
        System.exit(0);
    }
}

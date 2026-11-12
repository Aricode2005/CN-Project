package campus;

import java.io.File;
import java.util.Arrays;
import javax.net.ServerSocketFactory;

import telnet.server.CampusHooks;
import telnet.server.DeviceConfig;
import telnet.server.VtyPool;
import telnet.tap.WireTap;

/**
 * MAIN PROJECT: ARP + DHCP + Telnet running as one campus LAN (192.168.1.0/24).
 *
 *   DHCP cluster   UDP 6700 (load balancer / relay) + 6701-6703 (nodes)      dashboard http://localhost:8080
 *   Telnet router  TCP 2323 (plain), 9923 (TLS), wire taps 2324 / 9924       dashboard http://localhost:8081
 *   ARP lab        simulated switch: hosts, router JU-Main-R, attacker       dashboard http://localhost:8082
 *   LAN relay      TCP 2325 → 2323 and 9925 → 9923: Telnet sessions that also cross the simulated LAN
 *   Campus story   http://localhost:8089  (one step per Forward)
 *
 * The three modules are compiled together from their own folders; nothing in ARP/ or DHCP/ is changed.
 * Run from the MainProject folder:  run.bat   |   run.bat --verify
 */
public final class Main {

    public static final int HTTP = 8089, ARP_HTTP = 8082;

    public static void main(String[] args) throws Exception {
        boolean verify = Arrays.asList(args).contains("--verify");
        System.out.println("==============================================================================");
        System.out.println("   CN MAIN PROJECT  -  ARP + DHCP + TELNET as one campus LAN (192.168.1.0/24)   ");
        System.out.println("==============================================================================");
        File data = new File("data"); data.mkdirs();
        File dhcpData = new File(data, "dhcp");
        if (dhcpData.exists()) { File[] old = dhcpData.listFiles(); if (old != null) for (File f : old) f.delete(); }   // every run starts with an empty lease database

        // ---- DHCP cluster + ARP LAN, joined by the bus
        Bus bus = new Bus(data);
        bus.quiet = verify;
        arp.dashboard.DashboardServer arpDash = new arp.dashboard.DashboardServer(ARP_HTTP, bus.sw, bus.hosts, bus.router, bus.attacker, new File("../ARP/web"));
        arpDash.start();

        // ---- Telnet: the router JU-Main-R (192.168.1.1) is the ARP lab's gateway node
        telnet.core.Hub.I.quiet = true;
        DeviceConfig cfg = new DeviceConfig(new File(data, "startup-config.properties"));
        VtyPool pool = new VtyPool(cfg, dhcpData);
        pool.listen(telnet.Main.TELNET, ServerSocketFactory.getDefault(), "telnet");
        new WireTap(telnet.Main.TAP, telnet.Main.TELNET, false).start();
        boolean tls = telnet.Main.ensureKeystore();
        if (tls) { pool.listen(telnet.Main.TLS, telnet.Main.tlsFactory(), "telnets"); new WireTap(telnet.Main.TLS_TAP, telnet.Main.TLS, true).start(); }
        telnet.dashboard.DashboardServer.Ports p = new telnet.dashboard.DashboardServer.Ports();
        p.telnet = telnet.Main.TELNET; p.tap = telnet.Main.TAP; p.tls = tls ? telnet.Main.TLS : 0; p.tlsTap = tls ? telnet.Main.TLS_TAP : 0; p.http = telnet.Main.HTTP;
        telnet.dashboard.DashboardServer telDash = new telnet.dashboard.DashboardServer(p, pool, new File("../Telnet/web"), telnet.Main.KEYSTORE);
        telDash.start();
        CampusHooks.Holder.hooks = bus;                               // the router CLI can now see DHCP and ARP

        // ---- the cable between the admin laptop and the router
        LanRelay plain = new LanRelay(Story.PLAIN_RELAY, telnet.Main.TELNET, false, bus).start();
        LanRelay secure = tls ? new LanRelay(Story.TLS_RELAY, telnet.Main.TLS, true, bus).start() : null;

        Story story = new Story(bus, tls);
        Dashboard dash = new Dashboard(HTTP, bus, story, new File("web"), tls);
        dash.start();

        if (verify) {
            int failed = Verify.run(bus, story, tls);
            dash.stop(); plain.stop(); if (secure != null) secure.stop(); telDash.stop(); pool.shutdown(); arpDash.stop(); bus.shutdown();
            System.exit(failed == 0 ? 0 : 1);
        }

        System.out.println();
        System.out.println("  Campus story ...... http://localhost:" + HTTP + "      <-- start here: one step per Forward");
        System.out.println("  DHCP dashboard .... http://localhost:" + Bus.DHCP_HTTP);
        System.out.println("  Telnet dashboard .. http://localhost:" + telnet.Main.HTTP);
        System.out.println("  ARP dashboard ..... http://localhost:" + ARP_HTTP);
        System.out.println("  Telnet by hand .... telnet 127.0.0.1 " + Story.PLAIN_RELAY + "   (admin / cisco)   then:  show ip dhcp binding | show ip arp | show mac address-table");
        System.out.println("                      conf t  ->  ip arp inspection vlan 1        (this session also crosses the simulated LAN)");
        System.out.println("  Press Enter to stop.");
        System.in.read();
        dash.stop(); plain.stop(); if (secure != null) secure.stop(); telDash.stop(); pool.shutdown(); arpDash.stop(); bus.shutdown();
        System.exit(0);
    }
}

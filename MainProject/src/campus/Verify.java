package campus;

import arp.model.IpAddress;
import arp.model.MacAddress;
import arp.model.SwitchCamEntry;
import dhcp.model.LeaseRecord;

/** End-to-end checks ("run.bat --verify"): the whole story is run, and each cross-module link is asserted. */
final class Verify {

    private static int pass, fail;
    private static void check(String name, boolean ok, String detail) {
        if (ok) pass++; else fail++;
        System.out.printf("  [%s] %-76s %s%n", ok ? "PASS" : "FAIL", name, detail == null ? "" : detail);
    }

    static int run(Bus bus, Story story, boolean tls) {
        try {
            System.out.println("\n--- DHCP gives an address; ARP checks it -------------------------------------------");
            story.forward();                                                    // 1 DORA
            LeaseRecord first = lease(bus, "192.168.1.10");
            check("real DORA over UDP: the cluster leases 192.168.1.10 to the laptop", first != null && first.getMacAddress().equalsIgnoreCase(Bus.ADMIN_MAC), first == null ? "no lease" : first.getState().toString());
            Story.Result r2 = story.forward();                                  // 2 probe → conflict → DECLINE
            Thread.sleep(500);
            LeaseRecord declined = lease(bus, "192.168.1.10");
            check("ARP → DHCP: the probe finds Host-A on .10, the client sends DHCPDECLINE", "alarm".equals(r2.mood) && declined != null && declined.getState() == LeaseRecord.State.DECLINED, declined == null ? "" : declined.getState().toString());
            bus.syncLeases();
            check("after the decline, .10's snooping binding is Host-A's again (not the laptop's)", bus.snooping.isValid(IpAddress.parse("192.168.1.10"), MacAddress.parse("AA:AA:AA:11:11:11")), "");
            story.forward();                                                    // 3 second DORA + clean probe
            check("second lease is a different, conflict-free address", bus.adminIp != null && !bus.adminIp.equals("192.168.1.10"), bus.adminIp);
            check("DHCP → ARP: the lease is in the switch's DHCP-snooping table", bus.snooping.isValid(IpAddress.parse(bus.adminIp), MacAddress.parse(Bus.ADMIN_MAC)), bus.adminIp + " ↔ " + Bus.ADMIN_MAC);

            System.out.println("\n--- ARP resolves the gateway; Telnet manages the router ----------------------------");
            story.forward();                                                    // 4 ARP for the gateway
            MacAddress gw = bus.admin.getArpTable().lookupMac(IpAddress.parse(Bus.GATEWAY));
            check("the laptop's ARP cache maps 192.168.1.1 to the router's MAC", gw != null && gw.equals(bus.router.getNic().getMac()), String.valueOf(gw));
            boolean learned = false;
            for (SwitchCamEntry e : bus.sw.getCamEntries()) if (e.getMac().equals(MacAddress.parse(Bus.ADMIN_MAC)) && e.getPort() == Bus.ADMIN_PORT) learned = true;
            check("the switch learned the laptop's MAC on port 6", learned, "");
            story.forward();                                                    // 5 Telnet session
            String t = bus.lastTranscript;
            check("Telnet → DHCP: 'show ip dhcp binding' on the router lists the live lease", t.contains(bus.adminIp) && t.contains(Bus.ADMIN_NAME), "");
            check("Telnet → ARP: 'show ip arp' on the router lists the laptop", t.contains("Hardware Addr") && t.toUpperCase().contains(Bus.ADMIN_MAC), "");
            check("no interception yet: the attacker's notebook is empty", bus.sniffed().isEmpty(), "");

            System.out.println("\n--- the attack, and the fix that needs all three -----------------------------------");
            story.forward();                                                    // 6 poison
            check("ARP poisoning succeeds while inspection is off", bus.poisoned() && !bus.dai.isEnabled(), "gateway → 66:66:66:66:66:66");
            story.forward();                                                    // 7 sniffed login
            String s = bus.sniffed();
            check("ARP → Telnet: the attacker reads the Telnet user name and password", s.contains("admin") && s.contains("cisco"), s.replace("\n", " / ").trim());
            story.forward();                                                    // 8 enable DAI from the CLI
            check("Telnet → ARP: 'ip arp inspection vlan 1' typed on the router enables DAI", bus.dai.isEnabled(), "");
            check("the forged ARP replies are dropped, using the DHCP bindings", bus.dai.getDroppedCount() > 0 && !bus.poisoned(), bus.dai.getDroppedCount() + " dropped");
            int before = bus.sniffed().length();
            story.forward();                                                    // 9 safe login
            check("the next Telnet login is not intercepted", bus.sniffed().length() == before, "");

            System.out.println("\n--- Telnet over TLS ----------------------------------------------------------------");
            if (tls) {
                Story.Result r10 = story.forward();                             // 10 TLS on a poisoned LAN
                String got = bus.sniffed().substring(before);
                check("on a poisoned LAN, a TLS session leaks only encrypted records", got.contains("TLS record") && !got.contains("cisco") && "ok".equals(r10.mood), got.split("\n").length + " records captured");
                check("inspection is back on at the end", bus.dai.isEnabled(), "");
            } else System.out.println("  (skipped: keytool not available)");

            System.out.println("\n--- repeatable ---------------------------------------------------------------------");
            story.restart();
            story.forward();
            LeaseRecord again = lease(bus, "192.168.1.10");
            check("after Restart the story begins again from an empty lease database", again != null && story.index() == 1 && bus.sniffed().isEmpty(), "");
        } catch (Exception e) {
            e.printStackTrace();
            check("story ran without an exception", false, e.toString());
        }
        System.out.printf("%n  %d passed, %d failed%n", pass, fail);
        return fail;
    }

    private static LeaseRecord lease(Bus bus, String ip) { for (LeaseRecord r : bus.leases()) if (r.getIpAddress().equals(ip)) return r; return null; }
}

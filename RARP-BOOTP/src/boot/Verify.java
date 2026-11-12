package boot;

import java.util.List;
import boot.bootp.Bootp;
import boot.bootp.Packet;
import boot.core.Field;
import boot.rarp.Lan;
import boot.rarp.Rarp;

/** Automated checks ("run.bat --verify"). */
final class Verify {

    private static int pass, fail;
    private static void check(String name, boolean ok, String detail) {
        if (ok) pass++; else fail++;
        System.out.printf("  [%s] %-66s %s%n", ok ? "PASS" : "FAIL", name, detail == null ? "" : detail);
    }
    interface T { void run() throws Exception; }
    private static void test(String name, T t) { try { t.run(); } catch (Exception e) { check(name, false, e.getClass().getSimpleName() + ": " + e.getMessage()); } }

    static int run(Topology topo, Lan lan, Bootp bootp) {
        System.out.println("\n--- RARP frame format (RFC 903) -------------------------------------------------");
        test("rarp-wire", () -> {
            byte[] f = Rarp.frame(Rarp.BROADCAST, "08:00:20:0a:01:01", Rarp.REQUEST, "08:00:20:0a:01:01", "0.0.0.0", "08:00:20:0a:01:01", "0.0.0.0");
            Rarp.Decoded d = Rarp.decode(f);
            check("frame is padded to the 60-byte Ethernet minimum", f.length == 60, f.length + " bytes");
            check("EtherType 0x8035 (RARP), not 0x0806 (ARP)", d.type == 0x8035, String.format("0x%04x", d.type));
            check("op 3 = reverse request; SHA = THA = own MAC; SPA = TPA = 0.0.0.0", d.op == 3 && d.sha.equals(d.tha) && d.spa.equals("0.0.0.0"), "");
            check("RARP payload is 28 bytes, the same layout as ARP", d.fields.stream().filter(x -> x.part.equals("rarp")).mapToInt(x -> x.len).sum() == 28, "");
        });

        System.out.println("\n--- RARP on the simulated LAN -----------------------------------------------------");
        test("rarp-lan", () -> {
            List<Lan.Event> a = lan.boot("WS-1");
            Lan.Event req = a.stream().filter(e -> e.kind.equals("broadcast")).findFirst().get();
            check("request is a broadcast heard by every station on LAN A", req.to.containsAll(List.of("WS-2", "WS-3", "SERVER", "ROUTER")) && !req.to.contains("WS-4"), req.to.toString());
            Lan.Event rep = a.stream().filter(e -> e.kind.equals("unicast")).findFirst().get();
            Rarp.Decoded d = Rarp.decode(rep.frame);
            check("reply is unicast (op 4) with TPA = 10.0.1.21", d.op == 4 && d.dst.equals("08:00:20:0a:01:01") && d.tpa.equals("10.0.1.21"), d.tpa);
            check("WS-1 configured on the first try", a.get(a.size() - 1).kind.equals("done") && a.stream().filter(e -> e.kind.equals("broadcast")).count() == 1, "");
            List<Lan.Event> c = lan.boot("WS-3");
            check("unregistered MAC: server stays silent, 3 tries, then failure", c.stream().filter(e -> e.kind.equals("broadcast")).count() == 3 && c.get(c.size() - 1).kind.equals("fail"), "");
            List<Lan.Event> b = lan.boot("WS-4");
            check("WS-4 on LAN B fails: the router does not forward the broadcast", b.get(b.size() - 1).kind.equals("fail") && b.stream().noneMatch(e -> e.kind.equals("unicast")), "even though the server knows its MAC");
        });

        System.out.println("\n--- BOOTP packet (RFC 951 / 1497) ----------------------------------------------------");
        test("bootp-wire", () -> {
            Packet p = new Packet();
            p.op = Packet.BOOTREPLY; p.xid = 0x12345678L; p.chaddr = "08:00:20:0a:01:01"; p.yiaddr = "10.0.1.21"; p.file = "/tftpboot/x";
            p.options.put(Packet.OPT_MASK, Field.ipBytes("255.255.255.0"));
            byte[] b = p.encode();
            Packet d = Packet.decode(b, b.length);
            check("always 300 bytes", b.length == 300, "");
            check("round trip keeps xid, chaddr, yiaddr, file", d.xid == 0x12345678L && d.chaddr.equals(p.chaddr) && d.yiaddr.equals("10.0.1.21") && d.file.equals("/tftpboot/x"), "");
            check("vendor area starts with the magic cookie 99.130.83.99", (b[236] & 0xFF) == 99 && (b[237] & 0xFF) == 130 && (b[238] & 0xFF) == 83 && (b[239] & 0xFF) == 99, "");
            check("subnet-mask option decoded from the vendor area", "255.255.255.0".equals(Packet.optValue(1, d.options.get(1))), "");
        });

        System.out.println("\n--- BOOTP over UDP -------------------------------------------------------------------");
        test("bootp", () -> {
            Bootp.Result r = bootp.boot("WS-1");
            check("WS-1 (same LAN) gets IP 10.0.1.21 + mask, router, DNS, host name", r.ok && r.ip.equals("10.0.1.21") && r.mask.equals("255.255.255.0") && r.router.equals("10.0.1.1") && r.host.equals("ws1"), r.ip + " " + r.host);
            check("…and a boot server + boot file name (for TFTP)", r.server.equals("10.0.1.5") && r.file.endsWith("ws1.img"), r.file);
            Bootp.Result b = bootp.boot("WS-4");
            check("WS-4 (other LAN) succeeds through the relay agent", b.ok && b.ip.equals("10.0.2.24") && b.router.equals("10.0.2.1"), b.ip);
            boolean giaddr = b.steps.stream().anyMatch(s -> s.contains("\"kind\":\"forward\"") && s.contains("giaddr") && s.contains("10.0.2.1"));
            check("relay set giaddr = 10.0.2.1 and hops = 1", giaddr && b.steps.stream().anyMatch(s -> s.contains("hops") && s.contains("1 (incremented")), "");
            Bootp.Result u = bootp.boot("WS-3");
            check("unregistered MAC: no reply, 3 tries (BOOTP is static)", !u.ok && u.attempts == 3, "");
            bootp.relayOn = false;
            Bootp.Result n = bootp.boot("WS-4");
            bootp.relayOn = true;
            check("relay agent switched off: WS-4 fails, just like RARP", !n.ok, "");
        });

        System.out.println("\n================================================================================");
        System.out.printf("  %d passed, %d failed%n", pass, fail);
        System.out.println("================================================================================");
        return fail;
    }
}

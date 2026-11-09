package dns;

import java.util.ArrayList;
import java.util.List;
import dns.attack.Poisoner;
import dns.client.DnsClient;
import dns.server.Resolver;
import dns.wire.Message;
import dns.wire.Message.RR;

/** Automated end-to-end checks ("run.bat --verify"): real packets between our client, resolver and servers. */
final class Verify {

    private static int pass, fail;
    private static void check(String name, boolean ok, String detail) {
        if (ok) pass++; else fail++;
        System.out.printf("  [%s] %-68s %s%n", ok ? "PASS" : "FAIL", name, detail == null ? "" : detail);
    }
    interface T { void run() throws Exception; }
    private static void test(String name, T t) { try { t.run(); } catch (Exception e) { check(name, false, e.getClass().getSimpleName() + ": " + e.getMessage()); } }

    static String data(Message m, int type) { for (RR r : m.an) if (r.type == type) return r.data; return ""; }

    static int run(Lab lab, Resolver res, boolean on53) {
        System.out.println("\n--- wire format ----------------------------------------------------------------");
        test("wire", () -> {
            Message m = Message.query(0x1234, "www.cse.myuniv.edu", Message.A, true);
            Message r = m.reply(); r.aa = true;
            r.an.add(new RR("www.cse.myuniv.edu", Message.A, 120, "192.168.151.4"));
            r.ns.add(new RR("cse.myuniv.edu", Message.NS, 300, "dns.cse.myuniv.edu"));
            byte[] b = r.encode();
            List<Message.Field> f = new ArrayList<>();
            Message d = Message.decode(b, b.length, f);
            check("encode → decode round trip keeps ID, flags and records", d.id == 0x1234 && d.qr && d.aa && d.rd && "192.168.151.4".equals(d.an.get(0).data) && "dns.cse.myuniv.edu".equals(d.ns.get(0).data), b.length + " bytes");
            long ptrs = f.stream().filter(x -> x.kind.equals("ptr")).count();
            check("name compression: repeated names become 2-byte pointers (0xC0..)", ptrs >= 2, ptrs + " pointers");
            check("header is exactly 12 bytes: ID, flags, 4 counts", f.get(0).off == 0 && f.get(5).off == 10, "");
        });

        System.out.println("\n--- authoritative servers (asked directly, RD=0) ---------------------------------");
        test("auth", () -> {
            Message a = DnsClient.query("127.0.0.13", 5300, "www.cse.myuniv.edu", Message.A, false, false, 3000).msg;
            check("cse server: www.cse.myuniv.edu A 192.168.151.4, AA=1", a.aa && "192.168.151.4".equals(data(a, Message.A)), a.summary());
            Message c = DnsClient.query("127.0.0.13", 5300, "web.cse.myuniv.edu", Message.A, false, false, 3000).msg;
            check("CNAME: web → www, and the server adds www's A record", c.an.size() == 2 && c.an.get(0).type == Message.CNAME && "192.168.151.4".equals(data(c, Message.A)), c.summary());
            Message n = DnsClient.query("127.0.0.13", 5300, "nosuch.cse.myuniv.edu", Message.A, false, false, 3000).msg;
            check("NXDOMAIN carries the SOA (for negative caching)", n.rcode == Message.NXDOMAIN && !n.ns.isEmpty() && n.ns.get(0).type == Message.SOA, n.summary());
            Message nd = DnsClient.query("127.0.0.13", 5300, "www.cse.myuniv.edu", Message.MX, false, false, 3000).msg;
            check("NODATA: name exists, type does not → NOERROR, empty answer, SOA", nd.rcode == 0 && nd.an.isEmpty() && nd.aa && !nd.ns.isEmpty(), nd.summary());
            Message root = DnsClient.query("127.0.0.10", 5300, "www.cse.myuniv.edu", Message.A, false, false, 3000).msg;
            check("root: referral to edu. with glue (AA=0, no answer)", !root.aa && root.an.isEmpty() && "edu".equals(root.ns.get(0).name) && "127.0.0.11".equals(root.ar.get(0).data), root.summary());
            Message edu = DnsClient.query("127.0.0.11", 5300, "www.cse.myuniv.edu", Message.A, false, false, 3000).msg;
            check("edu: referral to myuniv.edu.", "myuniv.edu".equals(edu.ns.get(0).name), edu.summary());
            Message ref = DnsClient.query("127.0.0.13", 5300, "www.google.com", Message.A, false, false, 3000).msg;
            check("not my zone → REFUSED", ref.rcode == Message.REFUSED, ref.summary());
            DnsClient.Result big = DnsClient.query("127.0.0.13", 5300, "big.cse.myuniv.edu", Message.TXT, false, false, 3000);
            check("answer > 512 bytes: UDP reply has TC=1, client retries over TCP", big.truncatedFirst && big.tcp && big.msg.an.size() == 1 && big.raw.length > 512, big.raw.length + " bytes over TCP");
            Message mx = DnsClient.query("127.0.0.13", 5300, "cse.myuniv.edu", Message.MX, false, false, 3000).msg;
            check("MX 10 mail.cse.myuniv.edu + its A record as additional", "10 mail.cse.myuniv.edu".equals(data(mx, Message.MX)) && !mx.ar.isEmpty(), mx.summary());
            Message ptr = DnsClient.query("127.0.0.13", 5300, "4.151.168.192.in-addr.arpa", Message.PTR, false, false, 3000).msg;
            check("reverse lookup: 192.168.151.4 → www.cse.myuniv.edu (PTR)", "www.cse.myuniv.edu".equals(data(ptr, Message.PTR)), ptr.summary());
        });

        System.out.println("\n--- recursive resolver -----------------------------------------------------------");
        test("resolver", () -> {
            res.cache.flush(); res.secure = true;
            Resolver.Result r = res.resolve("www.cse.myuniv.edu", Message.A, true);
            long hops = r.steps.stream().filter(s -> !s.cached).count();
            check("iterative walk root → edu → myuniv → cse (4 servers)", hops == 4 && r.rcode == 0 && "192.168.151.4".equals(r.answers.get(0).data), hops + " servers, " + Math.round(r.ms) + " ms");
            check("steps: 3 referrals then an authoritative answer", "REFERRAL".equals(r.steps.get(0).kind) && "REFERRAL".equals(r.steps.get(2).kind) && "ANSWER".equals(r.steps.get(3).kind), "");
            Resolver.Result again = res.resolve("www.cse.myuniv.edu", Message.A, true);
            check("second lookup: straight from the cache, no server asked", again.fromCache && again.ms < r.ms, String.format("%.2f ms vs %.1f ms", again.ms, r.ms));
            check("cached record carries the remaining TTL (≤ 120)", again.answers.get(0).ttl <= 120, "TTL " + again.answers.get(0).ttl);
            Resolver.Result ftp = res.resolve("ftp.cse.myuniv.edu", Message.A, true);
            check("sibling name: starts at the cached cse servers (1 hop)", ftp.steps.size() == 1 && "192.168.151.5".equals(ftp.answers.get(0).data), ftp.steps.get(0).detail);
            Resolver.Result nx = res.resolve("nosuch.cse.myuniv.edu", Message.A, true);
            Resolver.Result nx2 = res.resolve("nosuch.cse.myuniv.edu", Message.A, true);
            check("NXDOMAIN, then a cached negative answer", nx.rcode == Message.NXDOMAIN && nx2.fromCache && nx2.rcode == Message.NXDOMAIN, "");
            Resolver.Result w = res.resolve("web.cse.myuniv.edu", Message.A, true);
            check("CNAME chain web → www returned to the client", w.answers.size() == 2 && w.answers.get(0).type == Message.CNAME, "");
            Message stub = DnsClient.query("127.0.0.1", 5300, "dhcp.cse.myuniv.edu", Message.A, true, false, 5000).msg;
            check("stub query to the resolver over UDP (RD=1 → RA=1)", stub.ra && "192.168.151.2".equals(data(stub, Message.A)), stub.summary());
            if (on53) {
                Message s53 = DnsClient.query("127.0.0.1", 53, "ftp.cse.myuniv.edu", Message.A, true, false, 5000).msg;
                check("resolver also on the real DNS port 53", "192.168.151.5".equals(data(s53, Message.A)), "");
            }
            res.cache.flush();
            Resolver.Result rv = res.resolve("4.151.168.192.in-addr.arpa", Message.PTR, true);
            check("reverse lookup through the resolver (root delegates the in-addr.arpa zone)", rv.rcode == 0 && "www.cse.myuniv.edu".equals(rv.answers.get(0).data), rv.steps.size() + " servers");
        });

        System.out.println("\n--- recursive resolution (each server asks the next) -----------------------------");
        test("recursive", () -> {
            res.cache.flush();
            Resolver.Result r = res.resolveRecursive("www.cse.myuniv.edu", Message.A);
            check("one RD=1 query to the root returns the final answer", r.rcode == 0 && "192.168.151.4".equals(r.answers.get(r.answers.size() - 1).data), Math.round(r.ms) + " ms");
            check("chain root → edu → myuniv → cse, each asked by the one above", r.steps.size() == 4 && r.steps.get(3).depth == 3 && "dns.cse.myuniv.edu".equals(r.steps.get(3).server) && "ANSWER".equals(r.steps.get(3).kind),
                    r.steps.stream().map(s -> s.server).reduce((a, b) -> a + " → " + b).orElse(""));
            check("the root stays busy for the whole chain (its time ≥ the time below it)", r.steps.get(0).ms >= r.steps.get(1).ms, r.steps.get(0).ms + " ms vs " + r.steps.get(1).ms + " ms");
            Message viaRoot = DnsClient.query("127.0.0.10", 5300, "ftp.cse.myuniv.edu", Message.A, true, false, 5000).msg;
            check("asking the root directly with RD=1 → RA=1 and the answer", viaRoot.ra && "192.168.151.5".equals(data(viaRoot, Message.A)), viaRoot.summary());
            dns.server.AuthServer.recursion = false;
            Message ref = DnsClient.query("127.0.0.10", 5300, "ftp.cse.myuniv.edu", Message.A, true, false, 5000).msg;
            Resolver.Result off = res.resolveRecursive("dhcp.cse.myuniv.edu", Message.A);
            dns.server.AuthServer.recursion = true;
            check("recursion switched off (like real roots): RA=0 and only a referral", !ref.ra && ref.an.isEmpty() && !ref.ns.isEmpty() && off.steps.get(0).kind.startsWith("REFERRAL"), ref.summary());
            res.recursiveUpstream = true; res.cache.flush();
            Message stub = DnsClient.query("127.0.0.1", 5300, "dhcp.cse.myuniv.edu", Message.A, true, false, 5000).msg;
            res.recursiveUpstream = false;
            check("resolver set to recursive upstream still answers stubs", "192.168.151.2".equals(data(stub, Message.A)), "");
        });

        System.out.println("\n--- cache poisoning race ---------------------------------------------------------");
        test("attack", () -> {
            String v = Poisoner.run(res, lab.cseServer, false);
            check("VULNERABLE resolver (fixed port, no checks): forged answer cached", v.contains("\"poisoned\":true"), v.replaceAll(".*\"sent\":(\\d+).*\"sprayMs\":(\\d+).*", "$1 forgeries in $2 ms"));
            res.cache.flush();
            String s = Poisoner.run(res, lab.cseServer, true);
            check("SECURE resolver (random port + ID + 0x20 + source check): not poisoned", s.contains("\"poisoned\":false") && s.contains("\"cached\":\"192.168.151.20\""), s.replaceAll(".*\"rejected\":(\\d+).*", "$1 forgeries rejected"));
        });

        System.out.println("\n================================================================================");
        System.out.printf("  %d passed, %d failed%n", pass, fail);
        System.out.println("================================================================================");
        return fail;
    }
}

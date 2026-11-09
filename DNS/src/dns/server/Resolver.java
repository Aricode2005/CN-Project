package dns.server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import dns.core.Hub;
import dns.core.Json;
import dns.wire.Message;
import dns.wire.Message.RR;
import dns.zone.Zone;

/**
 * A recursive resolver (what your ISP or 8.8.8.8 runs). Stub resolvers send it one recursive query
 * (RD=1); it does the work with iterative queries (RD=0): root → TLD → … → authoritative server,
 * following referrals and glue, chasing CNAMEs and caching everything for its TTL.
 *
 * Upstream queries can be made the safe way (random source port + random ID + 0x20 random case +
 * source-address check) or the 2008 way (fixed port, nothing else) for the cache-poisoning demo.
 */
public final class Resolver {

    public static final String LAB = "lab", NET = "internet";
    public static final String[][] LAB_ROOTS = {{"a.root-servers.lab", "127.0.0.10"}};
    public static final String[][] NET_ROOTS = {{"a.root-servers.net", "198.41.0.4"}, {"c.root-servers.net", "192.33.4.12"}, {"d.root-servers.net", "199.7.91.13"},
            {"f.root-servers.net", "192.5.5.241"}, {"k.root-servers.net", "193.0.14.129"}, {"l.root-servers.net", "199.7.83.42"}, {"m.root-servers.net", "202.12.27.33"}};
    public static final int LAB_PORT = 5300, VULN_PORT = 5399;

    public final Cache cache = new Cache();
    public volatile boolean secure = true;
    public final AtomicLong queries = new AtomicLong(), upstream = new AtomicLong(), rejected = new AtomicLong(), timeouts = new AtomicLong();
    public volatile String lastAccept = "";
    public volatile int lastUpstreamPort;
    private final SecureRandom rnd = new SecureRandom();
    private final AtomicInteger iterIds = new AtomicInteger(), stubIds = new AtomicInteger();
    private final Object vulnLock = new Object();
    private DatagramSocket vuln;
    public final List<String> listening = new CopyOnWriteArrayList<>();
    /** How the resolver serves stub queries for lab names: false = iterative walk, true = one recursive query to the root. */
    public volatile boolean recursiveUpstream;
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();

    /** Names served by the lab hierarchy on 127.0.0.10-13; everything else goes to the real root servers. */
    public static boolean labName(String n) {
        n = n.toLowerCase();
        return n.equals("myuniv.edu") || n.endsWith(".myuniv.edu") || n.endsWith(".lab") || n.equals("lab") || n.endsWith("151.168.192.in-addr.arpa");
    }
    public static String view(String n) { return labName(n) ? LAB : NET; }
    static int portFor(String ip) { return ip.startsWith("127.") ? LAB_PORT : 53; }

    // ================================================================== trace model
    public static final class Step {
        public final String server, ip, zone, question; public final int depth;
        public String kind = "", detail = ""; public double ms; public boolean aa, tcp, suspicious, cached; public int bytes;
        public final List<String> records = new ArrayList<>();
        public Step(String server, String ip, String zone, String question, int depth) { this.server = server; this.ip = ip; this.zone = zone; this.question = question; this.depth = depth; }
        public String json() {
            List<String> r = new ArrayList<>(); for (String s : records) r.add(Json.str(s));
            return Json.obj("server", server, "ip", ip, "zone", Message.fq(zone), "question", question, "depth", depth, "kind", kind, "detail", detail,
                    "ms", Math.round(ms * 10) / 10.0, "aa", aa, "tcp", tcp, "suspicious", suspicious, "cached", cached, "bytes", bytes, "records", Json.raw("[" + String.join(",", r) + "]"));
        }
    }

    public static final class Result {
        public String name, view, mode = "iterative"; public int type, rcode; public double ms; public boolean fromCache;
        public final List<RR> answers = new ArrayList<>(); public final List<Step> steps = new ArrayList<>();
        public String json() {
            List<String> a = new ArrayList<>(); for (RR r : answers) a.add(r.json());
            List<String> s = new ArrayList<>(); for (Step x : steps) s.add(x.json());
            return Json.obj("name", name, "type", Message.typeName(type), "view", view, "mode", mode, "rcode", Message.rcodeName(rcode), "ms", Math.round(ms * 10) / 10.0,
                    "fromCache", fromCache, "answers", Json.raw("[" + String.join(",", a) + "]"), "steps", Json.raw("[" + String.join(",", s) + "]"));
        }
    }

    private static final class Server { final String host; String ip; boolean lookedUp; Server(String h, String ip) { host = h; this.ip = ip; } }
    private static final class Hop { final int rcode; final String cname; Hop(int r) { rcode = r; cname = null; } Hop(String c) { rcode = 0; cname = c; } }
    private static final class Exchange { Message msg; int bytes; boolean tcp; double ms; String from; }

    // ================================================================== resolution
    public Result resolve(String name, int type, boolean useCache) {
        long t0 = System.nanoTime();
        Result r = new Result();
        r.name = name.toLowerCase(); r.type = type; r.view = view(name);
        r.rcode = resolveInto(r.name, type, r.answers, r.steps, 0, useCache, r.view);
        r.ms = (System.nanoTime() - t0) / 1e6;
        r.fromCache = !r.steps.isEmpty() && r.steps.stream().allMatch(s -> s.cached);
        return r;
    }

    /**
     * Recursive resolution (the textbook's other method): ONE query with RD=1 to the root. The root asks
     * .edu, .edu asks myuniv.edu, myuniv.edu asks cse.myuniv.edu, and the answer is relayed back up the chain.
     * The resolver itself sends a single message; the servers do the work and stay busy until the end.
     */
    public Result resolveRecursive(String name, int type) {
        long t0 = System.nanoTime();
        Result r = new Result();
        r.name = name.toLowerCase(); r.type = type; r.view = view(name); r.mode = "recursive";
        String[] root = LAB.equals(r.view) ? LAB_ROOTS[0] : NET_ROOTS[0];
        int id = rnd.nextInt(65536);
        List<Step> chain = new CopyOnWriteArrayList<>();
        Step s0 = new Step(root[0], root[1], "", r.name + " " + Message.typeName(type), 0);
        s0.kind = "ASKED BY THE RESOLVER";
        chain.add(s0);
        AuthServer.chains.put(id, chain);
        String sid = "rec#" + iterIds.incrementAndGet();
        try {
            byte[] out = Message.query(id, r.name, type, true).encode();
            int port = portFor(root[1]);
            Hub.I.line(new Hub.Line(sid, "DNS", true, String.format("query id=0x%04x %s %s? RD=1 -> %s %s:%d", id, r.name, Message.typeName(type), root[0], root[1], port),
                    "recursive resolution: one query to the root, asking it to do the whole job"));
            Message m;
            try (DatagramSocket s = new DatagramSocket()) {
                s.setSoTimeout(8000);
                s.send(new DatagramPacket(out, out.length, InetAddress.getByName(root[1]), port));
                byte[] buf = new byte[4096];
                while (true) {
                    DatagramPacket p = new DatagramPacket(buf, buf.length);
                    s.receive(p);
                    if (p.getLength() >= 12 && ((buf[0] & 0xFF) << 8 | buf[1] & 0xFF) == id) { m = lower(Message.decode(buf, p.getLength())); break; }
                }
            }
            if (m.tc) m = lower(askTcp(out, InetAddress.getByName(root[1]), port).msg);
            s0.ms = Math.round((System.nanoTime() - t0) / 1e5) / 10.0;
            Hub.I.line(new Hub.Line(sid, "DNS", false, m.summary(), m.ra ? "the root relayed the final answer (RA=1)" : "RA=0: this server refuses to recurse, it only refers you onward"));
            r.rcode = m.rcode;
            if (!m.an.isEmpty()) {
                s0.kind = "RELAYED"; s0.aa = m.aa;
                s0.detail = "the root did not know, so it asked the next server and waited " + s0.ms + " ms for the whole chain below it";
                for (RR a : m.an) { r.answers.add(a); if (s0.records.size() < 8) s0.records.add("AN " + a); }
                List<RR> fin = pick(m.an, r.name, type);
                if (!fin.isEmpty()) cache.put(r.view, r.name, type, fin, root[0] + " (recursive)");
                if (NET.equals(r.view)) { s0.suspicious = true; s0.detail = "INTERCEPTED? Real root servers refuse recursion (RA=0). Something on your network answered in their place."; }
            } else if (!m.ra && !m.ns.isEmpty()) {
                s0.kind = "REFERRAL (RA=0)";
                s0.detail = "this server does not offer recursion: it answered with a referral to " + Message.fq(m.ns.get(0).name) + " instead. Real root servers always do this, which is why resolvers work iteratively.";
                for (RR a : m.ns) if (s0.records.size() < 8) s0.records.add("NS " + a);
            } else { s0.kind = Message.rcodeName(m.rcode); s0.detail = "relayed " + Message.rcodeName(m.rcode); }
        } catch (IOException e) {
            s0.kind = "TIMEOUT"; s0.detail = e.getMessage(); r.rcode = Message.SERVFAIL;
        } finally {
            AuthServer.chains.remove(id);
        }
        r.steps.addAll(chain);
        r.ms = (System.nanoTime() - t0) / 1e6;
        return r;
    }

    private int resolveInto(String name, int type, List<RR> out, List<Step> steps, int depth, boolean useCache, String view) {
        if (depth > 6) return Message.SERVFAIL;
        String n = name;
        for (int chase = 0; chase < 8; chase++) {
            if (useCache) {
                Cache.Entry e = cache.get(view, n, type);
                if (e != null) { cache.hits++; steps.add(cacheStep(n, type, e, depth)); out.addAll(e.rrs); return e.negative() ? e.rcode : Message.NOERROR; }
                if (type != Message.CNAME) {
                    Cache.Entry c = cache.get(view, n, Message.CNAME);
                    if (c != null && !c.negative()) { cache.hits++; steps.add(cacheStep(n, Message.CNAME, c, depth)); out.addAll(c.rrs); n = c.rrs.get(0).target(); continue; }
                }
                cache.misses++;
            }
            Hop h = iterate(n, type, out, steps, depth, useCache, view);
            if (h.cname == null) return h.rcode;
            n = h.cname;
        }
        return Message.SERVFAIL;
    }

    private Step cacheStep(String n, int type, Cache.Entry e, int depth) {
        Step s = new Step("cache", "", "", n + " " + Message.typeName(type), depth);
        s.cached = true; s.kind = "CACHE HIT";
        s.detail = (e.negative() ? "cached negative answer (" + Message.rcodeName(e.rcode) + ")" : "cached " + Message.typeName(type)) + ", " + e.left() + " s of " + e.ttl + " s TTL left · learned from " + e.source;
        for (RR r : e.rrs) s.records.add("AN " + r);
        return s;
    }

    private Hop iterate(String name, int type, List<RR> out, List<Step> steps, int depth, boolean useCache, String view) {
        // start from the closest enclosing zone whose servers we already know, else the root hints
        String cut = name; List<Server> servers = null; String how = "root hints";
        while (servers == null) {
            if (useCache) {
                Cache.Entry e = cache.get(view, cut, Message.NS);
                if (e != null && !e.negative()) {
                    servers = new ArrayList<>(); how = "cached NS for " + Message.fq(cut);
                    for (RR r : e.rrs) { Cache.Entry a = cache.get(view, r.target(), Message.A); servers.add(new Server(r.target(), a != null && !a.negative() ? a.rrs.get(0).data : null)); }
                    break;
                }
            }
            if (cut.isEmpty()) break;
            int dot = cut.indexOf('.'); cut = dot < 0 ? "" : cut.substring(dot + 1);
        }
        if (servers == null) {
            cut = ""; servers = new ArrayList<>();
            for (String[] h : LAB.equals(view) ? LAB_ROOTS : NET_ROOTS) servers.add(new Server(h[0], h[1]));
        }
        Set<String> tried = new HashSet<>();
        boolean first = true;
        for (int hop = 0; hop < 16; hop++) {
            Server srv = pick(servers, tried, steps, depth, useCache);
            if (srv == null) { Step f = new Step("-", "", cut, name + " " + Message.typeName(type), depth); f.kind = "SERVFAIL"; f.detail = "no reachable name server for " + Message.fq(cut); steps.add(f); return new Hop(Message.SERVFAIL); }
            tried.add(srv.ip);
            Step st = new Step(srv.host, srv.ip, cut, name + " " + Message.typeName(type), depth);
            steps.add(st);
            Exchange x;
            try { x = ask(srv.host, srv.ip, portFor(srv.ip), name, type); }
            catch (IOException e) { timeouts.incrementAndGet(); st.kind = "TIMEOUT"; st.detail = e.getMessage() + " · trying the next server"; continue; }
            upstream.incrementAndGet();
            Message m = lower(x.msg);
            st.ms = x.ms; st.aa = m.aa; st.tcp = x.tcp; st.bytes = x.bytes;
            for (RR r : m.an) if (st.records.size() < 14) st.records.add("AN " + r);
            for (RR r : m.ns) if (st.records.size() < 14) st.records.add("NS " + r);
            for (RR r : m.ar) if (st.records.size() < 14) st.records.add("AR " + r);
            String pre = first && !how.equals("root hints") ? "(started from " + how + ") " : "";
            first = false;
            if (cut.isEmpty() && !name.isEmpty() && NET.equals(view) && !m.an.isEmpty()) {
                st.suspicious = true;
                pre = "INTERCEPTED? A root server never answers \"" + name + "\" itself, it only refers you to the TLD. Something on your network answered for it (a transparent DNS proxy on UDP 53). ";
            }

            if (m.rcode == Message.NXDOMAIN) {
                long ttl = soaMin(m);
                cache.putNegative(view, name, type, Message.NXDOMAIN, ttl, srv.host);
                st.kind = "NXDOMAIN"; st.detail = pre + "the name does not exist; negative answer cached for " + ttl + " s (SOA minimum)";
                return new Hop(Message.NXDOMAIN);
            }
            if (m.rcode != Message.NOERROR) { st.kind = Message.rcodeName(m.rcode); st.detail = pre + "server error · trying another server"; continue; }

            List<RR> direct = pick(m.an, name, type);
            if (!direct.isEmpty()) {
                cache.put(view, name, type, direct, srv.host);
                out.addAll(direct);
                st.kind = m.aa ? "ANSWER" : "ANSWER (not authoritative)";
                st.detail = pre + (m.aa ? "authoritative answer from the zone " + Message.fq(cut) + "; cached for " + direct.get(0).ttl + " s" : "answer without the AA bit");
                return new Hop(Message.NOERROR);
            }
            List<RR> cn = pick(m.an, name, Message.CNAME);
            if (!cn.isEmpty() && type != Message.CNAME) {
                cache.put(view, name, Message.CNAME, cn, srv.host);
                out.add(cn.get(0));
                String target = cn.get(0).target();
                for (int k = 0; k < 8; k++) {
                    List<RR> t = pick(m.an, target, type);
                    if (!t.isEmpty()) {
                        cache.put(view, target, type, t, srv.host); out.addAll(t);
                        st.kind = "ANSWER via CNAME"; st.detail = pre + name + " is an alias (CNAME) of " + target + "; the same server also sent the target's record";
                        return new Hop(Message.NOERROR);
                    }
                    List<RR> c2 = pick(m.an, target, Message.CNAME);
                    if (c2.isEmpty()) break;
                    cache.put(view, target, Message.CNAME, c2, srv.host); out.add(c2.get(0)); target = c2.get(0).target();
                }
                st.kind = "CNAME"; st.detail = pre + name + " is an alias of " + target + ": the lookup starts again for the target";
                return new Hop(target);
            }
            if (m.aa) {
                long ttl = soaMin(m);
                cache.putNegative(view, name, type, Message.NOERROR, ttl, srv.host);
                st.kind = "NODATA"; st.detail = pre + "the name exists but has no " + Message.typeName(type) + " record; cached for " + ttl + " s";
                return new Hop(Message.NOERROR);
            }
            List<RR> nsr = new ArrayList<>(); for (RR r : m.ns) if (r.type == Message.NS) nsr.add(r);
            if (!nsr.isEmpty()) {
                String nc = nsr.get(0).name.toLowerCase();
                if (!Zone.under(name, nc) || nc.equals(cut) || !Zone.under(nc, cut)) {
                    st.kind = "BAD REFERRAL"; st.detail = pre + "referral to " + Message.fq(nc) + " is not below " + Message.fq(cut) + ": ignored (bailiwick check)";
                    continue;
                }
                cache.put(view, nc, Message.NS, nsr, srv.host);
                List<Server> next = new ArrayList<>(); List<String> glueTxt = new ArrayList<>();
                for (RR n : nsr) {
                    String host = n.target(); String ip = null;
                    List<RR> glue = new ArrayList<>();
                    for (RR a : m.ar) if (a.type == Message.A && a.name.equalsIgnoreCase(host)) glue.add(a);
                    if (!glue.isEmpty() && Zone.under(host, cut)) { cache.put(view, host, Message.A, glue, srv.host + " (glue)"); ip = glue.get(0).data; glueTxt.add(host + "=" + ip); }
                    else { Cache.Entry a = cache.get(view, host, Message.A); if (a != null && !a.negative()) ip = a.rrs.get(0).data; }
                    next.add(new Server(host, ip));
                }
                st.kind = "REFERRAL";
                st.detail = pre + "\"ask the servers for " + Message.fq(nc) + "\": " + nsr.size() + " NS" + (glueTxt.isEmpty() ? ", no glue (their addresses must be looked up first)" : ", glue " + String.join(", ", glueTxt.subList(0, Math.min(2, glueTxt.size()))));
                cut = nc; servers = next; tried.clear();
                continue;
            }
            st.kind = "LAME"; st.detail = pre + "no answer and no referral · trying another server";
        }
        return new Hop(Message.SERVFAIL);
    }

    private Server pick(List<Server> servers, Set<String> tried, List<Step> steps, int depth, boolean useCache) {
        for (Server s : servers) if (s.ip != null && !tried.contains(s.ip)) return s;
        for (Server s : servers) {
            if (s.ip != null || s.lookedUp) continue;
            s.lookedUp = true;
            List<RR> a = new ArrayList<>();
            resolveInto(s.host, Message.A, a, steps, depth + 1, useCache, view(s.host));   // glueless delegation
            for (RR r : a) if (r.type == Message.A) { s.ip = r.data; break; }
            if (s.ip != null && !tried.contains(s.ip)) return s;
        }
        return null;
    }

    private static Message lower(Message m) {
        for (List<RR> sec : List.of(m.an, m.ns, m.ar))
            for (int i = 0; i < sec.size(); i++) { RR r = sec.get(i); String d = r.type == Message.TXT ? r.data : r.data.toLowerCase(); sec.set(i, new RR(r.name.toLowerCase(), r.type, r.cls, r.ttl, d)); }
        return m;
    }

    private static List<RR> pick(List<RR> l, String name, int type) {
        List<RR> o = new ArrayList<>();
        for (RR r : l) if (r.name.equalsIgnoreCase(name) && (r.type == type || type == Message.ANY)) o.add(r);
        return o;
    }

    private static long soaMin(Message m) {
        for (RR r : m.ns) if (r.type == Message.SOA) { String[] p = r.data.split("\\s+"); return Math.min(r.ttl, Long.parseLong(p[6])); }
        return 300;
    }

    // ================================================================== one upstream exchange
    private Exchange ask(String host, String ip, int port, String name, int type) throws IOException {
        boolean sec = secure;
        String qname = sec ? randomCase(name) : name;
        int id = rnd.nextInt(65536);
        byte[] out = Message.query(id, qname, type, false).encode();
        InetAddress to = InetAddress.getByName(ip);
        String sid = "iter#" + iterIds.incrementAndGet();
        int timeout = ip.startsWith("127.") ? 2500 : 2000;
        long t0 = System.nanoTime();
        Runnable logQ = () -> Hub.I.line(new Hub.Line(sid, "DNS", true, String.format("query id=0x%04x %s %s? → %s %s:%d", id, qname, Message.typeName(type), host, ip, port),
                sec ? "iterative (RD=0) · random source port " + lastUpstreamPort + ", random ID, 0x20 random case" : "iterative (RD=0) · FIXED source port " + VULN_PORT + ", no source check (2008-style)"));
        Exchange x = sec ? askSecure(out, to, port, id, qname, type, timeout, logQ) : askVulnerable(out, to, port, id, name, type, timeout, logQ);
        if (x.msg.tc) {
            Hub.I.line(new Hub.Line(sid, "DNS", false, x.msg.summary(), "TC=1: the answer did not fit in 512 bytes of UDP · retrying over TCP"));
            x = askTcp(out, to, port);
        }
        x.ms = (System.nanoTime() - t0) / 1e6;
        Hub.I.line(new Hub.Line(sid, "DNS", false, (x.tcp ? "[TCP] " : "") + x.msg.summary(), describe(x.msg) + String.format(" · %.1f ms", x.ms)));
        return x;
    }

    static String describe(Message m) {
        if (m.rcode == Message.NXDOMAIN) return "NXDOMAIN: no such name";
        if (m.rcode != 0) return Message.rcodeName(m.rcode);
        if (!m.an.isEmpty()) return m.aa ? "authoritative answer" : "answer (not authoritative)";
        if (!m.ns.isEmpty() && m.ns.get(0).type == Message.NS) return "referral to " + Message.fq(m.ns.get(0).name) + (m.ar.isEmpty() ? "" : " with glue");
        if (m.aa) return "NODATA";
        return "no data";
    }

    private Exchange askSecure(byte[] out, InetAddress to, int port, int id, String qname, int type, int timeout, Runnable logQ) throws IOException {
        try (DatagramSocket s = new DatagramSocket()) {                 // a fresh random source port every query
            s.setSoTimeout(100);
            lastUpstreamPort = s.getLocalPort();
            logQ.run();
            s.send(new DatagramPacket(out, out.length, to, port));
            long deadline = System.currentTimeMillis() + timeout;
            byte[] buf = new byte[4096];
            while (System.currentTimeMillis() < deadline) {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                try { s.receive(p); } catch (SocketTimeoutException e) { continue; }
                if (!p.getAddress().equals(to) || p.getPort() != port) { rejected.incrementAndGet(); continue; }   // not from the server we asked
                if (p.getLength() < 12 || ((buf[0] & 0xFF) << 8 | buf[1] & 0xFF) != id) { rejected.incrementAndGet(); continue; }
                Message m;
                try { m = Message.decode(buf, p.getLength()); } catch (IOException e) { rejected.incrementAndGet(); continue; }
                if (m.qd.isEmpty() || !m.qd.get(0).name.equals(qname) || m.qd.get(0).type != type) { rejected.incrementAndGet(); continue; }  // 0x20: exact case
                Exchange x = new Exchange(); x.msg = m; x.bytes = p.getLength(); x.from = p.getAddress().getHostAddress() + ":" + p.getPort();
                lastAccept = String.format("id 0x%04x from %s", id, x.from);
                return x;
            }
            throw new SocketTimeoutException("no answer from " + to.getHostAddress() + " within " + timeout + " ms");
        }
    }

    private Exchange askVulnerable(byte[] out, InetAddress to, int port, int id, String name, int type, int timeout, Runnable logQ) throws IOException {
        synchronized (vulnLock) {
            if (vuln == null || vuln.isClosed()) {
                vuln = new DatagramSocket(null);
                vuln.setReceiveBufferSize(8 << 20);
                vuln.bind(new InetSocketAddress(VULN_PORT));
            }
            byte[] buf = new byte[4096];
            vuln.setSoTimeout(1);
            try { while (true) vuln.receive(new DatagramPacket(buf, buf.length)); } catch (SocketTimeoutException e) { /* drained leftovers */ }
            vuln.setSoTimeout(100);
            lastUpstreamPort = VULN_PORT;
            logQ.run();
            vuln.send(new DatagramPacket(out, out.length, to, port));
            long deadline = System.currentTimeMillis() + timeout;
            while (System.currentTimeMillis() < deadline) {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                try { vuln.receive(p); } catch (SocketTimeoutException e) { continue; }
                // no source-address check: on a real network the attacker spoofs the server's IP anyway
                if (p.getLength() < 12 || ((buf[0] & 0xFF) << 8 | buf[1] & 0xFF) != id) { rejected.incrementAndGet(); continue; }
                Message m;
                try { m = Message.decode(buf, p.getLength()); } catch (IOException e) { rejected.incrementAndGet(); continue; }
                if (m.qd.isEmpty() || !m.qd.get(0).name.equalsIgnoreCase(name) || m.qd.get(0).type != type) { rejected.incrementAndGet(); continue; }
                Exchange x = new Exchange(); x.msg = m; x.bytes = p.getLength(); x.from = p.getAddress().getHostAddress() + ":" + p.getPort();
                lastAccept = String.format("id 0x%04x from %s", id, x.from);
                return x;
            }
            throw new SocketTimeoutException("no answer from " + to.getHostAddress() + " within " + timeout + " ms");
        }
    }

    private Exchange askTcp(byte[] out, InetAddress to, int port) throws IOException {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(to, port), 3000); s.setSoTimeout(3000);
            DataOutputStream o = new DataOutputStream(s.getOutputStream()); DataInputStream in = new DataInputStream(s.getInputStream());
            o.writeShort(out.length); o.write(out); o.flush();
            int len = in.readUnsignedShort(); byte[] b = new byte[len]; in.readFully(b);
            Exchange x = new Exchange(); x.msg = Message.decode(b, len); x.bytes = len; x.tcp = true; x.from = to.getHostAddress() + ":" + port;
            return x;
        }
    }

    private String randomCase(String n) {
        StringBuilder b = new StringBuilder(n.length());
        for (char c : n.toCharArray()) b.append(Character.isLetter(c) && rnd.nextBoolean() ? Character.toUpperCase(c) : c);
        return b.toString();
    }

    // ================================================================== serving stub resolvers
    public void listen(String ip, int port) throws IOException {
        listeners.add(new Listener(ip, port).start(this::serve, "resolver"));
        listening.add(ip + ":" + port);
        Hub.I.log("[DNS] recursive resolver on " + ip + ":" + port + " UDP+TCP");
    }

    Message serve(Message q, boolean tcp, String peer) {
        queries.incrementAndGet();
        Message r = q.reply(); r.ra = true;
        if (q.qd.isEmpty()) { r.rcode = Message.FORMERR; return r; }
        String sid = "stub#" + stubIds.incrementAndGet();
        Message.Question qq = q.qd.get(0);
        Hub.I.line(new Hub.Line(sid, "DNS", true, (tcp ? "[TCP] " : "") + q.summary(),
                "stub resolver at " + peer + (q.rd ? " asks for recursion (RD=1): \"do the whole job for me\"" : " sent RD=0: answer only from the cache")));
        if (!q.rd) {
            Cache.Entry e = cache.get(view(qq.name), qq.name, qq.type);
            if (e != null) { r.an.addAll(e.rrs); r.rcode = e.rcode; }
            Hub.I.line(new Hub.Line(sid, "DNS", false, r.summary(), e != null ? "answered from the cache" : "not in the cache, and recursion was not asked for"));
            return r;
        }
        Result res;
        if (recursiveUpstream && labName(qq.name)) {
            Cache.Entry e = cache.get(LAB, qq.name, qq.type);
            res = e != null ? resolve(qq.name, qq.type, true) : resolveRecursive(qq.name, qq.type);
        } else res = resolve(qq.name, qq.type, true);
        r.an.addAll(res.answers); r.rcode = res.rcode;
        long asked = res.steps.stream().filter(s -> !s.cached && !s.server.equals("-")).count();
        Hub.I.line(new Hub.Line(sid, "DNS", false, (tcp ? "[TCP] " : "") + r.summary(),
                res.fromCache ? String.format("answered from the cache in %.2f ms", res.ms)
                        : "recursive".equals(res.mode) ? String.format("resolved recursively: one query to the root, a chain of %d servers, %.1f ms", res.steps.size(), res.ms)
                        : String.format("resolved iteratively: %d server(s) asked, %.1f ms", asked, res.ms)));
        return r;
    }

    public void stop() { for (Listener l : listeners) l.stop(); synchronized (vulnLock) { if (vuln != null) vuln.close(); } }
}

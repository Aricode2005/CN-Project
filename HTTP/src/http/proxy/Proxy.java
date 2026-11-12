package http.proxy;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import http.core.Hub;
import http.core.Json;
import http.core.Msg;
import http.server.Site;

/**
 * A caching forward proxy ("web cache", RFC 9111), the box a university puts between its students and the Internet.
 *
 *   - fresh copy in the cache (Cache-Control: max-age not yet used up)    → HIT: answered locally, no WAN round trips
 *   - stale copy with a validator (ETag / Last-Modified)                  → conditional GET to the origin;
 *                                                                           304 → REVALIDATED (body served from cache), 200 → replaced
 *   - not cacheable (no-store, private, non-GET, Set-Cookie)              → passed through
 *   - CONNECT host:443                                                    → blind TCP tunnel: HTTPS cannot be cached or read
 *
 * Lab hosts (*.cse.myuniv.edu) are fetched through the WAN emulator; other hosts go out to the real Internet (port 80 only).
 */
public final class Proxy {

    public static final class Entry {
        public final String url; public final Msg resp; public volatile long storedAt; public volatile long freshMs; public volatile int hits;
        Entry(String url, Msg resp, long freshMs) { this.url = url; this.resp = resp; this.freshMs = freshMs; this.storedAt = System.currentTimeMillis(); }
        public long ageMs() { return System.currentTimeMillis() - storedAt; }
        public boolean fresh() { return ageMs() < freshMs; }
    }

    public final Map<String, Entry> cache = new ConcurrentHashMap<>();
    public final AtomicLong hits = new AtomicLong(), misses = new AtomicLong(), revalidated = new AtomicLong(), passed = new AtomicLong(), tunnels = new AtomicLong();
    public volatile boolean allowInternet = true;
    private final int linkPort;
    private ServerSocket ss;
    private volatile boolean running = true;

    public Proxy(int linkPort) { this.linkPort = linkPort; }

    public Proxy listen(int port) throws IOException {
        ss = new ServerSocket();
        ss.setReuseAddress(true);
        ss.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port), 64);
        Thread t = new Thread(() -> {
            while (running) {
                try { Socket c = ss.accept(); Thread w = new Thread(() -> serve(c), "proxy-conn"); w.setDaemon(true); w.start(); }
                catch (IOException e) { if (running) Hub.I.log("[PROXY] " + e.getMessage()); }
            }
        }, "proxy-accept");
        t.setDaemon(true); t.start();
        Hub.I.log("[PROXY] caching proxy on 127.0.0.1:" + port);
        return this;
    }

    public void stop() { running = false; try { if (ss != null) ss.close(); } catch (IOException ignored) { } }

    public void clear() { cache.clear(); hits.set(0); misses.set(0); revalidated.set(0); passed.set(0); tunnels.set(0); Hub.I.event("PROXY", "cache emptied"); }
    public void expireAll() { for (Entry e : cache.values()) e.storedAt = System.currentTimeMillis() - e.freshMs - 1; Hub.I.event("PROXY", "every cached copy is now stale: next use must revalidate"); }

    private void serve(Socket client) {
        try (Socket c = client) {
            c.setSoTimeout(15_000);
            InputStream in = new BufferedInputStream(c.getInputStream());
            OutputStream out = new BufferedOutputStream(c.getOutputStream());
            while (true) {
                Msg req;
                try { req = Msg.readHead(in); } catch (SocketTimeoutException e) { break; }
                if (req == null) break;
                if ("CONNECT".equals(req.method())) { tunnel(req, c, in, out); return; }
                req.readRequestBody(in);
                Msg resp = handle(req);
                boolean keep = req.keepAlive(req.version()) && !resp.headerHas("Connection", "close");
                resp.set("Connection", keep ? "keep-alive" : "close");
                out.write(resp.wire(!"HEAD".equals(req.method()), 4096)); out.flush();
                if (!keep) break;
            }
        } catch (IOException e) { /* client went away */ }
    }

    /** The cache decision for one request (also called directly by the dashboard). */
    public Msg handle(Msg req) {
        String url = req.target();
        if (!url.startsWith("http://")) {
            if (url.startsWith("/") && req.has("Host")) url = "http://" + req.get("Host") + url;   // tolerate origin-form with Host
            else return note(400, "A proxy needs the absolute URL: GET http://host/path HTTP/1.1");
        }
        String rest = url.substring(7); int slash = rest.indexOf('/');
        String hostPort = slash < 0 ? rest : rest.substring(0, slash), path = slash < 0 ? "/" : rest.substring(slash);
        String host = hostPort.replaceFirst(":\\d+$", "").toLowerCase();
        int port = hostPort.contains(":") ? Integer.parseInt(hostPort.substring(hostPort.indexOf(':') + 1)) : 80;
        boolean lab = host.endsWith("cse.myuniv.edu");
        if (!lab && !allowInternet) return note(403, "This lab proxy only fetches *.cse.myuniv.edu right now.");
        String key = "http://" + host + (port == 80 ? "" : ":" + port) + path;
        boolean cacheableReq = "GET".equals(req.method()) && !req.has("Authorization") && !req.headerHas("Cache-Control", "no-store");
        boolean clientNoCache = req.headerHas("Cache-Control", "no-cache") || req.headerHas("Pragma", "no-cache");

        Entry e = cacheableReq ? cache.get(key) : null;
        if (e != null && e.fresh() && !clientNoCache) {
            e.hits++; hits.incrementAndGet();
            Msg r = copy(e.resp).set("Age", e.ageMs() / 1000).set("X-Cache", "HIT").set("Via", "1.1 ju-proxy");
            Hub.I.event("PROXY", "HIT " + key + " (age " + e.ageMs() / 1000.0 + " s of " + e.freshMs / 1000 + " s): answered locally, the WAN is not touched");
            return r;
        }
        Msg up = Msg.request(req.method(), path, "HTTP/1.1");
        for (String[] h : req.headers) if (!hop(h[0])) up.add(h[0], h[1]);
        up.set("Host", host + (port == 80 ? "" : ":" + port)).set("Via", "1.1 ju-proxy").set("Connection", "close");
        up.remove("Accept-Encoding");                                         // one stored variant per URL (we ignore Vary)
        up.body = req.body;
        if (up.body.length > 0) up.set("Content-Length", up.body.length);
        boolean conditional = false;
        if (e != null) {                                                       // stale: revalidate instead of refetching
            if (e.resp.has("ETag")) { up.set("If-None-Match", e.resp.get("ETag")); conditional = true; }
            if (e.resp.has("Last-Modified")) { up.set("If-Modified-Since", e.resp.get("Last-Modified")); conditional = true; }
        }
        long t = System.nanoTime();
        Msg r;
        try { r = fetch(lab ? "127.0.0.1" : host, lab ? linkPort : port, up); }
        catch (IOException ex) { return note(502, "Origin " + hostPort + " did not answer: " + ex.getMessage()); }
        long ms = (System.nanoTime() - t) / 1_000_000;
        if (conditional && r.status() == 304 && e != null) {
            revalidated.incrementAndGet(); e.hits++;
            e.storedAt = System.currentTimeMillis(); e.freshMs = freshness(r, e.freshMs);
            Hub.I.event("PROXY", "REVALIDATED " + key + ": origin said 304 Not Modified in " + ms + " ms, cached body reused (no body crossed the WAN)");
            return copy(e.resp).set("Age", 0).set("X-Cache", "REVALIDATED").set("Via", "1.1 ju-proxy");
        }
        long fresh = freshness(r, -1);
        boolean store = cacheableReq && r.status() == 200 && fresh > 0 && !r.has("Set-Cookie") && !r.headerHas("Cache-Control", "no-store") && !r.headerHas("Cache-Control", "private");
        if (store) { cache.put(key, new Entry(key, r, fresh)); misses.incrementAndGet(); }
        else passed.incrementAndGet();
        Hub.I.event("PROXY", (store ? "MISS " : "PASS ") + key + " → " + r.status() + " in " + ms + " ms" + (store ? ", stored for " + fresh / 1000 + " s" : ", not cacheable (" + why(r, cacheableReq) + ")"));
        return copy(r).set("X-Cache", store ? "MISS" : "PASS").set("Via", "1.1 ju-proxy");
    }

    private static String why(Msg r, boolean cacheableReq) {
        if (!cacheableReq) return "not a plain GET";
        if (r.status() != 200) return "status " + r.status();
        if (r.has("Set-Cookie")) return "Set-Cookie";
        String cc = r.get("Cache-Control");
        return cc == null ? "no freshness information" : "Cache-Control: " + cc;
    }

    /** Freshness lifetime: max-age, else Expires, else 10% of the time since Last-Modified (RFC 9111 §4.2.2 heuristic). */
    static long freshness(Msg r, long fallback) {
        String cc = r.get("Cache-Control");
        if (cc != null) {
            if (cc.contains("no-cache")) return 0;
            for (String p : cc.split(",")) { p = p.trim(); if (p.startsWith("max-age=")) try { return Long.parseLong(p.substring(8)) * 1000; } catch (NumberFormatException ignored) { } }
        }
        if (r.has("Expires")) { long x = Msg.parseDate(r.get("Expires")); if (x > 0) return Math.max(0, x - System.currentTimeMillis()); }
        if (r.has("Last-Modified")) { long lm = Msg.parseDate(r.get("Last-Modified")); if (lm > 0) return Math.min(60_000, (System.currentTimeMillis() - lm) / 10); }
        return fallback;
    }

    private static boolean hop(String h) {
        for (String x : new String[] { "Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Content-Length" })
            if (x.equalsIgnoreCase(h)) return true;
        return false;
    }

    private static Msg fetch(String host, int port, Msg up) throws IOException {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), 5000); s.setSoTimeout(15_000);
            OutputStream o = s.getOutputStream(); o.write(up.wire(true, 4096)); o.flush();
            InputStream in = new BufferedInputStream(s.getInputStream());
            Msg r;
            do { r = Msg.readHead(in); if (r == null) throw new IOException("no response"); } while (r.status() == 100);
            r.readResponseBody(in, up.method());
            r.remove("Transfer-Encoding"); r.chunked = false;
            for (String h : new String[] { "Connection", "Keep-Alive" }) r.remove(h);
            r.set("Content-Length", r.body.length);
            return r;
        }
    }

    private static Msg copy(Msg m) {
        Msg c = new Msg(); c.start = m.start; for (String[] h : m.headers) c.add(h[0], h[1]); c.body = m.body; return c;
    }

    private static Msg note(int code, String why) {
        return Msg.response("HTTP/1.1", code).set("Date", Msg.now()).set("Server", "ju-proxy").set("Content-Type", "text/plain; charset=utf-8").set("Connection", "close").body(why + "\n");
    }

    /** CONNECT host:port → a blind byte pipe. Everything after this point is TLS: the proxy can neither read nor cache it. */
    private void tunnel(Msg req, Socket c, InputStream in, OutputStream out) throws IOException {
        String t = req.target(); int i = t.lastIndexOf(':');
        String host = i < 0 ? t : t.substring(0, i); int port = i < 0 ? 443 : Integer.parseInt(t.substring(i + 1));
        if (!allowInternet || port != 443) { out.write(note(403, "CONNECT is only allowed to port 443").wire(true, 4096)); out.flush(); return; }
        tunnels.incrementAndGet();
        Hub.I.event("PROXY", "TUNNEL " + host + ":443: HTTPS through the proxy as an opaque byte stream (cannot be cached or inspected)");
        try (Socket o = new Socket()) {
            o.connect(new InetSocketAddress(host, port), 5000);
            out.write("HTTP/1.1 200 Connection Established\r\nVia: 1.1 ju-proxy\r\n\r\n".getBytes("ISO-8859-1")); out.flush();
            c.setSoTimeout(0);
            Thread a = new Thread(() -> pump(in, outOf(o)), "tunnel-up"); a.setDaemon(true); a.start();
            pump(o.getInputStream(), out);
        } catch (IOException e) { out.write(note(502, "cannot reach " + t + ": " + e.getMessage()).wire(true, 4096)); out.flush(); }
    }
    private static OutputStream outOf(Socket s) { try { return s.getOutputStream(); } catch (IOException e) { throw new RuntimeException(e); } }
    private static void pump(InputStream in, OutputStream out) {
        byte[] b = new byte[16384]; int k;
        try { while ((k = in.read(b)) > 0) { out.write(b, 0, k); out.flush(); } } catch (IOException ignored) { }
        try { out.close(); } catch (IOException ignored) { }
    }

    public String json() {
        List<String> es = new ArrayList<>();
        for (Entry e : cache.values())
            es.add(Json.obj("url", e.url, "status", e.resp.status(), "bytes", e.resp.body.length, "age", e.ageMs() / 1000.0, "fresh", e.freshMs / 1000.0, "isFresh", e.fresh(), "hits", e.hits,
                "etag", e.resp.get("ETag"), "lm", e.resp.get("Last-Modified")));
        es.sort(String::compareTo);
        return Json.obj("hits", hits.get(), "misses", misses.get(), "revalidated", revalidated.get(), "passed", passed.get(), "tunnels", tunnels.get(), "allowInternet", allowInternet, "entries", Json.raw(Json.arr(es)));
    }

    /** For the dashboard: the lab site's own resources. */
    public static String labUrl(String path) { return "http://" + Site.WWW + path; }
}

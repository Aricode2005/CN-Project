package http;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import http.client.PageLoad;
import http.client.WebClient;
import http.core.Msg;
import http.link.Link;
import http.proxy.Proxy;
import http.server.Origin;
import http.server.Site;

/** Automated end-to-end checks ("run.bat --verify"): our client against our server, link and proxy over real TCP. */
final class Verify {

    private static int pass, fail;
    private static void check(String name, boolean ok, String detail) {
        if (ok) pass++; else fail++;
        System.out.printf("  [%s] %-70s %s%n", ok ? "PASS" : "FAIL", name, detail == null ? "" : detail);
    }
    interface T { void run() throws Exception; }
    private static void test(String name, T t) { try { t.run(); } catch (Exception e) { check(name, false, e.getClass().getSimpleName() + ": " + e.getMessage()); } }

    private static WebClient www() { return new WebClient("127.0.0.1", Main.ORIGIN, Site.WWW); }

    /** Raw bytes in, raw bytes out (to test framing without our own client in the way). */
    private static String raw(String req, int waitMs) throws Exception {
        try (Socket s = new Socket(InetAddress.getByName("127.0.0.1"), Main.ORIGIN)) {
            s.setSoTimeout(waitMs);
            OutputStream o = s.getOutputStream(); o.write(req.getBytes(StandardCharsets.ISO_8859_1)); o.flush();
            InputStream in = new BufferedInputStream(s.getInputStream());
            ByteArrayOutputStream b = new ByteArrayOutputStream(); byte[] buf = new byte[8192]; int k;
            try { while ((k = in.read(buf)) > 0) b.write(buf, 0, k); } catch (java.net.SocketTimeoutException e) { /* kept open */ }
            return new String(b.toByteArray(), StandardCharsets.ISO_8859_1);
        }
    }

    static int run(Origin origin, Link link, Proxy proxy, boolean on80) {
        Site site = origin.site;
        System.out.println("\n--- messages, methods and status codes ------------------------------------------");
        test("basics", () -> {
            WebClient c = www();
            try (WebClient.Conn k = c.connect()) {
                WebClient.Exchange x = c.send(k, c.get("/", "HTTP/1.1"));
                check("GET / → 200 with Content-Length matching the body", x.resp.status() == 200 && Integer.parseInt(x.resp.get("Content-Length")) == x.resp.body.length, x.resp.body.length + " bytes");
                check("response carries Date and Server header fields", x.resp.has("Date") && x.resp.has("Server"), x.resp.get("Date"));
                WebClient.Exchange h = c.send(k, Msg.request("HEAD", "/gallery.html", "HTTP/1.1").set("Host", Site.WWW));
                check("HEAD → same headers as GET, no body", h.resp.status() == 200 && h.resp.body.length == 0 && Integer.parseInt(h.resp.get("Content-Length")) > 0, "Content-Length " + h.resp.get("Content-Length"));
                check("unknown path → 404", c.send(k, c.get("/no/such/page", "HTTP/1.1")).resp.status() == 404, "");
                WebClient.Exchange m = c.send(k, Msg.request("DELETE", "/gallery.html", "HTTP/1.1").set("Host", Site.WWW));
                check("DELETE on a read-only page → 405 + Allow", m.resp.status() == 405 && m.resp.has("Allow"), "Allow: " + m.resp.get("Allow"));
                check("unknown method BREW → 501", c.send(k, Msg.request("BREW", "/", "HTTP/1.1").set("Host", Site.WWW)).resp.status() == 501, "");
                WebClient.Exchange o = c.send(k, Msg.request("OPTIONS", "/files/x.txt", "HTTP/1.1").set("Host", Site.WWW));
                check("OPTIONS → 204 with Allow listing PUT and DELETE", o.resp.status() == 204 && o.resp.get("Allow").contains("PUT") && o.resp.get("Allow").contains("DELETE"), o.resp.get("Allow"));
                check("GET /crash → 500 (server error, not the client's fault)", c.send(k, c.get("/crash", "HTTP/1.1")).resp.status() == 500, "");
            }
            check("HTTP/2.0 request line → 505 Version Not Supported", raw("GET / HTTP/2.0\r\nHost: x\r\n\r\n", 800).startsWith("HTTP/1.1 505"), "");
        });

        System.out.println("\n--- Host header and virtual hosting ----------------------------------------------");
        test("vhost", () -> {
            String a = raw("GET / HTTP/1.1\r\n\r\n", 800);
            check("HTTP/1.1 without Host → 400 Bad Request", a.startsWith("HTTP/1.1 400"), "");
            String b = raw("GET / HTTP/1.0\r\n\r\n", 2000);
            check("HTTP/1.0 without Host → 200, status line HTTP/1.0, connection closed", b.startsWith("HTTP/1.0 200") && b.contains("Connection: close"), "");
            WebClient c = www();
            try (WebClient.Conn k = c.connect()) {
                String w = c.send(k, c.get("/", "HTTP/1.1")).resp.text(), i = c.send(k, c.get("/", "HTTP/1.1").set("Host", Site.INTRANET)).resp.text();
                check("same IP + port, Host: intranet → a different site (virtual hosting)", w.contains("reading room") && i.contains("virtual hosting"), "");
            }
        });

        System.out.println("\n--- connections: persistent, non-persistent, pipelining --------------------------");
        test("conn", () -> {
            String three = raw("GET /img/1.svg HTTP/1.1\r\nHost: " + Site.WWW + "\r\n\r\nGET /img/2.svg HTTP/1.1\r\nHost: " + Site.WWW + "\r\n\r\nGET /img/3.svg HTTP/1.1\r\nHost: " + Site.WWW + "\r\nConnection: close\r\n\r\n", 3000);
            int n = three.split("HTTP/1.1 200 OK", -1).length - 1;
            int p1 = three.indexOf("plate 1"), p2 = three.indexOf("plate 2"), p3 = three.indexOf("plate 3");
            check("3 pipelined requests in one write → 3 responses, in order", n == 3 && p1 >= 0 && p1 < p2 && p2 < p3, n + " responses");
            WebClient c = www();
            try (WebClient.Conn k = c.connect()) {
                for (int i = 1; i <= 4; i++) c.send(k, c.get("/img/" + i + ".svg", "HTTP/1.1"));
                check("HTTP/1.1 keep-alive: 4 requests on one TCP connection", k.requests == 4 && !k.s.isClosed(), "Keep-Alive: timeout=" + Origin.KEEP_ALIVE_SECONDS);
            }
            try (WebClient.Conn k = c.connect()) {
                WebClient.Exchange x = c.send(k, c.get("/", "HTTP/1.0"));
                int next = k.s.getInputStream().read();
                check("HTTP/1.0 request → server closes after one response", x.resp.headerHas("Connection", "close") && next == -1, "");
            }
            try (WebClient.Conn k = c.connect()) {
                WebClient.Exchange x = c.send(k, c.get("/", "HTTP/1.0").set("Connection", "keep-alive"));
                WebClient.Exchange y = c.send(k, c.get("/img/1.svg", "HTTP/1.0").set("Connection", "keep-alive"));
                check("HTTP/1.0 + Connection: keep-alive → connection reused", x.resp.headerHas("Connection", "keep-alive") && y.resp.status() == 200, "");
            }
            try (WebClient.Conn k = c.connect()) {
                c.send(k, c.get("/", "HTTP/1.1").set("Connection", "close"));
                check("HTTP/1.1 + Connection: close → server closes", k.s.getInputStream().read() == -1, "");
            }
        });

        System.out.println("\n--- page load through the WAN emulator (RTT 100 ms) ------------------------------");
        test("pageload", () -> {
            link.rttMs = 100; link.kbps = 100_000;
            PageLoad.Result a = PageLoad.run(PageLoad.Mode.NONPERSISTENT, "127.0.0.1", Main.LINK, Site.WWW, 100, link.kbps, 4);
            PageLoad.Result b = PageLoad.run(PageLoad.Mode.PARALLEL, "127.0.0.1", Main.LINK, Site.WWW, 100, link.kbps, 5);
            PageLoad.Result p = PageLoad.run(PageLoad.Mode.PERSISTENT, "127.0.0.1", Main.LINK, Site.WWW, 100, link.kbps, 4);
            PageLoad.Result q = PageLoad.run(PageLoad.Mode.PIPELINED, "127.0.0.1", Main.LINK, Site.WWW, 100, link.kbps, 4);
            check("non-persistent: 11 objects use 11 TCP connections", a.connections == 11 && a.objects == 10, a.connections + " connections");
            check("non-persistent ≈ (N+1)·2·RTT = 2200 ms (within 15%)", Math.abs(a.totalMs - 2200) < 330, Math.round(a.totalMs) + " ms");
            check("5 parallel connections ≈ 2·RTT + ⌈10/5⌉·2·RTT = 600 ms (within 20%)", Math.abs(b.totalMs - 600) < 120, Math.round(b.totalMs) + " ms");
            check("persistent ≈ 2·RTT + N·RTT = 1200 ms (within 15%), 1 connection", Math.abs(p.totalMs - 1200) < 180 && p.connections == 1, Math.round(p.totalMs) + " ms");
            check("pipelined ≈ 3·RTT = 300 ms (within 25%), 1 connection", Math.abs(q.totalMs - 300) < 75 && q.connections == 1, Math.round(q.totalMs) + " ms");
            check("order: non-persistent > persistent > parallel > pipelined", a.totalMs > p.totalMs && p.totalMs > b.totalMs && b.totalMs > q.totalMs, "");
            link.kbps = 4000;
        });

        System.out.println("\n--- conditional GET, Range, content coding ---------------------------------------");
        test("cond", () -> {
            WebClient c = www();
            try (WebClient.Conn k = c.connect()) {
                WebClient.Exchange a = c.send(k, c.get("/news.html", "HTTP/1.1"));
                String etag = a.resp.get("ETag"), lm = a.resp.get("Last-Modified");
                check("200 carries validators ETag and Last-Modified", etag != null && lm != null, etag);
                WebClient.Exchange b = c.send(k, c.get("/news.html", "HTTP/1.1").set("If-None-Match", etag));
                check("If-None-Match with the same ETag → 304, no body", b.resp.status() == 304 && b.resp.body.length == 0, "");
                check("If-Modified-Since = Last-Modified → 304", c.send(k, c.get("/news.html", "HTTP/1.1").set("If-Modified-Since", lm)).resp.status() == 304, "");
                site.editNews();
                WebClient.Exchange d = c.send(k, c.get("/news.html", "HTTP/1.1").set("If-None-Match", etag));
                check("after the page changes, the same conditional GET → 200 + new ETag", d.resp.status() == 200 && !etag.equals(d.resp.get("ETag")), d.resp.get("ETag"));
                WebClient.Exchange r = c.send(k, c.get("/big.bin", "HTTP/1.1").set("Range", "bytes=1000-1999"));
                check("Range bytes=1000-1999 → 206, exactly those 1000 bytes", r.resp.status() == 206 && Arrays.equals(r.resp.body, Arrays.copyOfRange(site.big(), 1000, 2000)) && "bytes 1000-1999/65536".equals(r.resp.get("Content-Range")), r.resp.get("Content-Range"));
                WebClient.Exchange s = c.send(k, c.get("/big.bin", "HTTP/1.1").set("Range", "bytes=-100"));
                check("suffix Range bytes=-100 → the last 100 bytes", s.resp.status() == 206 && Arrays.equals(s.resp.body, Arrays.copyOfRange(site.big(), 65436, 65536)), "");
                check("Range beyond the end → 416", c.send(k, c.get("/big.bin", "HTTP/1.1").set("Range", "bytes=70000-")).resp.status() == 416, "");
                WebClient.Exchange plain = c.send(k, c.get("/gallery.html", "HTTP/1.1"));
                WebClient.Exchange z = c.send(k, c.get("/gallery.html", "HTTP/1.1").set("Accept-Encoding", "gzip"));
                check("Accept-Encoding: gzip → Content-Encoding: gzip, smaller, decodes to the same page", "gzip".equals(z.resp.get("Content-Encoding")) && z.wireBytes < plain.resp.body.length && Arrays.equals(z.resp.body, plain.resp.body), plain.resp.body.length + " → " + z.wireBytes + " bytes");
            }
        });

        System.out.println("\n--- bodies: PUT/DELETE, chunked, 100-continue, redirects --------------------------");
        test("bodies", () -> {
            WebClient c = www();
            try (WebClient.Conn k = c.connect()) {
                byte[] data = new byte[5000]; for (int i = 0; i < data.length; i++) data[i] = (byte) i;
                Msg put = Msg.request("PUT", "/files/v.bin", "HTTP/1.1").set("Host", Site.WWW).body(data); put.set("Content-Length", data.length);
                WebClient.Exchange a = c.send(k, put);
                check("PUT a new file → 201 Created + Location", a.resp.status() == 201 && "/files/v.bin".equals(a.resp.get("Location")), "");
                check("PUT the same URL again → 204 (replaced, idempotent)", c.send(k, put).resp.status() == 204, "");
                check("GET returns the exact bytes", Arrays.equals(c.send(k, c.get("/files/v.bin", "HTTP/1.1")).resp.body, data), data.length + " bytes");
                Msg ch = Msg.request("PUT", "/files/c.txt", "HTTP/1.1").set("Host", Site.WWW).body("a chunked request body, reassembled by the server\n"); ch.chunked = true; ch.chunkSize = 7;
                c.send(k, ch);
                check("chunked request body (7-byte chunks) → stored intact", c.send(k, c.get("/files/c.txt", "HTTP/1.1")).resp.text().equals("a chunked request body, reassembled by the server\n"), "");
                check("DELETE → 204, then GET → 404", c.send(k, Msg.request("DELETE", "/files/v.bin", "HTTP/1.1").set("Host", Site.WWW)).resp.status() == 204 && c.send(k, c.get("/files/v.bin", "HTTP/1.1")).resp.status() == 404, "");
                Msg big = Msg.request("PUT", "/files/e.txt", "HTTP/1.1").set("Host", Site.WWW).body("y".repeat(3000));
                WebClient.Exchange e = c.sendExpecting(k, big);
                check("Expect: 100-continue → 100 Continue first, then 201", e.rawResponseHead.startsWith("HTTP/1.1 100 Continue") && e.resp.status() == 201, "");
                WebClient.Exchange r = c.send(k, c.get("/old-page", "HTTP/1.1"));
                check("301 Moved Permanently with Location", r.resp.status() == 301 && "/news.html".equals(r.resp.get("Location")), "");
            }
            try (WebClient.Conn k = c.connect()) {
                WebClient.Exchange x = c.send(k, c.get("/clock", "HTTP/1.1"));
                check("/clock → Transfer-Encoding: chunked, 5 data chunks + the 0 chunk, no Content-Length", x.resp.chunked && x.resp.chunkSizes.size() == 6 && x.resp.chunkSizes.get(5) == 0 && !x.resp.has("Content-Length"), x.resp.chunkSizes.toString());
            }
            String noLen = raw("POST /echo HTTP/1.1\r\nHost: " + Site.WWW + "\r\n\r\n", 800);
            check("POST without Content-Length or chunked → 411 Length Required", noLen.startsWith("HTTP/1.1 411"), "");
        });

        System.out.println("\n--- state: cookies and authentication --------------------------------------------");
        test("state", () -> {
            WebClient c = www();
            try (WebClient.Conn k = c.connect()) {
                check("GET /cart without a cookie → the server doesn't know you", c.send(k, c.get("/cart", "HTTP/1.1")).resp.text().contains("Who are you"), "");
                Msg login = Msg.request("POST", "/login", "HTTP/1.1").set("Host", Site.WWW).set("Content-Type", "application/x-www-form-urlencoded").body("user=alice&pass=alice123"); login.set("Content-Length", login.body.length);
                WebClient.Exchange l = c.send(k, login);
                check("POST /login → 303 See Other + Set-Cookie sid (HttpOnly)", l.resp.status() == 303 && l.resp.get("Set-Cookie").startsWith("sid=") && l.resp.get("Set-Cookie").contains("HttpOnly"), "");
                Msg add = Msg.request("POST", "/cart/add", "HTTP/1.1").set("Host", Site.WWW).body("item=router"); add.set("Content-Length", add.body.length); c.attachCookies(add); c.send(k, add);
                Msg cart = c.get("/cart", "HTTP/1.1"); c.attachCookies(cart);
                check("Cookie sent back → the server remembers alice and her cart", c.send(k, cart).resp.text().contains("alice") , "");
                Msg bad = Msg.request("POST", "/login", "HTTP/1.1").set("Host", Site.WWW).body("user=alice&pass=nope"); bad.set("Content-Length", bad.body.length);
                check("wrong password → 403, no cookie", c.send(k, bad).resp.status() == 403, "");
                WebClient.Exchange u = c.send(k, c.get("/private/", "HTTP/1.1"));
                check("/private/ without credentials → 401 + WWW-Authenticate: Basic", u.resp.status() == 401 && u.resp.get("WWW-Authenticate").startsWith("Basic"), u.resp.get("WWW-Authenticate"));
                String cred = Base64.getEncoder().encodeToString("alice:alice123".getBytes(StandardCharsets.UTF_8));
                check("Authorization: Basic base64(alice:alice123) → 200", c.send(k, c.get("/private/", "HTTP/1.1").set("Authorization", "Basic " + cred)).resp.status() == 200, cred);
            }
        });

        System.out.println("\n--- the caching proxy ------------------------------------------------------------");
        test("proxy", () -> {
            proxy.clear(); link.rttMs = 100;
            WebClient c = new WebClient("127.0.0.1", Main.PROXY, Site.WWW);
            try (WebClient.Conn k = c.connect()) {
                WebClient.Exchange a = c.send(k, c.get(Proxy.labUrl("/img/5.svg"), "HTTP/1.1"));
                WebClient.Exchange b = c.send(k, c.get(Proxy.labUrl("/img/5.svg"), "HTTP/1.1"));
                check("first fetch through the proxy → MISS (crosses the WAN)", "MISS".equals(a.resp.get("X-Cache")) && a.tDone - a.tSend > 150, Math.round(a.tDone - a.tSend) + " ms");
                check("second fetch → HIT, served locally (≥ 5× faster), Via + Age set", "HIT".equals(b.resp.get("X-Cache")) && (b.tDone - b.tSend) * 5 < (a.tDone - a.tSend) && b.resp.has("Age") && b.resp.has("Via"), Math.round(b.tDone - b.tSend) + " ms");
                proxy.expireAll();
                WebClient.Exchange r = c.send(k, c.get(Proxy.labUrl("/img/5.svg"), "HTTP/1.1"));
                check("stale copy → conditional GET to the origin → 304 → REVALIDATED", "REVALIDATED".equals(r.resp.get("X-Cache")) && r.resp.body.length > 0, "");
                WebClient.Exchange n1 = c.send(k, c.get(Proxy.labUrl("/slow?ms=1"), "HTTP/1.1"));
                WebClient.Exchange n2 = c.send(k, c.get(Proxy.labUrl("/slow?ms=1"), "HTTP/1.1"));
                check("Cache-Control: no-store → never cached (PASS both times)", "PASS".equals(n1.resp.get("X-Cache")) && "PASS".equals(n2.resp.get("X-Cache")), "");
                check("origin-form request without Host to a proxy → 400", c.send(k, Msg.request("GET", "/x", "HTTP/1.1")).resp.status() == 400, "");
            }
        });

        System.out.println("\n--- real ports -------------------------------------------------------------------");
        check("origin also listens on the real HTTP port 80", on80, on80 ? "http://localhost/ works" : "port 80 was busy (another web server?)");

        System.out.printf("%n  %d passed, %d failed%n", pass, fail);
        return fail;
    }
}

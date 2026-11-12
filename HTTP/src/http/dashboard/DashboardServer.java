package http.dashboard;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import http.client.PageLoad;
import http.client.WebClient;
import http.core.Codes;
import http.core.Hub;
import http.core.Json;
import http.core.Msg;
import http.link.Link;
import http.proxy.Proxy;
import http.server.Origin;
import http.server.Site;

/** HTTP API + static page for the HTTP dashboard (http://localhost:8087). Every demo is our real client talking to our real server. */
public final class DashboardServer {

    private final int port, originPort, linkPort, proxyPort; private final boolean on80;
    private final Origin origin; private final Site site; private final Link link; private final Proxy proxy; private final File web;
    private HttpServer http;
    private final Object experimentLock = new Object();

    public DashboardServer(int port, int originPort, int linkPort, int proxyPort, boolean on80, Origin origin, Link link, Proxy proxy, File web) {
        this.port = port; this.originPort = originPort; this.linkPort = linkPort; this.proxyPort = proxyPort; this.on80 = on80;
        this.origin = origin; this.site = origin.site; this.link = link; this.proxy = proxy; this.web = web;
    }

    public void start() throws IOException {
        http = HttpServer.create(new InetSocketAddress(port), 0);
        http.createContext("/", this::route);
        http.setExecutor(Executors.newFixedThreadPool(12));
        http.start();
    }
    public void stop() { if (http != null) http.stop(0); }

    private void route(HttpExchange ex) throws IOException {
        Map<String, String> q = params(ex);
        try {
            switch (ex.getRequestURI().getPath()) {
                case "/": case "/index.html": file(ex); return;
                case "/api/state": json(ex, state(Long.parseLong(q.getOrDefault("ev", "0")))); return;
                case "/api/lines": json(ex, lines(Long.parseLong(q.getOrDefault("since", "0")))); return;
                case "/api/link":
                    if (q.containsKey("rtt")) link.rttMs = clamp(Integer.parseInt(q.get("rtt")), 0, 600);
                    if (q.containsKey("kbps")) link.kbps = clamp(Integer.parseInt(q.get("kbps")), 64, 1_000_000);
                    json(ex, Json.obj("rtt", link.rttMs, "kbps", link.kbps)); return;
                case "/api/pageload": json(ex, pageload(q)); return;
                case "/api/send": json(ex, send(q)); return;
                case "/api/script": json(ex, script(q.getOrDefault("name", "conditional"))); return;
                case "/api/proxyrun": json(ex, proxyRun(q.getOrDefault("path", "/gallery.html"))); return;
                case "/api/proxy/clear": proxy.clear(); json(ex, proxy.json()); return;
                case "/api/proxy/expire": proxy.expireAll(); json(ex, proxy.json()); return;
                case "/api/proxy/internet": proxy.allowInternet = "1".equals(q.get("on")); json(ex, proxy.json()); return;
                case "/api/news/edit": site.editNews(); json(ex, Json.obj("version", site.newsVersion())); return;
                case "/api/raw": json(ex, raw(q.getOrDefault("text", ""))); return;
                case "/api/codes": json(ex, codes()); return;
                default: send(ex, 404, "text/plain", "not found".getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception e) { json(ex, Json.obj("error", e.getClass().getSimpleName() + ": " + e.getMessage())); }
    }

    private static int clamp(int v, int lo, int hi) { return Math.max(lo, Math.min(hi, v)); }

    // ------------------------------------------------------------------ state
    private String state(long evSince) {
        List<String> logs = new ArrayList<>(); List<String> all = Hub.I.logs();
        for (String l : all.subList(Math.max(0, all.size() - 80), all.size())) logs.add(Json.str(l));
        List<String> ev = new ArrayList<>(); for (Hub.Event e : Hub.I.eventsSince(evSince)) ev.add(e.json());
        return Json.obj("ports", Json.raw(Json.obj("origin", originPort, "on80", on80, "link", linkPort, "proxy", proxyPort, "dashboard", port)),
            "origin", Json.raw(Json.obj("connections", origin.connections.get(), "requests", origin.requests.get(), "sessions", site.sessions(), "news", site.newsVersion())),
            "link", Json.raw(Json.obj("rtt", link.rttMs, "kbps", link.kbps, "connections", link.connections.get(), "up", link.bytesUp.get(), "down", link.bytesDown.get())),
            "proxy", Json.raw(proxy.json()), "logs", Json.raw(Json.arr(logs)), "events", Json.raw(Json.arr(ev)));
    }

    private String lines(long since) {
        List<String> l = new ArrayList<>(); List<Hub.Line> ls = Hub.I.linesSince(since);
        for (Hub.Line x : ls.subList(Math.max(0, ls.size() - 300), ls.size())) l.add(x.json());
        return Json.arr(l);
    }

    // ------------------------------------------------------------------ experiments
    private String pageload(Map<String, String> q) throws Exception {
        synchronized (experimentLock) {
            if (q.containsKey("rtt")) link.rttMs = clamp(Integer.parseInt(q.get("rtt")), 0, 600);
            if (q.containsKey("kbps")) link.kbps = clamp(Integer.parseInt(q.get("kbps")), 64, 1_000_000);
            int k = clamp(Integer.parseInt(q.getOrDefault("k", "4")), 1, 10);
            List<String> out = new ArrayList<>();
            String modes = q.getOrDefault("modes", "NONPERSISTENT,PARALLEL,PERSISTENT,PIPELINED");
            for (String m : modes.split(",")) out.add(PageLoad.run(PageLoad.Mode.valueOf(m.trim()), "127.0.0.1", linkPort, Site.WWW, link.rttMs, link.kbps, k).json());
            return Json.obj("rtt", link.rttMs, "kbps", link.kbps, "k", k, "runs", Json.raw(Json.arr(out)));
        }
    }

    /** The gallery through the caching proxy on one persistent client↔proxy connection. */
    private String proxyRun(String path) throws Exception {
        synchronized (experimentLock) {
            WebClient c = new WebClient("127.0.0.1", proxyPort, Site.WWW);
            List<String> rows = new ArrayList<>();
            try (WebClient.Conn k = c.connect()) {
                WebClient.Exchange base = c.send(k, c.get(Proxy.labUrl(path), "HTTP/1.1"));
                rows.add(row(base, path));
                if (path.endsWith("gallery.html"))
                    for (String u : WebClient.references(base.resp.text())) rows.add(row(c.send(k, c.get(Proxy.labUrl(u), "HTTP/1.1")), u));
            }
            return Json.obj("rows", Json.raw(Json.arr(rows)), "proxy", Json.raw(proxy.json()), "totalMs", Math.round((System.nanoTime() - c.t0) / 1e5) / 10.0, "rtt", link.rttMs);
        }
    }
    private static String row(WebClient.Exchange x, String path) {
        return Json.obj("path", path, "status", x.resp.status(), "cache", x.resp.get("X-Cache"), "age", x.resp.get("Age"), "ms", Math.round((x.tDone - x.tSend) * 10) / 10.0, "bytes", x.resp.body.length);
    }

    /** One hand-built request (the "request slip"): direct to the origin, across the WAN link, or via the proxy. */
    private String send(Map<String, String> q) throws Exception {
        String via = q.getOrDefault("via", "direct"), method = q.getOrDefault("method", "GET").trim().toUpperCase(), path = q.getOrDefault("path", "/").trim();
        String version = q.getOrDefault("version", "HTTP/1.1"), host = q.getOrDefault("host", Site.WWW).trim();
        if (!path.startsWith("/")) path = "/" + path;
        int p = "proxy".equals(via) ? proxyPort : "link".equals(via) ? linkPort : originPort;
        WebClient c = new WebClient("127.0.0.1", p, host.isEmpty() ? null : host);
        Msg r = Msg.request(method, "proxy".equals(via) ? "http://" + (host.isEmpty() ? Site.WWW : host) + path : path, version);
        if (!host.isEmpty()) r.set("Host", host);
        for (String line : q.getOrDefault("headers", "").split("\n")) {
            int i = line.indexOf(':'); if (i > 0) r.add(line.substring(0, i).trim(), line.substring(i + 1).trim());
        }
        String body = q.getOrDefault("body", "");
        if (!body.isEmpty() || method.equals("POST") || method.equals("PUT")) {
            r.body(body);
            if (!r.has("Content-Type")) r.set("Content-Type", method.equals("POST") ? "application/x-www-form-urlencoded" : "text/plain; charset=utf-8");
            r.set("Content-Length", r.body.length);
        }
        try (WebClient.Conn k = c.connect()) {
            WebClient.Exchange x = c.send(k, r);
            return exchange(x, "");
        }
    }

    private static String exchange(WebClient.Exchange x, String note) {
        Msg s = x.resp;
        List<String> chunks = new ArrayList<>(); for (int n : s.chunkSizes) chunks.add(String.valueOf(n));
        return Json.obj("rawRequest", x.rawRequest, "rawResponse", x.rawResponseHead, "status", s.status(), "reason", Codes.reason(s.status()), "family", Codes.family(s.status()),
            "meaning", Codes.meaning(s.status()), "body", s.preview(1800), "bodyBytes", s.body.length, "wireBytes", x.wireBytes, "chunks", Json.raw("[" + String.join(",", chunks) + "]"),
            "ms", Math.round((x.tDone - x.tSend) * 10) / 10.0, "note", note, "conn", x.conn, "newConn", x.newConnection);
    }

    // ------------------------------------------------------------------ scripted demos (stepped with Forward ▶ on the page)
    private String script(String name) throws Exception {
        List<String> steps = new ArrayList<>();
        WebClient c = new WebClient("127.0.0.1", originPort, Site.WWW);
        WebClient.Conn k = c.connect();
        try {
            switch (name) {
                case "conditional": {
                    WebClient.Exchange a = c.send(k, c.get("/news.html", "HTTP/1.1"));
                    steps.add(exchange(a, "First visit: 200 OK with the whole page, plus two validators: ETag " + a.resp.get("ETag") + " and Last-Modified."));
                    Msg b = c.get("/news.html", "HTTP/1.1").set("If-None-Match", a.resp.get("ETag")).set("If-Modified-Since", a.resp.get("Last-Modified"));
                    steps.add(exchange(c.send(k, b), "Revisit: the client asks 'only if changed' with If-None-Match. Unchanged → 304 Not Modified, an empty body. The cached copy is reused."));
                    site.editNews();
                    Msg d = c.get("/news.html", "HTTP/1.1").set("If-None-Match", a.resp.get("ETag"));
                    WebClient.Exchange dx = c.send(k, d);
                    steps.add(exchange(dx, "Someone edited the page on the server (new ETag " + dx.resp.get("ETag") + "). The same conditional GET now gets a full 200 with the new version."));
                    break;
                }
                case "range": {
                    steps.add(exchange(c.send(k, c.get("/big.bin", "HTTP/1.1").set("Range", "bytes=0-1023")), "Only the first KB: 206 Partial Content, Content-Range says which bytes of how many. Download managers resume like this (compare FTP's REST)."));
                    steps.add(exchange(c.send(k, c.get("/big.bin", "HTTP/1.1").set("Range", "bytes=-100")), "A suffix range: the last 100 bytes."));
                    steps.add(exchange(c.send(k, c.get("/big.bin", "HTTP/1.1").set("Range", "bytes=70000-")), "A range past the end (the file is 65536 bytes): 416 Range Not Satisfiable."));
                    break;
                }
                case "auth": {
                    steps.add(exchange(c.send(k, c.get("/private/", "HTTP/1.1")), "No credentials: 401 Unauthorized, and WWW-Authenticate tells the browser which scheme to use (it pops up the login box)."));
                    String cred = Base64.getEncoder().encodeToString("alice:alice123".getBytes(StandardCharsets.UTF_8));
                    steps.add(exchange(c.send(k, c.get("/private/", "HTTP/1.1").set("Authorization", "Basic " + cred)), "Retry with Authorization: Basic " + cred + ". That is only base64 of alice:alice123: encoding, not encryption. Anyone on the path can read it, so Basic is safe only over HTTPS."));
                    break;
                }
                case "cookies": {
                    steps.add(exchange(c.send(k, c.get("/cart", "HTTP/1.1")), "No cookie yet: to the server this request is from a stranger."));
                    Msg login = Msg.request("POST", "/login", "HTTP/1.1").set("Host", Site.WWW).set("Content-Type", "application/x-www-form-urlencoded").body("user=alice&pass=alice123");
                    login.set("Content-Length", login.body.length);
                    WebClient.Exchange lx = c.send(k, login);
                    steps.add(exchange(lx, "Log in with a POST: 303 See Other + Set-Cookie: sid=…. The client stores the cookie."));
                    Msg cart = c.get("/cart", "HTTP/1.1"); c.attachCookies(cart);
                    steps.add(exchange(c.send(k, cart), "The client sends Cookie: sid=… back. The server looks the id up and knows it is alice. The state lives on the server; the cookie is only the key."));
                    Msg add = Msg.request("POST", "/cart/add", "HTTP/1.1").set("Host", Site.WWW).set("Content-Type", "application/x-www-form-urlencoded").body("item=Forouzan+5e"); add.set("Content-Length", add.body.length); c.attachCookies(add);
                    steps.add(exchange(c.send(k, add), "Add to the cart: a POST, again identified only by the cookie."));
                    Msg cart2 = c.get("/cart", "HTTP/1.1"); c.attachCookies(cart2);
                    steps.add(exchange(c.send(k, cart2), "The cart remembers the item across separate requests."));
                    break;
                }
                case "methods": {
                    steps.add(exchange(c.send(k, Msg.request("OPTIONS", "/files/notes.txt", "HTTP/1.1").set("Host", Site.WWW)), "OPTIONS asks which methods a resource supports: the answer is in the Allow header."));
                    Msg put = Msg.request("PUT", "/files/notes.txt", "HTTP/1.1").set("Host", Site.WWW).set("Content-Type", "text/plain").body("CN viva notes, version 1\n"); put.set("Content-Length", put.body.length);
                    steps.add(exchange(c.send(k, put), "PUT stores the body at this exact URL: 201 Created the first time."));
                    Msg put2 = Msg.request("PUT", "/files/notes.txt", "HTTP/1.1").set("Host", Site.WWW).set("Content-Type", "text/plain").body("CN viva notes, version 2\n"); put2.set("Content-Length", put2.body.length);
                    steps.add(exchange(c.send(k, put2), "PUT again replaces it: 204 No Content. PUT is idempotent (doing it twice = doing it once); POST is not."));
                    steps.add(exchange(c.send(k, c.get("/files/notes.txt", "HTTP/1.1")), "GET reads it back."));
                    steps.add(exchange(c.send(k, Msg.request("DELETE", "/files/notes.txt", "HTTP/1.1").set("Host", Site.WWW)), "DELETE removes it: 204."));
                    steps.add(exchange(c.send(k, c.get("/files/notes.txt", "HTTP/1.1")), "Now it is gone: 404 Not Found."));
                    steps.add(exchange(c.send(k, Msg.request("DELETE", "/gallery.html", "HTTP/1.1").set("Host", Site.WWW)), "DELETE on a page that doesn't allow it: 405 Method Not Allowed (+ Allow)."));
                    steps.add(exchange(c.send(k, Msg.request("BREW", "/", "HTTP/1.1").set("Host", Site.WWW)), "A method the server has never heard of: 501 Not Implemented."));
                    break;
                }
                case "vhost": {
                    steps.add(exchange(c.send(k, c.get("/", "HTTP/1.1")), "Host: " + Site.WWW + " → the main site."));
                    steps.add(exchange(c.send(k, c.get("/", "HTTP/1.1").set("Host", Site.INTRANET)), "Same IP and port, Host: " + Site.INTRANET + " → a different site. This is virtual hosting, and why Host became mandatory in HTTP/1.1."));
                    Msg noHost = Msg.request("GET", "/", "HTTP/1.1");
                    steps.add(exchange(c.send(k, noHost), "HTTP/1.1 without Host: 400 Bad Request."));
                    k.close(); k = c.connect();
                    steps.add(exchange(c.send(k, Msg.request("GET", "/", "HTTP/1.0")), "HTTP/1.0 without Host is allowed (the server picks its default site), and the connection closes after the response."));
                    break;
                }
                case "chunked": {
                    steps.add(exchange(c.send(k, c.get("/clock", "HTTP/1.1")), "The server starts sending before it knows the total length, so there is no Content-Length: Transfer-Encoding: chunked. Each chunk = size in hex, CRLF, data, CRLF; a 0-size chunk ends the body."));
                    k.close(); k = c.connect();
                    Msg put = Msg.request("PUT", "/files/chunked.txt", "HTTP/1.1").set("Host", Site.WWW).set("Content-Type", "text/plain").body("This upload was sent in 16-byte chunks; the server reassembled it.\n");
                    put.chunked = true; put.chunkSize = 16;
                    steps.add(exchange(c.send(k, put), "Requests can be chunked too: this PUT body went out in 16-byte chunks (see the raw request). The server reassembled them and stored the file."));
                    break;
                }
                case "expect": {
                    Msg put = Msg.request("PUT", "/files/big-upload.txt", "HTTP/1.1").set("Host", Site.WWW).set("Content-Type", "text/plain").body("x".repeat(4000) + "\n");
                    steps.add(exchange(c.sendExpecting(k, put), "Expect: 100-continue: the client sends only the headers and waits. The server answers 100 Continue (an interim 1xx response), then the body goes, then the final 201. This avoids sending a big body the server would refuse."));
                    break;
                }
                case "gzip": {
                    WebClient.Exchange plain = c.send(k, c.get("/gallery.html", "HTTP/1.1"));
                    steps.add(exchange(plain, "Without Accept-Encoding: " + plain.resp.body.length + " bytes on the wire."));
                    WebClient.Exchange z = c.send(k, c.get("/gallery.html", "HTTP/1.1").set("Accept-Encoding", "gzip"));
                    steps.add(exchange(z, "With Accept-Encoding: gzip: Content-Encoding: gzip and only " + z.wireBytes + " bytes on the wire (the client decompressed them back to the same " + z.resp.body.length + " bytes). Vary: Accept-Encoding warns caches that the representation depends on this header."));
                    break;
                }
                case "redirect": {
                    WebClient.Exchange a = c.send(k, c.get("/old-page", "HTTP/1.1"));
                    steps.add(exchange(a, "301 Moved Permanently: the Location header gives the new URL. Browsers follow it automatically and update bookmarks."));
                    steps.add(exchange(c.send(k, c.get(a.resp.get("Location"), "HTTP/1.1")), "The client follows Location with a new GET."));
                    steps.add(exchange(c.send(k, c.get("/go", "HTTP/1.1")), "302 Found: temporarily elsewhere. Keep using the old URL next time."));
                    break;
                }
                default: return Json.obj("error", "unknown script " + name);
            }
        } finally { k.close(); }
        return Json.obj("name", name, "steps", Json.raw(Json.arr(steps)));
    }

    /** "Drive it by hand": send the typed text (LF → CRLF) on a fresh TCP connection and show every byte that comes back. */
    private String raw(String text) throws IOException {
        String req = text.replace("\r\n", "\n").replace("\n", "\r\n");
        if (!req.endsWith("\r\n\r\n")) req = req.endsWith("\r\n") ? req + "\r\n" : req + "\r\n\r\n";
        ByteArrayOutputStream got = new ByteArrayOutputStream();
        long t = System.nanoTime(); boolean closed = false;
        try (Socket s = new Socket(InetAddress.getByName("127.0.0.1"), originPort)) {
            s.setSoTimeout(1500);
            OutputStream o = s.getOutputStream(); o.write(req.getBytes(StandardCharsets.ISO_8859_1)); o.flush();
            InputStream in = new BufferedInputStream(s.getInputStream());
            byte[] b = new byte[8192]; int k;
            try { while ((k = in.read(b)) > 0) { got.write(b, 0, k); if (got.size() > 200_000) break; } closed = true; } catch (SocketTimeoutException e) { /* server keeps the connection open */ }
        }
        String r = new String(got.toByteArray(), StandardCharsets.ISO_8859_1);
        return Json.obj("sent", req, "received", r.length() > 12000 ? r.substring(0, 12000) + "\n… (" + (r.length() - 12000) + " more bytes)" : r, "bytes", got.size(),
            "closed", closed, "ms", (System.nanoTime() - t) / 1_000_000);
    }

    private String codes() {
        List<String> l = new ArrayList<>();
        for (Map.Entry<Integer, String[]> e : Codes.ALL.entrySet()) l.add(Json.obj("code", e.getKey(), "reason", e.getValue()[0], "meaning", e.getValue()[1], "family", Codes.family(e.getKey())));
        return Json.arr(l);
    }

    // ------------------------------------------------------------------ http helpers
    private static Map<String, String> params(HttpExchange ex) throws IOException {
        Map<String, String> m = new HashMap<>(); parse(ex.getRequestURI().getRawQuery(), m);
        if ("POST".equalsIgnoreCase(ex.getRequestMethod())) try (InputStream in = ex.getRequestBody()) { parse(new String(in.readAllBytes(), StandardCharsets.UTF_8), m); }
        return m;
    }
    private static void parse(String q, Map<String, String> m) {
        if (q == null || q.isEmpty()) return;
        for (String kv : q.split("&")) { int i = kv.indexOf('='); try { if (i > 0) m.put(URLDecoder.decode(kv.substring(0, i), "UTF-8"), URLDecoder.decode(kv.substring(i + 1), "UTF-8")); } catch (Exception ignored) { } }
    }
    private void file(HttpExchange ex) throws IOException {
        File f = new File(web, "dashboard.html");
        if (!f.exists()) { send(ex, 404, "text/plain", ("missing " + f.getAbsolutePath()).getBytes(StandardCharsets.UTF_8)); return; }
        send(ex, 200, "text/html; charset=utf-8", Files.readAllBytes(f.toPath()));
    }
    private static void json(HttpExchange ex, String s) throws IOException { send(ex, 200, "application/json; charset=utf-8", s.getBytes(StandardCharsets.UTF_8)); }
    private static void send(HttpExchange ex, int code, String type, byte[] b) throws IOException {
        ex.getResponseHeaders().set("Content-Type", type); ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream o = ex.getResponseBody()) { o.write(b); }
    }
}

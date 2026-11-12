package http.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.GZIPOutputStream;
import http.core.Codes;
import http.core.Hub;
import http.core.Msg;

/**
 * The content of our two virtual hosts and every HTTP feature we demonstrate:
 * virtual hosting (Host), keep-alive, conditional GET (ETag / Last-Modified → 304), Range (206),
 * cookies (Set-Cookie / Cookie), Basic authentication (401), redirects (301/302/303),
 * PUT / DELETE, chunked transfer coding, gzip content coding, and the standard error codes.
 */
public final class Site {

    public static final String WWW = "www.cse.myuniv.edu", INTRANET = "intranet.cse.myuniv.edu";
    public static final int IMAGES = 10;
    public static final Map<String, String> USERS = Map.of("alice", "alice123", "bob", "bob123", "subham", "ju2026");

    private final long started = System.currentTimeMillis() / 1000 * 1000;
    private volatile long newsModified = started;
    private volatile int newsVersion = 1;
    private final Map<String, byte[]> files = new ConcurrentHashMap<>();
    private final Map<String, Long> filesModified = new ConcurrentHashMap<>();
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final SecureRandom rnd = new SecureRandom();
    private final byte[] big;

    static final class Session { final String user; final List<String> cart = new ArrayList<>(); Session(String u) { user = u; } }

    public Site() {
        big = new byte[64 * 1024];
        for (int i = 0; i < big.length; i++) big[i] = (byte) ((i * 31 + (i >> 8)) & 0xff);
        files.put("readme.txt", "Files stored on the server with PUT, read with GET, removed with DELETE.\n".getBytes(StandardCharsets.UTF_8));
        filesModified.put("readme.txt", started);
    }

    /** Dashboard "edit the page on the server": bumps Last-Modified and the ETag of /news.html. */
    public void editNews() { newsVersion++; newsModified = Math.max(System.currentTimeMillis() / 1000 * 1000, newsModified + 1000); Hub.I.event("ORIGIN", "news.html edited on the server: now version " + newsVersion + " (new ETag, new Last-Modified)"); }
    public int newsVersion() { return newsVersion; }
    public int sessions() { return sessions.size(); }
    public byte[] big() { return big; }

    // ------------------------------------------------------------------ dispatch
    /** Returns the response, or null if the handler streamed its own response (chunked clock) and the connection must close. */
    public Msg handle(Msg req, String sess, OutputStream out) throws IOException {
        String v = req.version();
        String hostHdr = req.get("Host");
        if ("HTTP/1.1".equals(v) && hostHdr == null) return error(400, v, "HTTP/1.1 requires a Host header field (RFC 9112 §3.2): it says which virtual host you want.");
        String host = hostHdr == null ? WWW : hostHdr.replaceFirst(":\\d+$", "").toLowerCase();
        String m = req.method(), p;
        try { p = URLDecoder.decode(req.path(), "UTF-8"); } catch (Exception e) { return error(400, v, "bad percent-encoding"); }
        if (p.startsWith("http://")) { int i = p.indexOf('/', 7); host = p.substring(7, i < 0 ? p.length() : i).replaceFirst(":\\d+$", ""); p = i < 0 ? "/" : p.substring(i); }   // absolute-form
        if (!List.of("GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS").contains(m)) return error(501, v, "Method " + m + " is not implemented here.").set("Allow", "GET, HEAD, POST, PUT, DELETE, OPTIONS");

        if (host.equals(INTRANET)) return intranet(req, m, p, v);

        if (m.equals("OPTIONS")) return Msg.response(v11(v), 204).set("Date", Msg.now()).set("Server", server()).set("Allow", allow(p));
        if (p.equals("/") || p.equals("/index.html")) return page(req, v, "text/html; charset=utf-8", lobby(host), started, "\"lobby-1\"", "no-cache", m);
        if (p.equals("/gallery.html")) return page(req, v, "text/html; charset=utf-8", gallery(), started, "\"gallery-1\"", "max-age=30", m);
        if (p.startsWith("/img/") && p.endsWith(".svg")) {
            int n; try { n = Integer.parseInt(p.substring(5, p.length() - 4)); } catch (Exception e) { n = -1; }
            if (n < 1 || n > IMAGES) return error(404, v, "No image " + p);
            return page(req, v, "image/svg+xml", svg(n), started, "\"img-" + n + "\"", "max-age=300", m);
        }
        if (p.equals("/news.html")) return page(req, v, "text/html; charset=utf-8", news(), newsModified, "\"news-" + newsVersion + "\"", "max-age=5", m);
        if (p.equals("/big.bin")) return page(req, v, "application/octet-stream", big, started, "\"big-1\"", "max-age=300", m);
        if (p.equals("/old-page")) return redirect(301, v, "/news.html");
        if (p.equals("/go")) return redirect(302, v, "/gallery.html");
        if (p.equals("/login")) return login(req, v, m);
        if (p.equals("/logout")) { Msg r = redirect(303, v, "/cart"); r.add("Set-Cookie", "sid=; Path=/; Max-Age=0"); return r; }
        if (p.equals("/cart") || p.equals("/cart/add")) return cart(req, v, m, p);
        if (p.startsWith("/private")) return privateArea(req, v, m);
        if (p.equals("/files/") || p.equals("/files")) return listFiles(req, v, m);
        if (p.startsWith("/files/")) return fileOp(req, v, m, p.substring(7));
        if (p.equals("/echo")) return echo(req, v);
        if (p.equals("/slow")) { int ms = 1000; try { ms = Math.min(5000, Integer.parseInt(param(req.query(), "ms", "1000"))); } catch (Exception ignored) { } sleep(ms); return page(req, v, "text/plain; charset=utf-8", ("slept " + ms + " ms before answering\n").getBytes(StandardCharsets.UTF_8), System.currentTimeMillis(), null, "no-store", m); }
        if (p.equals("/clock")) {
            if (!"HTTP/1.1".equals(v) || m.equals("HEAD")) return page(req, v, "text/plain; charset=utf-8", "chunked streaming needs HTTP/1.1\n".getBytes(StandardCharsets.UTF_8), System.currentTimeMillis(), null, "no-store", m);
            return clock(out, sess);
        }
        if (p.equals("/teapot")) return error(403, v, "This is not a teapot. (Try a real status code: 2xx, 3xx, 4xx, 5xx.)");
        if (p.equals("/crash")) return error(500, v, "Simulated server bug: the request was fine, the server failed.");
        if (p.equals("/favicon.ico")) return error(404, v, "no favicon");
        return error(404, v, "Nothing at " + p + " on " + host + ".");
    }

    // ------------------------------------------------------------------ building blocks
    private static String server() { return "JU-HTTP/1.1 (pure Java)"; }
    private static String v11(String v) { return "HTTP/1.1"; }
    private static String allow(String p) {
        if (p.startsWith("/files/")) return "GET, HEAD, PUT, DELETE, OPTIONS";
        if (p.equals("/login") || p.equals("/cart/add") || p.equals("/echo")) return "GET, HEAD, POST, OPTIONS";
        return "GET, HEAD, OPTIONS";
    }

    public Msg error(int code, String v, String why) {
        String html = "<!doctype html><title>" + code + " " + Codes.reason(code) + "</title><h1>" + code + " " + Codes.reason(code) + "</h1><p>" + esc(why) + "</p><p><i>" + Codes.meaning(code) + "</i></p>";
        return Msg.response("HTTP/1.1", code).set("Date", Msg.now()).set("Server", server()).set("Content-Type", "text/html; charset=utf-8").set("Cache-Control", "no-store").body(html);
    }

    private Msg redirect(int code, String v, String to) {
        return Msg.response("HTTP/1.1", code).set("Date", Msg.now()).set("Server", server()).set("Location", to).set("Content-Type", "text/html; charset=utf-8").body("<a href=\"" + to + "\">" + to + "</a>");
    }

    /** A cacheable representation: conditional GET, Range, gzip and HEAD all handled here. */
    private Msg page(Msg req, String v, String type, byte[] content, long modified, String etag, String cacheControl, String method) {
        if (!method.equals("GET") && !method.equals("HEAD")) return error(405, v, method + " is not allowed on " + req.path()).set("Allow", allow(req.path()));
        Msg r = Msg.response("HTTP/1.1", 200).set("Date", Msg.now()).set("Server", server()).set("Content-Type", type);
        if (cacheControl != null) r.set("Cache-Control", cacheControl);
        boolean validators = etag != null;
        if (validators) { r.set("Last-Modified", Msg.date(modified)).set("ETag", etag); }
        // ---- conditional GET (RFC 9110 §13): If-None-Match wins over If-Modified-Since
        if (validators) {
            String inm = req.get("If-None-Match"), ims = req.get("If-Modified-Since");
            boolean notModified = false;
            if (inm != null) { for (String t : inm.split(",")) if (t.trim().equals(etag) || t.trim().equals("*")) notModified = true; }
            else if (ims != null) { long since = Msg.parseDate(ims); notModified = since >= 0 && modified / 1000 <= since / 1000; }
            if (notModified) {
                Msg nm = Msg.response("HTTP/1.1", 304).set("Date", Msg.now()).set("Server", server()).set("ETag", etag).set("Last-Modified", Msg.date(modified));
                if (cacheControl != null) nm.set("Cache-Control", cacheControl);
                return nm;
            }
        }
        // ---- byte ranges (RFC 9110 §14)
        String range = req.get("Range");
        if (range != null && validators && method.equals("GET")) {
            r.set("Accept-Ranges", "bytes");
            long[] ab = parseRange(range, content.length);
            if (ab == null) return error(416, v, "Range " + range + " is outside 0-" + (content.length - 1)).set("Content-Range", "bytes */" + content.length);
            int a = (int) ab[0], b = (int) ab[1];
            byte[] part = new byte[b - a + 1]; System.arraycopy(content, a, part, 0, part.length);
            r.start = "HTTP/1.1 206 Partial Content";
            return r.set("Content-Range", "bytes " + a + "-" + b + "/" + content.length).body(part);
        }
        if (validators) r.set("Accept-Ranges", "bytes");
        // ---- content coding: gzip text if the client says it can decode it
        boolean textual = type.startsWith("text/") || type.contains("svg");
        if (textual && content.length > 256 && accepts(req.get("Accept-Encoding"), "gzip")) {
            r.set("Content-Encoding", "gzip").set("Vary", "Accept-Encoding");
            return r.body(gzip(content));
        }
        return r.body(content);
    }

    static long[] parseRange(String h, int len) {
        if (!h.startsWith("bytes=") || h.contains(",")) return null;
        String s = h.substring(6).trim(); int d = s.indexOf('-'); if (d < 0) return null;
        try {
            long a, b;
            if (d == 0) { long n = Long.parseLong(s.substring(1)); if (n <= 0) return null; a = Math.max(0, len - n); b = len - 1; }
            else { a = Long.parseLong(s.substring(0, d)); b = d == s.length() - 1 ? len - 1 : Math.min(len - 1, Long.parseLong(s.substring(d + 1))); }
            if (a >= len || a > b) return null;
            return new long[] { a, b };
        } catch (NumberFormatException e) { return null; }
    }

    private static boolean accepts(String ae, String coding) {
        if (ae == null) return false;
        for (String t : ae.split(",")) { String[] p = t.trim().split(";"); if (p[0].trim().equalsIgnoreCase(coding)) return !(p.length > 1 && p[1].replace(" ", "").equals("q=0")); }
        return false;
    }

    public static byte[] gzip(byte[] b) {
        try { ByteArrayOutputStream o = new ByteArrayOutputStream(); try (GZIPOutputStream g = new GZIPOutputStream(o)) { g.write(b); } return o.toByteArray(); }
        catch (IOException e) { return b; }
    }

    // ------------------------------------------------------------------ cookies: state on a stateless protocol
    private Session session(Msg req) {
        for (String c : req.all("Cookie")) for (String kv : c.split(";")) { String[] p = kv.trim().split("=", 2); if (p.length == 2 && p[0].equals("sid")) { Session s = sessions.get(p[1]); if (s != null) return s; } }
        return null;
    }

    private Msg login(Msg req, String v, String m) {
        if (m.equals("GET") || m.equals("HEAD"))
            return page(req, v, "text/html; charset=utf-8", wrap("Log in", "<form method=post action=/login><label>user <input name=user value=alice></label> <label>password <input name=pass type=password value=alice123></label> <button>Log in</button></form><p>The server answers with <code>Set-Cookie: sid=…</code>. Your browser sends it back on every later request: that is how a stateless protocol remembers you.</p>"), System.currentTimeMillis(), null, "no-store", m);
        if (!m.equals("POST")) return error(405, v, "Use POST to log in.").set("Allow", "GET, HEAD, POST, OPTIONS");
        Map<String, String> f = form(req.text());
        String u = f.getOrDefault("user", ""), pw = f.getOrDefault("pass", "");
        if (!pw.equals(USERS.get(u))) return error(403, v, "Wrong user name or password.");
        byte[] id = new byte[12]; rnd.nextBytes(id);
        String sid = Base64.getUrlEncoder().withoutPadding().encodeToString(id);
        sessions.put(sid, new Session(u));
        Hub.I.event("COOKIE", "login: " + u + " gets Set-Cookie sid=" + sid);
        Msg r = redirect(303, v, "/cart");
        r.add("Set-Cookie", "sid=" + sid + "; Path=/; HttpOnly; SameSite=Lax");
        return r;
    }

    private Msg cart(Msg req, String v, String m, String p) {
        Session s = session(req);
        if (p.equals("/cart/add")) {
            if (!m.equals("POST")) return error(405, v, "Use POST to add to the cart.").set("Allow", "POST, OPTIONS");
            if (s == null) return error(401, v, "Who are you? No session cookie came with this request: log in first.");
            String item = form(req.text()).getOrDefault("item", "something");
            s.cart.add(item);
            return redirect(303, v, "/cart");
        }
        String body = s == null
            ? "<p><b>Who are you?</b> This request carried no <code>Cookie</code> header, so to the server it is a stranger. HTTP itself remembers nothing between requests.</p><p><a href=/login>Log in</a></p>"
            : "<p>Hello <b>" + esc(s.user) + "</b>: the server recognised you from the cookie alone.</p><p>Cart (" + s.cart.size() + "): " + esc(String.join(", ", s.cart)) + "</p><form method=post action=/cart/add><input name=item value=\"CN textbook\"><button>Add</button></form><p><a href=/logout>Log out</a> (Set-Cookie with Max-Age=0)</p>";
        return page(req, v, "text/html; charset=utf-8", wrap("Cart", body), System.currentTimeMillis(), null, "no-store, private", m);
    }

    // ------------------------------------------------------------------ Basic authentication
    private Msg privateArea(Msg req, String v, String m) {
        String a = req.get("Authorization");
        if (a != null && a.regionMatches(true, 0, "Basic ", 0, 6)) {
            String dec;
            try { dec = new String(Base64.getDecoder().decode(a.substring(6).trim()), StandardCharsets.UTF_8); } catch (IllegalArgumentException e) { dec = ""; }
            int c = dec.indexOf(':');
            if (c > 0 && dec.substring(c + 1).equals(USERS.get(dec.substring(0, c)))) {
                Hub.I.event("AUTH", "Basic credentials accepted for " + dec.substring(0, c) + " (they crossed the wire only base64-encoded: not encrypted)");
                return page(req, v, "text/html; charset=utf-8", wrap("Staff area", "<p>Welcome, <b>" + esc(dec.substring(0, c)) + "</b>. You sent <code>Authorization: " + esc(a) + "</code>.</p><p>That is just base64 of <code>" + esc(dec.substring(0, c)) + ":********</code>: anyone on the path can decode it. Use HTTPS.</p>"), System.currentTimeMillis(), null, "no-store, private", m);
            }
        }
        return error(401, v, "This area needs a user name and password.").set("WWW-Authenticate", "Basic realm=\"CSE staff\", charset=\"UTF-8\"");
    }

    // ------------------------------------------------------------------ PUT / DELETE
    private Msg listFiles(Msg req, String v, String m) {
        StringBuilder b = new StringBuilder("<ul>");
        for (String n : new java.util.TreeSet<>(files.keySet())) b.append("<li><a href=\"/files/").append(esc(n)).append("\">").append(esc(n)).append("</a> (").append(files.get(n).length).append(" B)");
        return page(req, v, "text/html; charset=utf-8", wrap("Files", b.append("</ul><p>Upload with <code>PUT /files/name</code>, remove with <code>DELETE</code>.</p>").toString()), System.currentTimeMillis(), null, "no-cache", m);
    }

    private Msg fileOp(Msg req, String v, String m, String name) {
        if (name.isEmpty() || name.contains("/") || name.contains("\\") || name.startsWith(".") || name.length() > 80) return error(400, v, "Bad file name.");
        switch (m) {
            case "PUT": {
                boolean existed = files.containsKey(name);
                files.put(name, req.body); filesModified.put(name, System.currentTimeMillis() / 1000 * 1000);
                Hub.I.event("ORIGIN", "PUT /files/" + name + ": " + req.body.length + " bytes " + (existed ? "replaced" : "created") + (req.chunked ? " (the request body came chunked)" : ""));
                if (existed) return Msg.response("HTTP/1.1", 204).set("Date", Msg.now()).set("Server", server());
                return Msg.response("HTTP/1.1", 201).set("Date", Msg.now()).set("Server", server()).set("Location", "/files/" + name).set("Content-Type", "text/plain; charset=utf-8").body("created /files/" + name + " (" + req.body.length + " bytes)\n");
            }
            case "DELETE":
                if (files.remove(name) == null) return error(404, v, "No file " + name);
                Hub.I.event("ORIGIN", "DELETE /files/" + name);
                return Msg.response("HTTP/1.1", 204).set("Date", Msg.now()).set("Server", server());
            case "GET": case "HEAD": {
                byte[] b = files.get(name);
                if (b == null) return error(404, v, "No file " + name);
                return page(req, v, name.endsWith(".txt") ? "text/plain; charset=utf-8" : name.endsWith(".html") ? "text/html; charset=utf-8" : "application/octet-stream", b, filesModified.getOrDefault(name, started), "\"f-" + Integer.toHexString(java.util.Arrays.hashCode(b)) + "\"", "no-cache", m);
            }
            default: return error(405, v, m + " is not allowed on files.").set("Allow", allow("/files/x"));
        }
    }

    // ------------------------------------------------------------------ chunked streaming
    private Msg clock(OutputStream out, String sess) throws IOException {
        String head = "HTTP/1.1 200 OK\r\nDate: " + Msg.now() + "\r\nServer: " + server() + "\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
        out.write(head.getBytes(StandardCharsets.ISO_8859_1)); out.flush();
        Hub.I.line(new Hub.Line(sess, "HTTP", false, "HTTP/1.1 200 OK   [Transfer-Encoding: chunked: length unknown in advance]", "the server starts answering before it knows how long the body will be"));
        for (int i = 1; i <= 5; i++) {
            String piece = "tick " + i + " at " + java.time.LocalTime.now().withNano(0) + "\n";
            byte[] b = piece.getBytes(StandardCharsets.UTF_8);
            out.write((Integer.toHexString(b.length) + "\r\n").getBytes(StandardCharsets.ISO_8859_1)); out.write(b); out.write("\r\n".getBytes(StandardCharsets.ISO_8859_1)); out.flush();
            Hub.I.line(new Hub.Line(sess, "HTTP", false, "chunk " + Integer.toHexString(b.length) + " (" + b.length + " bytes): " + piece.trim(), "one chunk = hex size, CRLF, data, CRLF"));
            sleep(300);
        }
        out.write("0\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1)); out.flush();
        Hub.I.line(new Hub.Line(sess, "HTTP", false, "chunk 0: end of body", "a zero-size chunk ends the message"));
        return null;
    }

    private Msg echo(Msg req, String v) {
        StringBuilder b = new StringBuilder("This is exactly what your client sent:\n\n").append(req.rawHead);
        if (req.body.length > 0) b.append(new String(req.body, StandardCharsets.UTF_8));
        return Msg.response("HTTP/1.1", 200).set("Date", Msg.now()).set("Server", server()).set("Content-Type", "text/plain; charset=utf-8").set("Cache-Control", "no-store").body(b.toString());
    }

    private Msg intranet(Msg req, String m, String p, String v) {
        if (!p.equals("/") && !p.equals("/index.html")) return error(404, v, "The intranet host has only a front page.");
        return page(req, v, "text/html; charset=utf-8", wrap("CSE intranet", "<p>Same IP address, same port, <b>different site</b>. The server chose this page only because the request said <code>Host: " + INTRANET + "</code>. That is <b>virtual hosting</b>.</p>"), started, "\"intra-1\"", "max-age=60", m);
    }

    // ------------------------------------------------------------------ pages
    private static byte[] wrap(String title, String body) {
        return ("<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>" + esc(title) + "</title>"
            + "<style>body{font:17px/1.55 Georgia,serif;max-width:46rem;margin:2rem auto;padding:0 1rem;background:#f3ecdc;color:#1f2a24}h1{font-weight:normal;border-bottom:3px double #1f2a24}code{background:#e6dcc6;padding:0 .25em}a{color:#2f5d50}</style>"
            + "<h1>" + esc(title) + "</h1>" + body + "<hr><small>JU-HTTP · cse.myuniv.edu</small></html>").getBytes(StandardCharsets.UTF_8);
    }

    private byte[] lobby(String host) {
        return wrap("cse.myuniv.edu: the reading room", "<p>This page came from our own HTTP/1.1 server (no libraries). Try each link and watch the dashboard.</p><ul>"
            + "<li><a href=/gallery.html>gallery.html</a>: one page + " + IMAGES + " images (persistent vs non-persistent)"
            + "<li><a href=/news.html>news.html</a>: cacheable for 5 s, then revalidated (304)"
            + "<li><a href=/login>login</a> and <a href=/cart>cart</a>: cookies"
            + "<li><a href=/private/>private/</a>: Basic authentication (alice / alice123)"
            + "<li><a href=/old-page>old-page</a> (301) · <a href=/go>go</a> (302)"
            + "<li><a href=/clock>clock</a>: a chunked response that arrives tick by tick"
            + "<li><a href=/files/>files/</a>: PUT and DELETE · <a href=/echo>echo</a>: see your own request"
            + "<li><a href=/nothing-here>nothing-here</a> (404) · <a href=/crash>crash</a> (500)</ul>");
    }

    private byte[] gallery() {
        StringBuilder b = new StringBuilder("<p>One base page plus " + IMAGES + " referenced objects. The browser must fetch each one: with HTTP/1.0 that means " + (IMAGES + 1) + " TCP connections.</p><div style=\"display:grid;grid-template-columns:repeat(5,1fr);gap:8px\">");
        for (int i = 1; i <= IMAGES; i++) b.append("<img src=\"/img/").append(i).append(".svg\" alt=\"plate ").append(i).append("\" width=120 height=120>");
        return wrap("Gallery", b.append("</div>").toString());
    }

    private byte[] news() {
        return wrap("Department news (version " + newsVersion + ")", "<p>Last modified " + Msg.date(newsModified) + ".</p><p>Cache-Control: max-age=5. For 5 seconds a cache may answer without asking; after that it must <b>revalidate</b> with If-None-Match / If-Modified-Since. If the page hasn't changed, the answer is a tiny <b>304 Not Modified</b> with no body.</p>");
    }

    /** Ten distinct "plates" (each a few KB) so the gallery has real objects to transfer. */
    static byte[] svg(int n) {
        String[] ink = { "#2f5d50", "#b3261e", "#a8812c", "#1f2a24", "#5b6f8a" };
        StringBuilder b = new StringBuilder("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 120 120\" width=\"120\" height=\"120\"><rect width=\"120\" height=\"120\" fill=\"#efe6d2\"/>");
        String c = ink[n % ink.length];
        for (int i = 0; i < 40; i++) {
            double a = (i * (n + 2) * 0.37), r = 8 + (i * 7 + n * 13) % 44;
            b.append(String.format(java.util.Locale.ROOT, "<circle cx=\"%.1f\" cy=\"%.1f\" r=\"%.1f\" fill=\"none\" stroke=\"%s\" stroke-width=\"%.1f\" opacity=\"%.2f\"/>", 60 + Math.cos(a) * r, 60 + Math.sin(a) * r, 3 + (i % 5) * 1.5, c, 0.6 + (i % 3) * 0.4, 0.35 + (i % 4) * 0.15));
        }
        b.append("<text x=\"60\" y=\"112\" text-anchor=\"middle\" font-family=\"Georgia\" font-size=\"11\" fill=\"#1f2a24\">plate ").append(n).append("</text></svg>");
        return b.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------ helpers
    public String explainResponse(Msg r) {
        int s = r.status();
        StringBuilder b = new StringBuilder(Codes.family(s)).append(": ").append(Codes.meaning(s));
        if (r.has("Set-Cookie")) b.append(" · sets a cookie");
        if (r.has("Location")) b.append(" · → ").append(r.get("Location"));
        if (r.has("Content-Range")) b.append(" · ").append(r.get("Content-Range"));
        return b.toString();
    }

    static Map<String, String> form(String body) {
        Map<String, String> m = new LinkedHashMap<>();
        for (String kv : body.split("&")) { int i = kv.indexOf('='); if (i > 0) try { m.put(URLDecoder.decode(kv.substring(0, i), "UTF-8"), URLDecoder.decode(kv.substring(i + 1), "UTF-8")); } catch (Exception ignored) { } }
        return m;
    }
    static String param(String q, String k, String def) { String v = form(q).get(k); return v == null ? def : v; }
    static String esc(String s) { return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;"); }
    static void sleep(long ms) { try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); } }
}

package ftp.dashboard;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import ftp.client.FtpClient;
import ftp.core.Hub;
import ftp.core.Json;
import ftp.server.FtpServer;
import ftp.tap.Tap;

/** HTTP API + static page for the FTP dashboard (http://localhost:8086). Every demo uses our real client against our real server. */
public final class DashboardServer {

    private final int port, ftpPort; private final FtpServer srv; private final Tap tap; private final File web, local;
    private HttpServer http;

    public DashboardServer(int port, int ftpPort, FtpServer srv, Tap tap, File web, File local) { this.port = port; this.ftpPort = ftpPort; this.srv = srv; this.tap = tap; this.web = web; this.local = local; }

    public void start() throws IOException {
        http = HttpServer.create(new InetSocketAddress(port), 0);
        http.createContext("/", this::route);
        http.setExecutor(Executors.newFixedThreadPool(12));
        http.start();
    }
    public void stop() { if (http != null) http.stop(0); for (Raw r : raws.values()) r.close(); }

    private void route(HttpExchange ex) throws IOException {
        Map<String, String> q = params(ex);
        try {
            switch (ex.getRequestURI().getPath()) {
                case "/": case "/index.html": file(ex); return;
                case "/api/state": json(ex, state()); return;
                case "/api/lines": json(ex, lines(Long.parseLong(q.getOrDefault("since", "0")))); return;
                case "/api/run": json(ex, run(q)); return;
                case "/api/modes": json(ex, modes()); return;
                case "/api/resume": json(ex, resume(Double.parseDouble(q.getOrDefault("cut", "0.4")))); return;
                case "/api/fm": json(ex, fm(q)); return;
                case "/api/tap": json(ex, tapRun("1".equals(q.get("tls")))); return;
                case "/api/real": json(ex, real(q)); return;
                case "/api/settings":
                    if (q.containsKey("slow")) srv.slowLink = "1".equals(q.get("slow"));
                    if (q.containsKey("anon")) srv.allowAnonymous = "1".equals(q.get("anon"));
                    json(ex, state()); return;
                case "/api/raw/open": json(ex, rawOpen()); return;
                case "/api/raw/send": json(ex, rawSend(Integer.parseInt(q.get("id")), q.getOrDefault("line", ""))); return;
                case "/api/raw/read": json(ex, rawRead(Integer.parseInt(q.get("id")), Integer.parseInt(q.getOrDefault("c", "0")), Integer.parseInt(q.getOrDefault("d", "0")))); return;
                case "/api/raw/close": { Raw r = raws.remove(Integer.parseInt(q.get("id"))); if (r != null) r.close(); json(ex, "{}"); return; }
                default: send(ex, 404, "text/plain", "not found".getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception e) { json(ex, Json.obj("error", e.getClass().getSimpleName() + ": " + e.getMessage())); }
    }

    private FtpClient alice(FtpClient.Mode m) throws IOException { FtpClient c = new FtpClient("127.0.0.1", ftpPort); c.mode = m; c.login("alice", "alice123"); return c; }

    private String state() {
        List<String> logs = new ArrayList<>(); for (String l : Hub.I.logs()) logs.add(Json.str(l));
        List<String> ev = new ArrayList<>(); for (Hub.Event e : Hub.I.eventsSince(0)) ev.add(e.json());
        return Json.obj("server", Json.raw(srv.json()), "tapPort", Tap.PORT, "logs", Json.raw("[" + String.join(",", logs.subList(Math.max(0, logs.size() - 120), logs.size())) + "]"),
                "events", Json.raw("[" + String.join(",", ev.subList(Math.max(0, ev.size() - 30), ev.size())) + "]"));
    }
    private String lines(long since) {
        List<String> l = new ArrayList<>(); for (Hub.Line x : Hub.I.linesSince(since)) l.add(x.json());
        if (l.size() > 800) l = l.subList(l.size() - 800, l.size());
        return Json.obj("lines", Json.raw("[" + String.join(",", l) + "]"));
    }

    // ------------------------------------------------------------------ 1. one operation, fully traced (two connections, active vs passive, firewall)
    private String run(Map<String, String> q) throws IOException {
        FtpClient c = new FtpClient("127.0.0.1", ftpPort);
        String result = "", error = null;
        try {
            c.mode = "active".equals(q.get("mode")) ? FtpClient.Mode.ACTIVE : FtpClient.Mode.PASSIVE;
            c.firewall = "1".equals(q.get("firewall"));
            if ("1".equals(q.get("tls"))) c.authTls(true);
            c.login("alice", "alice123");
            String op = q.getOrDefault("op", "list");
            if (op.equals("retr")) { c.type('I'); ByteArrayOutputStream b = new ByteArrayOutputStream(); FtpClient.Reply r = c.retr("/pub/rfc959-notes.txt", b, 0, -1, null); result = r.code == 226 ? b.toString(StandardCharsets.UTF_8) : r.text; if (r.code != 226) error = r.text; }
            else if (op.equals("stor")) { c.type('I'); FtpClient.Reply r = c.stor("upload-" + System.currentTimeMillis() % 100000 + ".txt", new ByteArrayInputStream("uploaded by the dashboard\n".getBytes(StandardCharsets.UTF_8))); result = r.text; if (r.code != 226) error = r.text; }
            else { try { result = new String(c.list("/pub"), StandardCharsets.UTF_8); } catch (IOException e) { error = e.getMessage(); } }
            c.quit();
        } catch (IOException e) { error = e.getMessage(); c.close(); }
        return Json.obj("trace", Json.raw(c.traceJson()), "result", result, "error", error, "mode", q.getOrDefault("mode", "passive"), "firewall", "1".equals(q.get("firewall")));
    }

    // ------------------------------------------------------------------ 2. ASCII vs binary: what TYPE A does to an image
    private static String sha(byte[] b) throws Exception { byte[] d = MessageDigest.getInstance("SHA-256").digest(b); StringBuilder s = new StringBuilder(); for (int i = 0; i < 8; i++) s.append(String.format("%02x", d[i])); return s.toString(); }
    private static String hexWin(byte[] b, int from, int n) { StringBuilder s = new StringBuilder(); for (int i = from; i < Math.min(b.length, from + n); i++) s.append(String.format("%02x ", b[i])); return s.toString().trim(); }
    private String modes() throws Exception {
        try (FtpClient c = alice(FtpClient.Mode.PASSIVE)) {
            c.type('I'); ByteArrayOutputStream orig = new ByteArrayOutputStream(); c.retr("/pub/logo.png", orig, 0, -1, null);
            byte[] o = orig.toByteArray();
            c.type('A'); c.stor("/home/alice/logo-ascii.png", new ByteArrayInputStream(o));
            c.type('I'); c.stor("/home/alice/logo-binary.png", new ByteArrayInputStream(o));
            ByteArrayOutputStream a = new ByteArrayOutputStream(), b = new ByteArrayOutputStream();
            c.retr("/home/alice/logo-ascii.png", a, 0, -1, null); c.retr("/home/alice/logo-binary.png", b, 0, -1, null);
            byte[] ab = a.toByteArray(), bb = b.toByteArray();
            int diff = -1; for (int i = 0; i < Math.min(o.length, ab.length); i++) if (o[i] != ab[i]) { diff = i; break; }
            // text file: LF on disk, CRLF on the wire in ASCII mode
            ByteArrayOutputStream ta = new ByteArrayOutputStream(), ti = new ByteArrayOutputStream();
            c.type('A'); c.retr("/pub/readme.txt", ta, 0, -1, null); c.type('I'); c.retr("/pub/readme.txt", ti, 0, -1, null);
            c.quit();
            int w = Math.max(0, diff - 4);
            return Json.obj("orig", Json.raw(Json.obj("size", o.length, "sha", sha(o), "img", Base64.getEncoder().encodeToString(o))),
                    "ascii", Json.raw(Json.obj("size", ab.length, "sha", sha(ab), "img", Base64.getEncoder().encodeToString(ab), "same", java.util.Arrays.equals(o, ab))),
                    "binary", Json.raw(Json.obj("size", bb.length, "sha", sha(bb), "img", Base64.getEncoder().encodeToString(bb), "same", java.util.Arrays.equals(o, bb))),
                    "diff", diff, "origHex", hexWin(o, w, 16), "asciiHex", hexWin(ab, w, 16), "hexFrom", w,
                    "textA", Json.raw(Json.obj("size", ta.size(), "hex", hexWin(ta.toByteArray(), 0, 48))), "textI", Json.raw(Json.obj("size", ti.size(), "hex", hexWin(ti.toByteArray(), 0, 48))),
                    "trace", Json.raw(c.traceJson()));
        }
    }

    // ------------------------------------------------------------------ 3. REST: break a download, then resume it
    private String resume(double cut) throws Exception {
        File f = new File(srv.root, "pub/big.bin");
        long total = f.length(), stop = (long) (total * Math.max(0.05, Math.min(0.95, cut)));
        ByteArrayOutputStream got = new ByteArrayOutputStream();
        long t0 = System.currentTimeMillis();
        FtpClient c = alice(FtpClient.Mode.PASSIVE);
        c.type('I');
        FtpClient.Reply r1 = c.retr("/pub/big.bin", got, 0, stop, null);
        long part = got.size(), t1 = System.currentTimeMillis();
        long size = c.size("/pub/big.bin");
        FtpClient.Reply r2 = c.retr("/pub/big.bin", got, part, -1, null);
        long t2 = System.currentTimeMillis();
        c.quit();
        byte[] all = got.toByteArray(), server = Files.readAllBytes(f.toPath());
        return Json.obj("total", total, "part", part, "after", all.length, "size", size, "first", r1.text, "second", r2.text,
                "ms1", t1 - t0, "ms2", t2 - t1, "sha", sha(all), "serverSha", sha(server), "ok", java.util.Arrays.equals(all, server), "trace", Json.raw(c.traceJson()));
    }

    // ------------------------------------------------------------------ 4. file manager (local folder ↔ server)
    private String fm(Map<String, String> q) throws Exception {
        String op = q.getOrDefault("op", "ls"), path = q.getOrDefault("path", "/home/alice"), name = q.getOrDefault("name", "");
        String msg = "";
        FtpClient.Mode m = "active".equals(q.get("mode")) ? FtpClient.Mode.ACTIVE : FtpClient.Mode.PASSIVE;
        try (FtpClient c = alice(m)) {
            c.type('I');
            FtpClient.Reply r;
            switch (op) {
                case "get": { ByteArrayOutputStream b = new ByteArrayOutputStream(); r = c.retr(path + "/" + name, b, 0, -1, null); if (r.code == 226) Files.write(new File(local, name).toPath(), b.toByteArray()); msg = r.text; break; }
                case "put": { File lf = new File(local, name); try (InputStream fi = new java.io.FileInputStream(lf)) { r = c.stor(path + "/" + name, fi); } msg = r.text; break; }
                case "del": msg = c.cmd("DELE " + path + "/" + name).text; break;
                case "mkdir": msg = c.cmd("MKD " + path + "/" + name).text; break;
                case "rmdir": msg = c.cmd("RMD " + path + "/" + name).text; break;
                case "rename": { r = c.cmd("RNFR " + path + "/" + name); msg = r.code == 350 ? c.cmd("RNTO " + path + "/" + q.getOrDefault("to", name + ".old")).text : r.text; break; }
                case "ldel": msg = new File(local, name).delete() ? "deleted locally" : "not found"; break;
                default: break;
            }
            String listing = new String(c.list(path), StandardCharsets.UTF_8);
            String pwd = path;
            c.quit();
            List<String> lf = new ArrayList<>();
            File[] files = local.listFiles(); if (files != null) for (File x : files) if (x.isFile()) lf.add(Json.obj("name", x.getName(), "size", x.length()));
            return Json.obj("path", pwd, "listing", listing, "local", Json.raw("[" + String.join(",", lf) + "]"), "msg", msg, "trace", Json.raw(c.traceJson()));
        }
    }

    // ------------------------------------------------------------------ 5. the wire tap: plain FTP vs FTPS
    private String tapRun(boolean tls) throws Exception {
        int before = tap.latest();
        FtpClient c = new FtpClient("127.0.0.1", Tap.PORT);
        if (tls) c.authTls(true);
        c.login("alice", "alice123");
        c.list("/home/alice");
        c.quit();
        Thread.sleep(300);
        int conn = tap.latest();
        return Json.obj("conn", conn, "tls", tls, "frames", Json.raw(tap.json(conn > before ? conn : -1)));
    }

    // ------------------------------------------------------------------ 6. our client against a real FTP server
    private String real(Map<String, String> q) {
        String host = q.getOrDefault("host", "test.rebex.net"); int p = Integer.parseInt(q.getOrDefault("port", "21"));
        FtpClient c = null; String listing = "", error = null, pwd = "";
        try {
            c = new FtpClient(host, p);
            c.mode = "active".equals(q.get("mode")) ? FtpClient.Mode.ACTIVE : FtpClient.Mode.PASSIVE;
            if ("1".equals(q.get("tls"))) c.authTls(true);
            c.login(q.getOrDefault("user", "demo"), q.getOrDefault("pass", "password"));
            pwd = c.pwd(); c.cmd("SYST");
            listing = new String(c.list(""), StandardCharsets.UTF_8);
            c.quit();
        } catch (Exception e) { error = e.getMessage(); if (c != null) c.close(); }
        return Json.obj("host", host, "port", p, "pwd", pwd, "listing", listing, "error", error, "trace", Json.raw(c == null ? "[]" : c.traceJson()));
    }

    // ------------------------------------------------------------------ 7. raw console: control channel + an automatic data channel
    private final Map<Integer, Raw> raws = new ConcurrentHashMap<>();
    private final AtomicInteger rawIds = new AtomicInteger();
    private final class Raw {
        final Socket s; final StringBuffer ctrl = new StringBuffer(), data = new StringBuffer(); volatile ServerSocket listen;
        Raw() throws IOException {
            s = new Socket("127.0.0.1", ftpPort);
            Thread t = new Thread(() -> {
                try (InputStream i = s.getInputStream()) {
                    byte[] b = new byte[4096]; int k;
                    while ((k = i.read(b)) > 0) {
                        String txt = new String(b, 0, k, StandardCharsets.UTF_8);
                        ctrl.append(txt);
                        Matcher m = Pattern.compile("227 [^(]*\\((\\d+),(\\d+),(\\d+),(\\d+),(\\d+),(\\d+)\\)").matcher(txt);
                        if (m.find()) openData(m.group(1) + "." + m.group(2) + "." + m.group(3) + "." + m.group(4), Integer.parseInt(m.group(5)) * 256 + Integer.parseInt(m.group(6)));
                        Matcher e = Pattern.compile("229 [^(]*\\(\\|\\|\\|(\\d+)\\|\\)").matcher(txt);
                        if (e.find()) openData("127.0.0.1", Integer.parseInt(e.group(1)));
                    }
                } catch (IOException ignored) { }
                ctrl.append("\n[control connection closed]\n");
            }, "raw-ctrl"); t.setDaemon(true); t.start();
        }
        void openData(String ip, int p) {
            Thread t = new Thread(() -> {
                try (Socket d = new Socket(ip, p)) {
                    data.append("── data connection opened: client → ").append(ip).append(':').append(p).append(" (passive) ──\n");
                    pump(d);
                } catch (IOException e) { data.append("── could not open data connection: ").append(e.getMessage()).append(" ──\n"); }
            }, "raw-data"); t.setDaemon(true); t.start();
        }
        void active(int port) {
            Thread t = new Thread(() -> {
                try (ServerSocket l = listen) { l.setSoTimeout(60_000); try (Socket d = l.accept()) { data.append("── data connection opened: server port ").append(d.getPort()).append(" → my port ").append(port).append(" (active) ──\n"); pump(d); } }
                catch (IOException e) { data.append("── no data connection: ").append(e.getMessage()).append(" ──\n"); }
            }, "raw-active"); t.setDaemon(true); t.start();
        }
        void pump(Socket d) throws IOException {
            InputStream i = d.getInputStream(); byte[] b = new byte[8192]; int k; long n = 0;
            while ((k = i.read(b)) > 0) { n += k; String txt = new String(b, 0, k, StandardCharsets.ISO_8859_1); data.append(txt.length() > 4000 ? txt.substring(0, 4000) + "\n…" : txt); }
            data.append("── data connection closed after ").append(n).append(" bytes ──\n");
        }
        void close() { try { s.close(); } catch (IOException ignored) { } }
    }
    private String rawOpen() throws IOException { int id = rawIds.incrementAndGet(); raws.put(id, new Raw()); return Json.obj("id", id, "port", ftpPort); }
    private String rawSend(int id, String line) throws IOException {
        Raw r = raws.get(id); if (r == null) return Json.obj("error", "closed");
        String l = line;
        if (l.trim().equalsIgnoreCase("PORT auto")) {                       // open a listener and send a real PORT for it
            r.listen = new ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"));
            int p = r.listen.getLocalPort();
            l = "PORT 127,0,0,1," + p / 256 + "," + p % 256;
            r.ctrl.append("› ").append(l).append("   (listening on ").append(p).append(")\n");
            r.active(p);
        } else r.ctrl.append("› ").append(l.toUpperCase().startsWith("PASS ") ? "PASS ********" : l).append('\n');
        OutputStream o = r.s.getOutputStream(); o.write((l + "\r\n").getBytes(StandardCharsets.UTF_8)); o.flush();
        return "{}";
    }
    private String rawRead(int id, int c, int d) {
        Raw r = raws.get(id); if (r == null) return Json.obj("closed", true);
        String cs = r.ctrl.toString(), ds = r.data.toString();
        return Json.obj("ctrl", cs.substring(Math.min(c, cs.length())), "c", cs.length(), "data", ds.substring(Math.min(d, ds.length())), "d", ds.length(), "closed", r.s.isClosed());
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

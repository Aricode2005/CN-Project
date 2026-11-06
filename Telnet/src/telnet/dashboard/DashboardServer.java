package telnet.dashboard;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import telnet.client.TelnetClient;
import telnet.core.Hub;
import telnet.core.Json;
import telnet.protocol.LoopExperiment;
import telnet.protocol.Telnet;
import telnet.server.TelnetSession;
import telnet.server.VtyPool;

/**
 * Zero-dependency web dashboard + REST API (JDK HttpServer).
 *
 * The browser terminal is a real Telnet client: the browser sends keystrokes to this server,
 * which forwards them through a {@link TelnetClient} socket (via the wire tap, directly, or
 * over TLS). So everything typed in the page is visible in the sniffer and in Wireshark.
 */
public final class DashboardServer {

    public static final class Ports { public int telnet, tap, tls, tlsTap, http; }

    private final Ports ports;
    private final VtyPool pool;
    private final File webDir, trustStore;
    private HttpServer http;
    private final Map<Integer, TelnetClient> terms = new ConcurrentHashMap<>();
    private final Map<Integer, Long> lastPoll = new ConcurrentHashMap<>();
    private final AtomicInteger termIds = new AtomicInteger();
    private final List<String> botLog = new ArrayList<>();
    private volatile boolean botRunning;

    public DashboardServer(Ports ports, VtyPool pool, File webDir, File trustStore) {
        this.ports = ports; this.pool = pool; this.webDir = webDir; this.trustStore = trustStore;
    }

    public void start() throws IOException {
        http = HttpServer.create(new InetSocketAddress(ports.http), 0);
        http.createContext("/", this::route);
        http.setExecutor(Executors.newFixedThreadPool(8));
        http.start();
        // A browser tab that was closed or reloaded stops polling: free its VTY line after 20 s.
        pool.timer.scheduleAtFixedRate(() -> {
            long now = System.currentTimeMillis();
            for (Map.Entry<Integer, Long> e : lastPoll.entrySet()) {
                if (now - e.getValue() > 20_000) {
                    TelnetClient c = terms.remove(e.getKey());
                    lastPoll.remove(e.getKey());
                    if (c != null) { c.close(); Hub.I.log("[DASHBOARD] browser terminal " + e.getKey() + " abandoned: connection closed"); }
                }
            }
        }, 10, 10, java.util.concurrent.TimeUnit.SECONDS);
    }

    public void stop() {
        for (TelnetClient c : terms.values()) c.close();
        if (http != null) http.stop(0);
    }

    // ================================================================== routing

    private void route(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        Map<String, String> q = query(ex);
        try {
            switch (path) {
                case "/": case "/index.html": file(ex, "dashboard.html", "text/html; charset=utf-8"); return;
                case "/api/state": json(ex, state()); return;
                case "/api/neg": json(ex, neg(intOf(q.get("session"), -1))); return;
                case "/api/wire": json(ex, wire(Long.parseLong(q.getOrDefault("since", "0")))); return;
                case "/api/term/open": json(ex, termOpen(q)); return;
                case "/api/term/send": termSend(intOf(q.get("id"), -1), body(ex)); json(ex, "{\"ok\":true}"); return;
                case "/api/term/cmd": termCmd(intOf(q.get("id"), -1), q.get("cmd")); json(ex, "{\"ok\":true}"); return;
                case "/api/term/embed": { TelnetClient c = terms.get(intOf(q.get("id"), -1)); if (c != null) c.embedEraseDemo(); json(ex, "{\"ok\":true}"); return; }
                case "/api/term/resize": termResize(intOf(q.get("id"), -1), intOf(q.get("cols"), 80), intOf(q.get("rows"), 24)); json(ex, "{\"ok\":true}"); return;
                case "/api/term/read": json(ex, termRead(intOf(q.get("id"), -1), Long.parseLong(q.getOrDefault("since", "0")))); return;
                case "/api/term/close": { TelnetClient c = terms.remove(intOf(q.get("id"), -1)); if (c != null) c.close(); json(ex, "{\"ok\":true}"); return; }
                case "/api/recording": json(ex, recording(intOf(q.get("id"), -1))); return;
                case "/api/loop": json(ex, loop()); return;
                case "/api/action": json(ex, action(q.getOrDefault("name", ""))); return;
                default: send(ex, 404, "text/plain", "not found".getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception e) {
            json(ex, Json.obj("error", String.valueOf(e.getMessage())));
        }
    }

    // ================================================================== state

    private String state() {
        List<String> ss = new ArrayList<>();
        for (TelnetSession s : pool.sessions()) ss.add(s.json());
        List<String> caps = new ArrayList<>();
        for (Hub.Capture c : Hub.I.captures) caps.add(c.json());
        List<String> recs = new ArrayList<>();
        for (Hub.Recording r : Hub.I.recordings.snapshot()) recs.add(Json.obj("id", r.id, "user", r.user, "from", r.from, "start", r.start, "live", false));
        for (TelnetSession s : pool.sessions()) recs.add(Json.obj("id", s.id, "user", s.user.isEmpty() ? "(logging in)" : s.user, "from", s.from, "start", s.startedAt, "live", true));
        List<String> logs = new ArrayList<>();
        List<String> all = Hub.I.logs();
        for (int i = Math.max(0, all.size() - 120); i < all.size(); i++) logs.add(Json.str(all.get(i)));
        List<String> bl;
        synchronized (botLog) { bl = new ArrayList<>(); for (String s : botLog) bl.add(Json.str(s)); }
        return Json.obj(
                "hostname", pool.cfg.hostname,
                "ports", Json.raw(Json.obj("telnet", ports.telnet, "tap", ports.tap, "tls", ports.tls, "tlsTap", ports.tlsTap, "http", ports.http)),
                "uptime", (System.currentTimeMillis() - pool.bootTime) / 1000,
                "vtyMax", VtyPool.LINES, "refusedBusy", pool.refusedBusy.get(),
                "sessions", Json.raw(Json.arr(ss)),
                "security", Json.raw(pool.guard.json()),
                "captures", Json.raw(Json.arr(caps)),
                "recordings", Json.raw(Json.arr(recs)),
                "bot", Json.raw(Json.obj("running", botRunning, "log", Json.raw(Json.arr(bl)))),
                "logs", Json.raw(Json.arr(logs)));
    }

    private String neg(int session) {
        List<String> ev = new ArrayList<>();
        for (Hub.NegEvent e : Hub.I.negFor(session)) ev.add(e.json());
        TelnetSession s = pool.byId(session);
        return Json.obj("session", session, "events", Json.raw(Json.arr(ev)), "live", s != null, "info", s == null ? null : Json.raw(s.json()));
    }

    private String wire(long since) {
        List<String> f = new ArrayList<>();
        for (Hub.WireFrame w : Hub.I.wireSince(since)) f.add(w.json());
        return Json.obj("frames", Json.raw(Json.arr(f)));
    }

    private String recording(int id) {
        TelnetSession s = pool.byId(id);
        if (s != null) return Json.obj("id", id, "user", s.user, "events", Json.raw(s.recordingJson()));
        for (Hub.Recording r : Hub.I.recordings.snapshot()) if (r.id == id) return Json.obj("id", id, "user", r.user, "events", Json.raw(r.eventsJson));
        return Json.obj("error", "no such recording");
    }

    private String loop() {
        LoopExperiment.Result[] rs = {LoopExperiment.naive(), LoopExperiment.qMethod()};
        List<String> out = new ArrayList<>();
        for (LoopExperiment.Result r : rs) {
            List<String> tr = new ArrayList<>();
            for (LoopExperiment.Msg m : r.trace) tr.add(Json.obj("from", m.from, "text", m.text));
            out.add(Json.obj("name", r.name, "looped", r.looped, "final", r.finalState, "trace", Json.raw(Json.arr(tr))));
        }
        return Json.arr(out);
    }

    // ================================================================== browser terminal bridge

    private String termOpen(Map<String, String> q) throws IOException {
        String mode = q.getOrDefault("mode", "tap");
        int cols = intOf(q.get("cols"), 100), rows = intOf(q.get("rows"), 28);
        boolean tls = mode.startsWith("tls");
        int port = "direct".equals(mode) ? ports.telnet : "tls".equals(mode) ? ports.tlsTap : "tls-direct".equals(mode) ? ports.tls : ports.tap;
        if (tls && ports.tls <= 0) return Json.obj("error", "TLS listener is not running (keytool missing?)");
        TelnetClient c = new TelnetClient("127.0.0.1", port, tls, trustStore, new String[]{"XTERM-256COLOR", "XTERM", "VT100"}, cols, rows, true, null);
        int id = termIds.incrementAndGet();
        terms.put(id, c);
        lastPoll.put(id, System.currentTimeMillis());
        return Json.obj("id", id, "port", port, "tls", tls);
    }

    private void termSend(int id, String s) { TelnetClient c = terms.get(id); if (c != null) c.type(s); }

    private void termCmd(int id, String cmd) {
        TelnetClient c = terms.get(id);
        if (c == null) return;
        if ("STATUS".equals(cmd)) { c.requestStatus(); return; }
        int code;
        switch (cmd == null ? "" : cmd) {
            case "AYT": code = Telnet.AYT; break;
            case "IP": code = Telnet.IP; break;
            case "BRK": code = Telnet.BRK; break;
            case "EC": code = Telnet.EC; break;
            case "EL": code = Telnet.EL; break;
            case "AO": code = Telnet.AO; break;
            case "GA": code = Telnet.GA; break;
            case "EOF": code = Telnet.EOF; break;
            case "EOR": code = Telnet.EOR; break;
            case "DM": code = Telnet.DM; break;
            default: code = Telnet.NOP;
        }
        c.command(code);
    }

    private void termResize(int id, int cols, int rows) { TelnetClient c = terms.get(id); if (c != null) c.resize(cols, rows); }

    private String termRead(int id, long since) {
        if (terms.containsKey(id)) lastPoll.put(id, System.currentTimeMillis());
        TelnetClient c = terms.get(id);
        if (c == null) return Json.obj("text", "", "next", since, "closed", true);
        long end = System.currentTimeMillis() + 800;               // light long-poll
        while (c.mark() <= since && !c.isClosed() && System.currentTimeMillis() < end) {
            try { Thread.sleep(25); } catch (InterruptedException e) { break; }
        }
        long m = c.mark();
        return Json.obj("text", c.since(since), "next", m, "closed", c.isClosed());
    }

    // ================================================================== actions

    private String action(String name) {
        switch (name) {
            case "unblock": pool.guard.unblock(); return "{\"ok\":true}";
            case "bruteforce":
                if (botRunning) return Json.obj("error", "already running");
                Thread t = new Thread(this::bruteForce, "bruteforce-bot");
                t.setDaemon(true); t.start();
                return "{\"ok\":true}";
            case "clearcaptures": Hub.I.captures.clear(); return "{\"ok\":true}";
            default: return Json.obj("error", "unknown action " + name);
        }
    }

    /** A dictionary attack against "admin" through the wire tap: shows quiet mode stopping it. */
    private void bruteForce() {
        botRunning = true;
        String[] words = {"123456", "password", "admin", "letmein", "qwerty", "router", "cisco"};
        synchronized (botLog) { botLog.clear(); }
        bot("Dictionary attack on user 'admin' via TCP " + ports.tap + " (" + words.length + " guesses, last one is correct)");
        int i = 0;
        try {
            while (i < words.length) {
                TelnetClient c;
                try { c = new TelnetClient("127.0.0.1", ports.tap, false, null, new String[]{"BOT"}, 80, 24, true, null); }
                catch (IOException e) { bot("connect failed: " + e.getMessage()); break; }
                long m = c.mark();
                boolean progressed = false;
                while (i < words.length) {
                    long u = c.expect(m, "Username: ", 4000);
                    if (u < 0) {
                        String t = c.since(m);
                        if (t.contains("quiet mode") || t.contains("blocked")) { bot("REFUSED: device is in quiet mode (login block-for) - attack stopped before reaching the right password"); i = words.length + 1; }
                        break;
                    }
                    c.line("admin");
                    long p = c.expect(u, "Password: ", 3000);
                    if (p < 0) break;
                    c.line(words[i]);
                    long r1 = c.expect(p, "#", 2500);
                    String res = c.since(p);
                    if (r1 >= 0 && res.contains("Welcome")) { bot("guess " + (i + 1) + " '" + words[i] + "': SUCCESS - password found"); i = words.length + 1; break; }
                    bot("guess " + (i + 1) + " '" + words[i] + "': % Login invalid");
                    progressed = true;
                    i++;
                    m = p;
                    if (res.contains("blocked") || res.contains("Bad passwords")) break;
                }
                c.close();
                if (!progressed && i <= words.length) break;
                Thread.sleep(300);
            }
        } catch (InterruptedException ignored) {
        } finally {
            bot("bot finished");
            botRunning = false;
        }
    }

    private void bot(String s) {
        synchronized (botLog) { botLog.add(s); }
        Hub.I.log("[BOT] " + s);
    }

    // ================================================================== http helpers

    private static int intOf(String s, int d) { try { return Integer.parseInt(s); } catch (Exception e) { return d; } }

    private static Map<String, String> query(HttpExchange ex) {
        Map<String, String> m = new HashMap<>();
        String q = ex.getRequestURI().getRawQuery();
        if (q == null) return m;
        for (String kv : q.split("&")) {
            int i = kv.indexOf('=');
            try {
                if (i > 0) m.put(URLDecoder.decode(kv.substring(0, i), "UTF-8"), URLDecoder.decode(kv.substring(i + 1), "UTF-8"));
            } catch (Exception ignored) { }
        }
        return m;
    }

    private static String body(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            byte[] buf = new byte[1024]; int n;
            while ((n = in.read(buf)) > 0) b.write(buf, 0, n);
            return new String(b.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    private void file(HttpExchange ex, String name, String type) throws IOException {
        File f = new File(webDir, name);
        if (!f.exists()) { send(ex, 404, "text/plain", ("missing " + f.getAbsolutePath()).getBytes(StandardCharsets.UTF_8)); return; }
        send(ex, 200, type, Files.readAllBytes(f.toPath()));
    }

    private static void json(HttpExchange ex, String s) throws IOException {
        send(ex, 200, "application/json; charset=utf-8", s.getBytes(StandardCharsets.UTF_8));
    }

    private static void send(HttpExchange ex, int code, String type, byte[] b) throws IOException {
        ex.getResponseHeaders().set("Content-Type", type);
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream o = ex.getResponseBody()) { o.write(b); }
    }
}

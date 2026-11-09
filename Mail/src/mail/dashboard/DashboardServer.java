package mail.dashboard;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import mail.Main;
import mail.client.ImapClient;
import mail.client.LineClient;
import mail.client.LineClient.Tls;
import mail.client.Pop3Client;
import mail.client.SmtpClient;
import mail.core.Hub;
import mail.core.Json;
import mail.mime.Mime;
import mail.store.MailStore;

/**
 * Dashboard + REST API. Every action here uses OUR clients over real sockets to OUR servers
 * (or to a real provider), so all of it appears in the protocol transcripts.
 */
public final class DashboardServer {

    private final int port;
    private final MailStore store;
    private final File web;
    private final boolean tls;
    private HttpServer http;

    public DashboardServer(int port, MailStore store, File web, boolean tls) { this.port = port; this.store = store; this.web = web; this.tls = tls; }

    public void start() throws IOException {
        http = HttpServer.create(new InetSocketAddress(port), 0);
        http.createContext("/", this::route);
        http.setExecutor(Executors.newFixedThreadPool(10));
        http.start();
    }

    public void stop() { if (http != null) http.stop(0); for (Raw r : raws.values()) r.close(); idleRun = false; }

    private void route(HttpExchange ex) throws IOException {
        Map<String, String> q = params(ex);
        String p = ex.getRequestURI().getPath();
        try {
            switch (p) {
                case "/": case "/index.html": file(ex, "dashboard.html"); return;
                case "/api/state": json(ex, state()); return;
                case "/api/lines": json(ex, lines(Long.parseLong(q.getOrDefault("since", "0")))); return;
                case "/api/mailbox": json(ex, mailbox(q.get("user"), q.getOrDefault("folder", "INBOX"))); return;
                case "/api/message": json(ex, message(q.get("user"), q.get("folder"), Long.parseLong(q.get("uid")))); return;
                case "/api/send": json(ex, send(q)); return;
                case "/api/device": json(ex, device(q)); return;
                case "/api/devices": json(ex, devicesJson(null)); return;
                case "/api/idle": json(ex, idle(q.getOrDefault("on", "1").equals("1"))); return;
                case "/api/raw/open": json(ex, rawOpen(q.get("proto"))); return;
                case "/api/raw/send": rawSend(Integer.parseInt(q.get("id")), q.getOrDefault("line", "")); json(ex, "{\"ok\":true}"); return;
                case "/api/raw/read": json(ex, rawRead(Integer.parseInt(q.get("id")), Long.parseLong(q.getOrDefault("since", "0")))); return;
                case "/api/raw/close": { Raw r = raws.remove(Integer.parseInt(q.get("id"))); if (r != null) r.close(); json(ex, "{\"ok\":true}"); return; }
                case "/api/real": json(ex, real(q)); return;
                default: send(ex, 404, "text/plain", "not found".getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception e) {
            json(ex, Json.obj("error", e.getClass().getSimpleName() + ": " + e.getMessage()));
        }
    }

    // ================================================================== state / mailboxes

    private String state() {
        List<String> users = new ArrayList<>();
        for (String u : store.userNames()) {
            List<String> fs = new ArrayList<>();
            for (String f : store.folderNames(u)) {
                MailStore.Folder fo = store.folder(u, f);
                fs.add(Json.obj("name", f, "count", fo.count(), "unseen", fo.unseen()));
            }
            users.add(Json.obj("user", u, "folders", Json.raw(Json.arr(fs))));
        }
        List<String> ev = new ArrayList<>();
        for (Hub.Event e : Hub.I.eventsSince(0)) ev.add(e.json());
        List<String> logs = new ArrayList<>();
        List<String> all = Hub.I.logs();
        for (int i = Math.max(0, all.size() - 80); i < all.size(); i++) logs.add(Json.str(all.get(i)));
        return Json.obj("domain", store.domain, "tls", tls,
                "ports", Json.raw(Json.obj("smtp", Main.SMTP, "smtps", Main.SMTPS, "pop3", Main.POP3, "pop3s", Main.POP3S, "imap", Main.IMAP, "imaps", Main.IMAPS)),
                "users", Json.raw(Json.arr(users)), "events", Json.raw(Json.arr(ev.subList(Math.max(0, ev.size() - 60), ev.size()))),
                "logs", Json.raw(Json.arr(logs)), "idle", idleRun);
    }

    private String lines(long since) {
        List<String> l = new ArrayList<>();
        for (Hub.Line x : Hub.I.linesSince(since)) l.add(x.json());
        return Json.obj("lines", Json.raw(Json.arr(l)));
    }

    private String mailbox(String user, String folder) {
        MailStore.Folder f = store.folder(user, folder);
        if (f == null) return Json.obj("error", "no such folder");
        List<String> rows = new ArrayList<>();
        for (MailStore.Message m : f.list()) {
            Mime.Part p = Mime.parse(m.raw);
            rows.add(Json.obj("uid", m.uid, "flags", String.join(" ", m.flags), "from", Mime.decodeWords(p.header("From")),
                    "to", Mime.decodeWords(p.header("To")), "subject", Mime.decodeWords(p.header("Subject")), "date", p.header("Date"),
                    "size", m.size(), "attach", p.multipart()));
        }
        return Json.obj("user", user, "folder", f.name, "uidValidity", f.uidValidity, "uidNext", f.uidNext(), "messages", Json.raw(Json.arr(rows)));
    }

    private String message(String user, String folder, long uid) {
        MailStore.Folder f = store.folder(user, folder);
        MailStore.Message m = null;
        for (MailStore.Message x : f.list()) if (x.uid == uid) m = x;
        if (m == null) return Json.obj("error", "no such message");
        String raw = new String(m.raw, StandardCharsets.UTF_8);
        return Json.obj("uid", uid, "flags", String.join(" ", m.flags), "raw", raw.length() > 12000 ? raw.substring(0, 12000) + "\n…" : raw,
                "tree", Json.raw(tree(Mime.parse(m.raw), "")));
    }

    private String tree(Mime.Part p, String path) {
        List<String> kids = new ArrayList<>();
        for (int i = 0; i < p.children.size(); i++) kids.add(tree(p.children.get(i), path.isEmpty() ? String.valueOf(i + 1) : path + "." + (i + 1)));
        String preview = "";
        if (!p.multipart()) {
            if (p.type.equals("text")) preview = p.text();
            else preview = "(" + p.decoded().length + " bytes of " + p.type + "/" + p.subtype + ")";
            if (preview.length() > 1500) preview = preview.substring(0, 1500) + "…";
        }
        String encSample = new String(p.body, StandardCharsets.ISO_8859_1);
        if (encSample.length() > 300) encSample = encSample.substring(0, 300) + "…";
        return Json.obj("path", path.isEmpty() ? "TEXT" : path, "type", p.type + "/" + p.subtype, "encoding", p.encoding, "size", p.body.length,
                "params", p.params.toString(), "disposition", p.header("Content-Disposition"), "preview", preview, "encoded", encSample,
                "children", Json.raw(Json.arr(kids)));
    }

    // ================================================================== compose & send (our SMTP client → our SMTP server)

    private String send(Map<String, String> q) throws Exception {
        String user = q.get("user"), pass = q.get("pass");
        String mode = q.getOrDefault("tls", "STARTTLS");
        int port = mode.equals("IMPLICIT") ? Main.SMTPS : Main.SMTP;
        List<String> to = new ArrayList<>();
        for (String t : q.getOrDefault("to", "").split("[,;]")) if (!t.trim().isEmpty()) to.add(t.trim().contains("@") ? t.trim() : t.trim() + "@" + store.domain);
        byte[] att = q.containsKey("attData") && !q.get("attData").isEmpty() ? Base64.getDecoder().decode(q.get("attData")) : null;
        String from = user + "@" + store.domain;
        String msg = Mime.build(cap(user) + " <" + from + ">", String.join(", ", to), q.getOrDefault("subject", "(no subject)"),
                q.getOrDefault("body", ""), att == null ? null : q.getOrDefault("attName", "file.bin"), att, "mail." + store.domain);
        SmtpClient c = new SmtpClient("localhost", port, Tls.valueOf(mode.equals("NONE") ? "NONE" : mode));
        if (c.extensions.isEmpty()) c.ehlo("webmail." + store.domain);
        c.login(user, pass);
        String r = c.send(from, to, msg);
        c.quit();
        // keep a copy in Sent, exactly as Thunderbird/Outlook do: IMAP APPEND
        ImapClient i = new ImapClient("localhost", Main.IMAP, Tls.NONE);
        i.login(user, pass);
        i.append("Sent", "\\Seen", msg.getBytes(StandardCharsets.UTF_8));
        i.logout();
        return Json.obj("ok", true, "reply", r);
    }

    private static String cap(String s) { return s.isEmpty() ? s : Character.toUpperCase(s.charAt(0)) + s.substring(1); }

    // ================================================================== POP3 vs IMAP: two devices of bob

    private static final class LocalMsg {
        String key, subject, from; boolean read; long uid;
        String json() { return Json.obj("key", key, "uid", uid, "subject", subject, "from", from, "read", read); }
    }

    private static final class Device {
        final String name; String proto = "IMAP";
        final List<LocalMsg> local = new ArrayList<>();
        final java.util.Set<String> popSeen = new java.util.HashSet<>();   // UIDLs already downloaded (keep mode)
        String last = "";
        Device(String n) { name = n; }
    }

    private final Map<String, Device> devices = new LinkedHashMap<>();
    { devices.put("phone", new Device("phone")); devices.put("laptop", new Device("laptop")); }

    private synchronized String device(Map<String, String> q) throws Exception {
        String action = q.getOrDefault("action", "");
        if (action.equals("reset")) { resetDemo(); return devicesJson("Demo reset: bob's INBOX refilled with 3 messages, both devices empty."); }
        if (action.equals("newmail")) {
            SmtpClient c = new SmtpClient("localhost", Main.SMTP, Tls.NONE);
            c.ehlo("demo");
            String subj = "New message " + new java.text.SimpleDateFormat("HH:mm:ss").format(new java.util.Date());
            c.send("alice@" + store.domain, Collections.singletonList("bob@" + store.domain),
                    Mime.build("Alice <alice@" + store.domain + ">", "Bob <bob@" + store.domain + ">", subj, "Sent by SMTP to show arrival on both devices.", null, null, "x"));
            c.quit();
            return devicesJson("Alice sent \"" + subj + "\" to bob via SMTP (push).");
        }
        Device d = devices.get(q.get("dev"));
        if (d == null) return Json.obj("error", "no such device");
        if (q.containsKey("proto")) { d.proto = q.get("proto"); d.local.clear(); d.popSeen.clear(); d.last = "switched to " + d.proto; }
        String msg;
        switch (action) {
            case "check": msg = check(d); break;
            case "read": msg = read(d, q.get("key")); break;
            case "delete": msg = delete(d, q.get("key")); break;
            case "move": msg = move(d, q.get("key"), q.getOrDefault("to", "Projects")); break;
            default: msg = d.last;
        }
        d.last = msg;
        return devicesJson(msg);
    }

    private String check(Device d) throws Exception {
        if (d.proto.startsWith("POP3")) {
            boolean keep = d.proto.equals("POP3KEEP");
            Pop3Client p = new Pop3Client("localhost", Main.POP3, Tls.NONE);
            try {
                p.login("bob", "bob123");
                Map<Integer, String> uidl = p.uidl();
                int got = 0;
                for (Map.Entry<Integer, String> e : uidl.entrySet()) {
                    if (keep && d.popSeen.contains(e.getValue())) continue;
                    Mime.Part m = Mime.parse(p.retr(e.getKey()));
                    LocalMsg l = new LocalMsg();
                    l.key = e.getValue(); l.subject = Mime.decodeWords(m.header("Subject")); l.from = Mime.decodeWords(m.header("From"));
                    d.local.add(l); d.popSeen.add(e.getValue()); got++;
                    if (!keep) p.dele(e.getKey());
                }
                p.quit();
                return "POP3 " + (keep ? "keep" : "delete") + " mode: downloaded " + got + " message(s)" + (keep ? "; copies left on the server" : " and DELETED them from the server");
            } catch (Exception e) { p.close(); throw e; }
        }
        ImapClient i = new ImapClient("localhost", Main.IMAP, Tls.NONE);
        try {
            i.login("bob", "bob123");
            int n = i.select("INBOX");
            d.local.clear();
            if (n > 0) for (ImapClient.Summary s : i.summaries("1:*")) {
                LocalMsg l = new LocalMsg();
                l.key = "uid" + s.uid; l.uid = s.uid; l.subject = s.subject; l.from = s.from; l.read = s.flags.contains("\\Seen");
                d.local.add(l);
            }
            i.logout();
            return "IMAP: synchronised with the server — " + n + " message(s), read/unread state comes from the server's \\Seen flags";
        } catch (Exception e) { i.close(); throw e; }
    }

    private String read(Device d, String key) throws Exception {
        LocalMsg l = find(d, key);
        if (l == null) return "no such message on this device";
        if (d.proto.startsWith("POP3")) { l.read = true; return "POP3: marked read LOCALLY only — the server (and the other device) never learns it"; }
        ImapClient i = new ImapClient("localhost", Main.IMAP, Tls.NONE);
        i.login("bob", "bob123"); i.select("INBOX"); i.body(l.uid, false); i.logout();
        l.read = true;
        return "IMAP: FETCH BODY[] set \\Seen ON THE SERVER — the other IMAP device will show it read after its next sync";
    }

    private String delete(Device d, String key) throws Exception {
        LocalMsg l = find(d, key);
        if (l == null) return "no such message on this device";
        d.local.remove(l);
        if (d.proto.startsWith("POP3")) return "POP3: deleted from this device only" + (d.proto.equals("POP3KEEP") ? " (the server copy remains)" : "");
        ImapClient i = new ImapClient("localhost", Main.IMAP, Tls.NONE);
        i.login("bob", "bob123"); i.select("INBOX"); i.store(l.uid, "+FLAGS", "\\Deleted"); i.expunge(); i.logout();
        return "IMAP: STORE +FLAGS (\\Deleted) + EXPUNGE — removed from the SERVER, so it disappears on every IMAP device";
    }

    private String move(Device d, String key, String to) throws Exception {
        LocalMsg l = find(d, key);
        if (l == null) return "no such message on this device";
        if (d.proto.startsWith("POP3")) return "POP3 has no folders on the server: it can only download from INBOX";
        if (store.folder("bob", to) == null) store.createFolder("bob", to);
        ImapClient i = new ImapClient("localhost", Main.IMAP, Tls.NONE);
        i.login("bob", "bob123"); i.select("INBOX"); i.move(l.uid, to); i.logout();
        d.local.remove(l);
        return "IMAP: UID MOVE to \"" + to + "\" — the folder lives on the server, every device sees it there";
    }

    private static LocalMsg find(Device d, String key) { for (LocalMsg l : d.local) if (l.key.equals(key)) return l; return null; }

    private void resetDemo() {
        MailStore.Folder f = store.folder("bob", "INBOX");
        for (MailStore.Message m : f.list()) { java.util.Set<String> fl = new java.util.TreeSet<>(m.flags); fl.add("\\Deleted"); store.setFlags("bob", f, m, fl); }
        store.expunge("bob", f);
        String[][] seed = {{"Alice", "Lunch at 1?", "Canteen, usual table."}, {"Subham", "Viva on Friday", "Bring the .pkt files and the report."}, {"Alice", "Slides attached", "Forouzan chapter 26 slides."}};
        for (String[] s : seed)
            store.append("bob", "INBOX", Mime.build(s[0] + " <" + s[0].toLowerCase() + "@" + store.domain + ">", "Bob <bob@" + store.domain + ">", s[1], s[2], null, null, "x").getBytes(StandardCharsets.UTF_8), null);
        for (Device d : devices.values()) { d.local.clear(); d.popSeen.clear(); d.last = ""; }
        Hub.I.event("DEMO", "POP3 vs IMAP demo reset");
    }

    private String devicesJson(String message) {
        List<String> ds = new ArrayList<>();
        for (Device d : devices.values()) {
            List<String> l = new ArrayList<>();
            for (LocalMsg m : d.local) l.add(m.json());
            ds.add(Json.obj("name", d.name, "proto", d.proto, "local", Json.raw(Json.arr(l)), "last", d.last));
        }
        return Json.obj("devices", Json.raw(Json.arr(ds)), "server", Json.raw(mailbox("bob", "INBOX")), "message", message);
    }

    // ================================================================== IMAP IDLE watcher (push notifications)

    private volatile boolean idleRun;

    private String idle(boolean on) {
        if (on && !idleRun) {
            idleRun = true;
            Thread t = new Thread(() -> {
                try {
                    ImapClient i = new ImapClient("localhost", Main.IMAP, Tls.NONE);
                    i.login("bob", "bob123");
                    i.select("INBOX");
                    while (idleRun) i.idle(25_000, l -> { if (l.contains("EXISTS") || l.contains("EXPUNGE") || l.contains("FETCH")) Hub.I.event("PUSH", "IMAP IDLE → bob: " + l); });
                    i.logout();
                } catch (Exception e) { Hub.I.log("[IDLE] " + e.getMessage()); idleRun = false; }
            }, "dashboard-idle");
            t.setDaemon(true);
            t.start();
        } else if (!on) idleRun = false;
        return Json.obj("idle", idleRun);
    }

    // ================================================================== raw console ("telnet" to our servers)

    private static final class Raw {
        final Socket s; final StringBuffer text = new StringBuffer(); volatile boolean closed;
        Raw(Socket s) { this.s = s; }
        void close() { closed = true; try { s.close(); } catch (IOException ignored) { } }
    }
    private final Map<Integer, Raw> raws = new ConcurrentHashMap<>();
    private final AtomicInteger rawIds = new AtomicInteger();

    private String rawOpen(String proto) throws IOException {
        int p = "pop3".equals(proto) ? Main.POP3 : "imap".equals(proto) ? Main.IMAP : Main.SMTP;
        Socket s = new Socket("localhost", p);
        Raw r = new Raw(s);
        int id = rawIds.incrementAndGet();
        raws.put(id, r);
        Thread t = new Thread(() -> {
            byte[] b = new byte[4096];
            try { InputStream in = s.getInputStream(); int n; while ((n = in.read(b)) > 0) r.text.append(new String(b, 0, n, StandardCharsets.UTF_8)); }
            catch (IOException ignored) { }
            r.closed = true;
        }, "raw-" + id);
        t.setDaemon(true);
        t.start();
        return Json.obj("id", id, "port", p);
    }

    private void rawSend(int id, String line) throws IOException {
        Raw r = raws.get(id);
        if (r == null) return;
        r.s.getOutputStream().write((line + "\r\n").getBytes(StandardCharsets.UTF_8));
        r.s.getOutputStream().flush();
    }

    private String rawRead(int id, long since) throws InterruptedException {
        Raw r = raws.get(id);
        if (r == null) return Json.obj("text", "", "next", since, "closed", true);
        for (int i = 0; i < 30 && r.text.length() <= since && !r.closed; i++) Thread.sleep(25);
        int from = (int) Math.min(since, r.text.length());
        return Json.obj("text", r.text.substring(from), "next", r.text.length(), "closed", r.closed);
    }

    // ================================================================== a REAL provider (Gmail, Outlook …)

    private String real(Map<String, String> q) throws Exception {
        String kind = q.getOrDefault("kind", "imap"), host = q.get("host"), user = q.get("user"), pass = q.get("pass");
        int port = Integer.parseInt(q.get("port"));
        Tls t = Tls.valueOf(q.getOrDefault("tls", "IMPLICIT"));
        List<String> out = new ArrayList<>();
        switch (kind) {
            case "imap": {
                ImapClient c = new ImapClient(host, port, t);
                c.maskSecrets = true;
                try {
                    c.login(user, pass);
                    out.add("Folders: " + String.join(", ", c.list()));
                    int n = c.select("INBOX");
                    out.add("INBOX: " + n + " messages");
                    List<Long> uids = n > 0 ? c.uidSearch("ALL") : new ArrayList<>();
                    List<Long> last = uids.subList(Math.max(0, uids.size() - 5), uids.size());
                    if (!last.isEmpty()) {
                        StringBuilder set = new StringBuilder();
                        for (long u : last) set.append(set.length() > 0 ? "," : "").append(u);
                        for (ImapClient.Summary s : c.summaries(set.toString()))        // BODY.PEEK: nothing gets marked read
                            out.add("  " + (s.flags.contains("\\Seen") ? "  " : "● ") + s.subject + "  —  " + s.from);
                    }
                    c.logout();
                } finally { c.close(); }
                break;
            }
            case "pop3": {
                Pop3Client c = new Pop3Client(host, port, t);
                c.maskSecrets = true;
                try {
                    c.login(user, pass);
                    long[] st = c.stat();
                    out.add("Maildrop: " + st[0] + " messages, " + st[1] + " octets");
                    for (long i = st[0]; i > Math.max(0, st[0] - 3); i--) {
                        Mime.Part m = Mime.parse(c.top((int) i, 0));
                        out.add("  #" + i + "  " + Mime.decodeWords(m.header("Subject")) + "  —  " + Mime.decodeWords(m.header("From")));
                    }
                    c.quit();
                } finally { c.close(); }
                break;
            }
            default: {
                SmtpClient c = new SmtpClient(host, port, t);
                c.maskSecrets = true;
                try {
                    if (c.extensions.isEmpty()) c.ehlo("jumail-client");
                    c.login(user, pass);
                    String to = q.getOrDefault("to", user);
                    String r = c.send(user, Collections.singletonList(to), Mime.build(user, to, "Test from the JU Mail Lab SMTP client",
                            "Sent by our own Java SMTP client (no libraries), through " + host + ".", null, null, "jumail.local"));
                    out.add("Server reply: " + r);
                    c.quit();
                } finally { c.close(); }
            }
        }
        List<String> lj = new ArrayList<>();
        for (String s : out) lj.add(Json.str(s));
        return Json.obj("ok", true, "result", Json.raw(Json.arr(lj)));
    }

    // ================================================================== http helpers

    private static Map<String, String> params(HttpExchange ex) throws IOException {
        Map<String, String> m = new HashMap<>();
        parse(ex.getRequestURI().getRawQuery(), m);
        if ("POST".equalsIgnoreCase(ex.getRequestMethod())) {
            try (InputStream in = ex.getRequestBody()) {
                ByteArrayOutputStream b = new ByteArrayOutputStream();
                byte[] buf = new byte[8192]; int n;
                while ((n = in.read(buf)) > 0) b.write(buf, 0, n);
                parse(new String(b.toByteArray(), StandardCharsets.UTF_8), m);
            }
        }
        return m;
    }

    private static void parse(String q, Map<String, String> m) {
        if (q == null || q.isEmpty()) return;
        for (String kv : q.split("&")) {
            int i = kv.indexOf('=');
            try { if (i > 0) m.put(URLDecoder.decode(kv.substring(0, i), "UTF-8"), URLDecoder.decode(kv.substring(i + 1), "UTF-8")); }
            catch (Exception ignored) { }
        }
    }

    private void file(HttpExchange ex, String name) throws IOException {
        File f = new File(web, name);
        if (!f.exists()) { send(ex, 404, "text/plain", ("missing " + f.getAbsolutePath()).getBytes(StandardCharsets.UTF_8)); return; }
        send(ex, 200, "text/html; charset=utf-8", Files.readAllBytes(f.toPath()));
    }

    private static void json(HttpExchange ex, String s) throws IOException { send(ex, 200, "application/json; charset=utf-8", s.getBytes(StandardCharsets.UTF_8)); }

    private static void send(HttpExchange ex, int code, String type, byte[] b) throws IOException {
        ex.getResponseHeaders().set("Content-Type", type);
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream o = ex.getResponseBody()) { o.write(b); }
    }

    @SuppressWarnings("unused") private static LineClient.Tls tlsOf(String s) { return Tls.valueOf(s); }
}

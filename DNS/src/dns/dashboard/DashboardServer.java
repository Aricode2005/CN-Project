package dns.dashboard;

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
import java.util.concurrent.Executors;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import dns.Lab;
import dns.attack.Poisoner;
import dns.client.DnsClient;
import dns.core.Hub;
import dns.core.Json;
import dns.server.AuthServer;
import dns.server.Cache;
import dns.server.Resolver;
import dns.wire.Message;
import dns.wire.Message.RR;
import dns.zone.Zone;

/** HTTP API + static page for the DNS dashboard (http://localhost:8084). */
public final class DashboardServer {

    private final int port; private final Lab lab; private final Resolver res; private final File web;
    private HttpServer http;

    public DashboardServer(int port, Lab lab, Resolver res, File web) { this.port = port; this.lab = lab; this.res = res; this.web = web; }

    public void start() throws IOException {
        http = HttpServer.create(new InetSocketAddress(port), 0);
        http.createContext("/", this::route);
        http.setExecutor(Executors.newFixedThreadPool(10));
        http.start();
    }
    public void stop() { if (http != null) http.stop(0); }

    private void route(HttpExchange ex) throws IOException {
        Map<String, String> q = params(ex);
        String p = ex.getRequestURI().getPath();
        try {
            switch (p) {
                case "/": case "/index.html": file(ex, "dashboard.html"); return;
                case "/api/state": json(ex, state()); return;
                case "/api/lines": json(ex, lines(Long.parseLong(q.getOrDefault("since", "0")))); return;
                case "/api/dig": json(ex, dig(q)); return;
                case "/api/trace": {
                    String n = q.get("name").trim(); int t = Message.typeOf(q.getOrDefault("type", "A"));
                    if ("recursive".equals(q.get("mode"))) { if ("1".equals(q.get("fresh"))) res.cache.removeName(n); json(ex, res.resolveRecursive(n, t).json()); }
                    else json(ex, res.resolve(n, t, !"1".equals(q.get("fresh"))).json());
                    return;
                }
                case "/api/recursion": {
                    if (q.containsKey("servers")) AuthServer.recursion = "1".equals(q.get("servers"));
                    if (q.containsKey("upstream")) res.recursiveUpstream = "1".equals(q.get("upstream"));
                    json(ex, Json.obj("servers", AuthServer.recursion, "upstream", res.recursiveUpstream)); return;
                }
                case "/api/flush": res.cache.flush(); Hub.I.event("CACHE", "cache flushed"); json(ex, "{\"ok\":true}"); return;
                case "/api/zone": json(ex, zones()); return;
                case "/api/zone/add": json(ex, zoneEdit(q, true)); return;
                case "/api/zone/del": json(ex, zoneEdit(q, false)); return;
                case "/api/attack": json(ex, Poisoner.run(res, lab.cseServer, !"vulnerable".equals(q.get("mode")))); return;
                case "/api/mode": res.secure = !"0".equals(q.get("secure")); json(ex, Json.obj("secure", res.secure)); return;
                default: send(ex, 404, "text/plain", "not found".getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception e) {
            json(ex, Json.obj("error", e.getClass().getSimpleName() + ": " + e.getMessage()));
        }
    }

    private String state() {
        List<String> srv = new ArrayList<>();
        for (AuthServer a : lab.servers) srv.add(Json.obj("label", a.label, "host", a.host, "ip", a.ip, "port", a.port, "queries", a.queries.get(), "zones", a.zoneNames()));
        List<String> cache = new ArrayList<>(); for (Cache.Entry e : res.cache.list()) cache.add(e.json());
        List<String> ev = new ArrayList<>(); for (Hub.Event e : Hub.I.eventsSince(0)) ev.add(e.json());
        List<String> logs = new ArrayList<>(); for (String l : Hub.I.logs()) logs.add(Json.str(l));
        List<String> lis = new ArrayList<>(); for (String l : res.listening) lis.add(Json.str(l));
        return Json.obj("servers", Json.raw(arr(srv)),
                "recursion", Json.raw(Json.obj("servers", AuthServer.recursion, "upstream", res.recursiveUpstream)),
                "resolver", Json.raw(Json.obj("listening", Json.raw(arr(lis)), "secure", res.secure, "queries", res.queries.get(), "upstream", res.upstream.get(),
                        "rejected", res.rejected.get(), "timeouts", res.timeouts.get(), "hits", res.cache.hits, "misses", res.cache.misses, "size", res.cache.size())),
                "cache", Json.raw(arr(cache)), "events", Json.raw(arr(ev.subList(Math.max(0, ev.size() - 40), ev.size()))),
                "logs", Json.raw(arr(logs.subList(Math.max(0, logs.size() - 150), logs.size()))));
    }

    private String lines(long since) {
        List<String> l = new ArrayList<>();
        for (Hub.Line x : Hub.I.linesSince(since)) l.add(x.json());
        if (l.size() > 600) l = l.subList(l.size() - 600, l.size());
        return Json.obj("lines", Json.raw(arr(l)));
    }

    private static final Map<String, String[]> SERVERS = new HashMap<>();
    static {
        SERVERS.put("resolver", new String[]{"127.0.0.1", "5300"});
        SERVERS.put("root", new String[]{"127.0.0.10", "5300"});
        SERVERS.put("edu", new String[]{"127.0.0.11", "5300"});
        SERVERS.put("myuniv", new String[]{"127.0.0.12", "5300"});
        SERVERS.put("cse", new String[]{"127.0.0.13", "5300"});
        SERVERS.put("google", new String[]{"8.8.8.8", "53"});
        SERVERS.put("cloudflare", new String[]{"1.1.1.1", "53"});
        SERVERS.put("aroot", new String[]{"198.41.0.4", "53"});
    }

    private String dig(Map<String, String> q) throws IOException {
        String[] s = SERVERS.get(q.getOrDefault("server", "resolver"));
        String host = s != null ? s[0] : q.getOrDefault("host", "127.0.0.1");
        int port = s != null ? Integer.parseInt(s[1]) : Integer.parseInt(q.getOrDefault("port", "53"));
        String name = q.getOrDefault("name", "www.cse.myuniv.edu").trim();
        if (name.endsWith(".")) name = name.substring(0, name.length() - 1);
        DnsClient.Result r = DnsClient.query(host, port, name, Message.typeOf(q.getOrDefault("type", "A")),
                !"0".equals(q.get("rd")), "1".equals(q.get("tcp")), host.startsWith("127.") ? 6000 : 3000);
        return r.json();
    }

    private Zone zone(String key) {
        switch (key == null ? "cse" : key) {
            case "root": return lab.root; case "edu": return lab.edu; case "myuniv": return lab.uni; case "rev": return lab.rev; default: return lab.cse;
        }
    }

    private String zones() {
        List<String> z = new ArrayList<>();
        String[][] keys = {{"root", "a.root-servers.lab", "127.0.0.10"}, {"edu", "ns.edu-servers.lab", "127.0.0.11"}, {"myuniv", "ns1.myuniv.edu", "127.0.0.12"},
                {"cse", "dns.cse.myuniv.edu", "127.0.0.13"}, {"rev", "dns.cse.myuniv.edu", "127.0.0.13"}};
        for (String[] k : keys) {
            Zone zz = zone(k[0]);
            List<String> rr = new ArrayList<>(); for (RR r : zz.records) rr.add(r.json());
            z.add(Json.obj("key", k[0], "origin", Message.fq(zz.origin), "server", k[1], "ip", k[2], "records", Json.raw(arr(rr)), "file", zz.zoneFile()));
        }
        return Json.obj("zones", Json.raw(arr(z)));
    }

    private String zoneEdit(Map<String, String> q, boolean add) {
        Zone z = zone(q.get("zone"));
        String name = q.getOrDefault("name", "").trim().toLowerCase();
        if (name.endsWith(".")) name = name.substring(0, name.length() - 1);
        if (name.isEmpty() || name.equals("@")) name = z.origin;
        else if (!z.contains(name)) name = name + "." + z.origin;
        int type = Message.typeOf(q.getOrDefault("type", "A"));
        String value = q.getOrDefault("value", "").trim();
        if (add) {
            if (value.isEmpty()) return Json.obj("error", "value is empty");
            if ((type == Message.CNAME || type == Message.NS || type == Message.PTR) && value.endsWith(".")) value = value.substring(0, value.length() - 1);
            RR test = new RR(name, type, 300, value);
            Message m = new Message(); m.an.add(test); m.encode();                    // validates the data
            z.add(name, type, Long.parseLong(q.getOrDefault("ttl", "300")), value);
            res.cache.removeName(name);
            Hub.I.event("ZONE", "added " + test.toString().replace("  ", " ") + " to zone " + Message.fq(z.origin));
        } else {
            boolean ok = z.remove(name, type, value.isEmpty() ? null : value);
            res.cache.removeName(name);
            Hub.I.event("ZONE", (ok ? "removed " : "no record ") + name + " " + Message.typeName(type) + " from zone " + Message.fq(z.origin));
        }
        return zones();
    }

    private static String arr(List<String> l) { return "[" + String.join(",", l) + "]"; }

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
            try { if (i > 0) m.put(URLDecoder.decode(kv.substring(0, i), "UTF-8"), URLDecoder.decode(kv.substring(i + 1), "UTF-8")); } catch (Exception ignored) { }
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
}

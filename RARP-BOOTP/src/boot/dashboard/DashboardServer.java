package boot.dashboard;

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
import boot.Topology;
import boot.bootp.Bootp;
import boot.core.Hub;
import boot.core.Json;
import boot.rarp.Lan;

/** HTTP API + static page (http://localhost:8085). */
public final class DashboardServer {

    private final int port; private final Topology topo; private final Lan lan; private final Bootp bootp; private final File web;
    private HttpServer http;

    public DashboardServer(int port, Topology topo, Lan lan, Bootp bootp, File web) { this.port = port; this.topo = topo; this.lan = lan; this.bootp = bootp; this.web = web; }

    public void start() throws IOException {
        http = HttpServer.create(new InetSocketAddress(port), 0);
        http.createContext("/", this::route);
        http.setExecutor(Executors.newFixedThreadPool(8));
        http.start();
    }
    public void stop() { if (http != null) http.stop(0); }

    private void route(HttpExchange ex) throws IOException {
        Map<String, String> q = params(ex);
        try {
            switch (ex.getRequestURI().getPath()) {
                case "/": case "/index.html": file(ex); return;
                case "/api/state": json(ex, state()); return;
                case "/api/lines": json(ex, lines(Long.parseLong(q.getOrDefault("since", "0")))); return;
                case "/api/rarp": {
                    List<String> e = new ArrayList<>(); for (Lan.Event x : lan.boot(q.getOrDefault("ws", "WS-1"))) e.add(x.json());
                    json(ex, Json.obj("events", Json.raw("[" + String.join(",", e) + "]"))); return;
                }
                case "/api/bootp": json(ex, bootp.boot(q.getOrDefault("ws", "WS-1")).json()); return;
                case "/api/relay": bootp.relayOn = !"0".equals(q.get("on")); json(ex, Json.obj("relay", bootp.relayOn)); return;
                case "/api/register": {
                    Topology.Station s = topo.station(q.getOrDefault("ws", ""));
                    if (s == null) { json(ex, Json.obj("error", "no such station")); return; }
                    if ("0".equals(q.get("on"))) topo.table.remove(s.mac);
                    else topo.reg(s.mac, q.getOrDefault("ip", "10.0.1.23"), s.name.toLowerCase().replace("-", ""), "/tftpboot/sunos-" + s.name.toLowerCase().replace("-", "") + ".img");
                    Hub.I.event("TABLE", ("0".equals(q.get("on")) ? "removed " : "registered ") + s.name + " " + s.mac);
                    json(ex, state()); return;
                }
                default: send(ex, 404, "text/plain", "not found".getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception e) { json(ex, Json.obj("error", e.getClass().getSimpleName() + ": " + e.getMessage())); }
    }

    private String state() {
        List<String> logs = new ArrayList<>(); for (String l : Hub.I.logs()) logs.add(Json.str(l));
        return Json.obj("topology", Json.raw(topo.json()), "relay", bootp.relayOn, "logs", Json.raw("[" + String.join(",", logs.subList(Math.max(0, logs.size() - 100), logs.size())) + "]"));
    }

    private String lines(long since) {
        List<String> l = new ArrayList<>(); for (Hub.Line x : Hub.I.linesSince(since)) l.add(x.json());
        return Json.obj("lines", Json.raw("[" + String.join(",", l) + "]"));
    }

    private static Map<String, String> params(HttpExchange ex) throws IOException {
        Map<String, String> m = new HashMap<>();
        parse(ex.getRequestURI().getRawQuery(), m);
        if ("POST".equalsIgnoreCase(ex.getRequestMethod())) {
            try (InputStream in = ex.getRequestBody()) { ByteArrayOutputStream b = new ByteArrayOutputStream(); in.transferTo(b); parse(b.toString(StandardCharsets.UTF_8), m); }
        }
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

package route.dashboard;

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
import route.core.Hub;
import route.core.Json;
import route.sim.Scenarios;
import route.sim.Topo;
import route.wire.Bgp;
import route.wire.Ospf;
import route.wire.Rip;

/** HTTP API + static page for the routing dashboard (http://localhost:8088). */
public final class DashboardServer {

    private final int port; private final File web;
    private HttpServer http;

    public DashboardServer(int port, File web) { this.port = port; this.web = web; }

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
                case "/api/run": json(ex, Scenarios.run(q.getOrDefault("scn", "dijkstra"), q)); return;
                case "/api/decode": json(ex, decode(q.getOrDefault("proto", "rip"), q.getOrDefault("hex", ""), Topo.byId(q.getOrDefault("topo", "six")).names)); return;
                case "/api/state": {
                    List<String> logs = new ArrayList<>(); List<String> all = Hub.I.logs();
                    for (String l : all.subList(Math.max(0, all.size() - 60), all.size())) logs.add(Json.str(l));
                    json(ex, Json.obj("rip520", Scenarios.lastRealRip, "bgp179", Scenarios.lastRealBgp, "logs", Json.raw(Json.arr(logs))));
                    return;
                }
                default: send(ex, 404, "text/plain", "not found".getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception e) { json(ex, Json.obj("error", e.getClass().getSimpleName() + ": " + e.getMessage())); }
    }

    /** Field-by-field breakdown of one captured packet for the inspector. */
    private static String decode(String proto, String hex, String[] names) {
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        List<String[]> f = proto.equals("ospf") ? Ospf.fields(b, names) : proto.equals("bgp") ? Bgp.fields(b) : Rip.fields(b, names);
        List<String> out = new ArrayList<>();
        for (String[] x : f) out.add(Json.obj("off", Integer.parseInt(x[0]), "len", Integer.parseInt(x[1]), "name", x[2], "value", x[3]));
        return Json.obj("proto", proto, "bytes", b.length, "fields", Json.raw(Json.arr(out)));
    }

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

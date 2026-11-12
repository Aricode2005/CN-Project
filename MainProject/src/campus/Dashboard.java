package campus;

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

import arp.model.ArpCacheEntry;
import arp.model.SwitchCamEntry;
import arp.network.HostNode;
import arp.security.DhcpSnoopingTable;
import dhcp.model.LeaseRecord;

/** HTTP API + page for the integrated dashboard (http://localhost:8089). */
public final class Dashboard {

    private final int port; private final Bus bus; private final Story story; private final File web; private final boolean tls;
    private HttpServer http;

    public Dashboard(int port, Bus bus, Story story, File web, boolean tls) { this.port = port; this.bus = bus; this.story = story; this.web = web; this.tls = tls; }

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
                case "/": case "/index.html": {
                    File f = new File(web, "dashboard.html");
                    if (!f.exists()) { send(ex, 404, "text/plain", ("missing " + f.getAbsolutePath()).getBytes(StandardCharsets.UTF_8)); return; }
                    send(ex, 200, "text/html; charset=utf-8", Files.readAllBytes(f.toPath())); return;
                }
                case "/api/state": json(ex, state(Long.parseLong(q.getOrDefault("since", "0")))); return;
                case "/api/forward": { Story.Result r = story.forward(); json(ex, Json.obj("index", story.index(), "say", r.say, "mood", r.mood, "replay", Json.raw(Json.arr(r.replay)))); return; }
                case "/api/restart": story.restart(); json(ex, Json.obj("index", 0)); return;
                default: send(ex, 404, "text/plain", "not found".getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception e) { json(ex, Json.obj("error", e.getClass().getSimpleName() + ": " + e.getMessage())); }
    }

    private String state(long since) {
        List<String> steps = new ArrayList<>();
        for (Story.Step s : story.steps) steps.add(Json.obj("title", s.title, "lead", s.lead));

        List<String> ports = new ArrayList<>();
        ports.add(port(1, bus.hostA, "host")); ports.add(port(2, bus.hostB, "host")); ports.add(port(3, bus.hostC, "host"));
        ports.add(port(4, bus.router, "router")); ports.add(port(5, bus.attacker, "attacker"));
        HostNode a = bus.admin;
        if (a != null) ports.add(port(Bus.ADMIN_PORT, a, "laptop"));

        List<String> arp = new ArrayList<>();
        if (a != null) for (ArpCacheEntry e : a.getArpTable().getEntries())
            arp.add(Json.obj("ip", String.valueOf(e.getIp()), "mac", String.valueOf(e.getMac()), "state", String.valueOf(e.getState()),
                "bad", e.getMac() != null && e.getMac().equals(bus.attacker.getNic().getMac()) && !e.getIp().equals(bus.attacker.getNic().getIp())));
        List<String> cam = new ArrayList<>();
        for (SwitchCamEntry e : bus.sw.getCamEntries()) cam.add(Json.obj("mac", String.valueOf(e.getMac()), "port", e.getPort()));
        List<String> binds = new ArrayList<>();
        for (DhcpSnoopingTable.Binding b : bus.snooping.getBindings()) binds.add(Json.obj("ip", String.valueOf(b.ip), "mac", String.valueOf(b.mac), "port", b.port, "host", b.hostname));
        List<String> leases = new ArrayList<>();
        try {
            for (LeaseRecord r : bus.leases())
                leases.add(Json.obj("ip", r.getIpAddress(), "mac", r.getMacAddress().toUpperCase(), "host", r.getHostname(), "state", String.valueOf(r.getState()), "node", r.getAllocatedByNode(),
                    "left", r.isStaticReservation() ? -1 : r.getRemainingSeconds()));
        } catch (RuntimeException e) { /* cluster restarting */ }
        List<String> evs = new ArrayList<>();
        for (Bus.Ev e : bus.since(since)) evs.add(e.json());

        return Json.obj("step", story.index(), "total", story.steps.size(), "steps", Json.raw(Json.arr(steps)), "say", story.lastSay, "mood", story.lastMood,
            "ports", Json.raw(Json.arr(ports)), "arp", Json.raw(Json.arr(arp)), "cam", Json.raw(Json.arr(cam)), "bindings", Json.raw(Json.arr(binds)), "leases", Json.raw(Json.arr(leases)),
            "dai", Json.raw(Json.obj("enabled", bus.dai.isEnabled(), "inspected", bus.dai.getInspectedCount(), "passed", bus.dai.getPassedCount(), "dropped", bus.dai.getDroppedCount())),
            "mitm", bus.attacker.isMitmActive(), "poisoned", bus.poisoned(), "adminIp", bus.adminIp, "gatewayMac", String.valueOf(bus.router.getNic().getMac()),
            "sniffed", bus.sniffed(), "transcript", bus.lastTranscript, "tls", tls, "events", Json.raw(Json.arr(evs)));
    }

    private static String port(int p, HostNode h, String kind) {
        return Json.obj("port", p, "name", h.getHostname(), "ip", String.valueOf(h.getNic().getIp()), "mac", String.valueOf(h.getNic().getMac()), "kind", kind);
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
    private static void json(HttpExchange ex, String s) throws IOException { send(ex, 200, "application/json; charset=utf-8", s.getBytes(StandardCharsets.UTF_8)); }
    private static void send(HttpExchange ex, int code, String type, byte[] b) throws IOException {
        ex.getResponseHeaders().set("Content-Type", type); ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream o = ex.getResponseBody()) { o.write(b); }
    }
}

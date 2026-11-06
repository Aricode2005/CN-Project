package arp.dashboard;

import arp.core.Hub;
import arp.core.Json;
import arp.model.IpAddress;
import arp.model.MacAddress;
import arp.network.AttackerNode;
import arp.network.EthernetSwitch;
import arp.network.HostNode;
import arp.network.RouterNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Built-in Zero-Dependency HTTP Dashboard & Control Server on Port 8082.
 */
public final class DashboardServer {

    private final int port;
    private final EthernetSwitch ethernetSwitch;
    private final List<HostNode> hosts;
    private final RouterNode router;
    private final AttackerNode attacker;
    private final File webDir;
    private HttpServer server;

    public DashboardServer(
            int port,
            EthernetSwitch ethernetSwitch,
            List<HostNode> hosts,
            RouterNode router,
            AttackerNode attacker,
            File webDir) {
        this.port = port;
        this.ethernetSwitch = ethernetSwitch;
        this.hosts = hosts;
        this.router = router;
        this.attacker = attacker;
        this.webDir = webDir;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", this::handleStatic);
        server.createContext("/api/state", this::handleApiState);
        server.createContext("/api/action", this::handleApiAction);
        server.setExecutor(null);
        server.start();
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    private void handleStatic(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        if (path == null || path.equals("/") || path.isEmpty()) {
            path = "/dashboard.html";
        }

        File targetFile = new File(webDir, path.startsWith("/") ? path.substring(1) : path);
        if (targetFile.exists() && !targetFile.isDirectory()) {
            String mime = path.endsWith(".html") ? "text/html; charset=UTF-8"
                    : path.endsWith(".css") ? "text/css"
                    : path.endsWith(".js") ? "application/javascript"
                    : "text/plain";
            byte[] data = readFileToBytes(targetFile);
            ex.getResponseHeaders().set("Content-Type", mime);
            ex.sendResponseHeaders(200, data.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(data);
            }
        } else {
            // Serve fallback dashboard HTML if file is missing
            String html = getFallbackHtml();
            byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
            ex.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(bytes);
            }
        }
    }

    private byte[] readFileToBytes(File file) throws IOException {
        try (InputStream is = new FileInputStream(file)) {
            return is.readAllBytes();
        }
    }

    private void handleApiState(HttpExchange ex) throws IOException {
        List<String> hostJsons = new ArrayList<>();
        for (HostNode h : hosts) {
            hostJsons.add(h.json());
        }

        List<String> frameJsons = new ArrayList<>();
        for (Hub.CapturedFrame f : Hub.I.framesSince(0)) {
            frameJsons.add(f.json());
        }

        List<String> interceptedJsons = new ArrayList<>();
        for (Hub.InterceptedData id : Hub.I.intercepted.snapshot()) {
            interceptedJsons.add(id.json());
        }

        String json = Json.obj(
                "port", port,
                "hosts", Json.arr(hostJsons),
                "router", Json.raw(router.json()),
                "attacker", Json.raw(attacker.json()),
                "switch", Json.raw(ethernetSwitch.json()),
                "frames", Json.arr(frameJsons),
                "intercepted", Json.arr(interceptedJsons),
                "logs", Json.arr(Hub.I.logs())
        );

        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        ex.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void handleApiAction(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            ex.sendResponseHeaders(405, -1);
            return;
        }

        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> params = parseFormBody(body);
        String action = params.get("action");
        String message = "OK";

        try {
            if ("ping".equals(action)) {
                String from = params.get("from");
                String to = params.get("to");
                String text = params.get("msg");
                HostNode sender = findHost(from);
                if (sender != null && to != null) {
                    sender.ping(IpAddress.parse(to), text);
                    message = "Ping dispatched from " + from + " to " + to;
                }
            } else if ("arp_request".equals(action)) {
                String from = params.get("from");
                String target = params.get("target");
                HostNode sender = findHost(from);
                if (sender != null && target != null) {
                    sender.sendArpRequest(IpAddress.parse(target));
                    message = "ARP Request sent by " + from + " for " + target;
                }
            } else if ("garp".equals(action)) {
                String host = params.get("host");
                HostNode sender = findHost(host);
                if (sender != null) {
                    sender.sendGratuitousArp();
                    message = "Gratuitous ARP sent by " + host;
                }
            } else if ("probe".equals(action)) {
                String host = params.get("host");
                String candidate = params.get("candidate");
                HostNode sender = findHost(host);
                if (sender != null && candidate != null) {
                    sender.sendArpProbe(IpAddress.parse(candidate));
                    message = "ARP Probe sent for " + candidate;
                }
            } else if ("mitm_poison".equals(action)) {
                attacker.launchArpPoisoning();
                message = "MITM ARP Cache Poisoning launched!";
            } else if ("mitm_stop".equals(action)) {
                attacker.stopMitm();
                message = "MITM Attack stopped.";
            } else if ("dai_toggle".equals(action)) {
                boolean enable = Boolean.parseBoolean(params.get("enabled"));
                ethernetSwitch.getDai().setEnabled(enable);
                message = "Dynamic ARP Inspection (DAI) " + (enable ? "ENABLED" : "DISABLED");
            } else if ("proxy_arp_toggle".equals(action)) {
                boolean enable = Boolean.parseBoolean(params.get("enabled"));
                router.setProxyArpEnabled(enable);
                message = "Proxy ARP " + (enable ? "ENABLED" : "DISABLED");
            } else if ("clear_caches".equals(action)) {
                for (HostNode h : hosts) h.getArpTable().clearDynamic();
                router.getArpTable().clearDynamic();
                attacker.getArpTable().clearDynamic();
                ethernetSwitch.clearCamTable();
                message = "All host ARP tables and switch CAM flushed.";
            } else if ("cam_overflow".equals(action)) {
                int count = Integer.parseInt(params.getOrDefault("count", "30"));
                attacker.floodRandomMacs(count);
                message = "Flooded switch with " + count + " random MACs.";
            } else if ("static_vip".equals(action)) {
                String host = params.get("host");
                String ip = params.get("ip");
                String mac = params.get("mac");
                HostNode targetHost = findHost(host);
                if (targetHost != null && ip != null && mac != null) {
                    targetHost.getArpTable().putStatic(IpAddress.parse(ip), MacAddress.parse(mac));
                    message = "Static VIP entry added to " + host;
                }
            }
        } catch (Exception e) {
            message = "Error: " + e.getMessage();
        }

        String resJson = Json.obj("status", "ok", "message", message);
        byte[] bytes = resJson.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        ex.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private HostNode findHost(String name) {
        if (name == null) return null;
        if (router.getHostname().equalsIgnoreCase(name)) return router;
        if (attacker.getHostname().equalsIgnoreCase(name)) return attacker;
        for (HostNode h : hosts) {
            if (h.getHostname().equalsIgnoreCase(name)) return h;
        }
        return null;
    }

    private Map<String, String> parseFormBody(String body) {
        Map<String, String> map = new HashMap<>();
        if (body == null || body.isEmpty()) return map;
        String[] pairs = body.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf('=');
            if (idx > 0) {
                String k = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
                String v = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
                map.put(k, v);
            }
        }
        return map;
    }

    private String getFallbackHtml() {
        return "<!DOCTYPE html><html><head><title>ARP Lab Dashboard</title></head><body><h1>ARP Lab Running on port " + port + "</h1><p>Visit /api/state for JSON telemetry.</p></body></html>";
    }
}

package dhcp.dashboard;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import dhcp.client.DhcpClientSimulator;
import dhcp.cluster.DhcpServerNode;
import dhcp.lb.ConsistentHashRouter;
import dhcp.lb.DhcpLoadBalancer;
import dhcp.lb.RateLimiter;
import dhcp.model.LeaseRecord;
import dhcp.protocol.PcapRecorder;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

public class DashboardServer {

    private final int httpPort;
    private final DhcpLoadBalancer loadBalancer;
    private final List<DhcpServerNode> nodes;
    private final DhcpClientSimulator simulator;
    private final List<String> recentLogs;
    private HttpServer server;

    public DashboardServer(
            int httpPort,
            DhcpLoadBalancer loadBalancer,
            List<DhcpServerNode> nodes,
            DhcpClientSimulator simulator,
            List<String> recentLogs) {
        this.httpPort = httpPort;
        this.loadBalancer = loadBalancer;
        this.nodes = nodes;
        this.simulator = simulator;
        this.recentLogs = recentLogs;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(httpPort), 0);
        server.createContext("/", this::handleIndex);
        server.createContext("/api/state", this::handleApiState);
        server.createContext("/api/action", this::handleApiAction);
        server.createContext("/api/pcap", this::handlePcapDownload);
        server.createContext("/api/pcap/files", this::handlePcapFileList);
        server.createContext("/api/pcap/file", this::handlePcapFileDownload);
        server.setExecutor(null);
        server.start();
    }

    private static final java.nio.file.Path CAPTURE_DIR = java.nio.file.Paths.get(
            System.getenv().getOrDefault("CAPTURE_DIR", "captures"));
    private static final java.util.regex.Pattern SAFE_PCAP_NAME =
            java.util.regex.Pattern.compile("[A-Za-z0-9_.-]{1,120}\\.pcap");

    private void handlePcapFileList(HttpExchange exchange) throws IOException {
        StringBuilder json = new StringBuilder("{\"dir\":\"")
                .append(escape(CAPTURE_DIR.toAbsolutePath().toString())).append("\",\"files\":[");
        java.io.File[] files = CAPTURE_DIR.toFile().listFiles(
                (d, n) -> SAFE_PCAP_NAME.matcher(n).matches());
        if (files != null) {
            java.util.Arrays.sort(files, (a, b) -> Long.compare(b.lastModified(), a.lastModified()));
            for (int i = 0; i < files.length; i++) {
                if (i > 0) json.append(",");
                json.append("{\"name\":\"").append(escape(files[i].getName())).append("\",")
                    .append("\"size\":").append(files[i].length()).append(",")
                    .append("\"modified\":").append(files[i].lastModified()).append("}");
            }
        }
        json.append("]}");
        byte[] bytes = json.toString().getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void handlePcapFileDownload(HttpExchange exchange) throws IOException {
        String query = exchange.getRequestURI().getQuery();
        String name = null;
        if (query != null) {
            for (String part : query.split("&")) {
                if (part.startsWith("name=")) {
                    name = java.net.URLDecoder.decode(part.substring(5), "UTF-8");
                }
            }
        }
        java.nio.file.Path file = (name != null && SAFE_PCAP_NAME.matcher(name).matches())
                ? CAPTURE_DIR.resolve(name) : null;
        if (file == null || !java.nio.file.Files.isRegularFile(file)) {
            byte[] msg = "Capture file not found".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(404, msg.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(msg);
            }
            return;
        }
        byte[] data = java.nio.file.Files.readAllBytes(file);
        exchange.getResponseHeaders().set("Content-Type", "application/vnd.tcpdump.pcap");
        exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"" + name + "\"");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(200, data.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(data);
        }
    }

    private void handlePcapDownload(HttpExchange exchange) throws IOException {
        String query = exchange.getRequestURI().getQuery();
        boolean dhcpOnly = query != null && query.contains("filter=dhcp");
        byte[] pcap = PcapRecorder.exportPcap(!dhcpOnly);
        String stamp = new java.text.SimpleDateFormat("yyyyMMdd_HHmmss").format(new java.util.Date());
        String prefix = dhcpOnly ? "dhcp_gossip_traffic_" : "dhcp_full_cluster_";
        exchange.getResponseHeaders().set("Content-Type", "application/vnd.tcpdump.pcap");
        exchange.getResponseHeaders().set("Content-Disposition",
                "attachment; filename=\"" + prefix + stamp + ".pcap\"");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(200, pcap.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(pcap);
        }
    }

    private void handleIndex(HttpExchange exchange) throws IOException {
        String html = buildDashboardHtml();
        byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void handleApiState(HttpExchange exchange) throws IOException {
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"strategy\":\"").append(loadBalancer.getRouter().getStrategy().name()).append("\",");
        json.append("\"rateAlgorithm\":\"").append(loadBalancer.getRateLimiter().getAlgorithm().name()).append("\",");
        json.append("\"rateAllowed\":").append(loadBalancer.getRateLimiter().getTotalAllowed()).append(",");
        json.append("\"rateDropped\":").append(loadBalancer.getRateLimiter().getTotalDropped()).append(",");
        json.append("\"pcapEnabled\":").append(PcapRecorder.isEnabled()).append(",");
        json.append("\"pcapBuffered\":").append(PcapRecorder.getBufferedCount()).append(",");
        json.append("\"pcapDhcp\":").append(PcapRecorder.getDhcpCaptured()).append(",");
        json.append("\"pcapTotal\":").append(PcapRecorder.getTotalCaptured()).append(",");

        json.append("\"nodes\":[");
        Map<Integer, Boolean> healthMap = loadBalancer.getNodeHealthStatus();
        Map<Integer, Long> loadMap = loadBalancer.getRouter().getNodeLoadCounters();
        for (int i = 0; i < nodes.size(); i++) {
            DhcpServerNode n = nodes.get(i);
            if (i > 0) json.append(",");
            boolean lbHealthy = healthMap.getOrDefault(n.getUdpPort(), true);
            long routedCount = loadMap.getOrDefault(n.getUdpPort(), 0L);
            json.append("{")
                .append("\"nodeId\":\"").append(n.getNodeId()).append("\",")
                .append("\"serverIp\":\"").append(n.getServerIp()).append("\",")
                .append("\"port\":").append(n.getUdpPort()).append(",")
                .append("\"simulatedDown\":").append(n.isSimulatedDown()).append(",")
                .append("\"lbHealthy\":").append(lbHealthy).append(",")
                .append("\"routedPackets\":").append(routedCount).append(",")
                .append("\"offersSent\":").append(n.getOffersSent()).append(",")
                .append("\"acksSent\":").append(n.getAcksSent()).append(",")
                .append("\"peerSyncs\":").append(n.getPeerSyncsReceived())
                .append("}");
        }
        json.append("],");

        DhcpServerNode primaryView = nodes.get(0);
        for (DhcpServerNode n : nodes) {
            if (!n.isSimulatedDown()) {
                primaryView = n;
                break;
            }
        }
        List<LeaseRecord> leases = primaryView.getLeaseManager().getAllLeases();
        json.append("\"poolTotal\":").append(primaryView.getLeaseManager().getTotalPoolSize()).append(",");
        json.append("\"leases\":[");
        for (int i = 0; i < leases.size(); i++) {
            LeaseRecord l = leases.get(i);
            if (i > 0) json.append(",");
            json.append("{")
                .append("\"ip\":\"").append(escape(l.getIpAddress())).append("\",")
                .append("\"mac\":\"").append(escape(l.getMacAddress())).append("\",")
                .append("\"hostname\":\"").append(escape(l.getHostname())).append("\",")
                .append("\"state\":\"").append(l.getState().name()).append("\",")
                .append("\"node\":\"").append(escape(l.getAllocatedByNode())).append("\",")
                .append("\"ttl\":").append(l.isStaticReservation() ? -1 : l.getRemainingSeconds()).append(",")
                .append("\"isStatic\":").append(l.isStaticReservation())
                .append("}");
        }
        json.append("],");

        json.append("\"logs\":[");
        synchronized (recentLogs) {
            int start = Math.max(0, recentLogs.size() - 35);
            for (int i = start; i < recentLogs.size(); i++) {
                if (i > start) json.append(",");
                json.append("\"").append(escape(recentLogs.get(i))).append("\"");
            }
        }
        json.append("]}");

        byte[] bytes = json.toString().getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void handleApiAction(HttpExchange exchange) throws IOException {
        String query = exchange.getRequestURI().getQuery();
        String resultMsg = "OK";

        if (query != null) {
            if (query.contains("cmd=dora1")) {
                new Thread(() -> simulator.simulateConcurrentClients(1)).start();
                resultMsg = "Triggered 1 Client DORA Handshake";
            } else if (query.contains("cmd=dora5")) {
                new Thread(() -> simulator.simulateConcurrentClients(5)).start();
                resultMsg = "Triggered 5 Concurrent Client DORA Handshakes";
            } else if (query.contains("cmd=vip")) {
                new Thread(() -> simulator.runSingleClientDora("00:1A:2B:3C:4D:01", "gateway-admin-vip")).start();
                resultMsg = "Triggered Static VIP Reservation DORA (00:1A:2B:3C:4D:01)";
            } else if (query.contains("cmd=inform")) {
                new Thread(() -> simulator.sendInform("AA:BB:CC:99:88:77", "192.168.10.250", "static-printer-01")).start();
                resultMsg = "Triggered DHCPINFORM (static-printer-01)";
            } else if (query.contains("cmd=release")) {
                new Thread(() -> simulator.sendRelease("AA:BB:CC:11:22:02", "192.168.10.11")).start();
                resultMsg = "Triggered DHCPRELEASE for 192.168.10.11";
            } else if (query.contains("cmd=decline")) {
                new Thread(() -> simulator.sendDecline("AA:BB:CC:11:22:03", "192.168.10.12")).start();
                resultMsg = "Triggered DHCPDECLINE (ARP Conflict) for 192.168.10.12";
            } else if (query.contains("cmd=starvation")) {
                new Thread(() -> simulator.simulateStarvationAttack(40)).start();
                resultMsg = "Triggered Simulated DHCP Starvation Flood (40 rapid packets)";
            } else if (query.contains("cmd=strategy_ch")) {
                loadBalancer.getRouter().setStrategy(ConsistentHashRouter.Strategy.CONSISTENT_HASHING);
                resultMsg = "Switched to CONSISTENT_HASHING";
            } else if (query.contains("cmd=strategy_rr")) {
                loadBalancer.getRouter().setStrategy(ConsistentHashRouter.Strategy.ROUND_ROBIN);
                resultMsg = "Switched to ROUND_ROBIN";
            } else if (query.contains("cmd=strategy_ll")) {
                loadBalancer.getRouter().setStrategy(ConsistentHashRouter.Strategy.LEAST_LOADED);
                resultMsg = "Switched to LEAST_LOADED";
            } else if (query.contains("cmd=rate_tb")) {
                loadBalancer.getRateLimiter().setAlgorithm(RateLimiter.Algorithm.TOKEN_BUCKET);
                resultMsg = "Switched to TOKEN_BUCKET Rate Limiter";
            } else if (query.contains("cmd=rate_sw")) {
                loadBalancer.getRateLimiter().setAlgorithm(RateLimiter.Algorithm.SLIDING_WINDOW_COUNTER);
                resultMsg = "Switched to SLIDING_WINDOW_COUNTER Rate Limiter";
            } else if (query.contains("cmd=pcap_clear")) {
                PcapRecorder.clear();
                resultMsg = "Packet capture buffer cleared";
            } else if (query.contains("cmd=pcap_toggle")) {
                PcapRecorder.setEnabled(!PcapRecorder.isEnabled());
                resultMsg = PcapRecorder.isEnabled() ? "Packet capture resumed" : "Packet capture paused";
            } else if (query.startsWith("cmd=toggle_node_")) {
                int idx = Integer.parseInt(query.substring("cmd=toggle_node_".length()));
                if (idx >= 0 && idx < nodes.size()) {
                    DhcpServerNode node = nodes.get(idx);
                    node.setSimulatedDown(!node.isSimulatedDown());
                    resultMsg = "Toggled " + node.getNodeId();
                }
            }
        }

        byte[] resp = ("{\"status\":\"" + escape(resultMsg) + "\"}").getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, resp.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(resp);
        }
    }

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ").replace("\r", "");
    }

    public void shutdown() {
        if (server != null) {
            server.stop(0);
        }
    }

    private String buildDashboardHtml() {
        StringBuilder sb = new StringBuilder(47157);
        sb.append("<!DOCTYPE html>\n");
        sb.append("<html lang=\"en\">\n");
        sb.append("<head>\n");
        sb.append("<meta charset=\"UTF-8\">\n");
        sb.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        sb.append("<title>DHCP Cluster Control Center</title>\n");
        sb.append("<style>\n");
        sb.append(":root {\n");
        sb.append("  --bg: #0b1120; --panel: #111a2e; --panel-2: #16213a; --border: #22304d; --border-2: #2c3d60;\n");
        sb.append("  --text: #e6ebf5; --muted: #8b99b5; --dim: #5d6b88;\n");
        sb.append("  --accent: #4f8cff; --accent-soft: rgba(79,140,255,.14);\n");
        sb.append("  --green: #22c55e; --green-soft: rgba(34,197,94,.14);\n");
        sb.append("  --red: #ef4444; --red-soft: rgba(239,68,68,.14);\n");
        sb.append("  --amber: #f59e0b; --amber-soft: rgba(245,158,11,.14);\n");
        sb.append("  --violet: #a78bfa; --violet-soft: rgba(167,139,250,.14);\n");
        sb.append("  --cyan: #22d3ee;\n");
        sb.append("  --radius: 12px; --shadow: 0 1px 2px rgba(0,0,0,.3), 0 8px 24px rgba(0,0,0,.18);\n");
        sb.append("  --mono: 'Cascadia Code', Consolas, 'SFMono-Regular', Menlo, monospace;\n");
        sb.append("}\n");
        sb.append("* { box-sizing: border-box; }\n");
        sb.append("html, body { margin: 0; padding: 0; }\n");
        sb.append("body { background: var(--bg); color: var(--text); font: 14px/1.45 'Segoe UI', system-ui, -apple-system, Roboto, sans-serif; -webkit-font-smoothing: antialiased; }\n");
        sb.append("button { font-family: inherit; }\n");
        sb.append(".wrap { max-width: 1480px; margin: 0 auto; padding: 0 24px 32px; }\n");
        sb.append("\n");
        sb.append("/* Top bar */\n");
        sb.append(".topbar { position: sticky; top: 0; z-index: 50; background: rgba(11,17,32,.88); backdrop-filter: blur(10px); border-bottom: 1px solid var(--border); margin-bottom: 22px; }\n");
        sb.append(".topbar-inner { max-width: 1480px; margin: 0 auto; padding: 14px 24px; display: flex; align-items: center; gap: 18px; flex-wrap: wrap; }\n");
        sb.append(".brand { display: flex; align-items: center; gap: 12px; margin-right: auto; }\n");
        sb.append(".logo { width: 38px; height: 38px; border-radius: 10px; background: linear-gradient(135deg, #4f8cff, #7c5cff); display: grid; place-items: center; font-weight: 800; font-size: 15px; letter-spacing: .5px; box-shadow: 0 4px 14px rgba(79,140,255,.35); }\n");
        sb.append(".brand h1 { font-size: 17px; margin: 0; font-weight: 650; letter-spacing: .2px; }\n");
        sb.append(".brand p { margin: 1px 0 0; color: var(--muted); font-size: 12px; }\n");
        sb.append(".pill { display: inline-flex; align-items: center; gap: 7px; padding: 6px 12px; border-radius: 999px; background: var(--panel-2); border: 1px solid var(--border); font-size: 12px; color: var(--muted); white-space: nowrap; }\n");
        sb.append(".pill b { color: var(--text); font-weight: 600; }\n");
        sb.append(".live-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green); box-shadow: 0 0 0 0 rgba(34,197,94,.6); animation: pulse 1.8s infinite; }\n");
        sb.append(".live-dot.off { background: var(--red); animation: none; }\n");
        sb.append("@keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(34,197,94,.55); } 70% { box-shadow: 0 0 0 8px rgba(34,197,94,0); } 100% { box-shadow: 0 0 0 0 rgba(34,197,94,0); } }\n");
        sb.append("\n");
        sb.append(".banner { display: none; margin-bottom: 18px; padding: 12px 16px; border-radius: 10px; background: var(--red-soft); border: 1px solid rgba(239,68,68,.4); color: #fecaca; font-size: 13px; }\n");
        sb.append(".banner.show { display: block; }\n");
        sb.append("\n");
        sb.append("/* Section heading */\n");
        sb.append(".section-title { display: flex; align-items: center; gap: 8px; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); font-weight: 650; margin: 0 0 12px; }\n");
        sb.append(".section-title .help { cursor: help; }\n");
        sb.append("\n");
        sb.append("/* KPI cards */\n");
        sb.append(".kpis { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 14px; margin-bottom: 22px; }\n");
        sb.append(".kpi { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px 16px 14px; box-shadow: var(--shadow); cursor: help; transition: border-color .15s, transform .15s; min-width: 0; }\n");
        sb.append(".kpi:hover { border-color: var(--border-2); transform: translateY(-1px); }\n");
        sb.append(".kpi .label { color: var(--muted); font-size: 12px; font-weight: 600; display: flex; align-items: center; gap: 6px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }\n");
        sb.append(".kpi .value { font-size: 26px; font-weight: 700; margin-top: 6px; letter-spacing: -.5px; font-variant-numeric: tabular-nums; }\n");
        sb.append(".kpi .sub { color: var(--dim); font-size: 12px; margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }\n");
        sb.append(".kpi .bar { height: 5px; border-radius: 999px; background: var(--panel-2); margin-top: 10px; overflow: hidden; }\n");
        sb.append(".kpi .bar > span { display: block; height: 100%; border-radius: 999px; background: var(--accent); width: 0; transition: width .4s ease; }\n");
        sb.append(".ico { width: 22px; height: 22px; border-radius: 6px; display: inline-grid; place-items: center; font-size: 12px; flex: none; }\n");
        sb.append("\n");
        sb.append("/* Panels */\n");
        sb.append(".panel { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--shadow); min-width: 0; }\n");
        sb.append(".panel-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 14px 18px; border-bottom: 1px solid var(--border); flex-wrap: wrap; }\n");
        sb.append(".panel-head h2 { margin: 0; font-size: 15px; font-weight: 650; display: flex; align-items: center; gap: 8px; }\n");
        sb.append(".panel-body { padding: 16px 18px; }\n");
        sb.append("\n");
        sb.append("/* Control center */\n");
        sb.append(".controls { display: grid; grid-template-columns: 1.25fr 1fr 1.1fr 1.1fr; gap: 0; }\n");
        sb.append(".ctrl-group { padding: 16px 18px; border-right: 1px solid var(--border); min-width: 0; }\n");
        sb.append(".ctrl-group:last-child { border-right: none; }\n");
        sb.append(".ctrl-group h3 { margin: 0 0 12px; font-size: 12px; text-transform: uppercase; letter-spacing: .8px; color: var(--muted); font-weight: 650; }\n");
        sb.append(".btn-row { display: flex; flex-wrap: wrap; gap: 8px; }\n");
        sb.append(".btn { display: inline-flex; align-items: center; gap: 7px; border: 1px solid var(--border-2); background: var(--panel-2); color: var(--text); padding: 8px 13px; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer; transition: background .15s, border-color .15s, transform .05s, opacity .15s; white-space: nowrap; }\n");
        sb.append(".btn:hover { background: #1c2a48; border-color: #3a4f7a; }\n");
        sb.append(".btn:active { transform: translateY(1px); }\n");
        sb.append(".btn:disabled { opacity: .55; cursor: progress; }\n");
        sb.append(".btn.primary { background: var(--accent); border-color: var(--accent); color: #fff; }\n");
        sb.append(".btn.primary:hover { background: #3f7bf0; }\n");
        sb.append(".btn.warn { background: var(--amber-soft); border-color: rgba(245,158,11,.45); color: #fcd34d; }\n");
        sb.append(".btn.warn:hover { background: rgba(245,158,11,.24); }\n");
        sb.append(".btn.danger { background: var(--red-soft); border-color: rgba(239,68,68,.45); color: #fca5a5; }\n");
        sb.append(".btn.danger:hover { background: rgba(239,68,68,.24); }\n");
        sb.append(".btn.success { background: var(--green-soft); border-color: rgba(34,197,94,.45); color: #86efac; }\n");
        sb.append(".btn.success:hover { background: rgba(34,197,94,.24); }\n");
        sb.append(".btn.sm { padding: 5px 10px; font-size: 12px; }\n");
        sb.append("\n");
        sb.append(".seg { display: flex; flex-wrap: wrap; background: var(--bg); border: 1px solid var(--border); border-radius: 9px; padding: 3px; gap: 3px; }\n");
        sb.append(".seg button { flex: 1 1 auto; border: none; background: transparent; color: var(--muted); padding: 7px 10px; border-radius: 7px; font-size: 12.5px; font-weight: 600; cursor: pointer; transition: background .15s, color .15s; white-space: nowrap; }\n");
        sb.append(".seg button:hover { color: var(--text); background: var(--panel-2); }\n");
        sb.append(".seg button.active { background: var(--accent); color: #fff; box-shadow: 0 2px 8px rgba(79,140,255,.35); }\n");
        sb.append(".seg-label { font-size: 12px; color: var(--dim); margin: 12px 0 6px; }\n");
        sb.append(".meter { display: flex; gap: 14px; margin-top: 12px; font-size: 12px; color: var(--muted); flex-wrap: wrap; }\n");
        sb.append(".meter b { font-variant-numeric: tabular-nums; }\n");
        sb.append("\n");
        sb.append("/* Nodes */\n");
        sb.append(".nodes { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; margin: 22px 0; }\n");
        sb.append(".node { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--shadow); padding: 16px 18px; position: relative; overflow: hidden; min-width: 0; transition: border-color .2s; }\n");
        sb.append(".node::before { content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 3px; background: var(--green); }\n");
        sb.append(".node.down::before { background: var(--red); }\n");
        sb.append(".node.evicted::before { background: var(--amber); }\n");
        sb.append(".node.down { border-color: rgba(239,68,68,.35); }\n");
        sb.append(".node-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 12px; }\n");
        sb.append(".node-title { display: flex; align-items: center; gap: 10px; min-width: 0; }\n");
        sb.append(".node-title .name { font-weight: 650; font-size: 15px; }\n");
        sb.append(".node-title .addr { font-family: var(--mono); font-size: 12px; color: var(--muted); }\n");
        sb.append(".status-badge { display: inline-flex; align-items: center; gap: 6px; font-size: 11px; font-weight: 700; padding: 3px 9px; border-radius: 999px; letter-spacing: .4px; text-transform: uppercase; cursor: help; white-space: nowrap; }\n");
        sb.append(".status-badge::before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }\n");
        sb.append(".st-ok { background: var(--green-soft); color: #4ade80; }\n");
        sb.append(".st-down { background: var(--red-soft); color: #f87171; }\n");
        sb.append(".st-warn { background: var(--amber-soft); color: #fbbf24; }\n");
        sb.append(".node-stats { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }\n");
        sb.append(".stat { background: var(--panel-2); border: 1px solid var(--border); border-radius: 9px; padding: 9px 11px; cursor: help; min-width: 0; }\n");
        sb.append(".stat .k { font-size: 11px; color: var(--muted); font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }\n");
        sb.append(".stat .v { font-size: 18px; font-weight: 700; font-variant-numeric: tabular-nums; margin-top: 2px; }\n");
        sb.append(".share { margin-top: 12px; cursor: help; }\n");
        sb.append(".share .row { display: flex; justify-content: space-between; font-size: 12px; color: var(--muted); margin-bottom: 5px; }\n");
        sb.append(".share .track { height: 6px; background: var(--panel-2); border-radius: 999px; overflow: hidden; }\n");
        sb.append(".share .track span { display: block; height: 100%; background: linear-gradient(90deg, #4f8cff, #7c5cff); border-radius: 999px; transition: width .4s ease; }\n");
        sb.append("\n");
        sb.append("/* Bottom grid */\n");
        sb.append(".bottom { display: grid; grid-template-columns: minmax(0, 1.55fr) minmax(0, 1fr); gap: 14px; }\n");
        sb.append(".toolbar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }\n");
        sb.append(".search { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 7px 11px; color: var(--text); font-size: 13px; width: 200px; outline: none; transition: border-color .15s; }\n");
        sb.append(".search:focus { border-color: var(--accent); }\n");
        sb.append(".select { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 7px 9px; color: var(--text); font-size: 13px; outline: none; cursor: pointer; }\n");
        sb.append(".legend { display: flex; gap: 14px; flex-wrap: wrap; padding: 10px 18px; border-bottom: 1px solid var(--border); font-size: 12px; color: var(--muted); }\n");
        sb.append(".legend span { display: inline-flex; align-items: center; gap: 6px; cursor: help; }\n");
        sb.append(".legend i { width: 9px; height: 9px; border-radius: 3px; display: inline-block; }\n");
        sb.append("\n");
        sb.append(".table-wrap { max-height: 460px; overflow: auto; }\n");
        sb.append("table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 13px; }\n");
        sb.append("thead th { position: sticky; top: 0; background: var(--panel); z-index: 2; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: .7px; color: var(--muted); font-weight: 650; padding: 10px 14px; border-bottom: 1px solid var(--border); cursor: help; white-space: nowrap; }\n");
        sb.append("tbody td { padding: 10px 14px; border-bottom: 1px solid rgba(34,48,77,.6); white-space: nowrap; }\n");
        sb.append("tbody tr { transition: background .12s; }\n");
        sb.append("tbody tr:hover { background: rgba(79,140,255,.06); }\n");
        sb.append(".mono { font-family: var(--mono); font-size: 12.5px; }\n");
        sb.append(".ip { font-family: var(--mono); font-weight: 650; color: #cfe0ff; }\n");
        sb.append(".state { display: inline-flex; align-items: center; gap: 6px; font-size: 11px; font-weight: 700; padding: 3px 9px; border-radius: 6px; letter-spacing: .4px; cursor: help; }\n");
        sb.append(".s-ACTIVE { background: var(--green-soft); color: #4ade80; }\n");
        sb.append(".s-OFFERED { background: var(--accent-soft); color: #7fb0ff; }\n");
        sb.append(".s-DECLINED { background: var(--red-soft); color: #f87171; }\n");
        sb.append(".s-EXPIRED { background: rgba(139,153,181,.14); color: var(--muted); }\n");
        sb.append(".s-STATIC { background: var(--violet-soft); color: #c4b5fd; }\n");
        sb.append(".ttl { display: flex; align-items: center; gap: 8px; min-width: 110px; }\n");
        sb.append(".ttl .t { height: 5px; flex: 1; background: var(--panel-2); border-radius: 999px; overflow: hidden; }\n");
        sb.append(".ttl .t span { display: block; height: 100%; border-radius: 999px; }\n");
        sb.append(".ttl small { color: var(--muted); font-variant-numeric: tabular-nums; width: 38px; text-align: right; }\n");
        sb.append(".empty { text-align: center; color: var(--dim); padding: 40px 10px !important; white-space: normal !important; }\n");
        sb.append("\n");
        sb.append(".logs { height: 507px; overflow-y: auto; background: #070c18; font-family: var(--mono); font-size: 12px; padding: 10px 0; border-radius: 0 0 var(--radius) var(--radius); }\n");
        sb.append(".log { padding: 3px 16px 3px 14px; border-left: 2px solid transparent; white-space: pre-wrap; word-break: break-word; color: #b7c3dc; }\n");
        sb.append(".log:hover { background: rgba(255,255,255,.03); }\n");
        sb.append(".log.l-err { border-left-color: var(--red); color: #fca5a5; }\n");
        sb.append(".log.l-warn { border-left-color: var(--amber); color: #fcd34d; }\n");
        sb.append(".log.l-ok { border-left-color: var(--green); color: #86efac; }\n");
        sb.append(".log.l-sync { border-left-color: var(--violet); color: #c4b5fd; }\n");
        sb.append(".log.l-lb { border-left-color: var(--accent); color: #9cc2ff; }\n");
        sb.append("\n");
        sb.append("/* Packet capture */\n");
        sb.append(".capture { display: flex; align-items: center; gap: 18px; padding: 14px 18px; margin-top: 14px; flex-wrap: wrap; }\n");
        sb.append(".capture-info { display: flex; align-items: center; gap: 14px; flex: 1 1 380px; min-width: 0; }\n");
        sb.append(".cap-icon { width: 46px; height: 46px; border-radius: 10px; background: linear-gradient(135deg, #1679c8, #0f9fb8); display: grid; place-items: center; font-weight: 800; font-size: 11px; letter-spacing: .6px; flex: none; }\n");
        sb.append(".cap-title { font-weight: 650; font-size: 15px; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }\n");
        sb.append(".cap-sub { color: var(--muted); font-size: 12.5px; margin-top: 3px; }\n");
        sb.append(".cap-sub code { font-family: var(--mono); font-size: 12px; background: var(--bg); border: 1px solid var(--border); border-radius: 5px; padding: 1px 6px; color: #9cc2ff; cursor: help; white-space: nowrap; }\n");
        sb.append(".cap-stats { display: grid; grid-template-columns: repeat(2, minmax(110px, 1fr)); gap: 10px; }\n");
        sb.append(".cap-actions { flex: none; }\n");
        sb.append("a.btn { text-decoration: none; }\n");
        sb.append("\n");
        sb.append("/* Tooltip */\n");
        sb.append(".tooltip { position: fixed; z-index: 1000; max-width: 300px; background: #0f1830; border: 1px solid #34497a; color: var(--text); padding: 10px 12px; border-radius: 9px; font-size: 12.5px; line-height: 1.5; box-shadow: 0 10px 30px rgba(0,0,0,.45); pointer-events: none; opacity: 0; transform: translateY(4px); transition: opacity .12s ease, transform .12s ease; }\n");
        sb.append(".tooltip.show { opacity: 1; transform: translateY(0); }\n");
        sb.append(".tooltip .tt-title { font-weight: 700; margin-bottom: 3px; color: #fff; font-size: 13px; }\n");
        sb.append(".tooltip .tt-body { color: #b9c5de; }\n");
        sb.append(".help { display: inline-grid; place-items: center; width: 15px; height: 15px; border-radius: 50%; border: 1px solid var(--border-2); color: var(--dim); font-size: 10px; font-weight: 700; cursor: help; flex: none; }\n");
        sb.append("\n");
        sb.append("/* Toasts */\n");
        sb.append(".toasts { position: fixed; right: 20px; bottom: 20px; display: flex; flex-direction: column; gap: 10px; z-index: 900; }\n");
        sb.append(".toast { min-width: 260px; max-width: 380px; background: #12203d; border: 1px solid #34497a; border-left: 3px solid var(--accent); padding: 11px 14px; border-radius: 9px; font-size: 13px; box-shadow: 0 10px 30px rgba(0,0,0,.4); animation: slideIn .2s ease; }\n");
        sb.append(".toast.err { border-left-color: var(--red); }\n");
        sb.append("@keyframes slideIn { from { opacity: 0; transform: translateX(20px); } to { opacity: 1; transform: none; } }\n");
        sb.append("\n");
        sb.append("::-webkit-scrollbar { width: 9px; height: 9px; }\n");
        sb.append("::-webkit-scrollbar-thumb { background: #24324f; border-radius: 9px; }\n");
        sb.append("::-webkit-scrollbar-track { background: transparent; }\n");
        sb.append("\n");
        sb.append("@media (max-width: 1250px) {\n");
        sb.append("  .kpis { grid-template-columns: repeat(3, minmax(0, 1fr)); }\n");
        sb.append("  .controls { grid-template-columns: repeat(2, minmax(0, 1fr)); }\n");
        sb.append("  .ctrl-group:nth-child(2) { border-right: none; }\n");
        sb.append("  .ctrl-group:nth-child(-n+2) { border-bottom: 1px solid var(--border); }\n");
        sb.append("  .bottom { grid-template-columns: minmax(0, 1fr); }\n");
        sb.append("}\n");
        sb.append("@media (max-width: 820px) {\n");
        sb.append("  .kpis, .nodes { grid-template-columns: minmax(0, 1fr); }\n");
        sb.append("  .controls { grid-template-columns: minmax(0, 1fr); }\n");
        sb.append("  .ctrl-group { border-right: none; border-bottom: 1px solid var(--border); }\n");
        sb.append("}\n");
        sb.append("</style>\n");
        sb.append("</head>\n");
        sb.append("<body>\n");
        sb.append("\n");
        sb.append("<header class=\"topbar\">\n");
        sb.append("  <div class=\"topbar-inner\">\n");
        sb.append("    <div class=\"brand\">\n");
        sb.append("      <div class=\"logo\">DH</div>\n");
        sb.append("      <div>\n");
        sb.append("        <h1>DHCP Cluster Control Center</h1>\n");
        sb.append("        <p>RFC 2131 &middot; 3-node Active-Active cluster &middot; Layer-4 load balancer</p>\n");
        sb.append("      </div>\n");
        sb.append("    </div>\n");
        sb.append("    <span class=\"pill\" data-tip-title=\"Live connection\" data-tip=\"Shows whether the dashboard can reach the backend REST API (/api/state). The page refreshes automatically every second.\"><span id=\"liveDot\" class=\"live-dot\"></span><b id=\"liveText\">Live</b></span>\n");
        sb.append("    <span class=\"pill\" data-tip-title=\"Active routing strategy\" data-tip=\"The algorithm the load balancer is currently using to choose which DHCP node handles each client request.\">Routing <b id=\"pillStrategy\">-</b></span>\n");
        sb.append("    <span class=\"pill\" data-tip-title=\"Active rate limiter\" data-tip=\"The algorithm currently protecting the cluster against DHCP starvation floods.\">Limiter <b id=\"pillLimiter\">-</b></span>\n");
        sb.append("    <span class=\"pill\" data-tip-title=\"Last update\" data-tip=\"Local time when the dashboard last received fresh data from the server.\"><b id=\"clock\">--:--:--</b></span>\n");
        sb.append("    <a class=\"btn primary sm\" href=\"/api/pcap?filter=dhcp\" download data-tip-title=\"Export Wireshark .pcap\" data-tip=\"Download a standard Wireshark .pcap capture containing all DHCP handshakes (DISCOVER, OFFER, REQUEST, ACK, NAK, DECLINE, RELEASE, INFORM) and Active-Active Peer Gossip Sync packets.\">&#8595; Export Wireshark .pcap</a>\n");
        sb.append("  </div>\n");
        sb.append("</header>\n");
        sb.append("\n");
        sb.append("<main class=\"wrap\">\n");
        sb.append("  <div id=\"banner\" class=\"banner\">Unable to reach the DHCP backend. Retrying automatically&hellip; Make sure the server is running on this host and port.</div>\n");
        sb.append("\n");
        sb.append("  <!-- KPIs -->\n");
        sb.append("  <section class=\"kpis\">\n");
        sb.append("    <div class=\"kpi\" data-tip-title=\"Leased addresses\" data-tip=\"Number of IP addresses currently held by clients (offered, active, declined or static) compared to the total size of the address pool.\">\n");
        sb.append("      <div class=\"label\"><span class=\"ico\" style=\"background:var(--accent-soft);color:#7fb0ff\">IP</span>Leased Addresses</div>\n");
        sb.append("      <div class=\"value\" id=\"kLeases\">0</div>\n");
        sb.append("      <div class=\"sub\" id=\"kLeasesSub\">of 0 in pool</div>\n");
        sb.append("    </div>\n");
        sb.append("    <div class=\"kpi\" data-tip-title=\"Pool utilization\" data-tip=\"Percentage of the dynamic address pool currently in use. Above 80% the bar turns amber; above 95% it turns red, which indicates the pool is close to exhaustion.\">\n");
        sb.append("      <div class=\"label\"><span class=\"ico\" style=\"background:var(--violet-soft);color:#c4b5fd\">%</span>Pool Utilization</div>\n");
        sb.append("      <div class=\"value\" id=\"kUtil\">0%</div>\n");
        sb.append("      <div class=\"bar\"><span id=\"kUtilBar\"></span></div>\n");
        sb.append("    </div>\n");
        sb.append("    <div class=\"kpi\" data-tip-title=\"Healthy nodes\" data-tip=\"DHCP server nodes that are running and answering the load balancer's 700 ms heartbeat pings. Unhealthy nodes are removed from the routing ring.\">\n");
        sb.append("      <div class=\"label\"><span class=\"ico\" style=\"background:var(--green-soft);color:#4ade80\">&#10003;</span>Healthy Nodes</div>\n");
        sb.append("      <div class=\"value\" id=\"kHealthy\">0/0</div>\n");
        sb.append("      <div class=\"sub\" id=\"kHealthySub\">cluster status</div>\n");
        sb.append("    </div>\n");
        sb.append("    <div class=\"kpi\" data-tip-title=\"Allowed requests\" data-tip=\"Total DHCP requests that passed the rate limiter and were forwarded to a backend node.\">\n");
        sb.append("      <div class=\"label\"><span class=\"ico\" style=\"background:var(--green-soft);color:#4ade80\">&#8593;</span>Allowed Requests</div>\n");
        sb.append("      <div class=\"value\" id=\"kAllowed\">0</div>\n");
        sb.append("      <div class=\"sub\">passed rate limiter</div>\n");
        sb.append("    </div>\n");
        sb.append("    <div class=\"kpi\" data-tip-title=\"Dropped requests\" data-tip=\"Total DHCP requests blocked by the rate limiter because a client (or the whole cluster) exceeded its request quota. Rises sharply during a starvation attack.\">\n");
        sb.append("      <div class=\"label\"><span class=\"ico\" style=\"background:var(--red-soft);color:#f87171\">&#10005;</span>Dropped Requests</div>\n");
        sb.append("      <div class=\"value\" id=\"kDropped\">0</div>\n");
        sb.append("      <div class=\"sub\" id=\"kDropRate\">0% drop rate</div>\n");
        sb.append("    </div>\n");
        sb.append("    <div class=\"kpi\" data-tip-title=\"Gossip syncs\" data-tip=\"Total lease-replication messages received by all nodes. Each lease change on one node is broadcast to its peers so every node keeps an identical copy of the lease table.\">\n");
        sb.append("      <div class=\"label\"><span class=\"ico\" style=\"background:var(--violet-soft);color:#c4b5fd\">&#8646;</span>Gossip Syncs</div>\n");
        sb.append("      <div class=\"value\" id=\"kSync\">0</div>\n");
        sb.append("      <div class=\"sub\">peer replications</div>\n");
        sb.append("    </div>\n");
        sb.append("  </section>\n");
        sb.append("\n");
        sb.append("  <!-- Control center -->\n");
        sb.append("  <section class=\"panel\">\n");
        sb.append("    <div class=\"panel-head\">\n");
        sb.append("      <h2>Control Center <span class=\"help\" data-tip-title=\"Control center\" data-tip=\"Trigger real DHCP traffic, simulate failures and change load-balancer behaviour at runtime. Hover any button to see what it does.\">?</span></h2>\n");
        sb.append("      <span style=\"color:var(--dim);font-size:12px\">Actions take effect immediately on the running cluster</span>\n");
        sb.append("    </div>\n");
        sb.append("    <div class=\"controls\">\n");
        sb.append("      <div class=\"ctrl-group\">\n");
        sb.append("        <h3>Client Simulation</h3>\n");
        sb.append("        <div class=\"btn-row\">\n");
        sb.append("          <button class=\"btn primary\" data-cmd=\"dora1\" data-tip-title=\"Simulate 1 client\" data-tip=\"Runs a complete DISCOVER &rarr; OFFER &rarr; REQUEST &rarr; ACK handshake for one new virtual client, which receives an IP address from the pool.\">+ 1 Client (DORA)</button>\n");
        sb.append("          <button class=\"btn primary\" data-cmd=\"dora5\" data-tip-title=\"Simulate 5 concurrent clients\" data-tip=\"Starts five clients at the same time to show concurrent allocation, load distribution across nodes, and thread-safe lease handling (no duplicate IPs).\">+ 5 Concurrent</button>\n");
        sb.append("          <button class=\"btn\" data-cmd=\"vip\" data-tip-title=\"Static VIP reservation\" data-tip=\"Sends a DORA from MAC 00:1A:2B:3C:4D:01. This MAC has a fixed reservation, so it always receives 192.168.10.5 instead of a dynamic address.\">Static VIP</button>\n");
        sb.append("          <button class=\"btn\" data-cmd=\"inform\" data-tip-title=\"DHCPINFORM\" data-tip=\"A host that already has a manually configured IP (192.168.10.250) asks only for network settings (mask, gateway, DNS). No lease is created.\">DHCPINFORM</button>\n");
        sb.append("        </div>\n");
        sb.append("      </div>\n");
        sb.append("      <div class=\"ctrl-group\">\n");
        sb.append("        <h3>Lease Lifecycle &amp; Security</h3>\n");
        sb.append("        <div class=\"btn-row\">\n");
        sb.append("          <button class=\"btn\" data-cmd=\"release\" data-tip-title=\"DHCPRELEASE\" data-tip=\"A client voluntarily gives back 192.168.10.11. The address returns to the free pool and the release is replicated to every peer node.\">DHCPRELEASE</button>\n");
        sb.append("          <button class=\"btn warn\" data-cmd=\"decline\" data-tip-title=\"DHCPDECLINE (ARP conflict)\" data-tip=\"A client reports that 192.168.10.12 is already in use on the LAN. The address is quarantined (DECLINED) so it is not handed out again until the hold time expires.\">DHCPDECLINE</button>\n");
        sb.append("          <button class=\"btn danger\" data-cmd=\"starvation\" data-tip-title=\"Starvation attack\" data-tip=\"Floods the load balancer with 40 rapid DISCOVER packets from random spoofed MACs. Watch the Dropped Requests counter: the rate limiter blocks the flood and protects the pool.\">Starvation Flood</button>\n");
        sb.append("        </div>\n");
        sb.append("      </div>\n");
        sb.append("      <div class=\"ctrl-group\">\n");
        sb.append("        <h3>Load Balancing Strategy</h3>\n");
        sb.append("        <div class=\"seg\" id=\"segStrategy\">\n");
        sb.append("          <button data-cmd=\"strategy_ch\" data-val=\"CONSISTENT_HASHING\" data-tip-title=\"Consistent hashing\" data-tip=\"Hashes the client MAC onto a ring with 32 virtual nodes per server. The same client always reaches the same node, and only about 1/N of clients move when a node fails.\">Consistent Hash</button>\n");
        sb.append("          <button data-cmd=\"strategy_rr\" data-val=\"ROUND_ROBIN\" data-tip-title=\"Round robin\" data-tip=\"Sends each new request to the next healthy node in turn. Spreads load evenly but provides no client affinity; gossip sync keeps leases consistent.\">Round Robin</button>\n");
        sb.append("          <button data-cmd=\"strategy_ll\" data-val=\"LEAST_LOADED\" data-tip-title=\"Least loaded\" data-tip=\"Sends each request to the healthy node that has handled the fewest packets so far. Useful when nodes receive uneven traffic.\">Least Loaded</button>\n");
        sb.append("        </div>\n");
        sb.append("        <div class=\"meter\"><span>Total routed: <b id=\"mRouted\">0</b></span><span>Nodes in ring: <b id=\"mRing\">0</b></span></div>\n");
        sb.append("      </div>\n");
        sb.append("      <div class=\"ctrl-group\">\n");
        sb.append("        <h3>Rate Limiter Algorithm</h3>\n");
        sb.append("        <div class=\"seg\" id=\"segLimiter\">\n");
        sb.append("          <button data-cmd=\"rate_tb\" data-val=\"TOKEN_BUCKET\" data-tip-title=\"Token bucket\" data-tip=\"Each client and the cluster as a whole have a bucket of tokens that refills at a fixed rate. A request spends one token; with an empty bucket the packet is dropped. Allows short bursts.\">Token Bucket</button>\n");
        sb.append("          <button data-cmd=\"rate_sw\" data-val=\"SLIDING_WINDOW_COUNTER\" data-tip-title=\"Sliding window counter\" data-tip=\"Estimates the request rate over a rolling 1-second window by weighting the previous window's count. Smooths out the burst-at-boundary problem of fixed windows.\">Sliding Window</button>\n");
        sb.append("        </div>\n");
        sb.append("        <div class=\"meter\"><span style=\"color:#86efac\">Allowed <b id=\"mAllowed\">0</b></span><span style=\"color:#fca5a5\">Dropped <b id=\"mDropped\">0</b></span></div>\n");
        sb.append("      </div>\n");
        sb.append("    </div>\n");
        sb.append("  </section>\n");
        sb.append("\n");
        sb.append("  <!-- Packet capture -->\n");
        sb.append("  <section class=\"panel capture\">\n");
        sb.append("    <div class=\"capture-info\">\n");
        sb.append("      <div class=\"cap-icon\">PCAP</div>\n");
        sb.append("      <div style=\"min-width:0\">\n");
        sb.append("        <div class=\"cap-title\">Wireshark Packet Capture &amp; Export\n");
        sb.append("          <span id=\"capBadge\" class=\"status-badge st-ok\" data-tip-title=\"Capture status\" data-tip=\"Recording: every UDP datagram exchanged inside the cluster (client &harr; load balancer, load balancer &harr; nodes, heartbeats, gossip sync) is captured in memory. Paused: new packets are ignored.\">Recording</span>\n");
        sb.append("        </div>\n");
        sb.append("        <div class=\"cap-sub\">Exports internal cluster traffic as standard Ethernet II / IPv4 / UDP frames that decode automatically as <code>DHCP</code> in Wireshark. Useful filters: <code data-tip-title=\"Wireshark display filter\" data-tip=\"Show all DHCP and Gossip packets in Wireshark.\">dhcp</code> &middot; <code data-tip-title=\"Gossip sync filter\" data-tip=\"Show only Active-Active Peer Gossip Sync packets (Option 53 = 101, Option 225 = serialized lease).\">dhcp.option.dhcp == 101</code></div>\n");
        sb.append("      </div>\n");
        sb.append("    </div>\n");
        sb.append("    <div class=\"cap-stats\">\n");
        sb.append("      <div class=\"stat\" data-tip-title=\"DHCP &amp; Gossip packets\" data-tip=\"Captured D-O-R-A handshakes, INFORM/RELEASE/DECLINE messages, and Peer Gossip Sync packets (excluding 700 ms heartbeats).\"><div class=\"k\">DHCP + Gossip</div><div class=\"v\" id=\"capDhcp\">0</div></div>\n");
        sb.append("      <div class=\"stat\" data-tip-title=\"Packets in buffer\" data-tip=\"Total packets currently buffered in memory (including 700 ms heartbeat pings/pongs). Max buffer: 50,000 packets.\"><div class=\"k\">Buffered (All)</div><div class=\"v\" id=\"capBuf\">0</div></div>\n");
        sb.append("    </div>\n");
        sb.append("    <div class=\"btn-row cap-actions\">\n");
        sb.append("      <a class=\"btn primary\" href=\"/api/pcap?filter=dhcp\" download id=\"capDownloadDhcp\" data-tip-title=\"Export DHCP + Gossip (.pcap)\" data-tip=\"Download a clean Wireshark .pcap file with all DHCP client handshakes, relay forwards, and Active-Active Peer Gossip Sync packets (omits repetitive 700 ms heartbeat pings).\">&#8595; Export DHCP + Gossip (.pcap)</a>\n");
        sb.append("      <a class=\"btn\" href=\"/api/pcap\" download id=\"capDownloadAll\" data-tip-title=\"Export Full Capture (.pcap)\" data-tip=\"Download every captured packet including 700 ms CLUSTER_HEALTH_PING (102) and CLUSTER_HEALTH_PONG (103) heartbeats.\">&#8595; Full .pcap (+ Heartbeats)</a>\n");
        sb.append("      <button class=\"btn\" data-cmd=\"pcap_toggle\" id=\"capToggle\" data-tip-title=\"Pause / resume capture\" data-tip=\"Stop or restart recording new packets. Already captured packets stay in the buffer.\">Pause</button>\n");
        sb.append("      <button class=\"btn danger\" data-cmd=\"pcap_clear\" data-tip-title=\"Clear buffer\" data-tip=\"Delete all captured packets from memory and reset the counters before recording a fresh test scenario.\">Clear</button>\n");
        sb.append("    </div>\n");
        sb.append("  </section>\n");
        sb.append("\n");
        sb.append("  <div class=\"section-title\" style=\"margin-top:22px\">Server Nodes <span class=\"help\" data-tip-title=\"Server nodes\" data-tip=\"The three DHCP servers sharing one address pool. Use 'Simulate crash' to take a node offline and watch the load balancer evict it from the ring within about 1.8 seconds.\">?</span></div>\n");
        sb.append("  <section class=\"nodes\" id=\"nodes\" style=\"margin-top:0\"></section>\n");
        sb.append("\n");
        sb.append("  <!-- Leases & logs -->\n");
        sb.append("  <section class=\"bottom\">\n");
        sb.append("    <div class=\"panel\">\n");
        sb.append("      <div class=\"panel-head\">\n");
        sb.append("        <h2>Lease Table <span id=\"leaseCount\" style=\"color:var(--muted);font-weight:500;font-size:13px\"></span> <span class=\"help\" data-tip-title=\"Replicated lease table\" data-tip=\"All IP bindings as seen by a healthy node. Because of active-active gossip sync, every node holds the same table.\">?</span></h2>\n");
        sb.append("        <div class=\"toolbar\">\n");
        sb.append("          <input id=\"search\" class=\"search\" type=\"text\" placeholder=\"Search IP, MAC, hostname&hellip;\" autocomplete=\"off\" data-tip-title=\"Search\" data-tip=\"Filter the table by any part of the IP address, MAC address, hostname or allocating node.\">\n");
        sb.append("          <select id=\"stateFilter\" class=\"select\" data-tip-title=\"State filter\" data-tip=\"Show only leases in a particular state.\">\n");
        sb.append("            <option value=\"\">All states</option>\n");
        sb.append("            <option value=\"ACTIVE\">Active</option>\n");
        sb.append("            <option value=\"OFFERED\">Offered</option>\n");
        sb.append("            <option value=\"DECLINED\">Declined</option>\n");
        sb.append("            <option value=\"EXPIRED\">Expired</option>\n");
        sb.append("            <option value=\"STATIC\">Static</option>\n");
        sb.append("          </select>\n");
        sb.append("        </div>\n");
        sb.append("      </div>\n");
        sb.append("      <div class=\"legend\">\n");
        sb.append("        <span data-tip-title=\"ACTIVE\" data-tip=\"The client completed the handshake (received DHCPACK) and is using the address.\"><i style=\"background:#4ade80\"></i>Active</span>\n");
        sb.append("        <span data-tip-title=\"OFFERED\" data-tip=\"The server offered this IP (DHCPOFFER) and is holding it for 30 seconds while waiting for the client's DHCPREQUEST.\"><i style=\"background:#7fb0ff\"></i>Offered</span>\n");
        sb.append("        <span data-tip-title=\"DECLINED\" data-tip=\"A client reported an address conflict for this IP. It is quarantined and will not be offered until the hold expires.\"><i style=\"background:#f87171\"></i>Declined</span>\n");
        sb.append("        <span data-tip-title=\"STATIC\" data-tip=\"A permanent MAC-to-IP reservation (e.g. gateway or database server). It never expires.\"><i style=\"background:#c4b5fd\"></i>Static</span>\n");
        sb.append("      </div>\n");
        sb.append("      <div class=\"table-wrap\">\n");
        sb.append("        <table>\n");
        sb.append("          <thead>\n");
        sb.append("            <tr>\n");
        sb.append("              <th data-tip-title=\"IP address\" data-tip=\"The IPv4 address assigned to the client (the yiaddr field of the DHCP reply).\">IP Address</th>\n");
        sb.append("              <th data-tip-title=\"Client MAC\" data-tip=\"The client's hardware address (chaddr field). Used as the client's identity for leasing, hashing and rate limiting.\">Client MAC</th>\n");
        sb.append("              <th data-tip-title=\"Hostname\" data-tip=\"Name the client reported in DHCP option 12.\">Hostname</th>\n");
        sb.append("              <th data-tip-title=\"State\" data-tip=\"Current lease state: OFFERED, ACTIVE, DECLINED, EXPIRED, or STATIC for reservations.\">State</th>\n");
        sb.append("              <th data-tip-title=\"Allocated by\" data-tip=\"The server node that created this lease. Other nodes received it through gossip replication.\">Node</th>\n");
        sb.append("              <th data-tip-title=\"Time to live\" data-tip=\"Seconds left before the lease expires. Clients renew before expiry; unrenewed leases are reclaimed by the background reaper.\">TTL</th>\n");
        sb.append("            </tr>\n");
        sb.append("          </thead>\n");
        sb.append("          <tbody id=\"leaseBody\"><tr><td colspan=\"6\" class=\"empty\">Waiting for data&hellip;</td></tr></tbody>\n");
        sb.append("        </table>\n");
        sb.append("      </div>\n");
        sb.append("    </div>\n");
        sb.append("\n");
        sb.append("    <div class=\"panel\">\n");
        sb.append("      <div class=\"panel-head\">\n");
        sb.append("        <h2>Event Stream <span class=\"help\" data-tip-title=\"Event stream\" data-tip=\"Live log of packets, routing decisions, gossip syncs, failovers and security events. Colour-coded by category.\">?</span></h2>\n");
        sb.append("        <div class=\"toolbar\">\n");
        sb.append("          <select id=\"logFilter\" class=\"select\" data-tip-title=\"Log filter\" data-tip=\"Show only one category of events.\">\n");
        sb.append("            <option value=\"\">All events</option>\n");
        sb.append("            <option value=\"l-ok\">Success</option>\n");
        sb.append("            <option value=\"l-lb\">Load balancer</option>\n");
        sb.append("            <option value=\"l-sync\">Gossip sync</option>\n");
        sb.append("            <option value=\"l-warn\">Warnings</option>\n");
        sb.append("            <option value=\"l-err\">Errors &amp; security</option>\n");
        sb.append("          </select>\n");
        sb.append("          <button class=\"btn sm\" id=\"pauseBtn\" data-tip-title=\"Pause / resume\" data-tip=\"Freeze the log so you can read it without new lines scrolling in. Data keeps updating elsewhere.\">Pause</button>\n");
        sb.append("        </div>\n");
        sb.append("      </div>\n");
        sb.append("      <div class=\"logs\" id=\"logs\"></div>\n");
        sb.append("    </div>\n");
        sb.append("  </section>\n");
        sb.append("</main>\n");
        sb.append("\n");
        sb.append("<div class=\"tooltip\" id=\"tooltip\"><div class=\"tt-title\"></div><div class=\"tt-body\"></div></div>\n");
        sb.append("<div class=\"toasts\" id=\"toasts\"></div>\n");
        sb.append("\n");
        sb.append("<script>\n");
        sb.append("(function () {\n");
        sb.append("  'use strict';\n");
        sb.append("\n");
        sb.append("  var STRATEGY_NAMES = { CONSISTENT_HASHING: 'Consistent Hash', ROUND_ROBIN: 'Round Robin', LEAST_LOADED: 'Least Loaded' };\n");
        sb.append("  var LIMITER_NAMES = { TOKEN_BUCKET: 'Token Bucket', SLIDING_WINDOW_COUNTER: 'Sliding Window' };\n");
        sb.append("  var state = { data: null, paused: false, mouseX: -1, mouseY: -1, tipTarget: null };\n");
        sb.append("\n");
        sb.append("  function $(id) { return document.getElementById(id); }\n");
        sb.append("  function esc(v) {\n");
        sb.append("    return String(v == null ? '' : v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\"/g, '&quot;').replace(/'/g, '&#39;');\n");
        sb.append("  }\n");
        sb.append("  function fmt(n) { return Number(n || 0).toLocaleString(); }\n");
        sb.append("\n");
        sb.append("  /* ---------- Tooltip ---------- */\n");
        sb.append("  var tip = $('tooltip');\n");
        sb.append("  var tipTitle = tip.querySelector('.tt-title');\n");
        sb.append("  var tipBody = tip.querySelector('.tt-body');\n");
        sb.append("\n");
        sb.append("  function showTip(el) {\n");
        sb.append("    var body = el.getAttribute('data-tip');\n");
        sb.append("    if (!body) { hideTip(); return; }\n");
        sb.append("    state.tipTarget = el;\n");
        sb.append("    var title = el.getAttribute('data-tip-title') || '';\n");
        sb.append("    tipTitle.textContent = title;\n");
        sb.append("    tipTitle.style.display = title ? 'block' : 'none';\n");
        sb.append("    tipBody.textContent = body;\n");
        sb.append("    tip.classList.add('show');\n");
        sb.append("    positionTip(el);\n");
        sb.append("  }\n");
        sb.append("  function positionTip(el) {\n");
        sb.append("    var r = el.getBoundingClientRect();\n");
        sb.append("    var tw = tip.offsetWidth, th = tip.offsetHeight, m = 10;\n");
        sb.append("    var top = r.bottom + 8;\n");
        sb.append("    if (top + th > window.innerHeight - m) top = r.top - th - 8;\n");
        sb.append("    if (top < m) top = m;\n");
        sb.append("    var left = r.left + r.width / 2 - tw / 2;\n");
        sb.append("    left = Math.max(m, Math.min(left, window.innerWidth - tw - m));\n");
        sb.append("    tip.style.top = top + 'px';\n");
        sb.append("    tip.style.left = left + 'px';\n");
        sb.append("  }\n");
        sb.append("  function hideTip() { state.tipTarget = null; tip.classList.remove('show'); }\n");
        sb.append("\n");
        sb.append("  document.addEventListener('mouseover', function (e) {\n");
        sb.append("    var el = e.target.closest ? e.target.closest('[data-tip]') : null;\n");
        sb.append("    if (el) { if (el !== state.tipTarget) showTip(el); } else if (state.tipTarget) { hideTip(); }\n");
        sb.append("  });\n");
        sb.append("  document.addEventListener('mousemove', function (e) { state.mouseX = e.clientX; state.mouseY = e.clientY; });\n");
        sb.append("  document.addEventListener('mouseleave', hideTip);\n");
        sb.append("  window.addEventListener('scroll', hideTip, true);\n");
        sb.append("  window.addEventListener('resize', hideTip);\n");
        sb.append("\n");
        sb.append("  function revalidateTip() {\n");
        sb.append("    if (!state.tipTarget || document.body.contains(state.tipTarget)) return;\n");
        sb.append("    var el = state.mouseX >= 0 ? document.elementFromPoint(state.mouseX, state.mouseY) : null;\n");
        sb.append("    var t = el && el.closest ? el.closest('[data-tip]') : null;\n");
        sb.append("    if (t) showTip(t); else hideTip();\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  /* ---------- Toasts ---------- */\n");
        sb.append("  function toast(msg, isErr) {\n");
        sb.append("    var t = document.createElement('div');\n");
        sb.append("    t.className = 'toast' + (isErr ? ' err' : '');\n");
        sb.append("    t.textContent = msg;\n");
        sb.append("    $('toasts').appendChild(t);\n");
        sb.append("    setTimeout(function () { t.style.transition = 'opacity .3s'; t.style.opacity = '0'; }, 2800);\n");
        sb.append("    setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, 3200);\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  /* ---------- Actions ---------- */\n");
        sb.append("  function act(cmd, btn) {\n");
        sb.append("    if (btn) btn.disabled = true;\n");
        sb.append("    fetch('/api/action?cmd=' + encodeURIComponent(cmd), { method: 'POST' })\n");
        sb.append("      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })\n");
        sb.append("      .then(function (j) { toast(j.status || 'Done'); })\n");
        sb.append("      .catch(function (e) { toast('Action failed: ' + e.message, true); })\n");
        sb.append("      .then(function () {\n");
        sb.append("        if (btn) setTimeout(function () { btn.disabled = false; }, 400);\n");
        sb.append("        setTimeout(refresh, 250);\n");
        sb.append("      });\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  document.addEventListener('click', function (e) {\n");
        sb.append("    var b = e.target.closest ? e.target.closest('[data-cmd]') : null;\n");
        sb.append("    if (b && !b.disabled) act(b.getAttribute('data-cmd'), b);\n");
        sb.append("  });\n");
        sb.append("\n");
        sb.append("  $('pauseBtn').addEventListener('click', function () {\n");
        sb.append("    state.paused = !state.paused;\n");
        sb.append("    this.textContent = state.paused ? 'Resume' : 'Pause';\n");
        sb.append("    this.classList.toggle('warn', state.paused);\n");
        sb.append("    if (!state.paused && state.data) renderLogs(state.data.logs || []);\n");
        sb.append("  });\n");
        sb.append("  $('search').addEventListener('input', function () { if (state.data) renderLeases(state.data); });\n");
        sb.append("  $('stateFilter').addEventListener('change', function () { if (state.data) renderLeases(state.data); });\n");
        sb.append("  $('logFilter').addEventListener('change', function () { if (state.data) renderLogs(state.data.logs || []); });\n");
        sb.append("\n");
        sb.append("  /* ---------- Rendering ---------- */\n");
        sb.append("  function setSeg(id, value) {\n");
        sb.append("    var btns = $(id).querySelectorAll('button');\n");
        sb.append("    for (var i = 0; i < btns.length; i++) btns[i].classList.toggle('active', btns[i].getAttribute('data-val') === value);\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  function renderKpis(d) {\n");
        sb.append("    var nodes = d.nodes || [], leases = d.leases || [];\n");
        sb.append("    var healthy = nodes.filter(function (n) { return n.lbHealthy && !n.simulatedDown; }).length;\n");
        sb.append("    var pool = d.poolTotal || 0;\n");
        sb.append("    var util = pool > 0 ? Math.min(100, Math.round(leases.length / pool * 100)) : 0;\n");
        sb.append("    var total = (d.rateAllowed || 0) + (d.rateDropped || 0);\n");
        sb.append("    var syncs = nodes.reduce(function (a, n) { return a + (n.peerSyncs || 0); }, 0);\n");
        sb.append("    var routed = nodes.reduce(function (a, n) { return a + (n.routedPackets || 0); }, 0);\n");
        sb.append("\n");
        sb.append("    $('kLeases').textContent = fmt(leases.length);\n");
        sb.append("    $('kLeasesSub').textContent = 'of ' + fmt(pool) + ' in pool';\n");
        sb.append("    $('kUtil').textContent = util + '%';\n");
        sb.append("    var bar = $('kUtilBar');\n");
        sb.append("    bar.style.width = util + '%';\n");
        sb.append("    bar.style.background = util > 95 ? 'var(--red)' : util > 80 ? 'var(--amber)' : 'var(--accent)';\n");
        sb.append("    $('kHealthy').textContent = healthy + '/' + nodes.length;\n");
        sb.append("    $('kHealthy').style.color = healthy === nodes.length ? '#4ade80' : healthy === 0 ? '#f87171' : '#fbbf24';\n");
        sb.append("    $('kHealthySub').textContent = healthy === nodes.length ? 'all nodes operational' : healthy === 0 ? 'cluster unavailable' : 'degraded - failover active';\n");
        sb.append("    $('kAllowed').textContent = fmt(d.rateAllowed);\n");
        sb.append("    $('kDropped').textContent = fmt(d.rateDropped);\n");
        sb.append("    $('kDropRate').textContent = (total > 0 ? (d.rateDropped / total * 100).toFixed(1) : '0') + '% drop rate';\n");
        sb.append("    $('kSync').textContent = fmt(syncs);\n");
        sb.append("\n");
        sb.append("    $('pillStrategy').textContent = STRATEGY_NAMES[d.strategy] || d.strategy || '-';\n");
        sb.append("    $('pillLimiter').textContent = LIMITER_NAMES[d.rateAlgorithm] || d.rateAlgorithm || '-';\n");
        sb.append("    setSeg('segStrategy', d.strategy);\n");
        sb.append("    setSeg('segLimiter', d.rateAlgorithm);\n");
        sb.append("    $('mRouted').textContent = fmt(routed);\n");
        sb.append("    $('mRing').textContent = nodes.filter(function (n) { return n.lbHealthy; }).length + '/' + nodes.length;\n");
        sb.append("    $('mAllowed').textContent = fmt(d.rateAllowed);\n");
        sb.append("    $('mDropped').textContent = fmt(d.rateDropped);\n");
        sb.append("\n");
        sb.append("    var capOn = d.pcapEnabled !== false;\n");
        sb.append("    var capBadge = $('capBadge');\n");
        sb.append("    capBadge.textContent = capOn ? 'Recording' : 'Paused';\n");
        sb.append("    capBadge.className = 'status-badge ' + (capOn ? 'st-ok' : 'st-warn');\n");
        sb.append("    $('capDhcp').textContent = fmt(d.pcapDhcp);\n");
        sb.append("    $('capBuf').textContent = fmt(d.pcapBuffered);\n");
        sb.append("    $('capToggle').textContent = capOn ? 'Pause' : 'Resume';\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  function renderNodes(d) {\n");
        sb.append("    var nodes = d.nodes || [];\n");
        sb.append("    var routedTotal = nodes.reduce(function (a, n) { return a + (n.routedPackets || 0); }, 0);\n");
        sb.append("    var html = nodes.map(function (n, idx) {\n");
        sb.append("      var cls = '', badge;\n");
        sb.append("      if (n.simulatedDown) {\n");
        sb.append("        cls = 'down';\n");
        sb.append("        badge = '<span class=\"status-badge st-down\" data-tip-title=\"Offline\" data-tip=\"This node is crashed (simulated). It ignores all packets, including heartbeats.\">Offline</span>';\n");
        sb.append("      } else if (!n.lbHealthy) {\n");
        sb.append("        cls = 'evicted';\n");
        sb.append("        badge = '<span class=\"status-badge st-warn\" data-tip-title=\"Evicted\" data-tip=\"The node is running but the load balancer has not yet received a heartbeat reply, so it is temporarily removed from the routing ring.\">Evicted</span>';\n");
        sb.append("      } else {\n");
        sb.append("        badge = '<span class=\"status-badge st-ok\" data-tip-title=\"Healthy\" data-tip=\"The node answers heartbeats and is part of the routing ring, so it receives client requests.\">Healthy</span>';\n");
        sb.append("      }\n");
        sb.append("      var share = routedTotal > 0 ? Math.round((n.routedPackets || 0) / routedTotal * 100) : 0;\n");
        sb.append("      var toggle = n.simulatedDown\n");
        sb.append("        ? '<button class=\"btn success sm\" data-cmd=\"toggle_node_' + idx + '\" data-tip-title=\"Recover node\" data-tip=\"Bring this node back online. It resumes answering heartbeats and the load balancer re-adds it to the routing ring.\">Recover</button>'\n");
        sb.append("        : '<button class=\"btn danger sm\" data-cmd=\"toggle_node_' + idx + '\" data-tip-title=\"Simulate crash\" data-tip=\"Take this node offline. The load balancer detects missed heartbeats (~1.8 s) and fails traffic over to the remaining nodes. Leases survive thanks to gossip replication.\">Simulate crash</button>';\n");
        sb.append("      return '<div class=\"node ' + cls + '\">' +\n");
        sb.append("        '<div class=\"node-head\"><div class=\"node-title\"><div><div class=\"name\">' + esc(n.nodeId) + '</div>' +\n");
        sb.append("        '<div class=\"addr\">' + esc(n.serverIp) + ':' + esc(n.port) + '</div></div>' + badge + '</div>' + toggle + '</div>' +\n");
        sb.append("        '<div class=\"node-stats\">' +\n");
        sb.append("        '<div class=\"stat\" data-tip-title=\"Routed requests\" data-tip=\"Client packets the load balancer has forwarded to this node.\"><div class=\"k\">Routed Requests</div><div class=\"v\">' + fmt(n.routedPackets) + '</div></div>' +\n");
        sb.append("        '<div class=\"stat\" data-tip-title=\"Gossip syncs received\" data-tip=\"Lease updates this node received from its peers to keep its lease table identical to theirs.\"><div class=\"k\">Gossip Received</div><div class=\"v\">' + fmt(n.peerSyncs) + '</div></div>' +\n");
        sb.append("        '<div class=\"stat\" data-tip-title=\"DHCPOFFER sent\" data-tip=\"Number of IP offers this node has made in reply to DHCPDISCOVER messages.\"><div class=\"k\">Offers Sent</div><div class=\"v\">' + fmt(n.offersSent) + '</div></div>' +\n");
        sb.append("        '<div class=\"stat\" data-tip-title=\"DHCPACK sent\" data-tip=\"Number of leases this node has confirmed in reply to DHCPREQUEST messages.\"><div class=\"k\">ACKs Sent</div><div class=\"v\">' + fmt(n.acksSent) + '</div></div>' +\n");
        sb.append("        '</div>' +\n");
        sb.append("        '<div class=\"share\" data-tip-title=\"Traffic share\" data-tip=\"This node\\'s share of all requests routed by the load balancer. Compare across nodes to see how evenly the current strategy spreads load.\">' +\n");
        sb.append("        '<div class=\"row\"><span>Traffic share</span><b>' + share + '%</b></div><div class=\"track\"><span style=\"width:' + share + '%\"></span></div></div>' +\n");
        sb.append("        '</div>';\n");
        sb.append("    }).join('');\n");
        sb.append("    if (html !== state.nodesHtml) {\n");
        sb.append("      state.nodesHtml = html;\n");
        sb.append("      $('nodes').innerHTML = html;\n");
        sb.append("    }\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  function renderLeases(d) {\n");
        sb.append("    var q = $('search').value.trim().toLowerCase();\n");
        sb.append("    var sf = $('stateFilter').value;\n");
        sb.append("    var all = (d.leases || []).slice().sort(function (a, b) {\n");
        sb.append("      var pa = String(a.ip).split('.').map(Number), pb = String(b.ip).split('.').map(Number);\n");
        sb.append("      for (var i = 0; i < 4; i++) { if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0); }\n");
        sb.append("      return 0;\n");
        sb.append("    });\n");
        sb.append("    var rows = all.filter(function (l) {\n");
        sb.append("      var st = l.isStatic ? 'STATIC' : l.state;\n");
        sb.append("      if (sf && st !== sf) return false;\n");
        sb.append("      if (!q) return true;\n");
        sb.append("      return [l.ip, l.mac, l.hostname, l.node].join(' ').toLowerCase().indexOf(q) !== -1;\n");
        sb.append("    });\n");
        sb.append("    $('leaseCount').textContent = '(' + all.length + ' / ' + (d.poolTotal || 0) + ')';\n");
        sb.append("    if (!rows.length) {\n");
        sb.append("      $('leaseBody').innerHTML = '<tr><td colspan=\"6\" class=\"empty\">' + (all.length ? 'No leases match the current filter.' : 'No leases yet. Use <b>+ 1 Client (DORA)</b> to allocate an address.') + '</td></tr>';\n");
        sb.append("      return;\n");
        sb.append("    }\n");
        sb.append("    $('leaseBody').innerHTML = rows.map(function (l) {\n");
        sb.append("      var st = l.isStatic ? 'STATIC' : l.state;\n");
        sb.append("      var ttlCell;\n");
        sb.append("      if (l.isStatic) {\n");
        sb.append("        ttlCell = '<span style=\"color:#c4b5fd;font-size:12px\">Permanent</span>';\n");
        sb.append("      } else {\n");
        sb.append("        var ttl = Math.max(0, l.ttl || 0);\n");
        sb.append("        var max = l.state === 'OFFERED' ? 30 : 120;\n");
        sb.append("        var pct = Math.max(0, Math.min(100, ttl / max * 100));\n");
        sb.append("        var col = pct < 20 ? 'var(--red)' : pct < 50 ? 'var(--amber)' : 'var(--green)';\n");
        sb.append("        ttlCell = '<div class=\"ttl\"><div class=\"t\"><span style=\"width:' + pct.toFixed(0) + '%;background:' + col + '\"></span></div><small>' + ttl + 's</small></div>';\n");
        sb.append("      }\n");
        sb.append("      return '<tr>' +\n");
        sb.append("        '<td class=\"ip\">' + esc(l.ip) + '</td>' +\n");
        sb.append("        '<td class=\"mono\">' + esc(l.mac) + '</td>' +\n");
        sb.append("        '<td>' + (l.hostname ? esc(l.hostname) : '<span style=\"color:var(--dim)\">&mdash;</span>') + '</td>' +\n");
        sb.append("        '<td><span class=\"state s-' + st + '\">' + st + '</span></td>' +\n");
        sb.append("        '<td style=\"color:var(--muted)\">' + esc(l.node) + '</td>' +\n");
        sb.append("        '<td>' + ttlCell + '</td></tr>';\n");
        sb.append("    }).join('');\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  function classify(line) {\n");
        sb.append("    var s = line.toUpperCase();\n");
        sb.append("    if (/ERROR|FAIL|CRASH|DROP|STARVATION|ATTACK|FLOOD|EVICT|BLOCK|DENIED/.test(s)) return 'l-err';\n");
        sb.append("    if (/WARN|DECLINE|NAK|CONFLICT|QUARANTIN|EXPIRE/.test(s)) return 'l-warn';\n");
        sb.append("    if (/SYNC|GOSSIP|REPLICAT|PEER/.test(s)) return 'l-sync';\n");
        sb.append("    if (/ACK|COMPLETE|RECOVER|SUCCESS|ASSIGNED|STARTED|ONLINE/.test(s)) return 'l-ok';\n");
        sb.append("    if (/LOAD-BALANCER|\\[LB|ROUT|STRATEGY|HASH|RING/.test(s)) return 'l-lb';\n");
        sb.append("    return '';\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  function renderLogs(logs) {\n");
        sb.append("    if (state.paused) return;\n");
        sb.append("    var box = $('logs');\n");
        sb.append("    var atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;\n");
        sb.append("    var f = $('logFilter').value;\n");
        sb.append("    var html = logs.map(function (line) {\n");
        sb.append("      var c = classify(line);\n");
        sb.append("      if (f && c !== f) return '';\n");
        sb.append("      return '<div class=\"log ' + c + '\">' + esc(line) + '</div>';\n");
        sb.append("    }).join('');\n");
        sb.append("    box.innerHTML = html || '<div class=\"log\" style=\"color:var(--dim)\">No events to display.</div>';\n");
        sb.append("    if (atBottom) box.scrollTop = box.scrollHeight;\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  function setLive(ok) {\n");
        sb.append("    $('liveDot').classList.toggle('off', !ok);\n");
        sb.append("    $('liveText').textContent = ok ? 'Live' : 'Offline';\n");
        sb.append("    $('banner').classList.toggle('show', !ok);\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  var inFlight = false;\n");
        sb.append("  function refresh() {\n");
        sb.append("    if (inFlight) return;\n");
        sb.append("    inFlight = true;\n");
        sb.append("    fetch('/api/state', { cache: 'no-store' })\n");
        sb.append("      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })\n");
        sb.append("      .then(function (d) {\n");
        sb.append("        state.data = d;\n");
        sb.append("        setLive(true);\n");
        sb.append("        renderKpis(d);\n");
        sb.append("        renderNodes(d);\n");
        sb.append("        renderLeases(d);\n");
        sb.append("        renderLogs(d.logs || []);\n");
        sb.append("        $('clock').textContent = new Date().toLocaleTimeString();\n");
        sb.append("        revalidateTip();\n");
        sb.append("      })\n");
        sb.append("      .catch(function () { setLive(false); })\n");
        sb.append("      .then(function () { inFlight = false; });\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  refresh();\n");
        sb.append("  setInterval(refresh, 1000);\n");
        sb.append("})();\n");
        sb.append("</script>\n");
        sb.append("</body>\n");
        sb.append("</html>\n");
        return sb.toString();
    }
}

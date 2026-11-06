package dhcp.dashboard;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import dhcp.client.DhcpClientSimulator;
import dhcp.cluster.DhcpServerNode;
import dhcp.lb.ConsistentHashRouter;
import dhcp.lb.DhcpLoadBalancer;
import dhcp.model.LeaseRecord;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Built-in Zero-Dependency HTTP Dashboard & REST Control Server (Port 8080).
 * Provides:
 * - GET /            -> Real-time Distributed Systems UI Dashboard
 * - GET /api/state   -> JSON telemetry (Node health, load distribution, active leases, logs, rate limiter stats)
 * - POST /api/action -> Interactive controls (Simulate clients, toggle LB strategy, crash/recover nodes, test starvation attack)
 */
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
        server.setExecutor(null);
        server.start();
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
        json.append("\"rateAllowed\":").append(loadBalancer.getRateLimiter().getTotalAllowed()).append(",");
        json.append("\"rateDropped\":").append(loadBalancer.getRateLimiter().getTotalDropped()).append(",");

        // Nodes array
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

        // Leases from first online node (or Node-1 since state is replicated)
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

        // Recent Event Logs
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
        return "<!DOCTYPE html>\n" +
               "<html lang='en'>\n" +
               "<head>\n" +
               "  <meta charset='UTF-8'>\n" +
               "  <title>Distributed DHCP Cluster & Load Balancer Dashboard</title>\n" +
               "  <style>\n" +
               "    :root { --bg: #0f172a; --card: #1e293b; --border: #334155; --text: #f8fafc; --muted: #94a3b8; --accent: #38bdf8; --green: #22c55e; --red: #ef4444; --amber: #f59e0b; }\n" +
               "    * { box-sizing: border-box; font-family: 'Segoe UI', system-ui, sans-serif; }\n" +
               "    body { margin: 0; padding: 20px; background: var(--bg); color: var(--text); }\n" +
               "    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 14px; margin-bottom: 20px; }\n" +
               "    .badge { background: #0284c7; padding: 5px 12px; border-radius: 999px; font-size: 13px; font-weight: 600; }\n" +
               "    .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 20px; }\n" +
               "    .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }\n" +
               "    .card h3 { margin: 0 0 10px 0; font-size: 16px; display: flex; justify-content: space-between; align-items: center; }\n" +
               "    .status-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-right: 6px; }\n" +
               "    .btn { background: #2563eb; color: #fff; border: none; padding: 8px 14px; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 13px; margin-right: 8px; margin-bottom: 8px; transition: opacity 0.15s; }\n" +
               "    .btn:hover { opacity: 0.9; }\n" +
               "    .btn.warn { background: #d97706; }\n" +
               "    .btn.danger { background: #dc2626; }\n" +
               "    .btn.secondary { background: #475569; }\n" +
               "    table { width: 100%; border-collapse: collapse; font-size: 13px; }\n" +
               "    th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--border); }\n" +
               "    th { color: var(--muted); font-weight: 600; }\n" +
               "    .logs { background: #090d16; color: #38bdf8; font-family: Consolas, monospace; font-size: 12px; padding: 12px; border-radius: 8px; height: 240px; overflow-y: auto; border: 1px solid var(--border); }\n" +
               "    .stat-row { display: flex; justify-content: space-between; font-size: 13px; margin: 5px 0; color: var(--muted); }\n" +
               "    .stat-row strong { color: var(--text); }\n" +
               "  </style>\n" +
               "</head>\n" +
               "<body>\n" +
               "  <div class='header'>\n" +
               "    <div>\n" +
               "      <h2 style='margin:0;'>Distributed DHCP Server Cluster & L4 Load Balancer</h2>\n" +
               "      <div style='color:var(--muted);font-size:13px;margin-top:4px;'>RFC 2131 Binary UDP Protocol &bull; Consistent Hashing Ring &bull; Active-Active Gossip Replication &bull; Starvation Rate Limiter</div>\n" +
               "    </div>\n" +
               "    <div id='lbBadge' class='badge'>Strategy: CONSISTENT_HASHING</div>\n" +
               "  </div>\n" +
               "  <div class='card' style='margin-bottom:20px;'>\n" +
               "    <h3>Interactive System Design & Chaos Controls</h3>\n" +
               "    <button class='btn' onclick=\"act('dora1')\">+ Simulate 1 Client (DORA)</button>\n" +
               "    <button class='btn' onclick=\"act('dora5')\">+ Simulate 5 Concurrent Clients</button>\n" +
               "    <button class='btn secondary' onclick=\"act('vip')\">Test Static VIP MAC</button>\n" +
               "    <button class='btn secondary' onclick=\"act('inform')\">Send DHCPINFORM</button>\n" +
               "    <button class='btn secondary' onclick=\"act('release')\">Send DHCPRELEASE</button>\n" +
               "    <button class='btn warn' onclick=\"act('decline')\">Send DHCPDECLINE (ARP Conflict)</button>\n" +
               "    <button class='btn danger' onclick=\"act('starvation')\">Launch DHCP Starvation Flood (40 pkts)</button>\n" +
               "    <span style='margin-left:16px;color:var(--muted);font-size:13px;'>LB Algorithm:</span>\n" +
               "    <button class='btn secondary' onclick=\"act('strategy_ch')\">Consistent Hashing</button>\n" +
               "    <button class='btn secondary' onclick=\"act('strategy_rr')\">Round Robin</button>\n" +
               "    <button class='btn secondary' onclick=\"act('strategy_ll')\">Least Loaded</button>\n" +
               "    <div id='rateStats' style='margin-top:6px;font-size:13px;color:var(--muted);'></div>\n" +
               "  </div>\n" +
               "  <div class='grid' id='nodesGrid'></div>\n" +
               "  <div style='display:grid;grid-template-columns: 1.4fr 1fr; gap: 16px;'>\n" +
               "    <div class='card'>\n" +
               "      <h3>Replicated Active IP Leases <span id='poolCount' style='font-size:13px;color:var(--muted);'></span></h3>\n" +
               "      <table>\n" +
               "        <thead><tr><th>IP Address</th><th>Client MAC</th><th>Hostname</th><th>State</th><th>Allocated By</th><th>TTL</th></tr></thead>\n" +
               "        <tbody id='leaseTable'></tbody>\n" +
               "      </table>\n" +
               "    </div>\n" +
               "    <div class='card'>\n" +
               "      <h3>Real-Time Cluster & Packet Event Stream</h3>\n" +
               "      <div class='logs' id='logBox'></div>\n" +
               "    </div>\n" +
               "  </div>\n" +
               "  <script>\n" +
               "    async function act(cmd) {\n" +
               "      await fetch('/api/action?cmd=' + cmd, { method: 'POST' });\n" +
               "      setTimeout(refresh, 250);\n" +
               "    }\n" +
               "    async function refresh() {\n" +
               "      try {\n" +
               "        const res = await fetch('/api/state');\n" +
               "        const data = await res.json();\n" +
               "        document.getElementById('lbBadge').innerText = 'LB Strategy: ' + data.strategy;\n" +
               "        document.getElementById('rateStats').innerHTML = `Token-Bucket Rate Limiter &mdash; Allowed Packets: <strong style='color:#22c55e'>${data.rateAllowed}</strong> | Dropped Flood Packets: <strong style='color:#ef4444'>${data.rateDropped}</strong>`;\n" +
               "        document.getElementById('poolCount').innerText = `(${data.leases.length} / ${data.poolTotal} IPs in use)`;\n" +
               "        const ng = document.getElementById('nodesGrid');\n" +
               "        ng.innerHTML = data.nodes.map((n, idx) => `\n" +
               "          <div class='card'>\n" +
               "            <h3>\n" +
               "              <span><span class='status-dot' style='background:${n.lbHealthy && !n.simulatedDown ? '#22c55e' : '#ef4444'}'></span>${n.nodeId} (${n.serverIp}:${n.port})</span>\n" +
               "              <button class='btn ${n.simulatedDown ? '' : 'warn'}' style='margin:0;padding:4px 10px;font-size:12px;' onclick=\"act('toggle_node_${idx}')\">${n.simulatedDown ? 'Recover Node' : 'Simulate Crash'}</button>\n" +
               "            </h3>\n" +
               "            <div class='stat-row'><span>Load Balancer Status:</span><strong style='color:${n.lbHealthy ? '#22c55e' : '#ef4444'}'>${n.lbHealthy ? 'HEALTHY (In Ring)' : 'EVICTED (Failover)'}</strong></div>\n" +
               "            <div class='stat-row'><span>LB Routed Requests:</span><strong>${n.routedPackets}</strong></div>\n" +
               "            <div class='stat-row'><span>DHCPOFFERs / DHCPACKs:</span><strong>${n.offersSent} / ${n.acksSent}</strong></div>\n" +
               "            <div class='stat-row'><span>Peer Gossip Syncs Received:</span><strong>${n.peerSyncs}</strong></div>\n" +
               "          </div>`).join('');\n" +
               "        const tb = document.getElementById('leaseTable');\n" +
               "        tb.innerHTML = data.leases.map(l => `\n" +
               "          <tr>\n" +
               "            <td><strong>${l.ip}</strong></td>\n" +
               "            <td style='font-family:monospace'>${l.mac}</td>\n" +
               "            <td>${l.hostname}</td>\n" +
               "            <td><span style='color:${l.state==='ACTIVE'?'#22c55e':'#f59e0b'}'>${l.state}</span></td>\n" +
               "            <td>${l.node}</td>\n" +
               "            <td>${l.isStatic ? 'STATIC VIP' : l.ttl + 's'}</td>\n" +
               "          </tr>`).join('');\n" +
               "        const lb = document.getElementById('logBox');\n" +
               "        lb.innerHTML = data.logs.map(line => `<div>${line}</div>`).join('');\n" +
               "        lb.scrollTop = lb.scrollHeight;\n" +
               "      } catch (e) {}\n" +
               "    }\n" +
               "    refresh();\n" +
               "    setInterval(refresh, 1000);\n" +
               "  </script>\n" +
               "</body>\n" +
               "</html>";
    }
}

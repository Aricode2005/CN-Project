package http.client;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import http.core.Hub;
import http.core.Json;

/**
 * The classic textbook experiment: load a base page that references N objects, through a link with a known RTT,
 * using the four connection strategies, and compare the measured time with the formula.
 *
 *   non-persistent, serial     (N+1) × 2·RTT          HTTP/1.0: a new TCP connection per object
 *   non-persistent, k parallel 2·RTT + ⌈N/k⌉ × 2·RTT  what early browsers did
 *   persistent, no pipelining  2·RTT + N × RTT        HTTP/1.1 keep-alive
 *   persistent, pipelined      2·RTT + 1 × RTT        HTTP/1.1, all requests sent back-to-back
 */
public final class PageLoad {

    public enum Mode {
        NONPERSISTENT("non-persistent (HTTP/1.0)"), PARALLEL("non-persistent, parallel connections"), PERSISTENT("persistent (HTTP/1.1 keep-alive)"), PIPELINED("persistent + pipelining");
        public final String label; Mode(String l) { label = l; }
    }

    public static final class Result {
        public Mode mode; public int rtt, kbps, parallel, objects, connections; public long bytes;
        public double totalMs, theoryMs, theoryRtts; public String formula;
        public final List<WebClient.Exchange> rows = new ArrayList<>();
        public String json() {
            List<String> r = new ArrayList<>();
            for (WebClient.Exchange x : rows)
                r.add(Json.obj("label", x.label, "conn", x.conn, "newConn", x.newConnection, "tConn", x.tConnOpen, "tSend", x.tSend, "tFirst", x.tFirstByte, "tDone", x.tDone,
                    "status", x.resp == null ? 0 : x.resp.status(), "bytes", x.resp == null ? 0 : x.resp.body.length, "req", x.req.start));
            return Json.obj("mode", mode.name(), "label", mode.label, "rtt", rtt, "kbps", kbps, "parallel", parallel, "objects", objects, "connections", connections, "bytes", bytes,
                "totalMs", Math.round(totalMs * 10) / 10.0, "theoryMs", Math.round(theoryMs), "theoryRtts", theoryRtts, "formula", formula, "rows", Json.raw(Json.arr(r)));
        }
    }

    /** Runs one strategy against host:port (the WAN link in front of the origin). */
    public static Result run(Mode mode, String host, int port, String hostHeader, int rtt, int kbps, int parallel) throws Exception {
        WebClient c = new WebClient(host, port, hostHeader);
        Result res = new Result(); res.mode = mode; res.rtt = rtt; res.kbps = kbps; res.parallel = parallel;
        String ver = mode == Mode.NONPERSISTENT || mode == Mode.PARALLEL ? "HTTP/1.0" : "HTTP/1.1";
        Hub.I.event("PAGELOAD", "start: " + mode.label + " · RTT " + rtt + " ms");

        // 1. the base page
        WebClient.Conn first = c.connect();
        WebClient.Exchange base = c.send(first, c.get("/gallery.html", ver));
        base.label = "gallery.html";
        res.rows.add(base);
        List<String> refs = WebClient.references(base.resp.text());
        res.objects = refs.size();
        int conns = 1;

        // 2. the referenced objects
        switch (mode) {
            case NONPERSISTENT:
                first.close();
                for (String u : refs) {
                    try (WebClient.Conn k = c.connect()) { WebClient.Exchange x = c.send(k, c.get(u, ver)); x.label = name(u); res.rows.add(x); }
                    conns++;
                }
                break;
            case PARALLEL: {
                first.close();
                ConcurrentLinkedQueue<String> todo = new ConcurrentLinkedQueue<>(refs);
                List<WebClient.Exchange> got = Collections.synchronizedList(new ArrayList<>());
                List<Thread> ts = new ArrayList<>();
                int[] opened = { 0 };
                for (int i = 0; i < parallel; i++) {
                    Thread t = new Thread(() -> {
                        String u;
                        while ((u = todo.poll()) != null) {
                            try (WebClient.Conn k = connectSync(c)) { WebClient.Exchange x = c.send(k, c.get(u, ver)); x.label = name(u); got.add(x); synchronized (opened) { opened[0]++; } }
                            catch (Exception e) { Hub.I.log("[PAGELOAD] " + e.getMessage()); }
                        }
                    }, "parallel-" + i);
                    t.start(); ts.add(t);
                }
                for (Thread t : ts) t.join();
                got.sort((a, b) -> Double.compare(a.tSend, b.tSend));
                res.rows.addAll(got); conns += opened[0];
                break;
            }
            case PERSISTENT:
                for (String u : refs) { WebClient.Exchange x = c.send(first, c.get(u, ver)); x.label = name(u); res.rows.add(x); }
                first.close();
                break;
            case PIPELINED: {
                List<http.core.Msg> reqs = new ArrayList<>();
                for (String u : refs) reqs.add(c.get(u, ver));
                List<WebClient.Exchange> xs = c.pipeline(first, reqs);
                for (int i = 0; i < xs.size(); i++) xs.get(i).label = name(refs.get(i));
                res.rows.addAll(xs);
                first.close();
                break;
            }
        }
        res.connections = conns;
        for (WebClient.Exchange x : res.rows) { res.totalMs = Math.max(res.totalMs, x.tDone); res.bytes += x.resp == null ? 0 : x.resp.body.length; }
        int n = res.objects;
        switch (mode) {
            case NONPERSISTENT: res.theoryRtts = 2.0 * (n + 1); res.formula = "(N+1) × 2·RTT = " + (n + 1) + " × 2 × " + rtt; break;
            case PARALLEL: res.theoryRtts = 2 + 2.0 * Math.ceil(n / (double) parallel); res.formula = "2·RTT + ⌈N/k⌉ × 2·RTT = 2 + " + (int) Math.ceil(n / (double) parallel) + " × 2 RTTs"; break;
            case PERSISTENT: res.theoryRtts = 2 + n; res.formula = "2·RTT + N × RTT = 2 + " + n + " RTTs"; break;
            default: res.theoryRtts = 3; res.formula = "2·RTT + 1 RTT = 3 RTTs";
        }
        double txMs = res.bytes * 8.0 / Math.max(1, kbps);                   // transmission time of everything at the link rate
        res.theoryMs = res.theoryRtts * rtt + txMs;
        Hub.I.event("PAGELOAD", mode.label + ": " + Math.round(res.totalMs) + " ms measured vs ≈" + Math.round(res.theoryMs) + " ms predicted (" + res.connections + " TCP connection" + (res.connections == 1 ? "" : "s") + ")");
        return res;
    }

    private static synchronized WebClient.Conn connectSync(WebClient c) throws java.io.IOException { return c.connect(); }
    private static String name(String u) { int i = u.lastIndexOf('/'); return i < 0 ? u : u.substring(i + 1); }
}

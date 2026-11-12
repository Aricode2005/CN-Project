package http.server;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import http.core.Hub;
import http.core.Msg;

/**
 * Our HTTP/1.1 origin server (RFC 9110 / 9112), written on plain sockets.
 * One thread per TCP connection; requests on a connection are answered strictly in order,
 * which is exactly what makes pipelining work (and what causes head-of-line blocking).
 */
public final class Origin {

    public static final int KEEP_ALIVE_SECONDS = 15, MAX_PER_CONN = 100;

    public final Site site;
    private final List<ServerSocket> listeners = new CopyOnWriteArrayList<>();
    private final AtomicInteger connIds = new AtomicInteger();
    public final AtomicLong connections = new AtomicLong(), requests = new AtomicLong();
    private volatile boolean running = true;

    public Origin(Site site) { this.site = site; }

    public Origin listen(int port) throws IOException {
        ServerSocket ss = new ServerSocket();
        ss.setReuseAddress(true);
        ss.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port), 64);
        listeners.add(ss);
        Thread t = new Thread(() -> acceptLoop(ss), "http-accept-" + port); t.setDaemon(true); t.start();
        Hub.I.log("[ORIGIN] listening on 127.0.0.1:" + port);
        return this;
    }

    private void acceptLoop(ServerSocket ss) {
        while (running) {
            try {
                Socket s = ss.accept();
                Thread t = new Thread(() -> serve(s), "http-conn"); t.setDaemon(true); t.start();
            } catch (IOException e) { if (running) Hub.I.log("[ORIGIN] accept: " + e.getMessage()); }
        }
    }

    public void stop() { running = false; for (ServerSocket s : listeners) try { s.close(); } catch (IOException ignored) { } }

    private void serve(Socket s) {
        int id = connIds.incrementAndGet();
        String sess = "conn#" + id;
        connections.incrementAndGet();
        Hub.I.line(new Hub.Line(sess, "TCP", true, "── TCP connection opened from port " + s.getPort() + " ──", "a new connection: costs one RTT for the SYN / SYN-ACK handshake"));
        int served = 0;
        try (Socket sock = s) {
            sock.setSoTimeout(KEEP_ALIVE_SECONDS * 1000);
            sock.setTcpNoDelay(true);
            InputStream in = new BufferedInputStream(sock.getInputStream());
            OutputStream out = new BufferedOutputStream(sock.getOutputStream());
            while (served < MAX_PER_CONN) {
                Msg req;
                try { req = Msg.readHead(in); } catch (SocketTimeoutException e) { Hub.I.line(new Hub.Line(sess, "TCP", false, "── idle " + KEEP_ALIVE_SECONDS + " s: server closes the persistent connection ──", "Keep-Alive timeout")); break; }
                if (req == null) break;                                   // client closed
                served++; requests.incrementAndGet();
                String version = req.version();
                Hub.I.line(new Hub.Line(sess, "HTTP", true, req.start, explainRequest(req)));
                Msg resp;
                if (!version.startsWith("HTTP/1.")) resp = site.error(version.startsWith("HTTP/") ? 505 : 400, "HTTP/1.1", "This server speaks HTTP/1.0 and HTTP/1.1.");
                else {
                    try {
                        if (req.headerHas("Expect", "100-continue") && (req.has("Content-Length") || req.has("Transfer-Encoding"))) {
                            out.write((version + " 100 Continue\r\n\r\n").getBytes("ISO-8859-1")); out.flush();
                            Hub.I.line(new Hub.Line(sess, "HTTP", false, version + " 100 Continue", "interim response: the client may now send the body"));
                        }
                        if (!req.has("Content-Length") && !req.has("Transfer-Encoding") && ("PUT".equals(req.method()) || "POST".equals(req.method())))
                            resp = site.error(411, version, "Send Content-Length or Transfer-Encoding: chunked with a body.");
                        else { req.readRequestBody(in); resp = site.handle(req, sess, out); }
                    } catch (IOException e) {
                        String m = String.valueOf(e.getMessage());
                        resp = site.error(m.contains("too large") || m.contains("out of range") ? 413 : 400, version, m);
                        resp.set("Connection", "close");
                    }
                }
                if (resp == null) { served = MAX_PER_CONN; break; }        // the handler already streamed its own response and closed
                boolean keep = req.keepAlive(version) && !resp.headerHas("Connection", "close") && served < MAX_PER_CONN;
                if ("HTTP/1.0".equals(version)) { if (keep) resp.set("Connection", "keep-alive"); else resp.set("Connection", "close"); }
                else if (!keep) resp.set("Connection", "close");
                if (keep) resp.set("Keep-Alive", "timeout=" + KEEP_ALIVE_SECONDS + ", max=" + (MAX_PER_CONN - served));
                // status line uses the request's version for 1.0 clients (RFC 9110 §6.2)
                if ("HTTP/1.0".equals(version) && resp.start.startsWith("HTTP/1.1")) resp.start = "HTTP/1.0" + resp.start.substring(8);
                if ("HTTP/1.0".equals(version) && resp.chunked) resp.chunked = false;   // 1.0 clients don't understand chunked
                boolean body = !"HEAD".equals(req.method());
                out.write(resp.wire(body, 1024)); out.flush();
                Hub.I.line(new Hub.Line(sess, "HTTP", false, resp.start + "   [" + resp.body.length + " B" + (resp.chunked ? ", chunked" : "") + (resp.has("Content-Encoding") ? ", " + resp.get("Content-Encoding") : "") + "]", site.explainResponse(resp)));
                if (!keep) break;
            }
        } catch (IOException e) { /* client went away */ }
        Hub.I.line(new Hub.Line(sess, "TCP", false, "── TCP connection closed after " + served + " request" + (served == 1 ? "" : "s") + " ──", served > 1 ? "persistent: one handshake paid for " + served + " requests" : "non-persistent: one handshake per object"));
    }

    private static String explainRequest(Msg r) {
        StringBuilder b = new StringBuilder();
        String host = r.get("Host");
        b.append(r.method()).append(" ").append(r.path()).append(host != null ? " on host " + host : "");
        if (r.has("If-None-Match") || r.has("If-Modified-Since")) b.append(" · conditional GET");
        if (r.has("Range")) b.append(" · Range ").append(r.get("Range"));
        if (r.has("Cookie")) b.append(" · carries a cookie");
        if (r.has("Authorization")) b.append(" · carries credentials");
        if (r.headerHas("Connection", "close")) b.append(" · asks to close afterwards");
        return b.toString();
    }
}

package http.client;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import http.core.Hub;
import http.core.Msg;

/**
 * Our HTTP/1.1 client: opens TCP connections, sends requests (one at a time or pipelined),
 * reads responses, keeps a cookie jar, and timestamps every step for the waterfall diagrams.
 */
public final class WebClient {

    /** One TCP connection with its raw byte log. */
    public static final class Conn implements Closeable {
        public final int id; public final Socket s; final InputStream in; final OutputStream out;
        public final long tOpen, tConnected;
        final ByteArrayOutputStream rawIn = new ByteArrayOutputStream();
        public int requests;
        Conn(int id, String host, int port, long t0) throws IOException {
            this.id = id;
            tOpen = System.nanoTime() - t0;
            s = new Socket(InetAddress.getByName(host), port);
            s.setTcpNoDelay(true); s.setSoTimeout(20_000);
            tConnected = System.nanoTime() - t0;
            in = new BufferedInputStream(new FilterInputStream(s.getInputStream()) {
                @Override public int read() throws IOException { int c = super.read(); if (c >= 0) rawIn.write(c); return c; }
                @Override public int read(byte[] b, int o, int l) throws IOException { int k = super.read(b, o, l); if (k > 0) rawIn.write(b, o, k); return k; }
            });
            out = s.getOutputStream();
        }
        public boolean open() { return !s.isClosed(); }
        public String rawReceived() { return new String(rawIn.toByteArray(), StandardCharsets.ISO_8859_1); }
        @Override public void close() { try { s.close(); } catch (IOException ignored) { } }
    }

    /** One request/response with timestamps (ms since the experiment began). */
    public static final class Exchange {
        public Msg req, resp; public int conn; public String label;
        public double tSend, tFirstByte, tDone, tConnOpen = -1;
        public String rawRequest = "", rawResponseHead = "";
        public boolean newConnection;
        public int wireBytes;              // body bytes as they crossed the wire (before gzip decoding)
    }

    private final String host; private final int port;
    public String hostHeader;
    public final Map<String, String> cookies = new LinkedHashMap<>();
    private int nextConn;
    public final long t0 = System.nanoTime();

    public WebClient(String host, int port, String hostHeader) { this.host = host; this.port = port; this.hostHeader = hostHeader; }

    public Conn connect() throws IOException { return new Conn(++nextConn, host, port, t0); }

    public double ms(long nanos) { return nanos / 1e6; }
    private double now() { return (System.nanoTime() - t0) / 1e6; }

    public Msg get(String target, String version) {
        Msg m = Msg.request("GET", target, version);
        if (hostHeader != null) m.set("Host", hostHeader);
        m.set("User-Agent", "JU-WebClient/1.0");
        return m;
    }

    /** Adds the cookie jar to a request. */
    public void attachCookies(Msg req) {
        if (cookies.isEmpty()) return;
        StringBuilder b = new StringBuilder();
        for (Map.Entry<String, String> e : cookies.entrySet()) { if (b.length() > 0) b.append("; "); b.append(e.getKey()).append('=').append(e.getValue()); }
        req.set("Cookie", b.toString());
    }

    /** Stores Set-Cookie values (Max-Age=0 deletes). */
    public void storeCookies(Msg resp) {
        for (String sc : resp.all("Set-Cookie")) {
            String[] parts = sc.split(";"); String[] kv = parts[0].trim().split("=", 2);
            if (kv.length < 2) continue;
            boolean delete = kv[1].isEmpty();
            for (String p : parts) if (p.trim().equalsIgnoreCase("Max-Age=0")) delete = true;
            if (delete) cookies.remove(kv[0]); else cookies.put(kv[0], kv[1]);
        }
    }

    /** Send one request on a connection and wait for its response. */
    public Exchange send(Conn c, Msg req) throws IOException {
        List<Exchange> l = pipeline(c, List.of(req));
        return l.get(0);
    }

    /** Write all requests back-to-back, then read the responses in the same order (RFC 9112 §9.3.2). */
    public List<Exchange> pipeline(Conn c, List<Msg> reqs) throws IOException {
        List<Exchange> xs = new ArrayList<>();
        ByteArrayOutputStream all = new ByteArrayOutputStream();
        double tSend = now();
        for (Msg r : reqs) {
            Exchange x = new Exchange(); x.req = r; x.conn = c.id; x.tSend = tSend; x.newConnection = c.requests == 0;
            if (x.newConnection) x.tConnOpen = c.tOpen / 1e6;
            byte[] w = r.wire(true, r.chunkSize); x.rawRequest = new String(w, StandardCharsets.ISO_8859_1);
            all.write(w, 0, w.length); xs.add(x);
            Hub.I.line(new Hub.Line("client:c" + c.id, "HTTP", true, r.start, reqs.size() > 1 ? "pipelined: sent without waiting for the previous response" : "request"));
        }
        c.out.write(all.toByteArray()); c.out.flush();
        for (Exchange x : xs) {
            int before = c.rawIn.size();
            Msg resp;
            while (true) {
                resp = Msg.readHead(c.in);
                if (resp == null) throw new IOException("server closed the connection before answering " + x.req.start);
                if (x.tFirstByte == 0) x.tFirstByte = now();
                if (resp.status() == 100) continue;                         // interim response: keep reading
                break;
            }
            resp.readResponseBody(c.in, x.req.method());
            x.tDone = now();
            x.wireBytes = resp.body.length;
            if ("gzip".equalsIgnoreCase(resp.get("Content-Encoding"))) {
                try (GZIPInputStream g = new GZIPInputStream(new ByteArrayInputStream(resp.body))) { resp.body = g.readAllBytes(); }
            }
            x.resp = resp;
            String raw = c.rawReceived().substring(Math.min(before, c.rawIn.size()));
            int end = raw.indexOf("\r\n\r\n");
            x.rawResponseHead = end < 0 ? raw : raw.substring(0, end + 4);
            c.requests++;
            storeCookies(resp);
        }
        return xs;
    }

    /** Sends a request whose body is sent with Expect: 100-continue, waiting for the interim answer first. */
    public Exchange sendExpecting(Conn c, Msg req) throws IOException {
        Exchange x = new Exchange(); x.req = req; x.conn = c.id; x.tSend = now(); x.newConnection = c.requests == 0;
        req.set("Expect", "100-continue").set("Content-Length", req.body.length);
        String head = req.head(); x.rawRequest = head;
        c.out.write(head.getBytes(StandardCharsets.ISO_8859_1)); c.out.flush();
        Msg first = Msg.readHead(c.in);
        if (first == null) throw new IOException("closed");
        x.rawResponseHead = first.rawHead;
        if (first.status() == 100) {
            c.out.write(req.body); c.out.flush();
            x.rawRequest += "[" + req.body.length + " body bytes sent after 100 Continue]";
            Msg resp = Msg.readHead(c.in); resp.readResponseBody(c.in, req.method());
            x.rawResponseHead += resp.rawHead; x.resp = resp;
        } else { first.readResponseBody(c.in, req.method()); x.resp = first; }
        x.tFirstByte = x.tDone = now(); c.requests++;
        return x;
    }

    /** img src="…" references in an HTML page (what a browser would fetch next). */
    public static List<String> references(String html) {
        List<String> l = new ArrayList<>();
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("<img[^>]+src=\"([^\"]+)\"").matcher(html);
        while (m.find()) l.add(m.group(1));
        return l;
    }
}

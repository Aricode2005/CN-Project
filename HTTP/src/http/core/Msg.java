package http.core;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * One HTTP/1.x message (RFC 9112): a start line, header fields, an empty line, and an optional body.
 * The body length comes from Content-Length, from chunked transfer coding, or (old responses only)
 * from the server closing the connection.
 */
public final class Msg {

    public static final int MAX_BODY = 2 * 1024 * 1024;
    public static final DateTimeFormatter HTTP_DATE = DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US).withZone(ZoneOffset.UTC);

    public String start = "";
    public final List<String[]> headers = new ArrayList<>();
    public byte[] body = new byte[0];
    public boolean chunked;                       // body arrived (or will be sent) with Transfer-Encoding: chunked
    public final List<Integer> chunkSizes = new ArrayList<>();
    public int chunkSize = 1024;                  // piece size when this message is sent chunked
    public String rawHead = "";                   // the head exactly as it crossed the wire

    // ------------------------------------------------------------------ builders
    public static Msg request(String method, String target, String version) { Msg m = new Msg(); m.start = method + " " + target + " " + version; return m; }
    public static Msg response(String version, int code) { Msg m = new Msg(); m.start = version + " " + code + " " + Codes.reason(code); return m; }

    // ------------------------------------------------------------------ start line
    private String[] parts() { return start.split(" ", 3); }
    public String method() { return parts()[0]; }
    public String target() { String[] p = parts(); return p.length > 1 ? p[1] : ""; }
    public String version() { String[] p = parts(); return p.length > 2 ? p[2].trim() : "HTTP/0.9"; }
    public int status() { try { return Integer.parseInt(parts()[1]); } catch (Exception e) { return 0; } }
    public String path() { String t = target(); int q = t.indexOf('?'); return q < 0 ? t : t.substring(0, q); }
    public String query() { String t = target(); int q = t.indexOf('?'); return q < 0 ? "" : t.substring(q + 1); }

    // ------------------------------------------------------------------ headers
    public String get(String name) { for (String[] h : headers) if (h[0].equalsIgnoreCase(name)) return h[1]; return null; }
    public List<String> all(String name) { List<String> l = new ArrayList<>(); for (String[] h : headers) if (h[0].equalsIgnoreCase(name)) l.add(h[1]); return l; }
    public boolean has(String name) { return get(name) != null; }
    public Msg add(String name, Object value) { headers.add(new String[] { name, String.valueOf(value) }); return this; }
    public Msg set(String name, Object value) { remove(name); return add(name, value); }
    public Msg remove(String name) { headers.removeIf(h -> h[0].equalsIgnoreCase(name)); return this; }
    public boolean headerHas(String name, String token) {
        for (String v : all(name)) for (String t : v.split(",")) if (t.trim().equalsIgnoreCase(token)) return true;
        return false;
    }
    public Msg body(byte[] b) { body = b == null ? new byte[0] : b; return this; }
    public Msg body(String s) { return body(s.getBytes(StandardCharsets.UTF_8)); }
    public String text() { return new String(body, StandardCharsets.UTF_8); }

    public String head() {
        StringBuilder b = new StringBuilder(start).append("\r\n");
        for (String[] h : headers) b.append(h[0]).append(": ").append(h[1]).append("\r\n");
        return b.append("\r\n").toString();
    }

    /** Does this message keep the connection open afterwards? (1.1: yes unless "close"; 1.0: only with "keep-alive") */
    public boolean keepAlive(String version) {
        if (headerHas("Connection", "close")) return false;
        if ("HTTP/1.1".equals(version)) return true;
        return headerHas("Connection", "keep-alive");
    }

    // ------------------------------------------------------------------ reading
    /** Reads one line ending in LF (CR stripped). Returns null on a clean EOF before any byte. */
    public static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream(80);
        int c, n = 0;
        while ((c = in.read()) != -1) {
            if (c == '\n') break;
            b.write(c);
            if (++n > 16_384) throw new IOException("line too long");
        }
        if (c == -1 && n == 0) return null;
        String s = new String(b.toByteArray(), StandardCharsets.ISO_8859_1);
        return s.endsWith("\r") ? s.substring(0, s.length() - 1) : s;
    }

    /** Reads the start line and header fields only. Returns null on EOF. */
    public static Msg readHead(InputStream in) throws IOException {
        String line;
        do { line = readLine(in); if (line == null) return null; } while (line.isEmpty());   // RFC 9112 §2.2: ignore leading empty lines
        Msg m = new Msg();
        m.start = line;
        StringBuilder raw = new StringBuilder(line).append("\r\n");
        while (true) {
            String h = readLine(in);
            if (h == null) throw new EOFException("connection closed inside the header");
            raw.append(h).append("\r\n");
            if (h.isEmpty()) break;
            int i = h.indexOf(':');
            if (i <= 0) throw new IOException("bad header line: " + h);
            m.headers.add(new String[] { h.substring(0, i).trim(), h.substring(i + 1).trim() });
            if (m.headers.size() > 100) throw new IOException("too many header fields");
        }
        m.rawHead = raw.toString();
        return m;
    }

    /** Reads the body of a request (Content-Length or chunked; otherwise none). */
    public void readRequestBody(InputStream in) throws IOException {
        if (headerHas("Transfer-Encoding", "chunked")) readChunked(in);
        else if (has("Content-Length")) body = readN(in, contentLength());
    }

    /** Reads the body of a response to a request with the given method. */
    public void readResponseBody(InputStream in, String requestMethod) throws IOException {
        int s = status();
        if ("HEAD".equals(requestMethod) || (s >= 100 && s < 200) || s == 204 || s == 304) return;
        if (headerHas("Transfer-Encoding", "chunked")) readChunked(in);
        else if (has("Content-Length")) body = readN(in, contentLength());
        else {                                                         // HTTP/1.0 style: the body ends when the server closes
            ByteArrayOutputStream b = new ByteArrayOutputStream(); byte[] buf = new byte[8192]; int k;
            while ((k = in.read(buf)) > 0) { b.write(buf, 0, k); if (b.size() > MAX_BODY) throw new IOException("body too large"); }
            body = b.toByteArray();
        }
    }

    public int contentLength() throws IOException {
        try { long n = Long.parseLong(get("Content-Length").trim()); if (n < 0 || n > MAX_BODY) throw new IOException("Content-Length out of range: " + n); return (int) n; }
        catch (NumberFormatException e) { throw new IOException("bad Content-Length"); }
    }

    private static byte[] readN(InputStream in, int n) throws IOException {
        byte[] b = in.readNBytes(n);
        if (b.length < n) throw new EOFException("body ended after " + b.length + " of " + n + " bytes");
        return b;
    }

    private void readChunked(InputStream in) throws IOException {
        chunked = true;
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        while (true) {
            String line = readLine(in);
            if (line == null) throw new EOFException("connection closed inside a chunked body");
            int semi = line.indexOf(';');
            int size = Integer.parseInt((semi < 0 ? line : line.substring(0, semi)).trim(), 16);
            chunkSizes.add(size);
            if (size == 0) { String t; while ((t = readLine(in)) != null && !t.isEmpty()) add(t.substring(0, Math.max(0, t.indexOf(':'))).trim(), t.substring(t.indexOf(':') + 1).trim()); break; }
            b.write(readN(in, size));
            if (b.size() > MAX_BODY) throw new IOException("body too large");
            readLine(in);                                              // CRLF after the chunk data
        }
        body = b.toByteArray();
    }

    // ------------------------------------------------------------------ writing
    /** Writes the head and body. Sets Content-Length unless chunked; chunked bodies are cut into chunkSize pieces. */
    public byte[] wire(boolean withBody, int chunkSize) {
        if (chunked) { remove("Content-Length"); set("Transfer-Encoding", "chunked"); }
        else if (!has("Content-Length")) {
            boolean isResponse = start.startsWith("HTTP/");
            int s = isResponse ? status() : 0;
            boolean noBody = isResponse && ((s >= 100 && s < 200) || s == 204 || s == 304);
            if (!noBody && (isResponse || body.length > 0)) set("Content-Length", body.length);   // HEAD: the length the GET body would have
        }
        ByteArrayOutputStream o = new ByteArrayOutputStream(head().length() + body.length + 64);
        byte[] h = head().getBytes(StandardCharsets.ISO_8859_1);
        o.write(h, 0, h.length);
        if (withBody) {
            if (chunked) {
                for (int i = 0; i < body.length; i += chunkSize) {
                    int n = Math.min(chunkSize, body.length - i);
                    byte[] sz = (Integer.toHexString(n) + "\r\n").getBytes(StandardCharsets.ISO_8859_1);
                    o.write(sz, 0, sz.length); o.write(body, i, n); o.write('\r'); o.write('\n');
                }
                byte[] end = "0\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1); o.write(end, 0, end.length);
            } else o.write(body, 0, body.length);
        }
        return o.toByteArray();
    }

    public void writeTo(OutputStream out, boolean withBody) throws IOException { out.write(wire(withBody, 1024)); out.flush(); }

    public static String now() { return HTTP_DATE.format(Instant.now()); }
    public static String date(long millis) { return HTTP_DATE.format(Instant.ofEpochMilli(millis)); }
    public static long parseDate(String s) {
        try { return ZonedDateTime.parse(s.trim(), HTTP_DATE).toInstant().toEpochMilli(); } catch (Exception e) { return -1; }
    }

    /** A readable copy of the body for the dashboard (binary bodies are summarised). */
    public String preview(int max) {
        String ct = String.valueOf(get("Content-Type"));
        if (body.length == 0) return "";
        boolean textual = ct.startsWith("text/") || ct.contains("json") || ct.contains("svg") || ct.contains("xml") || ct.contains("x-www-form-urlencoded");
        if (has("Content-Encoding")) return "[" + body.length + " bytes, " + get("Content-Encoding") + "-compressed]";
        if (!textual) return "[" + body.length + " bytes of " + ct + "]";
        String s = text();
        return s.length() > max ? s.substring(0, max) + "\n… (" + (s.length() - max) + " more characters)" : s;
    }
}

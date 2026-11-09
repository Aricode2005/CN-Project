package mail.mime;

import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;

/**
 * RFC 5322 message + RFC 2045/2046 MIME: parsing (headers, multipart tree, base64 and
 * quoted-printable decoding) and building (text messages with attachments).
 * Used by the IMAP server (ENVELOPE / BODYSTRUCTURE / BODY[n]) and by the dashboard.
 */
public final class Mime {

    private Mime() { }

    // ================================================================== parsed part

    public static final class Part {
        public final List<String[]> headers = new ArrayList<>();   // {name, value} in order, unfolded
        public String headerText = "";                              // raw header block incl. final blank line
        public byte[] body = new byte[0];                            // raw (still encoded) body
        public String type = "text", subtype = "plain";
        public final Map<String, String> params = new LinkedHashMap<>();
        public String encoding = "7bit";
        public final List<Part> children = new ArrayList<>();

        public String header(String name) {
            for (String[] h : headers) if (h[0].equalsIgnoreCase(name)) return h[1];
            return null;
        }

        public boolean multipart() { return type.equals("multipart"); }

        /** Body after Content-Transfer-Encoding decoding. */
        public byte[] decoded() {
            if (encoding.equals("base64")) {
                try { return Base64.getMimeDecoder().decode(body); } catch (IllegalArgumentException e) { return body; }
            }
            if (encoding.equals("quoted-printable")) return decodeQP(new String(body, StandardCharsets.ISO_8859_1));
            return body;
        }

        public String text() {
            String cs = params.getOrDefault("charset", "utf-8");
            try { return new String(decoded(), cs); } catch (Exception e) { return new String(decoded(), StandardCharsets.UTF_8); }
        }

        public int lines() {
            int n = 0;
            for (byte b : body) if (b == '\n') n++;
            return n;
        }
    }

    // ================================================================== parse

    public static Part parse(byte[] raw) {
        Part p = new Part();
        int split = indexOf(raw, "\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
        int bodyStart;
        if (split >= 0) bodyStart = split + 4;
        else {
            split = indexOf(raw, "\n\n".getBytes(StandardCharsets.ISO_8859_1));
            bodyStart = split >= 0 ? split + 2 : raw.length;
            if (split < 0) split = raw.length;
        }
        String head = new String(raw, 0, Math.min(split, raw.length), StandardCharsets.ISO_8859_1);
        p.headerText = new String(raw, 0, Math.min(bodyStart, raw.length), StandardCharsets.ISO_8859_1);
        p.body = bodyStart <= raw.length ? java.util.Arrays.copyOfRange(raw, bodyStart, raw.length) : new byte[0];

        String cur = null;
        for (String line : head.split("\r?\n")) {
            if (line.isEmpty()) continue;
            if ((line.startsWith(" ") || line.startsWith("\t")) && cur != null) { cur += " " + line.trim(); continue; }
            if (cur != null) addHeader(p, cur);
            cur = line;
        }
        if (cur != null) addHeader(p, cur);

        String ct = p.header("Content-Type");
        if (ct != null) {
            String[] segs = ct.split(";");
            String[] tt = segs[0].trim().toLowerCase(Locale.ROOT).split("/");
            if (tt.length == 2) { p.type = tt[0]; p.subtype = tt[1]; }
            for (int i = 1; i < segs.length; i++) {
                int eq = segs[i].indexOf('=');
                if (eq > 0) p.params.put(segs[i].substring(0, eq).trim().toLowerCase(Locale.ROOT), unquote(segs[i].substring(eq + 1).trim()));
            }
        }
        String cte = p.header("Content-Transfer-Encoding");
        if (cte != null) p.encoding = cte.trim().toLowerCase(Locale.ROOT);

        if (p.multipart() && p.params.containsKey("boundary")) {
            String b = "--" + p.params.get("boundary");
            String body = new String(p.body, StandardCharsets.ISO_8859_1);
            int i = body.indexOf(b);
            while (i >= 0) {
                int start = body.indexOf('\n', i);
                if (start < 0) break;
                if (body.startsWith(b + "--", i)) break;
                int next = body.indexOf("\n" + b, start);
                if (next < 0) break;
                int end = next > 0 && body.charAt(next - 1) == '\r' ? next - 1 : next;
                p.children.add(parse(body.substring(start + 1, Math.max(start + 1, end)).getBytes(StandardCharsets.ISO_8859_1)));
                i = next + 1;
            }
        }
        return p;
    }

    private static void addHeader(Part p, String line) {
        int c = line.indexOf(':');
        if (c > 0) p.headers.add(new String[]{line.substring(0, c).trim(), line.substring(c + 1).trim()});
    }

    private static String unquote(String s) {
        return s.length() >= 2 && s.startsWith("\"") && s.endsWith("\"") ? s.substring(1, s.length() - 1) : s;
    }

    private static int indexOf(byte[] a, byte[] pat) {
        outer:
        for (int i = 0; i + pat.length <= a.length; i++) {
            for (int j = 0; j < pat.length; j++) if (a[i + j] != pat[j]) continue outer;
            return i;
        }
        return -1;
    }

    public static byte[] decodeQP(String s) {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '=' && i + 2 < s.length() && s.charAt(i + 1) == '\r' && s.charAt(i + 2) == '\n') { i += 2; continue; } // soft break
            if (c == '=' && i + 1 < s.length() && s.charAt(i + 1) == '\n') { i += 1; continue; }
            if (c == '=' && i + 2 < s.length()) {
                try { o.write(Integer.parseInt(s.substring(i + 1, i + 3), 16)); i += 2; continue; } catch (NumberFormatException ignored) { }
            }
            o.write(c);
        }
        return o.toByteArray();
    }

    /** RFC 2047 encoded words in headers: =?utf-8?B?...?= and =?utf-8?Q?...?= */
    public static String decodeWords(String s) {
        if (s == null || !s.contains("=?")) return s;
        StringBuilder out = new StringBuilder();
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("=\\?([^?]+)\\?([bBqQ])\\?([^?]*)\\?=").matcher(s);
        int last = 0;
        while (m.find()) {
            out.append(s, last, m.start());
            try {
                byte[] b = m.group(2).equalsIgnoreCase("B") ? Base64.getDecoder().decode(m.group(3)) : decodeQP(m.group(3).replace('_', ' '));
                out.append(new String(b, m.group(1)));
            } catch (Exception e) { out.append(m.group()); }
            last = m.end();
        }
        return out.append(s.substring(last)).toString();
    }

    // ================================================================== build

    public static String rfc822Date(Date d) {
        return new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss Z", Locale.US).format(d);
    }

    /** A text message, optionally with one attachment (→ multipart/mixed with a base64 part). */
    public static String build(String from, String to, String subject, String text, String attName, byte[] attData, String host) {
        StringBuilder m = new StringBuilder();
        String id = Long.toHexString(System.currentTimeMillis()) + "." + Integer.toHexString(new Random().nextInt()) + "@" + host;
        m.append("Date: ").append(rfc822Date(new Date())).append("\r\n");
        m.append("From: ").append(from).append("\r\n");
        m.append("To: ").append(to).append("\r\n");
        m.append("Subject: ").append(encodeWordIfNeeded(subject)).append("\r\n");
        m.append("Message-ID: <").append(id).append(">\r\n");
        m.append("MIME-Version: 1.0\r\n");
        boolean ascii = text.chars().allMatch(c -> c < 128);
        if (attData == null) {
            m.append("Content-Type: text/plain; charset=utf-8\r\n");
            m.append("Content-Transfer-Encoding: ").append(ascii ? "7bit" : "quoted-printable").append("\r\n\r\n");
            m.append(ascii ? crlf(text) : encodeQP(text)).append("\r\n");
            return m.toString();
        }
        String boundary = "=_JUMAIL_" + Long.toHexString(System.nanoTime());
        m.append("Content-Type: multipart/mixed; boundary=\"").append(boundary).append("\"\r\n\r\n");
        m.append("This is a multi-part message in MIME format.\r\n");
        m.append("--").append(boundary).append("\r\n");
        m.append("Content-Type: text/plain; charset=utf-8\r\n");
        m.append("Content-Transfer-Encoding: ").append(ascii ? "7bit" : "quoted-printable").append("\r\n\r\n");
        m.append(ascii ? crlf(text) : encodeQP(text)).append("\r\n");
        m.append("--").append(boundary).append("\r\n");
        m.append("Content-Type: ").append(guessType(attName)).append("; name=\"").append(attName).append("\"\r\n");
        m.append("Content-Transfer-Encoding: base64\r\n");
        m.append("Content-Disposition: attachment; filename=\"").append(attName).append("\"\r\n\r\n");
        String b64 = Base64.getEncoder().encodeToString(attData);
        for (int i = 0; i < b64.length(); i += 76) m.append(b64, i, Math.min(b64.length(), i + 76)).append("\r\n");
        m.append("--").append(boundary).append("--\r\n");
        return m.toString();
    }

    private static String crlf(String s) { return s.replace("\r\n", "\n").replace("\n", "\r\n"); }

    private static String encodeWordIfNeeded(String s) {
        if (s.chars().allMatch(c -> c < 128)) return s;
        return "=?utf-8?B?" + Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8)) + "?=";
    }

    public static String encodeQP(String text) {
        StringBuilder o = new StringBuilder();
        int col = 0;
        for (byte b : crlf(text).getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xFF;
            String piece;
            if (c == '\r' || c == '\n') { o.append((char) c); col = 0; continue; }
            if ((c >= 33 && c <= 126 && c != '=') || c == ' ') piece = String.valueOf((char) c);
            else piece = String.format("=%02X", c);
            if (col + piece.length() > 75) { o.append("=\r\n"); col = 0; }
            o.append(piece); col += piece.length();
        }
        return o.toString();
    }

    private static String guessType(String n) {
        String l = n.toLowerCase(Locale.ROOT);
        if (l.endsWith(".png")) return "image/png";
        if (l.endsWith(".jpg") || l.endsWith(".jpeg")) return "image/jpeg";
        if (l.endsWith(".pdf")) return "application/pdf";
        if (l.endsWith(".txt")) return "text/plain";
        return "application/octet-stream";
    }

    /** Pull "user@domain" out of "Name <user@domain>". */
    public static String addr(String s) {
        if (s == null) return "";
        int a = s.indexOf('<'), b = s.indexOf('>');
        return (a >= 0 && b > a ? s.substring(a + 1, b) : s).trim();
    }
}

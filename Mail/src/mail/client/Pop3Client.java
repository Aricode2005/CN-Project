package mail.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/** POP3 client: USER/PASS, STAT, LIST, UIDL, RETR, TOP, DELE, RSET, QUIT (and STLS). */
public final class Pop3Client extends LineClient {

    public final String greeting;

    public Pop3Client(String host, int port, Tls tls) throws IOException {
        super("POP3", host, port, tls);
        greeting = ok(readLine());
        if (tls == Tls.STARTTLS) { writeLine("STLS", null); ok(readLine()); wrapTls(); }
    }

    public void login(String user, String pass) throws IOException {
        writeLine("USER " + user, null); ok(readLine());
        writeLine("PASS " + pass, "PASS " + secret(pass)); ok(readLine());
    }

    /** {count, octets} */
    public long[] stat() throws IOException {
        writeLine("STAT", null);
        String[] p = ok(readLine()).split(" ");
        return new long[]{Long.parseLong(p[0]), Long.parseLong(p[1])};
    }

    public Map<Integer, String> uidl() throws IOException {
        writeLine("UIDL", null); ok(readLine());
        Map<Integer, String> m = new LinkedHashMap<>();
        for (String l : multiLines()) { String[] p = l.split(" ", 2); m.put(Integer.parseInt(p[0]), p[1]); }
        return m;
    }

    public Map<Integer, Long> list() throws IOException {
        writeLine("LIST", null); ok(readLine());
        Map<Integer, Long> m = new LinkedHashMap<>();
        for (String l : multiLines()) { String[] p = l.split(" "); m.put(Integer.parseInt(p[0]), Long.parseLong(p[1])); }
        return m;
    }

    public byte[] retr(int n) throws IOException { writeLine("RETR " + n, null); ok(readLine()); return multiBytes(); }

    public byte[] top(int n, int lines) throws IOException { writeLine("TOP " + n + " " + lines, null); ok(readLine()); return multiBytes(); }

    public void dele(int n) throws IOException { writeLine("DELE " + n, null); ok(readLine()); }

    public void quit() throws IOException { writeLine("QUIT", null); readLine(); close(); }

    // ------------------------------------------------------------------

    private static String ok(String l) throws ProtocolException {
        if (!l.startsWith("+OK")) throw new ProtocolException(l);
        return l.length() > 4 ? l.substring(4) : "";
    }

    private java.util.List<String> multiLines() throws IOException {
        java.util.List<String> ls = new java.util.ArrayList<>();
        String l;
        while (!(l = readLine()).equals(".")) ls.add(l.startsWith("..") ? l.substring(1) : l);
        return ls;
    }

    /** Read a multi-line message body: lines until ".", undoing byte-stuffing. */
    private byte[] multiBytes() throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        while (true) {
            ByteArrayOutputStream line = new ByteArrayOutputStream();
            int c;
            while ((c = in.read()) >= 0 && c != '\n') line.write(c);
            if (c < 0) throw new IOException("eof");
            String s = new String(line.toByteArray(), StandardCharsets.UTF_8);
            if (s.endsWith("\r")) s = s.substring(0, s.length() - 1);
            if (s.equals(".")) break;
            if (s.startsWith("..")) s = s.substring(1);
            b.write((s + "\r\n").getBytes(StandardCharsets.UTF_8));
        }
        mail.core.Hub.I.line(new mail.core.Hub.Line(id, proto, false, "(message: " + b.size() + " bytes) …", "multi-line response ended with \".\""));
        return b.toByteArray();
    }
}

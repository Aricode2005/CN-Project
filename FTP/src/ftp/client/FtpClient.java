package ftp.client;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.LongConsumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLSocket;
import ftp.core.Hub;
import ftp.core.Json;
import ftp.core.Tls;

/**
 * Our FTP client. Every control line and every data-connection event is recorded as a {@link Step},
 * which the dashboard replays (active vs passive, the firewall problem, ASCII vs binary, REST…).
 */
public final class FtpClient implements Closeable {

    public enum Mode { PASSIVE, ACTIVE }

    public static final class Step {
        public final long t; public final String ch, dir, text, note;
        Step(long t, String ch, String dir, String text, String note) { this.t = t; this.ch = ch; this.dir = dir; this.text = text; this.note = note; }
        public String json() { return Json.obj("t", t, "ch", ch, "dir", dir, "text", text, "note", note); }
    }
    public static final class Reply {
        public final int code; public final String text; public final List<String> lines;
        Reply(int code, List<String> lines) { this.code = code; this.lines = lines; this.text = lines.get(lines.size() - 1); }
        public boolean ok() { return code >= 100 && code < 400; }
    }

    private static final AtomicInteger IDS = new AtomicInteger();
    public final List<Step> trace = new ArrayList<>();
    public Mode mode = Mode.PASSIVE;
    /** Active mode behind a client firewall: the server's incoming data connection is dropped. */
    public boolean firewall;
    public String greeting = "";
    private final String sid = "client:ftp#" + IDS.incrementAndGet();
    private final long t0 = System.currentTimeMillis();
    private final String host; private final int port;
    private Socket ctrl; private InputStream in; private OutputStream out;
    private boolean tls, protP;

    public FtpClient(String host, int port) throws IOException {
        this.host = host; this.port = port;
        ctrl = new Socket();
        ctrl.connect(new InetSocketAddress(host, port), 6000);
        ctrl.setSoTimeout(20_000);
        in = new BufferedInputStream(ctrl.getInputStream()); out = ctrl.getOutputStream();
        step("tcp", "C", "TCP connection " + ctrl.getLocalPort() + " → " + host + ":" + port, "the CONTROL connection: opened once, kept for the whole session");
        greeting = read().text;
    }

    private void step(String ch, String dir, String text, String note) {
        trace.add(new Step(System.currentTimeMillis() - t0, ch, dir, text, note));
        Hub.I.line(new Hub.Line(sid, ch.equals("ctrl") || ch.equals("tcp") ? "CTRL" : "DATA", dir.equals("C"), text, note));
    }
    public String traceJson() { List<String> s = new ArrayList<>(); for (Step x : trace) s.add(x.json()); return "[" + String.join(",", s) + "]"; }

    // ------------------------------------------------------------------ control channel
    private String readLine() throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream(); int c;
        while ((c = in.read()) != -1) { if (c == '\n') break; if (c != '\r') b.write(c); }
        if (c == -1 && b.size() == 0) throw new IOException("control connection closed by the server");
        return b.toString(StandardCharsets.UTF_8);
    }
    /** A reply: one line "123 text", or several lines "123-…" ending with "123 text". */
    public Reply read() throws IOException {
        List<String> lines = new ArrayList<>();
        String l = readLine(); lines.add(l);
        if (l.length() > 3 && l.charAt(3) == '-') { String end = l.substring(0, 3) + " "; while (!(l = readLine()).startsWith(end)) lines.add(l); lines.add(l); }
        int code; try { code = Integer.parseInt(l.substring(0, 3)); } catch (Exception e) { code = 0; }
        for (String x : lines) step("ctrl", "S", x, x == lines.get(lines.size() - 1) ? ftp.server.Codes.meaning(x) : "");
        return new Reply(code, lines);
    }
    public Reply cmd(String line) throws IOException {
        out.write((line + "\r\n").getBytes(StandardCharsets.UTF_8)); out.flush();
        String shown = line.toUpperCase().startsWith("PASS ") ? "PASS " + "*".repeat(Math.max(4, line.length() - 5)) : line;
        step("ctrl", "C", shown, ftp.server.Codes.command(line.split(" ")[0].toUpperCase()) + (line.toUpperCase().startsWith("PASS ") && !tls ? " · travels in PLAINTEXT" : ""));
        return read();
    }
    private Reply expect(String line, int... ok) throws IOException {
        Reply r = cmd(line);
        for (int c : ok) if (r.code == c) return r;
        throw new IOException(r.text);
    }

    public void login(String user, String pass) throws IOException {
        Reply r = cmd("USER " + user);
        if (r.code == 331) r = cmd("PASS " + pass);
        if (r.code != 230 && r.code != 202) throw new IOException(r.text);
    }

    /** FTPS (explicit, RFC 4217): AUTH TLS upgrades the control connection; PBSZ 0 + PROT P protect data too. */
    public void authTls(boolean protectData) throws IOException {
        expect("AUTH TLS", 234);
        SSLSocket s = (SSLSocket) Tls.clientFor(host).getSocketFactory().createSocket(ctrl, host, port, true);
        s.setUseClientMode(true); s.startHandshake();
        ctrl = s; in = new BufferedInputStream(s.getInputStream()); out = s.getOutputStream(); tls = true;
        step("tcp", "C", "TLS handshake complete: " + s.getSession().getProtocol() + " · " + s.getSession().getCipherSuite(), "everything on the control connection is encrypted from here on");
        if (protectData) { expect("PBSZ 0", 200); expect("PROT P", 200); protP = true; }
    }

    public void type(char t) throws IOException { expect("TYPE " + t, 200); }
    public String pwd() throws IOException { Matcher m = Pattern.compile("\"(.*)\"").matcher(expect("PWD", 257).text); return m.find() ? m.group(1) : "/"; }
    public Reply cwd(String d) throws IOException { return cmd("CWD " + d); }
    public long size(String f) throws IOException { Reply r = cmd("SIZE " + f); return r.code == 213 ? Long.parseLong(r.text.substring(4).trim()) : -1; }

    // ------------------------------------------------------------------ data connections
    private ServerSocket listener; private InetSocketAddress pasvAddr;

    /** Before a transfer: PASV (we will connect) or PORT (the server will connect to us). */
    private void prepare() throws IOException {
        if (mode == Mode.PASSIVE) {
            Reply r = cmd("PASV");
            if (r.code == 227) {
                Matcher m = Pattern.compile("(\\d+),(\\d+),(\\d+),(\\d+),(\\d+),(\\d+)").matcher(r.text);
                if (!m.find()) throw new IOException("bad 227 reply");
                String ip = m.group(1) + "." + m.group(2) + "." + m.group(3) + "." + m.group(4);
                int p = Integer.parseInt(m.group(5)) * 256 + Integer.parseInt(m.group(6));
                if (ip.startsWith("0.") || ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("172.")) ip = host;   // server behind NAT
                pasvAddr = new InetSocketAddress(ip, p);
                step("note", "-", "decode 227: " + m.group(5) + "×256 + " + m.group(6) + " = port " + p, "the server is now listening on " + ip + ":" + p + " for us");
            } else {
                r = expect("EPSV", 229);
                Matcher m = Pattern.compile("\\|\\|\\|(\\d+)\\|").matcher(r.text);
                if (!m.find()) throw new IOException("bad 229 reply");
                pasvAddr = new InetSocketAddress(host, Integer.parseInt(m.group(1)));
            }
        } else {
            InetAddress local = ctrl.getLocalAddress();
            listener = new ServerSocket(0, 1, local);
            int p = listener.getLocalPort(), adv = p;
            if (firewall) {                                   // inbound connections are blocked: nothing will answer on the advertised port
                listener.close(); listener = null;
                try (ServerSocket tmp = new ServerSocket(0, 1, local)) { adv = tmp.getLocalPort(); }
                step("note", "-", "client firewall: inbound connections to port " + adv + " will be dropped", "a home router / NAT or a personal firewall blocks connections that come IN from the Internet");
            } else step("note", "-", "client opens a listening socket on " + local.getHostAddress() + ":" + p, "active mode: WE wait for the server to connect");
            byte[] a = local.getAddress();
            expect(String.format("PORT %d,%d,%d,%d,%d,%d", a[0] & 0xFF, a[1] & 0xFF, a[2] & 0xFF, a[3] & 0xFF, adv / 256, adv % 256), 200);
        }
    }

    private Socket dataBefore() throws IOException {
        if (mode != Mode.PASSIVE) return null;
        Socket s = new Socket();
        s.connect(pasvAddr, 6000);
        step("data", "C", "DATA connection: client " + s.getLocalPort() + " → server " + pasvAddr.getPort(), "passive: the CLIENT opens the data connection (outgoing, so firewalls allow it)");
        return s;
    }
    private Socket dataAfter(Socket pre) throws IOException {
        Socket s = pre;
        if (s == null) {
            if (listener == null) throw new IOException("nothing is listening for the server's connection");
            listener.setSoTimeout(6000);
            try { s = listener.accept(); } finally { listener.close(); listener = null; }
            step("data", "S", "DATA connection: server " + s.getPort() + " → client " + s.getLocalPort(), "active: the SERVER opened the data connection, from port " + s.getPort());
        }
        if (protP) {
            SSLSocket t = (SSLSocket) Tls.clientFor(host).getSocketFactory().createSocket(s, host, s.getPort(), true);
            t.setUseClientMode(true); t.startHandshake();
            step("data", "-", "TLS on the data connection", "PROT P: the file itself is encrypted");
            return t;
        }
        return s;
    }

    /** One transfer: prepare → (connect) → command → 150 → (accept) → bytes → close → 226. */
    private Reply transfer(String command, InputStream upload, OutputStream download, long stopAfter, LongConsumer progress) throws IOException {
        prepare();
        Socket pre = null;
        try { pre = dataBefore(); } catch (IOException e) { step("data", "-", "could not connect: " + e.getMessage(), ""); throw e; }
        Reply r = cmd(command);
        if (r.code != 150 && r.code != 125) { if (pre != null) pre.close(); if (listener != null) { listener.close(); listener = null; } return r; }
        Socket s;
        try { s = dataAfter(pre); }
        catch (IOException e) {
            step("data", "-", "no data connection: " + e.getMessage(), mode == Mode.ACTIVE && firewall ? "the server's connection never got through the client's firewall" : "");
            return read();                                     // 425 Can't open data connection
        }
        long n = 0;
        try (Socket d = s) {
            if (upload != null) {
                OutputStream o = d.getOutputStream(); byte[] b = new byte[16 * 1024]; int k;
                while ((k = upload.read(b)) > 0) { o.write(b, 0, k); n += k; if (progress != null) progress.accept(n); }
                o.flush();
            } else {
                InputStream i = d.getInputStream(); byte[] b = new byte[16 * 1024]; int k;
                while ((k = i.read(b)) > 0) {
                    download.write(b, 0, k); n += k; if (progress != null) progress.accept(n);
                    if (stopAfter >= 0 && n >= stopAfter) {
                        step("data", "-", "client stops after " + n + " bytes (the link \"breaks\")", "simulated failure: we abort the download half-way");
                        Reply a = cmd("ABOR");
                        Reply last = a;
                        while (last.code != 226 && last.code != 225) last = read();
                        return new Reply(426, List.of("426 aborted after " + n + " bytes"));
                    }
                }
            }
        }
        step("data", "-", "DATA connection closed · " + n + " bytes", "end of the transfer = end of the data connection");
        return read();
    }

    public byte[] list(String path) throws IOException { ByteArrayOutputStream b = new ByteArrayOutputStream(); Reply r = transfer(path == null || path.isEmpty() ? "LIST" : "LIST " + path, null, b, -1, null); if (r.code != 226 && r.code != 250) throw new IOException(r.text); return b.toByteArray(); }
    public byte[] nlst(String path) throws IOException { ByteArrayOutputStream b = new ByteArrayOutputStream(); Reply r = transfer(path == null || path.isEmpty() ? "NLST" : "NLST " + path, null, b, -1, null); if (r.code != 226 && r.code != 250) throw new IOException(r.text); return b.toByteArray(); }
    public Reply retr(String file, OutputStream o, long offset, long stopAfter, LongConsumer progress) throws IOException {
        if (offset > 0) expect("REST " + offset, 350);
        return transfer("RETR " + file, null, o, stopAfter, progress);
    }
    public Reply stor(String file, InputStream i) throws IOException { return transfer("STOR " + file, i, null, -1, null); }

    public void quit() { try { cmd("QUIT"); } catch (IOException ignored) { } close(); }
    @Override public void close() { try { ctrl.close(); } catch (IOException ignored) { } }
}

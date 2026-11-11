package ftp.server;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLSocket;
import ftp.core.Hub;
import ftp.core.Tls;

/**
 * One FTP control connection (RFC 959). Commands and replies travel here as lines of text; every
 * listing and file travels on a separate DATA connection, opened per transfer and closed after it:
 *   active  (PORT / EPRT): the SERVER connects to the client, from port control-1 (20 for 21)
 *   passive (PASV / EPSV): the CLIENT connects to a port the server opens for it
 */
final class Session implements Runnable {

    private static final AtomicInteger IDS = new AtomicInteger();
    private final FtpServer srv;
    private Socket ctrl;
    private InputStream in; private OutputStream out;
    final String sid;
    final long started = System.currentTimeMillis();
    String user = "", peer;
    private boolean loggedIn, tls, protP;
    private Vfs vfs;
    private String cwd = "/";
    private char type = 'A';
    private long rest;
    private String rnfr;
    private ServerSocket pasv;
    private InetSocketAddress active;
    private volatile Thread xfer;
    private volatile Socket dataSock;
    private volatile boolean aborted;

    Session(FtpServer srv, Socket s) { this.srv = srv; this.ctrl = s; this.sid = "ftp#" + IDS.incrementAndGet(); this.peer = s.getInetAddress().getHostAddress() + ":" + s.getPort(); }

    // ------------------------------------------------------------------ control channel I/O
    private synchronized void reply(String line, String note) {
        try { out.write((line + "\r\n").getBytes(StandardCharsets.UTF_8)); out.flush(); } catch (IOException ignored) { }
        Hub.I.line(new Hub.Line(sid, "CTRL", false, line, note == null ? Codes.meaning(line) : note));
    }
    private void reply(String line) { reply(line, null); }

    private String readLine() throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) != -1) { if (c == '\n') break; if (c != '\r') b.write(c); if (b.size() > 4096) break; }
        if (c == -1 && b.size() == 0) return null;
        return b.toString(StandardCharsets.UTF_8);
    }

    @Override public void run() {
        srv.sessions.add(this);
        try {
            ctrl.setSoTimeout(15 * 60_000);
            in = new BufferedInputStream(ctrl.getInputStream()); out = new BufferedOutputStream(ctrl.getOutputStream());
            Hub.I.line(new Hub.Line(sid, "CTRL", true, "(TCP connection from " + peer + " to control port " + ctrl.getLocalPort() + ")", "control connection: stays open for the whole session"));
            reply("220 JU-FTP ready · RFC 959 · ftp.cse.myuniv.edu", "service ready: send USER");
            String line;
            while ((line = readLine()) != null) {
                String cmd = line.contains(" ") ? line.substring(0, line.indexOf(' ')).toUpperCase(Locale.ROOT) : line.toUpperCase(Locale.ROOT);
                String arg = line.contains(" ") ? line.substring(line.indexOf(' ') + 1) : "";
                Hub.I.line(new Hub.Line(sid, "CTRL", true, cmd.equals("PASS") ? "PASS " + "*".repeat(Math.max(4, arg.length())) : line, Codes.command(cmd)));
                if (xfer != null && !cmd.equals("ABOR") && !cmd.equals("NOOP") && !cmd.equals("STAT")) { Thread t = xfer; if (t != null) try { t.join(); } catch (InterruptedException ignored) { } }
                if (!handle(cmd, arg)) break;
            }
        } catch (IOException e) {
            Hub.I.line(new Hub.Line(sid, "CTRL", false, "(control connection closed)", e.getMessage()));
        } finally {
            closePasv();
            try { ctrl.close(); } catch (IOException ignored) { }
            srv.sessions.remove(this);
        }
    }

    private boolean needLogin() { if (!loggedIn) reply("530 Please log in with USER and PASS first"); return !loggedIn; }

    // ------------------------------------------------------------------ commands
    private boolean handle(String cmd, String arg) throws IOException {
        switch (cmd) {
            case "USER":
                user = arg.trim(); loggedIn = false;
                if (user.equalsIgnoreCase("anonymous") || user.equalsIgnoreCase("ftp")) { user = "anonymous"; reply("331 Anonymous login ok, send your e-mail address as the password"); }
                else reply("331 Password required for " + user);
                return true;
            case "PASS":
                if (user.isEmpty()) { reply("503 Login with USER first"); return true; }
                if (user.equals("anonymous") ? srv.allowAnonymous : srv.check(user, arg)) {
                    loggedIn = true; vfs = new Vfs(srv.root, user); cwd = vfs.home();
                    reply("230 User " + user + " logged in" + (user.equals("anonymous") ? " (read-only, /pub)" : ", home " + cwd));
                    Hub.I.event("LOGIN", user + " from " + peer + (tls ? " over TLS" : " (password crossed the network in plaintext)"));
                } else { reply("530 Login incorrect"); Hub.I.event("LOGIN-FAIL", user + " from " + peer); }
                return true;
            case "AUTH":
                if (Tls.server() == null) { reply("502 TLS not available"); return true; }
                if (tls) { reply("503 Already using TLS"); return true; }
                if (!arg.equalsIgnoreCase("TLS") && !arg.equalsIgnoreCase("SSL")) { reply("504 AUTH type not supported"); return true; }
                reply("234 AUTH TLS ok: starting the TLS handshake on this connection");
                SSLSocket ss = (SSLSocket) Tls.server().getSocketFactory().createSocket(ctrl, ctrl.getInetAddress().getHostAddress(), ctrl.getPort(), true);
                ss.setUseClientMode(false); ss.startHandshake();
                ctrl = ss; in = new BufferedInputStream(ss.getInputStream()); out = new BufferedOutputStream(ss.getOutputStream()); tls = true;
                Hub.I.line(new Hub.Line(sid, "CTRL", false, "(TLS handshake complete: " + ss.getSession().getProtocol() + " " + ss.getSession().getCipherSuite() + ")", "from now on the control channel is encrypted: a sniffer sees only TLS records"));
                return true;
            case "PBSZ": reply(tls ? "200 PBSZ=0" : "503 PBSZ needs AUTH TLS first"); return true;
            case "PROT":
                if (!tls) { reply("503 PROT needs AUTH TLS first"); return true; }
                protP = arg.trim().equalsIgnoreCase("P");
                reply("200 PROT now " + (protP ? "Private: data connections will be encrypted too" : "Clear: data connections stay plaintext"));
                return true;
            case "SYST": reply("215 UNIX Type: L8"); return true;
            case "FEAT":
                reply("211-Extensions supported:", "multi-line reply: one feature per line, then \"211 End\"");
                for (String f : new String[]{" SIZE", " MDTM", " REST STREAM", " PASV", " EPSV", " EPRT", " UTF8", " TVFS", Tls.server() != null ? " AUTH TLS" : null, Tls.server() != null ? " PBSZ" : null, Tls.server() != null ? " PROT" : null})
                    if (f != null) { synchronized (this) { out.write((f + "\r\n").getBytes(StandardCharsets.UTF_8)); out.flush(); } Hub.I.line(new Hub.Line(sid, "CTRL", false, f, "")); }
                reply("211 End");
                return true;
            case "HELP": reply("214 Commands: USER PASS ACCT CWD CDUP PWD LIST NLST RETR STOR APPE DELE MKD RMD RNFR RNTO TYPE MODE STRU PORT PASV EPRT EPSV REST SIZE MDTM ABOR NOOP SYST FEAT STAT AUTH PBSZ PROT QUIT"); return true;
            case "NOOP": reply("200 NOOP ok"); return true;
            case "STAT": reply("211 " + (xfer != null ? "transfer in progress" : "connected from " + peer + ", user " + (loggedIn ? user : "(none)") + ", TYPE " + (type == 'I' ? "I (binary)" : "A (ASCII)") + (tls ? ", TLS" : ""))); return true;
            case "QUIT": reply("221 Goodbye"); Hub.I.line(new Hub.Line(sid, "CTRL", false, "(control connection closed)", "end of session")); return false;
            case "MODE": reply(arg.trim().equalsIgnoreCase("S") ? "200 MODE S (stream) ok" : "504 Only stream mode (S) is supported"); return true;
            case "STRU": reply(arg.trim().equalsIgnoreCase("F") ? "200 STRU F (file) ok" : "504 Only file structure (F) is supported"); return true;
            case "TYPE": {
                String t = arg.trim().toUpperCase(Locale.ROOT);
                if (t.startsWith("A")) { type = 'A'; reply("200 TYPE set to A (ASCII: line endings become CRLF on the wire)"); }
                else if (t.startsWith("I") || t.startsWith("L 8")) { type = 'I'; reply("200 TYPE set to I (binary: bytes sent exactly as stored)"); }
                else reply("504 TYPE " + t + " not supported");
                return true;
            }
            case "ABOR": abort(); return true;
            default: break;
        }
        if (needLogin()) return true;
        switch (cmd) {
            case "PWD": case "XPWD": reply("257 \"" + cwd + "\" is the current directory"); return true;
            case "CWD": case "XCWD": cd(Vfs.resolve(cwd, arg.trim())); return true;
            case "CDUP": case "XCUP": cd(Vfs.resolve(cwd, "..")); return true;
            case "PORT": port(arg.trim()); return true;
            case "EPRT": eprt(arg.trim()); return true;
            case "PASV": pasv(false); return true;
            case "EPSV": pasv(true); return true;
            case "REST":
                try { rest = Long.parseLong(arg.trim()); reply("350 Restarting at byte " + rest + ": send RETR or STOR to continue from there"); }
                catch (NumberFormatException e) { reply("501 REST needs a byte offset"); }
                return true;
            case "SIZE": { File f = vfs.file(Vfs.resolve(cwd, arg.trim())); reply(f.isFile() ? "213 " + f.length() : "550 No such file"); return true; }
            case "MDTM": { File f = vfs.file(Vfs.resolve(cwd, arg.trim())); reply(f.isFile() ? "213 " + Vfs.mdtm(f) : "550 No such file"); return true; }
            case "MKD": case "XMKD": {
                String v = Vfs.resolve(cwd, arg.trim()); File f = vfs.file(v);
                if (!vfs.canWrite(v)) { reply("550 Permission denied: " + v + " is outside your home"); return true; }
                reply(f.mkdir() ? "257 \"" + v + "\" created" : "550 Cannot create " + v); return true;
            }
            case "RMD": case "XRMD": {
                String v = Vfs.resolve(cwd, arg.trim()); File f = vfs.file(v);
                if (!vfs.canWrite(v) || v.equals(vfs.home())) { reply("550 Permission denied"); return true; }
                if (!f.isDirectory()) { reply("550 Not a directory"); return true; }
                if (Vfs.children(f).length > 0) { reply("550 Directory not empty"); return true; }
                reply(f.delete() ? "250 Directory removed" : "550 Cannot remove"); return true;
            }
            case "DELE": {
                String v = Vfs.resolve(cwd, arg.trim()); File f = vfs.file(v);
                if (!vfs.canWrite(v)) { reply("550 Permission denied"); return true; }
                reply(f.isFile() && f.delete() ? "250 File deleted" : "550 No such file"); return true;
            }
            case "RNFR": {
                String v = Vfs.resolve(cwd, arg.trim());
                if (!vfs.canWrite(v) || !vfs.file(v).exists()) { reply("550 Cannot rename " + v); return true; }
                rnfr = v; reply("350 Ready for RNTO"); return true;
            }
            case "RNTO": {
                if (rnfr == null) { reply("503 Send RNFR first"); return true; }
                String v = Vfs.resolve(cwd, arg.trim());
                if (!vfs.canWrite(v)) { reply("553 Not allowed"); rnfr = null; return true; }
                boolean ok = vfs.file(rnfr).renameTo(vfs.file(v)); rnfr = null;
                reply(ok ? "250 Renamed" : "550 Rename failed"); return true;
            }
            case "LIST": case "NLST": transfer(cmd, arg.startsWith("-") ? (arg.contains(" ") ? arg.substring(arg.indexOf(' ') + 1) : "") : arg.trim()); return true;
            case "RETR": case "STOR": case "APPE": transfer(cmd, arg.trim()); return true;
            default: reply("502 Command not implemented: " + cmd); return true;
        }
    }

    private void cd(String v) throws IOException {
        File f = vfs.file(v);
        if (f.isDirectory()) { cwd = v; reply("250 Directory changed to " + v); } else reply("550 " + v + ": no such directory");
    }

    // ------------------------------------------------------------------ data connection setup
    private void closePasv() { if (pasv != null) try { pasv.close(); } catch (IOException ignored) { } pasv = null; }

    private void port(String a) {
        String[] p = a.split(",");
        if (p.length != 6) { reply("501 PORT h1,h2,h3,h4,p1,p2"); return; }
        try { activeTo(p[0] + "." + p[1] + "." + p[2] + "." + p[3], Integer.parseInt(p[4].trim()) * 256 + Integer.parseInt(p[5].trim()), "PORT"); }
        catch (NumberFormatException e) { reply("501 Bad PORT numbers"); }
    }
    private void eprt(String a) {
        String[] p = a.split(a.isEmpty() ? "\\|" : java.util.regex.Pattern.quote(a.substring(0, 1)));
        if (p.length < 4) { reply("501 EPRT |1|address|port|"); return; }
        try { activeTo(p[2], Integer.parseInt(p[3]), "EPRT"); } catch (NumberFormatException e) { reply("501 Bad EPRT port"); }
    }
    private void activeTo(String ip, int port, String how) {
        // FTP bounce attack protection (RFC 2577): only connect back to the client itself, never to a privileged port
        if (!ip.equals(ctrl.getInetAddress().getHostAddress()) || port < 1024) {
            reply("500 Illegal " + how + " command: " + ip + ":" + port + " (bounce-attack protection, RFC 2577: data may only go back to " + ctrl.getInetAddress().getHostAddress() + ", port ≥ 1024)");
            Hub.I.event("BOUNCE", "refused " + how + " to " + ip + ":" + port + " from " + peer);
            return;
        }
        closePasv();
        active = new InetSocketAddress(ip, port);
        reply("200 " + how + " ok: I will connect to " + ip + ":" + port + " for the next transfer (active mode)");
    }
    private void pasv(boolean extended) throws IOException {
        closePasv(); active = null;
        pasv = srv.pasvSocket(ctrl.getLocalAddress());
        int p = pasv.getLocalPort();
        byte[] a = ctrl.getLocalAddress().getAddress();
        if (extended) reply("229 Entering Extended Passive Mode (|||" + p + "|)");
        else reply(String.format("227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)", a[0] & 0xFF, a[1] & 0xFF, a[2] & 0xFF, a[3] & 0xFF, p / 256, p % 256),
                "passive: I am listening on port " + p + " (= " + p / 256 + "×256 + " + p % 256 + "); YOU connect to me");
    }

    private Socket openData() throws IOException {
        Socket s;
        if (pasv != null) {
            pasv.setSoTimeout(10_000);
            try { s = pasv.accept(); } finally { closePasv(); }
            Hub.I.line(new Hub.Line(sid, "DATA", true, "(client " + s.getInetAddress().getHostAddress() + ":" + s.getPort() + " connected to my passive port " + s.getLocalPort() + ")", "passive: the CLIENT opened the data connection"));
        } else if (active != null) {
            InetSocketAddress to = active; active = null;
            s = new Socket(); s.setReuseAddress(true);
            int src = ctrl.getLocalPort() - 1;
            try { s.bind(new InetSocketAddress(ctrl.getLocalAddress(), src)); } catch (BindException e) { s.close(); s = new Socket(); src = 0; }
            try { s.connect(to, 4000); }
            catch (IOException e) { s.close(); Hub.I.line(new Hub.Line(sid, "DATA", false, "(could not connect to " + to.getAddress().getHostAddress() + ":" + to.getPort() + ")", "active mode failed: the client did not accept the connection (a firewall or NAT in the way)")); throw e; }
            Hub.I.line(new Hub.Line(sid, "DATA", false, "(I connected from port " + s.getLocalPort() + " to client " + to.getAddress().getHostAddress() + ":" + to.getPort() + ")", "active: the SERVER opened the data connection" + (src > 0 ? ", from port " + src + " (control port − 1)" : "")));
        } else throw new IOException("no PORT or PASV first");
        if (protP && tls) {
            SSLSocket t = (SSLSocket) Tls.server().getSocketFactory().createSocket(s, s.getInetAddress().getHostAddress(), s.getPort(), true);
            t.setUseClientMode(false); t.startHandshake();
            Hub.I.line(new Hub.Line(sid, "DATA", false, "(TLS on the data connection)", "PROT P: the file is encrypted too"));
            return t;
        }
        return s;
    }

    // ------------------------------------------------------------------ transfers (run in their own thread so ABOR still works)
    private void transfer(String cmd, String arg) throws IOException {
        String v = Vfs.resolve(cwd, arg);
        File f = vfs.file(v);
        boolean upload = cmd.equals("STOR") || cmd.equals("APPE");
        if (upload && !vfs.canWrite(v)) { reply("553 Permission denied: " + (vfs.anonymous ? "anonymous users are read-only" : v + " is outside your home")); rest = 0; return; }
        if (cmd.equals("RETR") && !f.isFile()) { reply("550 " + v + ": no such file"); rest = 0; return; }
        if ((cmd.equals("LIST") || cmd.equals("NLST")) && !f.exists()) { reply("550 " + v + ": no such file or directory"); return; }
        if (pasv == null && active == null) { reply("425 Use PORT or PASV first"); return; }
        long offset = rest; rest = 0;
        char mode = type;
        String what = cmd.equals("LIST") || cmd.equals("NLST") ? "directory listing of " + v : (upload ? "upload of " : "") + v + (cmd.equals("RETR") ? " (" + f.length() + " bytes)" : "");
        reply("150 Opening " + (mode == 'I' ? "BINARY" : "ASCII") + " mode data connection for " + what + (offset > 0 ? ", from byte " + offset : ""));
        aborted = false;
        Thread t = new Thread(() -> {
            long n = 0; long t0 = System.nanoTime();
            try (Socket s = openData()) {
                dataSock = s;
                if (upload) n = receive(s.getInputStream(), f, cmd.equals("APPE"), offset, mode);
                else if (cmd.equals("RETR")) n = send(s.getOutputStream(), f, offset, mode);
                else n = sendBytes(s.getOutputStream(), listing(f, v, cmd.equals("NLST")), 'A');
                s.shutdownOutput();
                Hub.I.line(new Hub.Line(sid, "DATA", false, "(data connection closed after " + n + " bytes)", "one data connection per transfer: it closes as soon as the transfer ends (that is how the receiver knows the file is complete in stream mode)"));
                double ms = (System.nanoTime() - t0) / 1e6;
                reply("226 Transfer complete: " + n + " bytes in " + String.format(Locale.ROOT, "%.0f", ms) + " ms" + (mode == 'A' && !cmd.equals("LIST") && !cmd.equals("NLST") ? " (ASCII mode: line endings converted)" : ""));
                srv.board(user, cmd, v, mode, n, "done", ms);
            } catch (IOException e) {
                if (aborted) { reply("426 Connection closed; transfer aborted after " + n + " bytes"); srv.board(user, cmd, v, mode, n, "aborted", 0); }
                else { String why = e.getMessage() == null ? "" : e.getMessage().toLowerCase().contains("refused") ? "connection refused" : e.getMessage().toLowerCase().contains("timed out") ? "timed out" : e.getMessage(); reply("425 Can't open data connection (" + why + ")"); srv.board(user, cmd, v, mode, 0, "failed", 0); }
            } finally { dataSock = null; xfer = null; }
        }, sid + "-data");
        xfer = t; t.start();
    }

    private void abort() {
        Thread t = xfer;
        if (t == null) { reply("226 ABOR ok: no transfer in progress"); return; }
        aborted = true;
        try { Socket s = dataSock; if (s != null) s.close(); } catch (IOException ignored) { }
        try { t.join(5000); } catch (InterruptedException ignored) { }
        reply("226 ABOR command successful");
    }

    private byte[] listing(File f, String v, boolean namesOnly) {
        StringBuilder b = new StringBuilder();
        File[] items = f.isDirectory() ? Vfs.children(f) : new File[]{f};
        for (File c : items) {
            String cv = f.isDirectory() ? (v.endsWith("/") ? v : v + "/") + c.getName() : v;
            b.append(namesOnly ? c.getName() : vfs.lsLine(c, cv)).append('\n');
        }
        return b.toString().getBytes(StandardCharsets.UTF_8);
    }

    private long sendBytes(OutputStream o, byte[] data, char mode) throws IOException {
        byte[] wire = mode == 'A' ? Codes.toCrlf(data) : data;
        o.write(wire); o.flush();
        return wire.length;
    }

    /** RETR: optional REST offset; ASCII turns every LF into CRLF; "slow link" throttling for big files. */
    private long send(OutputStream o, File f, long offset, char mode) throws IOException {
        long n = 0;
        boolean slow = srv.slowLink && f.length() > 64 * 1024;
        try (RandomAccessFile r = new RandomAccessFile(f, "r")) {
            r.seek(Math.min(offset, r.length()));
            byte[] buf = new byte[16 * 1024]; int k; int prev = -1;
            while ((k = r.read(buf)) > 0) {
                if (mode == 'A') {
                    ByteArrayOutputStream b = new ByteArrayOutputStream(k + k / 8);
                    for (int i = 0; i < k; i++) { int c = buf[i] & 0xFF; if (c == '\n' && prev != '\r') b.write('\r'); b.write(c); prev = c; }
                    byte[] w = b.toByteArray(); o.write(w); n += w.length;
                } else { o.write(buf, 0, k); n += k; }
                if (slow) { try { Thread.sleep(40); } catch (InterruptedException e) { break; } }
                srv.progress(sid, f.getName(), offset + n, f.length());
            }
            o.flush();
        }
        return n;
    }

    /** STOR / APPE: ASCII turns CRLF back into LF (so a binary file uploaded in ASCII mode loses bytes). */
    private long receive(InputStream i, File f, boolean append, long offset, char mode) throws IOException {
        long n = 0;
        try (RandomAccessFile w = new RandomAccessFile(f, "rw")) {
            if (append) w.seek(w.length()); else if (offset > 0) w.seek(offset); else w.setLength(0);
            byte[] buf = new byte[16 * 1024]; int k; boolean pendingCr = false;
            while ((k = i.read(buf)) > 0) {
                n += k;
                if (mode == 'A') {
                    ByteArrayOutputStream b = new ByteArrayOutputStream(k);
                    for (int x = 0; x < k; x++) {
                        int c = buf[x] & 0xFF;
                        if (pendingCr) { if (c != '\n') b.write('\r'); pendingCr = false; }
                        if (c == '\r') { pendingCr = true; continue; }
                        b.write(c);
                    }
                    w.write(b.toByteArray());
                } else w.write(buf, 0, k);
            }
            if (pendingCr) w.write('\r');
        }
        return n;
    }

    // used by the dashboard's sessions table
    String json() {
        return ftp.core.Json.obj("id", sid, "peer", peer, "user", loggedIn ? user : "", "cwd", cwd, "type", String.valueOf(type), "tls", tls, "prot", protP ? "P" : "C",
                "busy", xfer != null, "age", (System.currentTimeMillis() - started) / 1000);
    }
}

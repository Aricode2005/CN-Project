package telnet.lab;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import telnet.core.Hub;
import telnet.core.Json;
import telnet.protocol.Telnet;
import telnet.protocol.TelnetCodec;

/**
 * Character mode vs Nagle vs LINEMODE, measured.
 *
 * A scripted Telnet client logs in to the real server through a link that delays every chunk by RTT/2 in each direction,
 * then types the same commands at a fixed typing speed, three times:
 * <ol>
 *   <li><b>Character mode</b> (what the server normally negotiates: server ECHO + SUPPRESS-GO-AHEAD): every keystroke is
 *       sent at once (TCP_NODELAY) and echoed by the server: two tiny segments per key.</li>
 *   <li><b>Character mode with Nagle's rule</b> (RFC 896): while sent data is still unacknowledged, new keystrokes wait
 *       and go out together when the acknowledgement (here, the echo) arrives. Fewer segments, slower echo.</li>
 *   <li><b>LINEMODE</b> (RFC 1184, MODE EDIT): the client edits and echoes the line locally and sends it complete.</li>
 * </ol>
 * The link counts every segment and byte in each direction. Wire bytes add 40 bytes of IPv4 + TCP header per segment.
 */
public final class ModeLab {

    public static final String[] SCRIPT = {"show clock", "who", "show history"};
    static final int HEADER = 40;

    /** Run all three modes against the Telnet server on {@code port}. */
    public static String run(int port, int rttMs, int gapMs) {
        rttMs = Math.max(0, Math.min(400, rttMs)); gapMs = Math.max(20, Math.min(400, gapMs));
        List<String> out = new ArrayList<>();
        for (String mode : new String[]{"char", "nagle", "line"}) {
            try { out.add(new Run(port, mode, rttMs, gapMs).go()); }
            catch (Exception e) { out.add(Json.obj("mode", mode, "error", String.valueOf(e.getMessage()))); }
        }
        Hub.I.log("[LAB] linemode experiment done (RTT " + rttMs + " ms, " + gapMs + " ms per key)");
        return Json.obj("rtt", rttMs, "gap", gapMs, "header", HEADER, "script", Json.raw(Json.arr(quote(SCRIPT))), "runs", Json.raw(Json.arr(out)));
    }

    private static List<String> quote(String[] a) { List<String> l = new ArrayList<>(); for (String s : a) l.add(Json.str(s)); return l; }

    // ================================================================== the delaying link (counts segments)

    /** A TCP relay that delays every chunk by RTT/2 and counts what crosses it. */
    static final class Link implements AutoCloseable {
        final ServerSocket ss; final int half; final int target;
        volatile boolean measuring;
        long t0;
        final long[] segs = new long[2], bytes = new long[2];
        final List<long[]> timeline = new ArrayList<>();             // {ms since start, dir (0 = C>S), length}
        private final ScheduledExecutorService[] ex = {Executors.newSingleThreadScheduledExecutor(), Executors.newSingleThreadScheduledExecutor()};
        private Socket a, b;

        Link(int target, int rtt) throws IOException {
            this.target = target; this.half = rtt / 2;
            ss = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
            Thread t = new Thread(() -> {
                try {
                    a = ss.accept(); b = new Socket("127.0.0.1", target);
                    a.setTcpNoDelay(true); b.setTcpNoDelay(true);
                    pump(a, b, 0); pump(b, a, 1);
                } catch (IOException ignored) { }
            }, "lab-link");
            t.setDaemon(true); t.start();
        }

        int port() { return ss.getLocalPort(); }

        void startMeasuring() { synchronized (this) { segs[0] = segs[1] = bytes[0] = bytes[1] = 0; timeline.clear(); t0 = System.nanoTime(); measuring = true; } }

        private void pump(Socket from, Socket to, int dir) {
            Thread t = new Thread(() -> {
                byte[] buf = new byte[8192];
                try {
                    InputStream in = from.getInputStream(); OutputStream o = to.getOutputStream(); int n;
                    while ((n = in.read(buf)) > 0) {
                        byte[] c = java.util.Arrays.copyOf(buf, n);
                        count(dir, c);
                        ex[dir].schedule(() -> { try { o.write(c); o.flush(); } catch (IOException ignored) { } }, half, TimeUnit.MILLISECONDS);
                    }
                } catch (IOException ignored) { }
            }, "lab-pump");
            t.setDaemon(true); t.start();
        }

        private synchronized void count(int dir, byte[] c) {
            if (!measuring) return;
            // the server's periodic TIMING-MARK RTT probe (and its answer) is not part of the typing traffic
            if (c.length == 3 && (c[0] & 0xFF) == Telnet.IAC && (c[2] & 0xFF) == Telnet.OPT_TIMING_MARK) return;
            segs[dir]++; bytes[dir] += c.length;
            if (timeline.size() < 600) timeline.add(new long[]{(System.nanoTime() - t0) / 1_000_000, dir, c.length});
        }

        @Override public void close() {
            for (ScheduledExecutorService e : ex) e.shutdownNow();
            try { ss.close(); } catch (IOException ignored) { }
            try { if (a != null) a.close(); } catch (IOException ignored) { }
            try { if (b != null) b.close(); } catch (IOException ignored) { }
        }
    }

    // ================================================================== one scripted session

    static final class Run {
        final int port, rtt, gap; final String mode;
        Socket s; OutputStream out;
        final StringBuilder screen = new StringBuilder();
        final Object lock = new Object();
        final Deque<long[]> pendingEcho = new ArrayDeque<>();        // {char, keypress time ns}
        final List<Double> echoMs = new ArrayList<>();
        int outstanding;                                              // Nagle: sent bytes not yet echoed (= not yet acknowledged)
        final StringBuilder nagleBuf = new StringBuilder();
        volatile boolean serverEcho = true, linemodeOn;

        Run(int port, String mode, int rtt, int gap) { this.port = port; this.mode = mode; this.rtt = rtt; this.gap = gap; }

        String go() throws Exception {
            try (Link link = new Link(port, rtt)) {
                s = new Socket("127.0.0.1", link.port());
                s.setTcpNoDelay(true);
                out = s.getOutputStream();
                TelnetCodec codec = new TelnetCodec(new TelnetCodec.Listener() {
                    public void onData(int b) { data(b); }
                    public void onCommand(int c) { }
                    public void onNegotiation(int v, int o) { negotiate(v, o); }
                    public void onSubnegotiation(int o, byte[] p) { sub(o, p); }
                });
                Thread rd = new Thread(() -> {
                    byte[] b = new byte[4096];
                    try { InputStream in = s.getInputStream(); int n; while ((n = in.read(b)) > 0) synchronized (lock) { codec.feed(b, 0, n); lock.notifyAll(); } }
                    catch (IOException ignored) { }
                }, "lab-reader");
                rd.setDaemon(true); rd.start();

                await("Username: ", 6000 + 4 * rtt); write("admin\r\n");
                await("Password: ", 4000 + 4 * rtt); write("cisco\r\n");
                awaitPrompt(4000 + 4 * rtt);
                if (mode.equals("line")) {
                    write(Telnet.negotiation(Telnet.WILL, Telnet.OPT_LINEMODE));
                    long end = System.currentTimeMillis() + 3000 + 4 * rtt;
                    while (!(linemodeOn && !serverEcho) && System.currentTimeMillis() < end) Thread.sleep(20);
                    if (!linemodeOn) throw new IOException("server did not accept LINEMODE");
                    Thread.sleep(3L * rtt + 100);                     // let the option exchange finish before measuring
                }
                link.startMeasuring();
                long start = System.nanoTime();
                List<Double> cmdMs = new ArrayList<>();
                int keys = 0;
                for (String cmd : SCRIPT) {
                    for (char ch : cmd.toCharArray()) { key(ch); keys++; Thread.sleep(gap); }
                    long enter = System.nanoTime();
                    enter(); keys++;
                    awaitPrompt(8000 + 6 * rtt);
                    cmdMs.add((System.nanoTime() - enter) / 1e6);
                    Thread.sleep(150);
                }
                long total = (System.nanoTime() - start) / 1_000_000;
                Thread.sleep(rtt + 50);                               // let the last segments cross the link
                write("exit\r\n");
                synchronized (link) { link.measuring = false; }
                double avgEcho = echoMs.isEmpty() ? 0 : echoMs.stream().mapToDouble(x -> x).average().orElse(0);
                double maxEcho = echoMs.isEmpty() ? 0 : echoMs.stream().mapToDouble(x -> x).max().orElse(0);
                double avgCmd = cmdMs.stream().mapToDouble(x -> x).average().orElse(0);
                List<String> tl = new ArrayList<>();
                synchronized (link) { for (long[] e : link.timeline) tl.add("[" + e[0] + "," + e[1] + "," + e[2] + "]"); }
                long seg = link.segs[0] + link.segs[1], pay = link.bytes[0] + link.bytes[1];
                return Json.obj("mode", mode, "keys", keys, "segC2S", link.segs[0], "segS2C", link.segs[1], "bytesC2S", link.bytes[0], "bytesS2C", link.bytes[1],
                        "segments", seg, "payload", pay, "wire", pay + HEADER * seg, "overhead", pay + HEADER * seg == 0 ? 0 : Math.round(1000.0 * HEADER * seg / (pay + HEADER * seg)) / 10.0,
                        "segPerKey", Math.round(100.0 * link.segs[0] / Math.max(1, keys)) / 100.0,
                        "echoAvg", Math.round(avgEcho * 10) / 10.0, "echoMax", Math.round(maxEcho * 10) / 10.0, "cmdAvg", Math.round(avgCmd * 10) / 10.0,
                        "totalMs", total, "timeline", Json.raw("[" + String.join(",", tl) + "]"));
            } finally { if (s != null) try { s.close(); } catch (IOException ignored) { } }
        }

        // ---------------------------------------------------------------- typing, per mode

        void key(char ch) throws IOException {
            long now = System.nanoTime();
            switch (mode) {
                case "line":                                          // local edit + local echo: nothing on the wire yet
                    nagleBuf.append(ch); echoMs.add(0.0); return;
                case "nagle":
                    synchronized (lock) {
                        pendingEcho.addLast(new long[]{ch, now});
                        if (outstanding == 0) { outstanding = 1; write(String.valueOf(ch)); }   // nothing unacknowledged: send now
                        else nagleBuf.append(ch);                                                // RFC 896: wait for the ACK
                    }
                    return;
                default:
                    synchronized (lock) { pendingEcho.addLast(new long[]{ch, now}); }
                    write(String.valueOf(ch));
            }
        }

        void enter() throws IOException {
            if (mode.equals("line")) { write(nagleBuf + "\r\n"); nagleBuf.setLength(0); return; }
            if (mode.equals("nagle")) {
                synchronized (lock) {
                    if (outstanding == 0) { write("\r\n"); }
                    else { nagleBuf.append("\r\n"); }
                }
                return;
            }
            write("\r\n");
        }

        /** Server data: match echoes against keystrokes (the echo is our acknowledgement for Nagle's rule). */
        void data(int b) {
            screen.append((char) b);
            if (screen.length() > 20000) screen.delete(0, 10000);
            long[] head = pendingEcho.peekFirst();
            if (head != null && head[0] == b) {
                pendingEcho.pollFirst();
                echoMs.add((System.nanoTime() - head[1]) / 1e6);
                if (mode.equals("nagle") && outstanding > 0 && --outstanding == 0 && nagleBuf.length() > 0) {
                    String chunk = nagleBuf.toString(); nagleBuf.setLength(0);
                    int printable = 0; for (char c : chunk.toCharArray()) if (c >= 32) printable++;
                    outstanding = Math.max(printable, chunk.endsWith("\n") && printable == 0 ? 0 : printable);
                    try { write(chunk); } catch (IOException ignored) { }
                }
            }
        }

        void negotiate(int v, int o) {
            int reply;
            if (v == Telnet.WILL) { reply = (o == Telnet.OPT_ECHO || o == Telnet.OPT_SGA) ? Telnet.DO : Telnet.DONT; if (o == Telnet.OPT_ECHO) serverEcho = true; }
            else if (v == Telnet.WONT) { reply = Telnet.DONT; if (o == Telnet.OPT_ECHO) serverEcho = false; }
            else if (v == Telnet.DO) {
                if (o == Telnet.OPT_LINEMODE) { linemodeOn = true; return; }        // our WILL LINEMODE was accepted
                reply = (o == Telnet.OPT_SGA || o == Telnet.OPT_TTYPE || o == Telnet.OPT_NAWS || o == Telnet.OPT_TIMING_MARK) ? Telnet.WILL : Telnet.WONT;
            } else reply = Telnet.WONT;
            try {
                write(Telnet.negotiation(reply, o));
                if (v == Telnet.DO && o == Telnet.OPT_NAWS) write(Telnet.subnegotiation(Telnet.OPT_NAWS, new byte[]{0, 80, 0, 24}));
            } catch (IOException ignored) { }
        }

        void sub(int o, byte[] p) {
            try {
                if (o == Telnet.OPT_TTYPE && p.length > 0 && p[0] == Telnet.TTYPE_SEND) {
                    byte[] t = "XTERM".getBytes(StandardCharsets.US_ASCII), v = new byte[t.length + 1];
                    v[0] = Telnet.TTYPE_IS; System.arraycopy(t, 0, v, 1, t.length);
                    write(Telnet.subnegotiation(Telnet.OPT_TTYPE, v));
                } else if (o == Telnet.OPT_LINEMODE && p.length >= 2 && p[0] == 1 && (p[1] & 4) == 0) {
                    write(Telnet.subnegotiation(Telnet.OPT_LINEMODE, new byte[]{1, (byte) (p[1] | 4)}));   // MODE ... ACK
                }
            } catch (IOException ignored) { }
        }

        // ---------------------------------------------------------------- plumbing

        void write(String s) throws IOException { write(TelnetCodec.encodeData(s.getBytes(StandardCharsets.ISO_8859_1))); }
        void write(byte[] b) throws IOException { synchronized (this) { out.write(b); out.flush(); } }

        void await(String text, long ms) throws Exception {
            long end = System.currentTimeMillis() + ms;
            synchronized (lock) { while (screen.indexOf(text) < 0) { long w = end - System.currentTimeMillis(); if (w <= 0) throw new IOException("timeout waiting for \"" + text.trim() + "\""); lock.wait(w); } screen.setLength(0); }
        }

        void awaitPrompt(long ms) throws Exception {
            long end = System.currentTimeMillis() + ms;
            synchronized (lock) {
                while (!(screen.length() > 0 && endsWithPrompt())) { long w = end - System.currentTimeMillis(); if (w <= 0) throw new IOException("timeout waiting for the prompt"); lock.wait(w); }
                screen.setLength(0);
            }
        }

        private boolean endsWithPrompt() { String t = screen.toString(); int i = t.lastIndexOf('\n'); String last = t.substring(i + 1); return last.endsWith("#") && last.length() > 1 && !last.contains(" "); }
    }
}

package telnet.client;

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import telnet.protocol.OptionNegotiator;
import telnet.protocol.Telnet;
import telnet.protocol.TelnetCodec;

/**
 * A Telnet client (the other half of the protocol), used by the browser terminal, the CLI
 * client, the brute-force demo and the test suite.
 *
 * It agrees to: server ECHO (optional), SUPPRESS-GO-AHEAD, TERMINAL-TYPE (cycling through a
 * list, RFC 1091), NAWS (sending its window size, and again on every resize), and answers
 * TIMING-MARK. Everything else is refused, as RFC 854 requires.
 */
public final class TelnetClient implements Closeable {

    private final Socket sock;
    private final InputStream in;
    private final OutputStream out;
    public final OptionNegotiator neg;
    private final TelnetCodec codec;
    private final String[] ttypes;
    private int ttypeIdx;
    private volatile int cols, rows;
    private final StringBuilder text = new StringBuilder();
    private long textBase;                 // number of chars dropped from the front of `text`
    private volatile boolean closed;
    private final Consumer<String> onText;
    public final List<String> negLog = new ArrayList<>();

    public TelnetClient(String host, int port, boolean tls, File trustStore, String[] ttypes, int cols, int rows,
                        boolean acceptEcho, Consumer<String> onText) throws IOException {
        this.ttypes = ttypes;
        this.cols = cols; this.rows = rows;
        this.onText = onText;
        if (tls) {
            try {
                KeyStore ks = KeyStore.getInstance("PKCS12");
                try (FileInputStream f = new FileInputStream(trustStore)) { ks.load(f, "changeit".toCharArray()); }
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(ks);                       // trust exactly our server's certificate (pinning)
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, tmf.getTrustManagers(), null);
                SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(host, port);
                s.startHandshake();
                sock = s;
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                throw new IOException("TLS setup failed: " + e.getMessage(), e);
            }
        } else {
            sock = new Socket(host, port);
        }
        sock.setTcpNoDelay(true);
        in = sock.getInputStream();
        out = sock.getOutputStream();

        neg = new OptionNegotiator((v, o, m) -> { write(Telnet.negotiation(v, o)); log("C>S " + Telnet.describeNegotiation(v, o) + "  (" + m + ")"); },
            new OptionNegotiator.Policy() {
                public boolean acceptLocal(int o) { return o == Telnet.OPT_TTYPE || o == Telnet.OPT_NAWS || o == Telnet.OPT_SGA || o == Telnet.OPT_TSPEED; }
                public boolean acceptRemote(int o) { return (o == Telnet.OPT_ECHO && acceptEcho) || o == Telnet.OPT_SGA || o == Telnet.OPT_STATUS; }
            });
        neg.setObserver(new OptionNegotiator.Observer() {
            public void onStep(boolean r, int v, int o, boolean us, OptionNegotiator.Q b, OptionNegotiator.Q a, String meaning, String note) {
                if (r) log("S>C " + Telnet.describeNegotiation(v, o) + "  [" + (us ? "us " : "him ") + Telnet.optName(o) + " " + b + "->" + a + "] " + note);
            }
            public void onChange(boolean us, int o, boolean en) {
                if (us && o == Telnet.OPT_NAWS && en) sendNaws();
            }
        });
        codec = new TelnetCodec(new TelnetCodec.Listener() {
            public void onData(int b) { appendText(String.valueOf((char) b)); }
            public void onCommand(int c) { log("S>C IAC " + Telnet.cmdName(c)); }
            public void onNegotiation(int v, int o) {
                if (o == Telnet.OPT_TIMING_MARK) {
                    if (v == Telnet.DO) write(Telnet.negotiation(Telnet.WILL, Telnet.OPT_TIMING_MARK));   // RFC 860: "I have processed everything up to here"
                    return;
                }
                neg.receive(v, o);
            }
            public void onSubnegotiation(int o, byte[] p) {
                if (o == Telnet.OPT_TSPEED && p.length > 0 && p[0] == Telnet.SB_SEND) {
                    byte[] sp = "38400,38400".getBytes(StandardCharsets.US_ASCII);
                    byte[] pl = new byte[sp.length + 1];
                    pl[0] = Telnet.SB_IS;
                    System.arraycopy(sp, 0, pl, 1, sp.length);
                    write(Telnet.subnegotiation(Telnet.OPT_TSPEED, pl));
                    log("C>S SB TERMINAL-SPEED IS \"38400,38400\"");
                    return;
                }
                if (o == Telnet.OPT_STATUS) { log("S>C SB STATUS IS (" + p.length + " bytes)"); return; }
                if (o == Telnet.OPT_TTYPE && p.length > 0 && p[0] == Telnet.TTYPE_SEND) {
                    String t = TelnetClient.this.ttypes[Math.min(ttypeIdx, TelnetClient.this.ttypes.length - 1)];
                    ttypeIdx++;
                    byte[] name = t.getBytes(StandardCharsets.US_ASCII);
                    byte[] pl = new byte[name.length + 1];
                    pl[0] = Telnet.TTYPE_IS;
                    System.arraycopy(name, 0, pl, 1, name.length);
                    write(Telnet.subnegotiation(Telnet.OPT_TTYPE, pl));
                    log("C>S SB TERMINAL-TYPE IS \"" + t + "\"");
                }
            }
        });
        Thread t = new Thread(this::readLoop, "telnet-client");
        t.setDaemon(true);
        t.start();
    }

    private void readLoop() {
        byte[] b = new byte[4096];
        try {
            int n;
            while ((n = in.read(b)) > 0) codec.feed(b, 0, n);
        } catch (IOException ignored) {
        } finally {
            closed = true;
            appendText("");
        }
    }

    private synchronized void log(String s) { negLog.add(s); if (negLog.size() > 300) negLog.remove(0); }

    private void appendText(String s) {
        synchronized (text) {
            text.append(s);
            if (text.length() > 200_000) { textBase += 100_000; text.delete(0, 100_000); }
            text.notifyAll();
        }
        if (onText != null && !s.isEmpty()) onText.accept(s);
    }

    private synchronized void write(byte[] b) {
        try { out.write(b); out.flush(); } catch (IOException e) { closed = true; }
    }

    // ------------------------------------------------------------------ API

    /** Send keystrokes/text as typed (escaped for the wire). */
    public void type(String s) { write(TelnetCodec.encodeData(s.getBytes(StandardCharsets.ISO_8859_1))); }

    /** Textbook "embedding" example: c a t _ f i l e a IAC EC 1 CR LF in ONE TCP segment. */
    public void embedEraseDemo() {
        java.io.ByteArrayOutputStream b = new java.io.ByteArrayOutputStream();
        for (char ch : "cat filea".toCharArray()) b.write(ch);
        b.write(Telnet.IAC); b.write(Telnet.EC);
        b.write('1'); b.write(13); b.write(10);
        write(b.toByteArray());
        log("C>S embedded: cat filea IAC EC 1");
    }

    public void line(String s) { type(s + "\r\n"); }

    public void command(int cmd) { write(new byte[]{(byte) Telnet.IAC, (byte) cmd}); log("C>S IAC " + Telnet.cmdName(cmd)); }

    /** RFC 859: ask the server to report which options it believes are on. */
    public boolean requestStatus() {
        if (!neg.isRemote(Telnet.OPT_STATUS)) return false;
        write(Telnet.subnegotiation(Telnet.OPT_STATUS, new byte[]{Telnet.SB_SEND}));
        log("C>S SB STATUS SEND");
        return true;
    }

    public void resize(int c, int r) { cols = c; rows = r; if (neg.isLocal(Telnet.OPT_NAWS)) sendNaws(); }

    private void sendNaws() {
        byte[] p = {(byte) (cols >> 8), (byte) cols, (byte) (rows >> 8), (byte) rows};
        write(Telnet.subnegotiation(Telnet.OPT_NAWS, p));
        log("C>S SB NAWS " + cols + "x" + rows);
    }

    public boolean isClosed() { return closed; }

    /** Absolute offset of the end of received text. */
    public long mark() { synchronized (text) { return textBase + text.length(); } }

    /** Text received since absolute offset `from`. */
    public String since(long from) {
        synchronized (text) {
            int i = (int) Math.max(0, from - textBase);
            return i >= text.length() ? "" : text.substring(i);
        }
    }

    /** Wait until `needle` appears after offset `from`. Returns the offset just after it, or -1 on timeout/close. */
    public long expect(long from, String needle, long timeoutMs) {
        long end = System.currentTimeMillis() + timeoutMs;
        synchronized (text) {
            while (true) {
                int i = (int) Math.max(0, from - textBase);
                int at = text.indexOf(needle, i);
                if (at >= 0) return textBase + at + needle.length();
                long left = end - System.currentTimeMillis();
                if (left <= 0 || closed) return -1;
                try { text.wait(Math.min(left, 100)); } catch (InterruptedException e) { return -1; }
            }
        }
    }

    @Override
    public void close() { closed = true; try { sock.close(); } catch (IOException ignored) { } }
}

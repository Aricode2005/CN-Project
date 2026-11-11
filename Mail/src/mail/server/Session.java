package mail.server;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import mail.core.Hub;
import mail.store.MailStore;

/**
 * Base for SMTP, POP3 and IMAP sessions: all three are text protocols with CRLF-terminated
 * lines over TCP, so they share the line I/O, the transcript logging and the STARTTLS upgrade
 * (turning the already-open TCP connection into a TLS connection in place).
 */
public abstract class Session implements Runnable {

    /** Things every session needs. */
    public static final class Context {
        public final MailStore store;
        public final SSLSocketFactory tls;     // null if no certificate
        public final String host;
        public Context(MailStore store, SSLSocketFactory tls, String host) { this.store = store; this.tls = tls; this.host = host; }
    }

    private static final AtomicInteger IDS = new AtomicInteger();

    protected final Context ctx;
    protected Socket sock;
    protected InputStream in;
    protected OutputStream out;
    protected boolean secure;
    public final String id;
    public final String proto;
    public final String peer;

    protected Session(Context ctx, Socket s, String proto, boolean implicitTls) throws IOException {
        this.ctx = ctx;
        this.proto = proto;
        this.sock = s;
        this.secure = implicitTls;
        this.id = proto + "#" + IDS.incrementAndGet();
        this.peer = s.getInetAddress().getHostAddress() + ":" + s.getPort();
        s.setSoTimeout(10 * 60_000);
        in = new BufferedInputStream(s.getInputStream());
        out = s.getOutputStream();
    }

    @Override
    public final void run() {
        Hub.I.log("[" + id + "] connection from " + peer + (secure ? " (TLS)" : ""));
        try { session(); }
        catch (IOException e) { /* closed */ }
        finally {
            cleanup();
            try { sock.close(); } catch (IOException ignored) { }
            Hub.I.log("[" + id + "] closed");
        }
    }

    protected abstract void session() throws IOException;
    protected void cleanup() { }

    // ------------------------------------------------------------------ I/O

    /** One line without CRLF, or null at end of stream. */
    protected String readLine() throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) >= 0) {
            if (c == '\n') break;
            b.write(c);
            if (b.size() > 64 * 1024) throw new IOException("line too long");
        }
        if (c < 0 && b.size() == 0) return null;
        byte[] a = b.toByteArray();
        int n = a.length > 0 && a[a.length - 1] == '\r' ? a.length - 1 : a.length;
        return new String(a, 0, n, StandardCharsets.UTF_8);
    }

    protected byte[] readBytes(int n) throws IOException {
        byte[] b = new byte[n];
        int off = 0;
        while (off < n) { int r = in.read(b, off, n - off); if (r < 0) throw new IOException("eof"); off += r; }
        return b;
    }

    protected synchronized void send(String line, String note) throws IOException {
        out.write((line + "\r\n").getBytes(StandardCharsets.UTF_8));
        out.flush();
        Hub.I.line(new Hub.Line(id, proto, false, line, note));
    }

    /** Send bulk bytes (a message body); the transcript records only a summary. */
    protected synchronized void sendBytes(byte[] data, String summary) throws IOException {
        out.write(data);
        out.flush();
        Hub.I.line(new Hub.Line(id, proto, false, summary, "message content (" + data.length + " bytes)"));
    }

    protected void logClient(String line, String note) {
        Hub.I.line(new Hub.Line(id, proto, true, line, note));
    }

    /** STARTTLS / STLS: wrap the existing socket in TLS (server side). */
    protected void upgradeTls() throws IOException {
        SSLSocket s = (SSLSocket) ctx.tls.createSocket(sock, sock.getInetAddress().getHostAddress(), sock.getPort(), true);
        s.setUseClientMode(false);
        s.startHandshake();
        sock = s;
        in = new BufferedInputStream(s.getInputStream());
        out = s.getOutputStream();
        secure = true;
        Hub.I.log("[" + id + "] TLS established (" + s.getSession().getProtocol() + ", " + s.getSession().getCipherSuite() + ")");
        Hub.I.line(new Hub.Line(id, proto, false, "··· TLS handshake ···", "from here on everything is encrypted on the wire (" + s.getSession().getProtocol() + ")"));
    }

    // ------------------------------------------------------------------ listener

    /** Start a listener: one thread per connection. */
    public static ServerSocket listen(int port, ServerSocketFactory f, String name, Function<Socket, Session> make) throws IOException {
        ServerSocket ss = f.createServerSocket(port);
        Thread t = new Thread(() -> {
            while (!ss.isClosed()) {
                try {
                    Socket s = ss.accept();
                    Session sess = make.apply(s);
                    if (sess == null) { s.close(); continue; }
                    Thread w = new Thread(sess, sess.id);
                    w.setDaemon(true);
                    w.start();
                } catch (IOException e) {
                    if (!ss.isClosed()) Hub.I.log("[" + name + "] accept: " + e.getMessage());
                }
            }
        }, name);
        t.setDaemon(true);
        t.start();
        Hub.I.log("[SERVER] " + name + " listening on TCP " + port);
        return ss;
    }
}

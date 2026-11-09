package mail.client;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import mail.core.Hub;

/**
 * Base of our SMTP / POP3 / IMAP clients: a TCP (or TLS) connection exchanging CRLF lines.
 *
 * Security modes, as used by real providers:
 *   NONE      plain TCP (our lab ports 2525 / 1110 / 1143)
 *   STARTTLS  plain connect, then upgrade (SMTP submission 587, or STLS / STARTTLS)
 *   IMPLICIT  TLS from the first byte (SMTPS 465, POP3S 995, IMAPS 993)
 *
 * For localhost we trust exactly our own certificate; for anything else the JDK's normal CA
 * store, so the same client really works against Gmail, Outlook, etc. (with an app password).
 */
public abstract class LineClient implements Closeable {

    public enum Tls { NONE, STARTTLS, IMPLICIT }

    private static final AtomicInteger IDS = new AtomicInteger();
    public static volatile File localTrustStore;          // our self-signed certificate (set by Main)

    protected Socket sock;
    protected InputStream in;
    protected OutputStream out;
    protected final String host;
    protected final String id;
    protected final String proto;
    public boolean maskSecrets;                           // true when talking to a real provider

    protected LineClient(String proto, String host, int port, Tls tls) throws IOException {
        this.proto = proto;
        this.host = host;
        this.id = "client:" + proto + "#" + IDS.incrementAndGet();
        Socket s = new Socket();
        s.connect(new InetSocketAddress(host, port), 8000);
        s.setSoTimeout(20000);
        sock = s;
        if (tls == Tls.IMPLICIT) wrapTls(); else { in = new BufferedInputStream(s.getInputStream()); out = s.getOutputStream(); }
        maskSecrets = !isLocal(host);
    }

    static boolean isLocal(String h) { return h.equals("localhost") || h.equals("127.0.0.1") || h.equals("::1"); }

    protected void wrapTls() throws IOException {
        SSLSocket s = (SSLSocket) factory().createSocket(sock, host, sock.getPort(), true);
        s.setUseClientMode(true);
        s.startHandshake();
        sock = s;
        in = new BufferedInputStream(s.getInputStream());
        out = s.getOutputStream();
        Hub.I.line(new Hub.Line(id, proto, true, "··· TLS handshake ···", "client verified the server certificate; " + s.getSession().getProtocol() + " " + s.getSession().getCipherSuite()));
    }

    private SSLSocketFactory factory() throws IOException {
        if (!isLocal(host) || localTrustStore == null) return (SSLSocketFactory) SSLSocketFactory.getDefault();
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (FileInputStream f = new FileInputStream(localTrustStore)) { ks.load(f, "changeit".toCharArray()); }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            SSLContext c = SSLContext.getInstance("TLS");
            c.init(null, tmf.getTrustManagers(), null);
            return c.getSocketFactory();
        } catch (Exception e) { throw new IOException("TLS trust setup: " + e.getMessage(), e); }
    }

    protected String readLine() throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) >= 0) { if (c == '\n') break; b.write(c); }
        if (c < 0 && b.size() == 0) throw new IOException("connection closed by server");
        byte[] a = b.toByteArray();
        int n = a.length > 0 && a[a.length - 1] == '\r' ? a.length - 1 : a.length;
        String l = new String(a, 0, n, StandardCharsets.UTF_8);
        Hub.I.line(new Hub.Line(id, proto, false, l, ""));
        return l;
    }

    protected byte[] readBytes(int n) throws IOException {
        byte[] b = new byte[n];
        int off = 0;
        while (off < n) { int r = in.read(b, off, n - off); if (r < 0) throw new IOException("eof"); off += r; }
        return b;
    }

    protected void writeLine(String l, String shown) throws IOException {
        out.write((l + "\r\n").getBytes(StandardCharsets.UTF_8));
        out.flush();
        Hub.I.line(new Hub.Line(id, proto, true, shown == null ? l : shown, ""));
    }

    protected void writeRaw(byte[] data, String summary) throws IOException {
        out.write(data);
        out.flush();
        Hub.I.line(new Hub.Line(id, proto, true, summary, data.length + " bytes"));
    }

    protected String secret(String s) { return maskSecrets ? "********" : s; }

    @Override
    public void close() { try { sock.close(); } catch (IOException ignored) { } }

    /** A protocol-level failure (the server said no). */
    public static final class ProtocolException extends IOException {
        public ProtocolException(String m) { super(m); }
    }
}

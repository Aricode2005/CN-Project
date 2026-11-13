package telnet.tap;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import telnet.core.Hub;
import telnet.core.Json;
import telnet.protocol.Telnet;
import telnet.protocol.TelnetCodec;

/**
 * A man-in-the-middle TCP relay ("wire tap") placed between client and server:
 *
 *     client --> tap:listenPort --> server:targetPort
 *
 * It forwards every byte unchanged, and records each chunk for the dashboard with the
 * Telnet commands decoded. For plaintext Telnet it reconstructs what the user typed at
 * the "Username:" and "Password:" prompts - showing exactly what an attacker on the path
 * sees. For TLS (telnets) it can only see record headers: the content is encrypted.
 */
public final class WireTap {

    private static final AtomicInteger CONN = new AtomicInteger();
    private final int listenPort, targetPort;
    private final boolean tls;
    private ServerSocket ss;

    public WireTap(int listenPort, int targetPort, boolean tls) {
        this.listenPort = listenPort; this.targetPort = targetPort; this.tls = tls;
    }

    public void start() throws IOException {
        ss = new ServerSocket(listenPort);
        Thread t = new Thread(() -> {
            while (!ss.isClosed()) {
                try {
                    Socket c = ss.accept();
                    Socket s = new Socket("127.0.0.1", targetPort);
                    c.setTcpNoDelay(true); s.setTcpNoDelay(true);
                    int id = CONN.incrementAndGet();
                    Hub.I.tap(new Hub.TapConn(id, c.getInetAddress().getHostAddress(), s.getLocalPort(), tls));
                    Hub.I.log("[TAP] conn #" + id + " " + c.getRemoteSocketAddress() + " -> :" + listenPort + " -> server :" + targetPort + (tls ? " (TLS: opaque)" : " (plaintext)"));
                    Sniffer sn = new Sniffer(id, tls);
                    pump(c, s, id, true, sn);
                    pump(s, c, id, false, sn);
                } catch (IOException e) {
                    if (!ss.isClosed()) Hub.I.log("[TAP] " + e.getMessage());
                }
            }
        }, "tap-" + listenPort);
        t.setDaemon(true);
        t.start();
        Hub.I.log("[TAP] wire tap on TCP " + listenPort + " -> " + targetPort + (tls ? " (telnets/TLS)" : " (telnet)"));
    }

    public void stop() { try { ss.close(); } catch (IOException ignored) { } }

    private void pump(Socket a, Socket b, int id, boolean c2s, Sniffer sn) {
        Thread t = new Thread(() -> {
            byte[] buf = new byte[8192];
            try {
                InputStream in = a.getInputStream();
                OutputStream out = b.getOutputStream();
                int n;
                while ((n = in.read(buf)) > 0) {
                    out.write(buf, 0, n);
                    out.flush();
                    sn.chunk(c2s, buf, n);
                }
            } catch (IOException ignored) {
            } finally {
                try { a.close(); } catch (IOException ignored) { }
                try { b.close(); } catch (IOException ignored) { }
            }
        }, "tap-pump");
        t.setDaemon(true);
        t.start();
    }

    /**
     * Per-connection analyser: one decoder per direction + the credential state machine.
     * Public so that any relay on the path (the HA load balancer too) can show what it sees.
     */
    public static final class Sniffer {
        final int conn; final boolean tls;
        final TelnetCodec[] dec = new TelnetCodec[2];
        final List<String>[] tokens;
        final StringBuilder[] text = {new StringBuilder(), new StringBuilder()};
        final byte[][] tlsBuf = {new byte[0], new byte[0]};
        // credential sniffing
        String expecting;               // "user" / "pass" / null
        final StringBuilder typed = new StringBuilder();
        String sniffedUser;
        final StringBuilder serverTail = new StringBuilder();

        @SuppressWarnings("unchecked")
        public Sniffer(int conn, boolean tls) {
            this.conn = conn; this.tls = tls;
            tokens = new List[]{new ArrayList<String>(), new ArrayList<String>()};
            for (int d = 0; d < 2; d++) {
                final int dir = d;
                dec[d] = new TelnetCodec(new TelnetCodec.Listener() {
                    public void onData(int b) { text[dir].append((char) b); if (dir == 0) typedByte(b); else serverByte(b); }
                    public void onCommand(int c) { flush(dir); tokens[dir].add(tok("iac", "IAC " + Telnet.cmdName(c), new byte[]{(byte) 255, (byte) c})); }
                    public void onNegotiation(int v, int o) { flush(dir); tokens[dir].add(tok("iac", Telnet.describeNegotiation(v, o), Telnet.negotiation(v, o))); }
                    public void onSubnegotiation(int o, byte[] p) {
                        flush(dir);
                        String d2 = "SB " + Telnet.optName(o);
                        if (o == Telnet.OPT_NAWS && p.length >= 4) d2 += " " + (((p[0] & 255) << 8) | (p[1] & 255)) + "x" + (((p[2] & 255) << 8) | (p[3] & 255));
                        else if (o == Telnet.OPT_TTYPE && p.length > 0) d2 += p[0] == 1 ? " SEND" : " IS \"" + new String(p, 1, p.length - 1, StandardCharsets.US_ASCII) + "\"";
                        tokens[dir].add(tok("sb", d2, Telnet.subnegotiation(o, p)));
                    }
                });
            }
        }

        public synchronized void chunk(boolean c2s, byte[] b, int n) {
            int d = c2s ? 0 : 1;
            tokens[d].clear();
            if (tls) tlsRecords(d, b, n);
            else { dec[d].feed(b, 0, n); flush(d); }
            List<String> t = new ArrayList<>(tokens[d]);
            if (t.isEmpty()) t.add(tok("data", "", new byte[0]));
            Hub.I.wire(new Hub.WireFrame(conn, c2s, n, Json.arr(t), tls));
        }

        private void flush(int d) {
            if (text[d].length() == 0) return;
            String s = text[d].toString();
            text[d].setLength(0);
            String kind = "data";
            if (d == 0 && "pass".equals(expectingAt)) kind = "secret";
            tokens[d].add(tok(kind, s, s.getBytes(StandardCharsets.ISO_8859_1)));
        }

        private String expectingAt;   // credential state when the current client data began

        private void serverByte(int b) {
            serverTail.append((char) b);
            if (serverTail.length() > 40) serverTail.delete(0, serverTail.length() - 40);
            String t = serverTail.toString();
            if (t.endsWith("Username: ")) { expecting = "user"; typed.setLength(0); }
            else if (t.endsWith("Password: ")) { expecting = "pass"; typed.setLength(0); }
        }

        private void typedByte(int b) {
            expectingAt = expecting;
            if (expecting == null) return;
            if (b == '\r' || b == '\n') {
                if (typed.length() == 0) return;
                String v = typed.toString();
                if ("user".equals(expecting)) { sniffedUser = v; Hub.I.log("[TAP] conn #" + conn + " sniffed username: " + v); }
                else {
                    Hub.I.captures.add(new Hub.Capture(conn, sniffedUser == null ? "?" : sniffedUser, v));
                    Hub.I.log("[TAP] conn #" + conn + " SNIFFED PASSWORD IN PLAINTEXT: " + sniffedUser + " / " + v);
                }
                typed.setLength(0);
                expecting = null;
            } else if (b == 8 || b == 127) {
                if (typed.length() > 0) typed.setLength(typed.length() - 1);
            } else if (b >= 32 && b < 127) {
                typed.append((char) b);
            }
        }

        /** TLS: split into records (type 1 byte, version 2, length 2) - the payload is ciphertext. */
        private void tlsRecords(int d, byte[] b, int n) {
            byte[] all = new byte[tlsBuf[d].length + n];
            System.arraycopy(tlsBuf[d], 0, all, 0, tlsBuf[d].length);
            System.arraycopy(b, 0, all, tlsBuf[d].length, n);
            int i = 0;
            while (all.length - i >= 5) {
                int type = all[i] & 255, ver = ((all[i + 1] & 255) << 8) | (all[i + 2] & 255), len = ((all[i + 3] & 255) << 8) | (all[i + 4] & 255);
                if (all.length - i < 5 + len) break;
                String name = type == 20 ? "ChangeCipherSpec" : type == 21 ? "Alert" : type == 22 ? "Handshake" : type == 23 ? "Application Data" : "type " + type;
                byte[] sample = new byte[Math.min(len, 24)];
                System.arraycopy(all, i + 5, sample, 0, sample.length);
                tokens[d].add(Json.obj("k", "tls", "txt", "TLS " + name + " (v" + String.format("%04X", ver) + ", " + len + " bytes encrypted)",
                        "hex", String.format("%02X %02X %02X %02X %02X | ", type, all[i + 1] & 255, all[i + 2] & 255, all[i + 3] & 255, all[i + 4] & 255)
                                + Telnet.hex(sample) + (len > sample.length ? " ..." : "")));
                i += 5 + len;
            }
            tlsBuf[d] = java.util.Arrays.copyOfRange(all, i, all.length);
        }

        private static String tok(String k, String txt, byte[] bytes) {
            String hex = bytes.length > 48 ? Telnet.hex(bytes, 0, 48) + " ..." : Telnet.hex(bytes);
            return Json.obj("k", k, "txt", txt, "hex", hex);
        }
    }
}

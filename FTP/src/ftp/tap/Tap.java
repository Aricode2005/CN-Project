package ftp.tap;

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
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import ftp.core.Hub;
import ftp.core.Json;

/**
 * A wire tap on the CONTROL connection: clients connect to 2122, the tap forwards to the server on 2121
 * and records every byte, the way a sniffer on the path would. Plain FTP shows USER and PASS in clear text;
 * after AUTH TLS the tap sees only encrypted TLS records.
 */
public final class Tap {

    public static final int PORT = 2122;
    public static final class Frame {
        public final int conn; public final String dir, text, hex; public final boolean tls, secret; public final int len;
        Frame(int conn, String dir, String text, String hex, boolean tls, boolean secret, int len) { this.conn = conn; this.dir = dir; this.text = text; this.hex = hex; this.tls = tls; this.secret = secret; this.len = len; }
        public String json() { return Json.obj("conn", conn, "dir", dir, "text", text, "hex", hex, "tls", tls, "secret", secret, "len", len); }
    }
    private final List<Frame> frames = new CopyOnWriteArrayList<>();
    private final AtomicInteger ids = new AtomicInteger();
    private final int target;
    private ServerSocket ss;

    public Tap(int target) { this.target = target; }

    public Tap start() throws IOException {
        ss = new ServerSocket(); ss.setReuseAddress(true); ss.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), PORT));
        Thread t = new Thread(() -> {
            while (!ss.isClosed()) {
                try {
                    Socket c = ss.accept();
                    Socket s = new Socket("127.0.0.1", target);
                    int id = ids.incrementAndGet();
                    boolean[] enc = {false};
                    pump(id, c, s, "C→S", enc); pump(id, s, c, "S→C", enc);
                } catch (IOException e) { if (!ss.isClosed()) Hub.I.log("[TAP] " + e.getMessage()); }
            }
        }, "ftp-tap"); t.setDaemon(true); t.start();
        Hub.I.log("[TAP] wire tap on the control connection: 127.0.0.1:" + PORT + " → 127.0.0.1:" + target);
        return this;
    }

    public int latest() { return ids.get(); }

    private void pump(int id, Socket from, Socket to, String dir, boolean[] enc) {
        Thread t = new Thread(() -> {
            try (InputStream i = from.getInputStream(); OutputStream o = to.getOutputStream()) {
                byte[] b = new byte[8192]; int k;
                while ((k = i.read(b)) > 0) {
                    record(id, dir, java.util.Arrays.copyOf(b, k), enc);      // record first: a 234 reply must switch the tap to "encrypted" before the TLS hello arrives
                    o.write(b, 0, k); o.flush();
                }
            } catch (IOException ignored) {
            } finally { try { from.close(); to.close(); } catch (IOException ignored) { } }
        }, "tap-" + dir); t.setDaemon(true); t.start();
    }

    private synchronized void record(int id, String dir, byte[] b, boolean[] enc) {
        StringBuilder hx = new StringBuilder();
        for (int i = 0; i < Math.min(b.length, 48); i++) hx.append(String.format("%02x ", b[i]));
        if (b.length > 48) hx.append("…");
        if (enc[0]) {
            String kind = b.length > 0 ? (b[0] == 0x16 ? "handshake" : b[0] == 0x17 ? "application data" : b[0] == 0x14 ? "change cipher spec" : b[0] == 0x15 ? "alert" : "?") : "?";
            frames.add(new Frame(id, dir, "TLS record: " + kind + ", " + b.length + " bytes (unreadable)", hx.toString().trim(), true, false, b.length));
        } else {
            String s = new String(b, StandardCharsets.UTF_8).replace("\r\n", "↵\n").trim();
            for (String line : s.split("\n")) {
                if (line.isEmpty()) continue;
                boolean secret = line.toUpperCase().startsWith("PASS ");
                frames.add(new Frame(id, dir, line, hx.toString().trim(), false, secret, b.length));
                if (secret) Hub.I.event("SNIFFED", "the tap read a password off the wire: " + line.replace("↵", ""));
                if (dir.equals("S→C") && line.startsWith("234")) enc[0] = true;       // AUTH TLS accepted: from now on it is encrypted
            }
        }
        while (frames.size() > 2000) frames.remove(0);
    }

    public String json(int conn) {
        List<String> l = new ArrayList<>();
        for (Frame f : frames) if (conn <= 0 || f.conn == conn) l.add(f.json());
        return "[" + String.join(",", l) + "]";
    }

    public void stop() { try { ss.close(); } catch (IOException ignored) { } }
}

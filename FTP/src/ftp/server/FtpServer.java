package ftp.server;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.imageio.ImageIO;
import ftp.core.Hub;
import ftp.core.Json;

/** The FTP server: users, the file tree on disk, the passive port range, listeners on the control port(s). */
public final class FtpServer {

    public static final int PASV_FROM = 50000, PASV_TO = 50100;
    public final File root;
    private final Map<String, String> users = new ConcurrentHashMap<>();       // user -> salted SHA-256
    public volatile boolean allowAnonymous = true, slowLink = true;
    final List<Session> sessions = new CopyOnWriteArrayList<>();
    private final List<String> board = new CopyOnWriteArrayList<>();
    private final Map<String, String> progress = new ConcurrentHashMap<>();
    private final List<ServerSocket> listeners = new ArrayList<>();
    public final List<Integer> ports = new ArrayList<>();
    private int nextPasv = PASV_FROM;

    public FtpServer(File root) throws IOException {
        this.root = root;
        addUser("alice", "alice123"); addUser("bob", "bob123"); addUser("subham", "ju2026");
        seed();
    }

    public void addUser(String u, String p) { users.put(u, hash(u, p)); new File(root, "home/" + u).mkdirs(); }
    boolean check(String u, String p) { String h = users.get(u); return h != null && h.equals(hash(u, p)); }
    private static String hash(String u, String p) {
        try { byte[] d = MessageDigest.getInstance("SHA-256").digest(("ju-ftp:" + u + ":" + p).getBytes(StandardCharsets.UTF_8)); StringBuilder s = new StringBuilder(); for (byte b : d) s.append(String.format("%02x", b)); return s.toString(); }
        catch (Exception e) { throw new RuntimeException(e); }
    }

    /** The demo files: text (for ASCII mode), an image (to show what ASCII mode does to binary data), a 3 MB file (for REST). */
    private void seed() throws IOException {
        File pub = new File(root, "pub"); pub.mkdirs();
        File readme = new File(pub, "readme.txt");
        if (!readme.exists()) Files.writeString(readme.toPath(), "Welcome to the JU FTP lab (RFC 959).\nLines in this file end with LF only (Unix).\nDownload it in ASCII mode and every LF arrives as CR LF.\n");
        File rfc = new File(pub, "rfc959-notes.txt");
        if (!rfc.exists()) Files.writeString(rfc.toPath(), "RFC 959 (October 1985), J. Postel and J. Reynolds.\nTwo connections: control (port 21) and data (port 20 in active mode).\nReplies: 3-digit codes. 1yz preliminary, 2yz done, 3yz more needed, 4yz transient error, 5yz permanent error.\n");
        File logo = new File(pub, "logo.png");
        if (!logo.exists()) ImageIO.write(logo(), "png", logo);
        File big = new File(pub, "big.bin");
        if (!big.exists() || big.length() != 3 * 1024 * 1024) { byte[] b = new byte[3 * 1024 * 1024]; new Random(959).nextBytes(b); Files.write(big.toPath(), b); }
        File docs = new File(pub, "docs"); docs.mkdirs();
        File d1 = new File(docs, "ports.txt");
        if (!d1.exists()) Files.writeString(d1.toPath(), "control: 21 (lab 2121)\ndata (active): 20 (lab 2120)\npassive: a port chosen by the server (lab 50000-50100)\n");
        File an = new File(root, "home/alice/notes.txt");
        if (!an.exists()) { an.getParentFile().mkdirs(); Files.writeString(an.toPath(), "alice's notes\n- revise FTP active vs passive\n- REST resumes a broken download\n"); }
    }

    private static BufferedImage logo() {
        BufferedImage img = new BufferedImage(360, 200, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setColor(new Color(0xE9E6DF)); g.fillRect(0, 0, 360, 200);
        for (int i = -200; i < 400; i += 28) { g.setColor(new Color(0xFF6A13)); g.fillPolygon(new int[]{i, i + 14, i + 214, i + 200}, new int[]{0, 0, 200, 200}, 4); }
        g.setColor(new Color(0x16171A)); g.fillRect(24, 40, 312, 120);
        g.setColor(new Color(0xFF6A13)); g.setStroke(new BasicStroke(4)); g.drawRect(24, 40, 312, 120);
        g.setColor(Color.WHITE); g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 58)); g.drawString("FTP", 64, 118);
        g.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 16)); g.drawString("RFC 959 · port 21", 190, 92); g.drawString("binary: TYPE I", 190, 116); g.drawString("JU CSE lab", 190, 140);
        g.dispose();
        return img;
    }

    public FtpServer listen(int port) throws IOException {
        ServerSocket ss = new ServerSocket(); ss.setReuseAddress(true); ss.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port));
        listeners.add(ss); ports.add(port);
        Thread t = new Thread(() -> {
            while (!ss.isClosed()) {
                try { Socket s = ss.accept(); Thread w = new Thread(new Session(this, s), "ftp-session"); w.setDaemon(true); w.start(); }
                catch (IOException e) { if (!ss.isClosed()) Hub.I.log("[FTP] accept: " + e.getMessage()); }
            }
        }, "ftp-listen-" + port);
        t.setDaemon(true); t.start();
        Hub.I.log("[FTP] control port 127.0.0.1:" + port + " (active data from port " + (port - 1) + ", passive " + PASV_FROM + "-" + PASV_TO + ")");
        return this;
    }

    synchronized ServerSocket pasvSocket(InetAddress bind) throws IOException {
        for (int i = 0; i <= PASV_TO - PASV_FROM; i++) {
            int p = nextPasv; nextPasv = nextPasv >= PASV_TO ? PASV_FROM : nextPasv + 1;
            try { ServerSocket s = new ServerSocket(); s.bind(new InetSocketAddress(bind, p), 1); return s; } catch (IOException ignored) { }
        }
        throw new IOException("no free passive port");
    }

    void board(String user, String cmd, String path, char mode, long bytes, String status, double ms) {
        board.add(Json.obj("t", System.currentTimeMillis(), "user", user, "cmd", cmd, "path", path, "mode", mode == 'I' ? "BIN" : "ASC", "bytes", bytes, "status", status, "ms", Math.round(ms)));
        while (board.size() > 40) board.remove(0);
    }
    void progress(String sid, String file, long done, long total) { progress.put(sid, Json.obj("sid", sid, "file", file, "done", done, "total", total, "t", System.currentTimeMillis())); }

    public String json() {
        List<String> s = new ArrayList<>(); for (Session x : sessions) s.add(x.json());
        List<String> pr = new ArrayList<>(); long now = System.currentTimeMillis();
        progress.entrySet().removeIf(e -> !e.getValue().contains("\"t\":") || now - Long.parseLong(e.getValue().replaceAll(".*\"t\":(\\d+).*", "$1")) > 3000);
        pr.addAll(progress.values());
        return Json.obj("ports", Json.raw(ports.toString()), "anonymous", allowAnonymous, "slow", slowLink, "sessions", Json.raw("[" + String.join(",", s) + "]"),
                "board", Json.raw("[" + String.join(",", board) + "]"), "progress", Json.raw("[" + String.join(",", pr) + "]"));
    }

    public void stop() { for (ServerSocket s : listeners) try { s.close(); } catch (IOException ignored) { } }
}

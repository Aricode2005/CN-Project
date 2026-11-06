package telnet.server;

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ServerSocketFactory;
import telnet.core.Hub;

/**
 * The router's virtual terminal lines ("line vty 0 4"): at most 5 concurrent remote
 * sessions, shared by the plaintext listener (telnet) and the TLS listener (telnets).
 */
public final class VtyPool {

    public static final int LINES = 5;

    public final DeviceConfig cfg;
    public final LoginGuard guard;
    public final File dhcpDataDir;
    public final ScheduledExecutorService timer = Executors.newScheduledThreadPool(2, r -> {
        Thread t = new Thread(r, "vty-timer"); t.setDaemon(true); return t;
    });
    private final TelnetSession[] lines = new TelnetSession[LINES];
    private final AtomicInteger ids = new AtomicInteger();
    private final List<ServerSocket> listeners = new ArrayList<>();
    public volatile int plainPort, tlsPort;
    public final long bootTime = System.currentTimeMillis();
    public final AtomicInteger refusedBusy = new AtomicInteger();

    public VtyPool(DeviceConfig cfg, File dhcpDataDir) {
        this.cfg = cfg;
        this.guard = new LoginGuard(cfg);
        this.dhcpDataDir = dhcpDataDir;
        // Every 5 s measure each session's round-trip time with RFC 860 TIMING-MARK
        timer.scheduleAtFixedRate(() -> {
            for (TelnetSession s : sessions()) s.measureRtt(false);
        }, 3, 5, java.util.concurrent.TimeUnit.SECONDS);
    }

    /** Start a listener. factory = plain sockets or SSL sockets. */
    public void listen(int port, ServerSocketFactory factory, String transport) throws IOException {
        ServerSocket ss = factory.createServerSocket(port);
        listeners.add(ss);
        if ("telnets".equals(transport)) tlsPort = port; else plainPort = port;
        Thread t = new Thread(() -> acceptLoop(ss, transport), "listener-" + transport);
        t.setDaemon(true);
        t.start();
        Hub.I.log("[SERVER] " + transport + " listening on TCP " + port + " (line vty 0 " + (LINES - 1) + ")");
    }

    private void acceptLoop(ServerSocket ss, String transport) {
        while (!ss.isClosed()) {
            try {
                Socket s = ss.accept();
                int line = claim();
                if (line < 0) {
                    refusedBusy.incrementAndGet();
                    Hub.I.log("[SERVER] refused " + s.getRemoteSocketAddress() + ": all " + LINES + " VTY lines busy");
                    try {
                        s.getOutputStream().write("\r\n% All VTY lines are busy (line vty 0 4). Try again later.\r\n".getBytes("US-ASCII"));
                        s.getOutputStream().flush();
                    } catch (IOException ignored) { }
                    s.close();
                    continue;
                }
                TelnetSession sess = new TelnetSession(this, s, line, ids.incrementAndGet(), transport);
                synchronized (lines) { lines[line] = sess; }
                Thread t = new Thread(sess, "vty" + line);
                t.setDaemon(true);
                t.start();
            } catch (IOException e) {
                if (!ss.isClosed()) Hub.I.log("[SERVER] accept error: " + e.getMessage());
            }
        }
    }

    private int claim() {
        synchronized (lines) {
            for (int i = 0; i < LINES; i++) if (lines[i] == null) { lines[i] = TelnetSession.PLACEHOLDER; return i; }
            return -1;
        }
    }

    void release(TelnetSession s) {
        synchronized (lines) { if (lines[s.line] == s) lines[s.line] = null; }
    }

    public List<TelnetSession> sessions() {
        List<TelnetSession> l = new ArrayList<>();
        synchronized (lines) { for (TelnetSession s : lines) if (s != null && s != TelnetSession.PLACEHOLDER) l.add(s); }
        return l;
    }

    public TelnetSession byLine(int line) {
        synchronized (lines) {
            if (line < 0 || line >= LINES) return null;
            TelnetSession s = lines[line];
            return s == TelnetSession.PLACEHOLDER ? null : s;
        }
    }

    public TelnetSession byId(int id) {
        for (TelnetSession s : sessions()) if (s.id == id) return s;
        return null;
    }

    public void shutdown() {
        for (ServerSocket s : listeners) try { s.close(); } catch (IOException ignored) { }
        for (TelnetSession s : sessions()) s.close("shutdown");
        timer.shutdownNow();
    }
}

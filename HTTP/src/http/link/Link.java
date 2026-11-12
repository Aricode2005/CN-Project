package http.link;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicLong;
import http.core.Hub;

/**
 * A WAN emulator (like Linux netem) between the client side and the origin server.
 * Loopback has ~0 ms delay, so without this every HTTP strategy would look equally fast.
 *
 *   - TCP handshake: data from the client is held until one RTT after the connection opened
 *     (the SYN / SYN-ACK round trip the client would have waited for);
 *   - propagation: every chunk of bytes is delayed by RTT/2 in each direction;
 *   - transmission: bytes are serialised at the configured bandwidth (one queue per direction).
 */
public final class Link {

    public volatile int rttMs = 100;
    public volatile int kbps = 4000;                        // 4 Mbit/s
    public final AtomicLong connections = new AtomicLong(), bytesUp = new AtomicLong(), bytesDown = new AtomicLong();
    private final int upstreamPort;
    private ServerSocket ss;
    private volatile boolean running = true;

    public Link(int upstreamPort) { this.upstreamPort = upstreamPort; }

    public Link listen(int port) throws IOException {
        ss = new ServerSocket();
        ss.setReuseAddress(true);
        ss.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port), 64);
        Thread t = new Thread(() -> {
            while (running) {
                try { Socket c = ss.accept(); Thread w = new Thread(() -> carry(c), "link-conn"); w.setDaemon(true); w.start(); }
                catch (IOException e) { if (running) Hub.I.log("[LINK] " + e.getMessage()); }
            }
        }, "link-accept");
        t.setDaemon(true); t.start();
        Hub.I.log("[LINK] WAN emulator on 127.0.0.1:" + port + " → origin :" + upstreamPort + " (RTT " + rttMs + " ms, " + kbps + " kbit/s)");
        return this;
    }

    public void stop() { running = false; try { if (ss != null) ss.close(); } catch (IOException ignored) { } }

    private void carry(Socket client) {
        long opened = System.nanoTime();
        int rtt = rttMs, bw = kbps;
        connections.incrementAndGet();
        try (Socket c = client; Socket o = new Socket(InetAddress.getByName("127.0.0.1"), upstreamPort)) {
            c.setTcpNoDelay(true); o.setTcpNoDelay(true);
            long handshakeDone = opened + rtt * 1_000_000L;                  // client's first byte can't leave before the SYN/SYN-ACK round trip
            Thread up = pipe(c.getInputStream(), o.getOutputStream(), rtt, bw, handshakeDone, bytesUp, o);
            Thread down = pipe(o.getInputStream(), c.getOutputStream(), rtt, bw, 0, bytesDown, c);
            up.join(); down.join();
        } catch (Exception e) { /* one side closed */ }
    }

    private static final class Piece { final byte[] b; final int n; final long due; Piece(byte[] b, int n, long due) { this.b = b; this.n = n; this.due = due; } }
    private static final Piece EOF = new Piece(new byte[0], -1, 0);

    /** reader thread timestamps chunks; writer thread releases each one when its due time comes (order preserved). */
    private Thread pipe(InputStream in, OutputStream out, int rtt, int kbps, long notBefore, AtomicLong counter, Socket closeOnEnd) {
        BlockingQueue<Piece> q = new LinkedBlockingQueue<>();
        Thread reader = new Thread(() -> {
            long linkFree = 0;
            byte[] buf = new byte[16 * 1024]; int k;
            try {
                while ((k = in.read(buf)) > 0) {
                    long now = System.nanoTime();
                    long sendStart = Math.max(Math.max(now, notBefore), linkFree);
                    long txNanos = (long) k * 8L * 1_000_000L / Math.max(1, kbps);          // k bytes at kbps kbit/s
                    linkFree = sendStart + txNanos;
                    byte[] copy = java.util.Arrays.copyOf(buf, k);
                    q.put(new Piece(copy, k, linkFree + rtt * 500_000L));                  // + one-way propagation (RTT/2)
                    counter.addAndGet(k);
                }
            } catch (Exception ignored) { }
            try { q.put(EOF); } catch (InterruptedException ignored) { }
        }, "link-read");
        Thread writer = new Thread(() -> {
            try {
                while (true) {
                    Piece p = q.take();
                    if (p == EOF) break;
                    long wait = p.due - System.nanoTime();
                    if (wait > 0) Thread.sleep(wait / 1_000_000L, (int) (wait % 1_000_000L));
                    out.write(p.b, 0, p.n); out.flush();
                }
            } catch (Exception ignored) { }
            try { closeOnEnd.shutdownOutput(); } catch (IOException ignored) { }
        }, "link-write");
        reader.setDaemon(true); writer.setDaemon(true);
        reader.start(); writer.start();
        return writer;
    }
}

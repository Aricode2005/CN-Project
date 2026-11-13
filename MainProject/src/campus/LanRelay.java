package campus;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * The cable between the admin's laptop and the router.
 *
 * The Telnet session is a real TCP connection (laptop → this relay → the Telnet server). Every chunk that passes is
 * also handed to the bus, which sends it as an Ethernet frame across the ARP module's simulated switch. So the same
 * bytes travel twice: for real over TCP, and across the LAN model, where ARP caches (and ARP poisoning) decide
 * which station receives them.
 */
public final class LanRelay {

    private final int listenPort, targetPort; private final boolean tls; private final Bus bus;
    private ServerSocket ss;
    private volatile boolean running = true;

    public LanRelay(int listenPort, int targetPort, boolean tls, Bus bus) { this.listenPort = listenPort; this.targetPort = targetPort; this.tls = tls; this.bus = bus; }

    public LanRelay start() throws IOException {
        ss = new ServerSocket();
        ss.setReuseAddress(true);
        // all interfaces: a second laptop on the same network can be the campus admin's PC (telnet <this PC> 2325)
        ss.bind(new InetSocketAddress(listenPort), 16);
        Thread t = new Thread(() -> {
            while (running) {
                try { Socket c = ss.accept(); Thread w = new Thread(() -> carry(c), "lan-relay-conn"); w.setDaemon(true); w.start(); }
                catch (IOException e) { if (running) bus.ev("BUS", "LAN relay: " + e.getMessage()); }
            }
        }, "lan-relay-" + listenPort);
        t.setDaemon(true); t.start();
        return this;
    }

    public void stop() { running = false; try { ss.close(); } catch (IOException ignored) { } }

    private void carry(Socket client) {
        try (Socket c = client; Socket r = new Socket(InetAddress.getByName("127.0.0.1"), targetPort)) {
            c.setTcpNoDelay(true); r.setTcpNoDelay(true);
            bus.ev("TELNET", "TCP connection " + (bus.adminIp == null ? "client" : bus.adminIp) + " → " + Bus.GATEWAY + ":" + (tls ? "992 (Telnet over TLS)" : "23 (plain Telnet)"));
            Thread down = new Thread(() -> pump(r, c, false), "lan-relay-down"); down.setDaemon(true); down.start();
            pump(c, r, true);
            down.join(1500);
        } catch (Exception e) { /* session ended */ }
    }

    private void pump(Socket from, Socket to, boolean toRouter) {
        byte[] b = new byte[4096]; int k;
        try {
            InputStream in = from.getInputStream(); OutputStream out = to.getOutputStream();
            while ((k = in.read(b)) > 0) {
                try { bus.telnetBytes(toRouter, b, k, tls); } catch (RuntimeException e) { /* the LAN model must never break the real session */ }
                out.write(b, 0, k); out.flush();
            }
        } catch (IOException ignored) { }
        try { to.shutdownOutput(); } catch (IOException ignored) { }
    }
}

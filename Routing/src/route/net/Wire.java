package route.net;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import route.core.Hub;

/**
 * Real sockets between the lab routers. Router i lives on its own loopback address 127.0.0.(20+i):
 *   RIP  : UDP 127.0.0.(20+i):520   (the real RIP port, so Wireshark on the loopback adapter decodes it as RIPv2)
 *   OSPF : UDP 127.0.0.(20+i):8900  (real OSPF is IP protocol 89, which needs raw sockets)
 *   BGP  : TCP 127.0.0.(20+i):179   (the real BGP port), one TCP session per neighbour pair
 * Each simulated round sends the encoded bytes for real and the receiver decodes what actually arrived.
 * If a privileged/real port is busy, an ephemeral port on the same address is used instead.
 */
public final class Wire implements AutoCloseable {

    private final int n;
    private final DatagramSocket[] rip, ospf;
    private final ServerSocket[] bgpListen;
    private final Map<Long, Socket[]> sessions = new HashMap<>();
    public final boolean realRipPort, realBgpPort;
    public long datagrams, tcpMessages, bytes;

    public static InetAddress addr(int node) throws IOException { return InetAddress.getByName("127.0.0." + (20 + node)); }

    public Wire(int nodes, boolean withBgp) throws IOException {
        n = nodes;
        rip = new DatagramSocket[n]; ospf = new DatagramSocket[n]; bgpListen = new ServerSocket[withBgp ? n : 0];
        boolean r520 = true, r179 = true;
        for (int i = 0; i < n; i++) {
            try { rip[i] = new DatagramSocket(new InetSocketAddress(addr(i), 520)); } catch (IOException e) { rip[i] = new DatagramSocket(new InetSocketAddress(addr(i), 0)); r520 = false; }
            ospf[i] = bind(i, 8900);
            rip[i].setSoTimeout(3000); ospf[i].setSoTimeout(3000);
            if (withBgp) {
                ServerSocket s = new ServerSocket(); s.setReuseAddress(true);
                try { s.bind(new InetSocketAddress(addr(i), 179)); } catch (IOException e) { s.close(); s = new ServerSocket(); s.bind(new InetSocketAddress(addr(i), 0)); r179 = false; }
                s.setSoTimeout(3000);
                bgpListen[i] = s;
            }
        }
        realRipPort = r520; realBgpPort = withBgp && r179;
    }

    private DatagramSocket bind(int i, int port) throws IOException {
        try { return new DatagramSocket(new InetSocketAddress(addr(i), port)); } catch (IOException e) { return new DatagramSocket(new InetSocketAddress(addr(i), 0)); }
    }

    public int ripPort(int i) { return rip[i].getLocalPort(); }
    public int bgpPort(int i) { return bgpListen[i].getLocalPort(); }

    /** Send one datagram from router a to router b and return what b actually received. */
    public byte[] udp(int a, int b, byte[] payload, boolean isOspf) throws IOException {
        DatagramSocket from = (isOspf ? ospf : rip)[a], to = (isOspf ? ospf : rip)[b];
        from.send(new DatagramPacket(payload, payload.length, to.getLocalSocketAddress()));
        byte[] buf = new byte[65_535];
        while (true) {
            DatagramPacket p = new DatagramPacket(buf, buf.length);
            to.receive(p);
            if (p.getAddress().equals(from.getLocalAddress()) && p.getPort() == from.getLocalPort()) {
                datagrams++; bytes += p.getLength();
                byte[] got = new byte[p.getLength()]; System.arraycopy(buf, 0, got, 0, got.length);
                return got;
            }
        }
    }

    private static long key(int a, int b) { return ((long) Math.min(a, b) << 32) | Math.max(a, b); }

    /** Opens the TCP session a–b (the lower-numbered router connects to the other's port 179). */
    public void connect(int a, int b) throws IOException {
        int lo = Math.min(a, b), hi = Math.max(a, b);
        Socket c = new Socket();
        c.bind(new InetSocketAddress(addr(lo), 0));
        c.connect(new InetSocketAddress(addr(hi), bgpListen[hi].getLocalPort()), 3000);
        Socket s = bgpListen[hi].accept();
        c.setSoTimeout(3000); s.setSoTimeout(3000); c.setTcpNoDelay(true); s.setTcpNoDelay(true);
        sessions.put(key(a, b), new Socket[] { c, s });       // [0] = lo's end, [1] = hi's end
        Hub.I.log("[BGP] TCP session " + lo + "–" + hi + " established: " + c.getLocalSocketAddress() + " → " + s.getLocalSocketAddress());
    }

    public void disconnect(int a, int b) {
        Socket[] s = sessions.remove(key(a, b));
        if (s != null) for (Socket x : s) try { x.close(); } catch (IOException ignored) { }
    }

    public boolean connected(int a, int b) { return sessions.containsKey(key(a, b)); }

    /** Write a BGP message on a's end of the a–b session; read exactly one message on b's end (length from the header). */
    public byte[] tcp(int a, int b, byte[] msg) throws IOException {
        Socket[] s = sessions.get(key(a, b));
        if (s == null) throw new IOException("no BGP session " + a + "–" + b);
        Socket mine = a < b ? s[0] : s[1], theirs = a < b ? s[1] : s[0];
        OutputStream o = mine.getOutputStream(); o.write(msg); o.flush();
        InputStream in = theirs.getInputStream();
        byte[] head = in.readNBytes(19);
        if (head.length < 19) throw new IOException("BGP session closed");
        int len = ((head[16] & 0xff) << 8) | (head[17] & 0xff);
        byte[] rest = in.readNBytes(len - 19);
        byte[] all = new byte[len]; System.arraycopy(head, 0, all, 0, 19); System.arraycopy(rest, 0, all, 19, rest.length);
        tcpMessages++; bytes += len;
        return all;
    }

    @Override public void close() {
        for (DatagramSocket d : rip) if (d != null) d.close();
        for (DatagramSocket d : ospf) if (d != null) d.close();
        for (Socket[] s : sessions.values()) for (Socket x : s) try { x.close(); } catch (IOException ignored) { }
        sessions.clear();
        for (ServerSocket s : bgpListen) if (s != null) try { s.close(); } catch (IOException ignored) { }
    }
}

package dns.server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import dns.core.Hub;
import dns.wire.Message;

/**
 * A DNS endpoint on one address: UDP (classic 512-byte limit, TC=1 when the answer does not fit)
 * and TCP (2-byte length prefix, RFC 1035 §4.2.2). The handler builds the response message.
 */
public final class Listener {

    public interface Handler { Message handle(Message q, boolean tcp, String peer) throws Exception; }

    public static final int UDP_LIMIT = 512, LAB_PORT = 5300;
    private final ExecutorService pool = Executors.newCachedThreadPool(r -> { Thread t = new Thread(r, "dns-worker"); t.setDaemon(true); return t; });
    public final String ip; public final int port;
    private DatagramSocket udp; private ServerSocket tcp;

    public Listener(String ip, int port) { this.ip = ip; this.port = port; }

    public Listener start(Handler h, String name) throws IOException {
        InetAddress a = InetAddress.getByName(ip);
        udp = new DatagramSocket(new InetSocketAddress(a, port));
        tcp = new ServerSocket(port, 50, a);
        Thread u = new Thread(() -> udpLoop(h), name + "-udp"); u.setDaemon(true); u.start();
        Thread t = new Thread(() -> tcpLoop(h), name + "-tcp"); t.setDaemon(true); t.start();
        return this;
    }

    private void udpLoop(Handler h) {
        byte[] buf = new byte[4096];
        while (!udp.isClosed()) {
            try {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                udp.receive(p);
                byte[] in = java.util.Arrays.copyOf(p.getData(), p.getLength());
                InetAddress from = p.getAddress(); int fromPort = p.getPort();
                pool.execute(() -> {
                    try {
                        Message q = Message.decode(in, in.length);
                        Message r = h.handle(q, false, from.getHostAddress() + ":" + fromPort);
                        if (r == null) return;
                        byte[] out = r.encode();
                        if (out.length > UDP_LIMIT) {          // does not fit in a classic UDP answer: truncate, set TC
                            Message t = q.reply(); t.aa = r.aa; t.ra = r.ra; t.rcode = r.rcode; t.tc = true;
                            out = t.encode();
                        }
                        udp.send(new DatagramPacket(out, out.length, from, fromPort));
                    } catch (Exception e) { Hub.I.log("[DNS] bad UDP packet from " + from.getHostAddress() + ": " + e.getMessage()); }
                });
            } catch (IOException e) { if (!udp.isClosed()) Hub.I.log("[DNS] UDP " + e.getMessage()); }
        }
    }

    private void tcpLoop(Handler h) {
        while (!tcp.isClosed()) {
            try {
                Socket s = tcp.accept();
                pool.execute(() -> {
                    try (Socket c = s; DataInputStream in = new DataInputStream(c.getInputStream()); DataOutputStream out = new DataOutputStream(c.getOutputStream())) {
                        c.setSoTimeout(10000);
                        while (true) {
                            int len = in.readUnsignedShort();
                            byte[] b = new byte[len]; in.readFully(b);
                            Message r = h.handle(Message.decode(b, len), true, c.getInetAddress().getHostAddress() + ":" + c.getPort());
                            if (r == null) return;
                            byte[] o = r.encode();
                            out.writeShort(o.length); out.write(o); out.flush();
                        }
                    } catch (IOException e) { /* client closed */ } catch (Exception e) { Hub.I.log("[DNS] TCP " + e); }
                });
            } catch (IOException e) { if (!tcp.isClosed()) Hub.I.log("[DNS] TCP " + e.getMessage()); }
        }
    }

    public void stop() { try { udp.close(); tcp.close(); } catch (Exception ignored) { } }
}

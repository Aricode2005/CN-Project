package dns.client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import dns.core.Hub;
import dns.core.Json;
import dns.wire.Message;
import dns.wire.Message.Field;
import dns.wire.Message.RR;

/**
 * Our "dig": sends one query to any DNS server (ours, 8.8.8.8, a root server…) over UDP and
 * falls back to TCP when the answer comes back truncated (TC=1). Returns the decoded message,
 * the raw bytes and every field's byte span for the packet dissector.
 */
public final class DnsClient {

    private static final SecureRandom RND = new SecureRandom();
    private static final AtomicInteger IDS = new AtomicInteger();

    public static final class Result {
        public Message msg; public byte[] raw, query; public List<Field> fields = new ArrayList<>(), qfields = new ArrayList<>();
        public double ms; public boolean tcp, truncatedFirst; public String server;
        public String json() {
            List<String> f = new ArrayList<>(); for (Field x : fields) f.add(x.json());
            List<String> qf = new ArrayList<>(); for (Field x : qfields) qf.add(x.json());
            return Json.obj("server", server, "ms", Math.round(ms * 100) / 100.0, "tcp", tcp, "truncatedFirst", truncatedFirst, "size", raw.length, "qsize", query.length,
                    "id", msg.id, "rcode", Message.rcodeName(msg.rcode), "flags", Json.raw(Json.obj("qr", msg.qr, "opcode", msg.opcode, "aa", msg.aa, "tc", msg.tc, "rd", msg.rd, "ra", msg.ra, "rcode", msg.rcode)),
                    "answer", Json.raw(rrs(msg.an)), "authority", Json.raw(rrs(msg.ns)), "additional", Json.raw(rrs(msg.ar)),
                    "hex", hex(raw), "fields", Json.raw("[" + String.join(",", f) + "]"), "qhex", hex(query), "qfields", Json.raw("[" + String.join(",", qf) + "]"));
        }
        static String rrs(List<RR> l) { List<String> s = new ArrayList<>(); for (RR r : l) s.add(r.json()); return "[" + String.join(",", s) + "]"; }
    }

    public static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format("%02x", x)); return s.toString(); }

    public static Result query(String host, int port, String name, int type, boolean rd, boolean forceTcp, int timeoutMs) throws IOException {
        int id = RND.nextInt(65536);
        Message q = Message.query(id, name, type, rd);
        byte[] out = q.encode();
        Result r = new Result(); r.query = out; r.server = host + ":" + port;
        Message.decode(out, out.length, r.qfields);
        String sid = "client:dig#" + IDS.incrementAndGet();
        Hub.I.line(new Hub.Line(sid, "DNS", true, (forceTcp ? "[TCP] " : "") + q.summary() + " → " + host + ":" + port,
                "our client · " + (rd ? "RD=1: recursive query" : "RD=0: iterative query") + " · " + out.length + " bytes over " + (forceTcp ? "TCP" : "UDP")));
        long t0 = System.nanoTime();
        InetAddress to = InetAddress.getByName(host);
        if (!forceTcp) {
            try (DatagramSocket s = new DatagramSocket()) {
                s.setSoTimeout(timeoutMs);
                s.send(new DatagramPacket(out, out.length, to, port));
                byte[] buf = new byte[65535];
                long deadline = System.currentTimeMillis() + timeoutMs;
                while (true) {
                    if (System.currentTimeMillis() > deadline) throw new SocketTimeoutException("no answer from " + host + ":" + port + " within " + timeoutMs + " ms");
                    DatagramPacket p = new DatagramPacket(buf, buf.length);
                    s.receive(p);
                    if (p.getLength() < 12 || ((buf[0] & 0xFF) << 8 | buf[1] & 0xFF) != id) continue;
                    r.raw = java.util.Arrays.copyOf(buf, p.getLength());
                    break;
                }
            }
            Message m = Message.decode(r.raw, r.raw.length);
            if (m.tc) {
                r.truncatedFirst = true;
                Hub.I.line(new Hub.Line(sid, "DNS", false, m.summary(), "TC=1: the answer does not fit in 512 bytes of UDP · retrying the same query over TCP"));
                forceTcp = true;
            }
        }
        if (forceTcp) {
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(to, port), timeoutMs); s.setSoTimeout(timeoutMs);
                DataOutputStream o = new DataOutputStream(s.getOutputStream()); DataInputStream in = new DataInputStream(s.getInputStream());
                o.writeShort(out.length); o.write(out); o.flush();
                int len = in.readUnsignedShort(); r.raw = new byte[len]; in.readFully(r.raw);
                r.tcp = true;
            }
        }
        r.ms = (System.nanoTime() - t0) / 1e6;
        r.msg = Message.decode(r.raw, r.raw.length, r.fields);
        Hub.I.line(new Hub.Line(sid, "DNS", false, (r.tcp ? "[TCP] " : "") + r.msg.summary(), String.format("%d bytes in %.1f ms%s", r.raw.length, r.ms, r.msg.ra ? " · RA=1: the server offers recursion" : "")));
        return r;
    }
}

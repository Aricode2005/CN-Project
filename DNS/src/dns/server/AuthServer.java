package dns.server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import dns.core.Hub;
import dns.wire.Message;
import dns.zone.Zone;

/**
 * An authoritative name server for its own zones. In the lab hierarchy one instance plays the root,
 * one ".edu", one "myuniv.edu" and one "cse.myuniv.edu".
 *
 * Recursive resolution (textbook mode): when {@link #recursion} is on and a query arrives with RD=1
 * for a name it can only refer, the server does not send the referral back. It asks the next server
 * itself (also with RD=1), waits, and relays the final answer (RA=1). The chain root -> edu -> myuniv
 * -> cse forms, and the answer travels back up it. Real root and TLD servers switch this off (RA=0).
 */
public final class AuthServer {

    public final String label, host, ip; public final int port;
    public final List<Zone> zones;
    /** Artificial latency per query name (ms): makes a "slow, far-away" server for the poisoning race. */
    public final Map<String, Long> delays = new ConcurrentHashMap<>();
    public final AtomicLong queries = new AtomicLong();
    /** Lab servers offer recursion to clients that ask for it (RD=1). */
    public static volatile boolean recursion = true;
    /** Recursive chains in progress, keyed by query ID: every forwarding server appends the hop it made. */
    public static final Map<Integer, List<Resolver.Step>> chains = new ConcurrentHashMap<>();
    private Listener listener, listener53;
    /** True when this server could also bind the standard DNS port 53 on its address (so plain nslookup works). */
    public boolean on53;

    public AuthServer(String label, String host, String ip, int port, List<Zone> zones) {
        this.label = label; this.host = host; this.ip = ip; this.port = port; this.zones = zones;
    }

    public AuthServer start() throws IOException {
        listener = new Listener(ip, port).start(this::handle, "auth-" + label);
        try { listener53 = new Listener(ip, 53).start(this::handle, "auth53-" + label); on53 = true; } catch (IOException e) { on53 = false; }
        Hub.I.log("[DNS] authoritative " + label + " (" + host + ") on " + ip + ":" + port + (on53 ? " and :53" : "") + " UDP+TCP, zones " + zoneNames());
        return this;
    }

    public String zoneNames() { StringBuilder b = new StringBuilder(); for (Zone z : zones) b.append(b.length() > 0 ? ", " : "").append(Message.fq(z.origin)); return b.toString(); }

    public Zone zoneFor(String qname) {
        Zone best = null;
        for (Zone z : zones) if (z.contains(qname) && (best == null || z.origin.length() > best.origin.length())) best = z;
        return best;
    }

    Message handle(Message q, boolean tcp, String peer) throws Exception {
        queries.incrementAndGet();
        String qn = q.qd.isEmpty() ? "" : q.qd.get(0).name.toLowerCase();
        String sid = label;
        Hub.I.line(new Hub.Line(sid, "DNS", true, (tcp ? "[TCP] " : "") + q.summary(), (q.rd ? (recursion ? "recursive query (RD=1) from " + peer + ": get me the final answer" : "asks for recursion (RD=1), but recursion is switched off here (RA=0)") : "iterative query (RD=0) from " + peer)));
        Long d = delays.get(qn);
        if (d != null) Thread.sleep(d);
        Zone z = zoneFor(qn);
        Message r;
        if (z == null) { r = q.reply(); r.rcode = Message.REFUSED; }
        else r = z.answer(q);
        if (q.rd && recursion && !r.aa && r.rcode == Message.NOERROR && !r.ns.isEmpty() && r.ns.get(0).type == Message.NS) {
            Message f = forward(q, r);
            if (f != null) { Hub.I.line(new Hub.Line(sid, "DNS", false, f.summary(), "recursive: relaying the answer that came back up the chain (RA=1, AA=0: not my own data)")); return f; }
        }
        r.ra = false;
        Hub.I.line(new Hub.Line(sid, "DNS", false, (tcp ? "[TCP] " : "") + r.summary(), explain(r, z, tcp)));
        return r;
    }

    /** Recursive mode: ask the referred server ourselves (RD=1, same ID) and relay its answer. */
    private Message forward(Message q, Message referral) {
        String nextZone = referral.ns.get(0).name, nextHost = referral.ns.get(0).target(), nextIp = null;
        for (Message.RR a : referral.ar) if (a.type == Message.A && a.name.equalsIgnoreCase(nextHost)) { nextIp = a.data; break; }
        if (nextIp == null) return null;                       // no glue: fall back to a plain referral
        List<Resolver.Step> chain = chains.get(q.id);
        Resolver.Step st = new Resolver.Step(nextHost, nextIp, nextZone, q.qd.get(0).name.toLowerCase() + " " + Message.typeName(q.qd.get(0).type), chain == null ? 1 : chain.size());
        st.kind = "ASKED BY " + host.toUpperCase();
        if (chain != null) chain.add(st);
        Hub.I.line(new Hub.Line(label + "->", "DNS", true, String.format("query id=0x%04x %s? RD=1 -> %s %s:%d", q.id, q.qd.get(0).toString(), nextHost, nextIp, port),
                host + " cannot answer, so it asks the next server itself and waits (recursive resolution)"));
        long t0 = System.nanoTime();
        try {
            byte[] out = q.encode();
            Message d = udp(out, nextIp, q.id);
            if (d.tc) d = tcp(out, nextIp);
            st.ms = Math.round((System.nanoTime() - t0) / 1e5) / 10.0;
            st.aa = d.aa;
            st.kind = d.aa ? "ANSWER" : d.rcode == Message.NXDOMAIN ? "NXDOMAIN" : d.an.isEmpty() ? Message.rcodeName(d.rcode) : "RELAYED";
            st.detail = d.aa ? "authoritative for " + Message.fq(nextZone) + ": answers from its own zone and sends it back up the chain"
                    : nextHost + " did not know either, asked the next server and relayed what came back (" + st.ms + " ms incl. the servers below it)";
            for (Message.RR rr : d.an) if (st.records.size() < 8) st.records.add("AN " + rr);
            Message r = q.reply();
            r.ra = true; r.rcode = d.rcode;
            r.an.addAll(d.an); r.ns.addAll(d.ns); r.ar.addAll(d.ar);
            return r;
        } catch (IOException e) {
            st.kind = "TIMEOUT"; st.detail = e.getMessage();
            return null;
        }
    }

    private static Message udp(byte[] out, String ip, int id) throws IOException {
        try (DatagramSocket s = new DatagramSocket()) {
            s.setSoTimeout(6000);
            s.send(new DatagramPacket(out, out.length, InetAddress.getByName(ip), Listener.LAB_PORT));
            byte[] buf = new byte[4096];
            long end = System.currentTimeMillis() + 6000;
            while (System.currentTimeMillis() < end) {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                s.receive(p);
                if (p.getLength() >= 12 && ((buf[0] & 0xFF) << 8 | buf[1] & 0xFF) == id) return Message.decode(buf, p.getLength());
            }
            throw new SocketTimeoutException("no answer from " + ip);
        }
    }

    private static Message tcp(byte[] out, String ip) throws IOException {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(ip, Listener.LAB_PORT), 3000); s.setSoTimeout(6000);
            DataOutputStream o = new DataOutputStream(s.getOutputStream()); DataInputStream in = new DataInputStream(s.getInputStream());
            o.writeShort(out.length); o.write(out); o.flush();
            int len = in.readUnsignedShort(); byte[] b = new byte[len]; in.readFully(b);
            return Message.decode(b, len);
        }
    }

    static String explain(Message r, Zone z, boolean tcp) {
        if (r.rcode == Message.REFUSED) return "not my zone: refused";
        if (r.rcode == Message.NXDOMAIN) return "authoritative NXDOMAIN: the name does not exist (SOA attached for negative caching)";
        if (!r.aa && !r.ns.isEmpty()) {
            StringBuilder b = new StringBuilder("referral: \"I don't know, ask the servers for " + Message.fq(r.ns.get(0).name) + "\"");
            if (!r.ar.isEmpty()) b.append(" + glue ").append(r.ar.get(0).name).append(" = ").append(r.ar.get(0).data);
            return b.toString();
        }
        if (r.an.isEmpty()) return "authoritative NODATA: the name exists but has no record of that type";
        String s = "authoritative answer (AA=1) from zone " + Message.fq(z.origin);
        if (!tcp && r.encode().length > Listener.UDP_LIMIT) s = "answer is " + r.encode().length + " bytes > 512: sent truncated (TC=1), client must retry over TCP";
        return s;
    }

    public void stop() { if (listener != null) listener.stop(); if (listener53 != null) listener53.stop(); }
}

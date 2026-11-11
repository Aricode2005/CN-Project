package boot.bootp;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import boot.Topology;
import boot.Topology.Station;
import boot.core.Field;
import boot.core.Hub;
import boot.core.Json;

/**
 * BOOTP over real UDP: a server (port 67 in real life, 1067 here), a relay agent on the router
 * (BOOTP's big improvement over RARP: requests cross routers) and a diskless client (port 68 → 1068).
 *
 * Every packet below is a real 300-byte BOOTP message sent through a real UDP socket on 127.0.0.1.
 * The 10.0.x.x addresses inside the packets are the lab's virtual network; the client's broadcast to
 * 255.255.255.255 is delivered to the server (LAN A) or the relay (LAN B) directly.
 */
public final class Bootp {

    public static final int SERVER_PORT = 1067, RELAY_PORT = 2067, CLIENT_PORT = 1068;
    private static final InetAddress LO;
    static { try { LO = InetAddress.getByName("127.0.0.1"); } catch (Exception e) { throw new RuntimeException(e); } }

    private final Topology topo;
    private DatagramSocket server, relay;
    private final SecureRandom rnd = new SecureRandom();
    /** Steps of each transaction (by xid) as the client, the relay and the server see them. */
    private final Map<Long, List<String>> traces = new ConcurrentHashMap<>();
    public volatile boolean relayOn = true;

    public Bootp(Topology topo) { this.topo = topo; }

    private void step(long xid, String from, String to, String kind, String note, byte[] pkt) {
        List<String> t = traces.get(xid);
        String fields = "[]";
        if (pkt != null) { List<String> f = new ArrayList<>(); for (Field x : Packet.dissect(pkt)) f.add(x.json()); fields = "[" + String.join(",", f) + "]"; }
        if (t != null) t.add(Json.obj("from", from, "to", to, "kind", kind, "note", note, "hex", pkt == null ? null : Field.hex(pkt), "fields", Json.raw(fields)));
    }

    // ================================================================== server
    public void start() throws IOException {
        server = new DatagramSocket(new InetSocketAddress(LO, SERVER_PORT));
        relay = new DatagramSocket(new InetSocketAddress(LO, RELAY_PORT));
        Thread s = new Thread(this::serverLoop, "bootp-server"); s.setDaemon(true); s.start();
        Thread r = new Thread(this::relayLoop, "bootp-relay"); r.setDaemon(true); r.start();
        Hub.I.log("[BOOTP] server on 127.0.0.1:" + SERVER_PORT + " (real port 67), relay agent on 127.0.0.1:" + RELAY_PORT + ", clients use " + CLIENT_PORT + " (real port 68)");
    }

    private void serverLoop() {
        byte[] buf = new byte[1500];
        while (!server.isClosed()) {
            try {
                DatagramPacket dp = new DatagramPacket(buf, buf.length);
                server.receive(dp);
                Packet q = Packet.decode(buf, dp.getLength());
                if (q.op != Packet.BOOTREQUEST) continue;
                Hub.I.line(new Hub.Line("bootp-server", "BOOTP", true, q.summary(), q.giaddr.equals("0.0.0.0") ? "request heard on the server's own LAN" : "request forwarded by the relay agent at " + q.giaddr));
                Topology.Entry e = topo.table.get(q.chaddr);
                if (e == null) {
                    step(q.xid, "SERVER", "-", "silent", "The server looks up " + q.chaddr + " in /etc/bootptab: no entry. BOOTP is static: unknown machines get no reply.", null);
                    Hub.I.line(new Hub.Line("bootp-server", "BOOTP", false, "(no reply)", q.chaddr + " is not in bootptab"));
                    continue;
                }
                Packet r = new Packet();
                r.op = Packet.BOOTREPLY; r.xid = q.xid; r.secs = q.secs; r.hops = q.hops; r.flags = q.flags; r.giaddr = q.giaddr; r.chaddr = q.chaddr; r.ciaddr = q.ciaddr;
                r.yiaddr = e.ip; r.siaddr = Topology.SERVER_IP; r.sname = Topology.SERVER_NAME; r.file = e.file;
                r.options.put(Packet.OPT_MASK, Field.ipBytes(Topology.MASK));
                r.options.put(Packet.OPT_ROUTER, Field.ipBytes(e.ip.startsWith("10.0.2.") ? Topology.ROUTER_B_IP : Topology.ROUTER_A_IP));
                r.options.put(Packet.OPT_DNS, Field.ipBytes(Topology.DNS));
                r.options.put(Packet.OPT_HOST, e.host.getBytes());
                byte[] out = r.encode();
                boolean viaRelay = !q.giaddr.equals("0.0.0.0");
                step(q.xid, "SERVER", viaRelay ? "RELAY" : "CLIENT", "reply", "The server finds " + q.chaddr + " in /etc/bootptab and builds a BOOTREPLY: yiaddr " + e.ip + ", boot server " + Topology.SERVER_IP + ", boot file " + e.file
                        + ", plus mask, router, DNS and host name in the vendor area. " + (viaRelay ? "giaddr is set, so it sends the reply to the relay agent at " + q.giaddr + " (port 67)." : "It sends the reply to port 68 on the client's LAN."), out);
                server.send(new DatagramPacket(out, out.length, LO, viaRelay ? RELAY_PORT : CLIENT_PORT));
                Hub.I.line(new Hub.Line("bootp-server", "BOOTP", false, r.summary(), viaRelay ? "unicast to the relay agent (giaddr)" : "to the client, port 68"));
            } catch (Exception e) { if (!server.isClosed()) Hub.I.log("[BOOTP] server: " + e.getMessage()); }
        }
    }

    // ================================================================== relay agent on the router (RFC 951 §7, RFC 1542)
    private void relayLoop() {
        byte[] buf = new byte[1500];
        while (!relay.isClosed()) {
            try {
                DatagramPacket dp = new DatagramPacket(buf, buf.length);
                relay.receive(dp);
                Packet p = Packet.decode(buf, dp.getLength());
                if (p.op == Packet.BOOTREQUEST) {
                    if (!relayOn) { step(p.xid, "RELAY", "-", "dropped", "The router has no relay agent configured: like RARP, the broadcast dies at the router.", null); continue; }
                    if (p.hops >= 4) { step(p.xid, "RELAY", "-", "dropped", "hops limit reached, discarded", null); continue; }
                    p.hops++;
                    if (p.giaddr.equals("0.0.0.0")) p.giaddr = Topology.ROUTER_B_IP;
                    byte[] out = p.encode();
                    step(p.xid, "RELAY", "SERVER", "forward", "The relay agent on the router (LAN B side, " + Topology.ROUTER_B_IP + ") catches the broadcast, writes its own address into giaddr, adds 1 to hops, and forwards it as a unicast UDP packet to the server " + Topology.SERVER_IP + ".", out);
                    Hub.I.line(new Hub.Line("bootp-relay", "BOOTP", true, p.summary(), "forwarded across the router to the server"));
                    relay.send(new DatagramPacket(out, out.length, LO, SERVER_PORT));
                } else {
                    byte[] out = p.encode();
                    step(p.xid, "RELAY", "CLIENT", "deliver", "The relay agent gets the reply back (it is the giaddr) and delivers it on LAN B to the client's port 68.", out);
                    Hub.I.line(new Hub.Line("bootp-relay", "BOOTP", false, p.summary(), "delivered on LAN B to port 68"));
                    relay.send(new DatagramPacket(out, out.length, LO, CLIENT_PORT));
                }
            } catch (Exception e) { if (!relay.isClosed()) Hub.I.log("[BOOTP] relay: " + e.getMessage()); }
        }
    }

    // ================================================================== client
    public static final class Result {
        public boolean ok; public String ws, mac, ip = "", mask = "", router = "", dns = "", host = "", server = "", file = "";
        public int attempts; public double ms; public List<String> steps = new ArrayList<>();
        public String json() {
            return Json.obj("ok", ok, "ws", ws, "mac", mac, "ip", ip, "mask", mask, "router", router, "dns", dns, "host", host, "server", server, "file", file,
                    "attempts", attempts, "ms", Math.round(ms * 10) / 10.0, "steps", Json.raw("[" + String.join(",", steps) + "]"));
        }
    }

    /** Boot a diskless workstation with BOOTP: broadcast a BOOTREQUEST, wait for the BOOTREPLY, retry with a growing secs. */
    public synchronized Result boot(String wsName) throws IOException {
        Result res = new Result();
        Station ws = topo.station(wsName);
        res.ws = wsName;
        if (ws == null || ws.fixedIp != null) { res.steps.add(Json.obj("from", "-", "to", "-", "kind", "error", "note", "not a diskless workstation")); return res; }
        res.mac = ws.mac;
        long xid = rnd.nextInt() & 0xFFFFFFFFL;
        List<String> trace = new CopyOnWriteArrayList<>();
        traces.put(xid, trace);
        long t0 = System.nanoTime();
        try (DatagramSocket c = new DatagramSocket(null)) {
            c.setReuseAddress(true);
            c.bind(new InetSocketAddress(LO, CLIENT_PORT));
            byte[] buf = new byte[1500];
            for (int attempt = 1; attempt <= 3; attempt++) {
                res.attempts = attempt;
                Packet q = new Packet();
                q.op = Packet.BOOTREQUEST; q.xid = xid; q.chaddr = ws.mac; q.secs = (attempt - 1) * 2;
                byte[] out = q.encode();
                boolean remote = ws.segment.equals("B");
                step(xid, "CLIENT", remote ? "RELAY" : "SERVER", "broadcast", (attempt > 1 ? "Retry " + attempt + " (secs = " + q.secs + "). " : "") + ws.name + " sends a BOOTREQUEST from 0.0.0.0:68 to 255.255.255.255:67 (UDP broadcast): op 1, its MAC in chaddr, a random xid, every address 0.0.0.0."
                        + (remote ? " It is on LAN B: the server is behind the router." : ""), out);
                Hub.I.line(new Hub.Line("bootp-client:" + ws.name, "BOOTP", true, q.summary(), "broadcast to 255.255.255.255:67"));
                c.send(new DatagramPacket(out, out.length, LO, remote ? RELAY_PORT : SERVER_PORT));
                c.setSoTimeout(1500);
                long end = System.currentTimeMillis() + 1500;
                while (System.currentTimeMillis() < end) {
                    DatagramPacket dp = new DatagramPacket(buf, buf.length);
                    try { c.receive(dp); } catch (SocketTimeoutException e) { break; }
                    Packet r = Packet.decode(buf, dp.getLength());
                    if (r.op != Packet.BOOTREPLY || r.xid != xid || !r.chaddr.equals(ws.mac)) continue;    // someone else's reply
                    res.ok = true; res.ip = r.yiaddr; res.server = r.siaddr; res.file = r.file;
                    byte[] v;
                    if ((v = r.options.get(Packet.OPT_MASK)) != null) res.mask = Packet.optValue(Packet.OPT_MASK, v);
                    if ((v = r.options.get(Packet.OPT_ROUTER)) != null) res.router = Packet.optValue(Packet.OPT_ROUTER, v);
                    if ((v = r.options.get(Packet.OPT_DNS)) != null) res.dns = Packet.optValue(Packet.OPT_DNS, v);
                    if ((v = r.options.get(Packet.OPT_HOST)) != null) res.host = Packet.optValue(Packet.OPT_HOST, v);
                    step(xid, "CLIENT", "-", "configured", ws.name + " matches xid and chaddr, and configures itself: IP " + res.ip + ", mask " + res.mask + ", router " + res.router + ", DNS " + res.dns + ", host name " + res.host
                            + ". Next it would download " + res.file + " from " + res.server + " with TFTP and boot from it. The binding is permanent: BOOTP has no leases.", null);
                    Hub.I.line(new Hub.Line("bootp-client:" + ws.name, "BOOTP", false, r.summary(), "configured: " + res.ip));
                    Hub.I.event("BOOTP", ws.name + " (" + ws.mac + ") booted as " + res.host + " " + res.ip);
                    res.ms = (System.nanoTime() - t0) / 1e6;
                    res.steps.addAll(trace);
                    return res;
                }
                step(xid, "CLIENT", "-", "timeout", "No BOOTREPLY within 1.5 s. The client tries again.", null);
            }
            step(xid, "CLIENT", "-", "fail", ws.name + " gives up after 3 tries.", null);
            Hub.I.event("BOOTP", ws.name + " got no reply");
        } finally {
            traces.remove(xid);
        }
        res.ms = (System.nanoTime() - t0) / 1e6;
        res.steps.addAll(trace);
        return res;
    }

    public void stop() { if (server != null) server.close(); if (relay != null) relay.close(); }
}

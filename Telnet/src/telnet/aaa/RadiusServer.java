package telnet.aaa;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import telnet.core.Hub;
import telnet.core.Json;

/**
 * A small RADIUS server (like FreeRADIUS with a users file): authentication on UDP 1812, accounting on UDP 1813.
 *
 * Users live HERE, not on the routers: "netops" can log in to any router that uses this server even though no router
 * has a local account for it. The answer carries the privilege level as a Cisco AV-pair "shell:priv-lvl=15".
 * Accounting records (Start, Interim-Update per command, Stop) are kept as the central audit trail.
 */
public final class RadiusServer {

    public static final class Account { final String password; final int priv; Account(String p, int v) { password = p; priv = v; } }

    /** One accounting session, built from Start / Interim-Update / Stop records. */
    public static final class Acct {
        String id, user, nas, client, cause = "", authentic = ""; int port; long start, stop; long in, out, seconds;
        final List<String> commands = new ArrayList<>();
    }

    public final int authPort, acctPort;
    public volatile byte[] secret;
    /** Simulates a server failure: packets are received and silently ignored. */
    public volatile boolean online = true;
    public final Map<String, Account> users = new LinkedHashMap<>();
    public final Map<String, Acct> acct = new LinkedHashMap<>();
    private DatagramSocket auth, acc;
    public volatile long accessRequests, accepts, rejects, acctRequests, dropped, badAuthenticator;

    public RadiusServer(int authPort, int acctPort, String secret) {
        this.authPort = authPort; this.acctPort = acctPort; this.secret = secret.getBytes(StandardCharsets.UTF_8);
        users.put("admin", new Account("cisco", 15));
        users.put("student", new Account("ju2026", 1));
        users.put("netops", new Account("radius123", 15));     // exists only on the RADIUS server
        users.put("intern", new Account("intern2026", 1));     // exists only on the RADIUS server
    }

    public void start() throws IOException {
        auth = new DatagramSocket(new InetSocketAddress(authPort));
        acc = new DatagramSocket(new InetSocketAddress(acctPort));
        loop(auth, "radius-auth");
        loop(acc, "radius-acct");
        Hub.I.log("[RADIUS] server on UDP " + authPort + " (authentication) and " + acctPort + " (accounting), " + users.size() + " users");
    }

    public void stop() { if (auth != null) auth.close(); if (acc != null) acc.close(); }

    private void loop(DatagramSocket s, String name) {
        Thread t = new Thread(() -> {
            byte[] b = new byte[4096];
            while (!s.isClosed()) {
                try {
                    DatagramPacket p = new DatagramPacket(b, b.length);
                    s.receive(p);
                    if (!online) { dropped++; continue; }
                    byte[] reply = handle(java.util.Arrays.copyOf(p.getData(), p.getLength()));
                    if (reply != null) s.send(new DatagramPacket(reply, reply.length, p.getSocketAddress()));
                } catch (IOException e) { if (!s.isClosed()) Hub.I.log("[RADIUS] " + e.getMessage()); }
                catch (RuntimeException e) { Hub.I.log("[RADIUS] malformed packet ignored: " + e.getMessage()); }
            }
        }, name);
        t.setDaemon(true);
        t.start();
    }

    synchronized byte[] handle(byte[] wire) {
        Radius.Packet q = Radius.decode(wire, wire.length);
        if (q.code == Radius.ACCESS_REQUEST) return access(q);
        if (q.code == Radius.ACCOUNTING_REQUEST) return accounting(q, wire);
        return null;
    }

    private byte[] access(Radius.Packet q) {
        accessRequests++;
        Radius.Attr un = q.get(Radius.USER_NAME), pw = q.get(Radius.USER_PASSWORD);
        String user = un == null ? "" : un.text();
        String pass = pw == null ? "" : Radius.unhidePassword(pw.value, secret, q.auth);
        Account a = users.get(user);
        Radius.Packet r;
        boolean ok = a != null && MessageDigest.isEqual(a.password.getBytes(StandardCharsets.UTF_8), pass.getBytes(StandardCharsets.UTF_8));
        if (ok) {
            accepts++;
            r = new Radius.Packet(Radius.ACCESS_ACCEPT, q.id)
                    .addInt(Radius.SERVICE_TYPE, a.priv >= 15 ? Radius.SERVICE_ADMINISTRATIVE : Radius.SERVICE_NAS_PROMPT)
                    .addCisco("shell:priv-lvl=" + a.priv)
                    .add(Radius.REPLY_MESSAGE, "Welcome " + user + ", authorised by the central RADIUS server (privilege " + a.priv + ")");
            Hub.I.log("[RADIUS] Access-Accept " + user + " (priv " + a.priv + ") from " + text(q, Radius.CALLING_STATION_ID));
        } else {
            rejects++;
            r = new Radius.Packet(Radius.ACCESS_REJECT, q.id).add(Radius.REPLY_MESSAGE, a == null ? "Unknown user" : "Wrong password");
            Hub.I.log("[RADIUS] Access-Reject " + user + " from " + text(q, Radius.CALLING_STATION_ID));
        }
        r.auth = Radius.responseAuth(r, q.auth, secret);
        return r.encode();
    }

    private byte[] accounting(Radius.Packet q, byte[] wire) {
        acctRequests++;
        // RFC 2866: the request authenticator proves the NAS knows the secret; a wrong one is silently discarded
        if (!MessageDigest.isEqual(q.auth, Radius.accountingRequestAuth(q, secret))) { badAuthenticator++; Hub.I.log("[RADIUS] Accounting-Request with a bad authenticator dropped"); return null; }
        Radius.Attr st = q.get(Radius.ACCT_STATUS_TYPE), sid = q.get(Radius.ACCT_SESSION_ID);
        if (st != null && sid != null) {
            Acct x = acct.computeIfAbsent(sid.text(), k -> new Acct());
            x.id = sid.text();
            if (x.user == null) x.user = text(q, Radius.USER_NAME);
            if (x.nas == null) x.nas = text(q, Radius.NAS_IDENTIFIER);
            if (x.client == null) x.client = text(q, Radius.CALLING_STATION_ID);
            Radius.Attr port = q.get(Radius.NAS_PORT); if (port != null) x.port = port.integer();
            Radius.Attr au = q.get(Radius.ACCT_AUTHENTIC); if (au != null) x.authentic = au.integer() == 1 ? "RADIUS" : "Local";
            long now = System.currentTimeMillis();
            switch (st.integer()) {
                case Radius.STATUS_START: x.start = now; break;
                case Radius.STATUS_INTERIM: for (String c : q.ciscoPairs()) if (c.startsWith("cmd=")) x.commands.add(c.substring(4)); break;
                case Radius.STATUS_STOP:
                    x.stop = now;
                    Radius.Attr t = q.get(Radius.ACCT_SESSION_TIME); if (t != null) x.seconds = t.integer();
                    Radius.Attr i = q.get(Radius.ACCT_INPUT_OCTETS); if (i != null) x.in = i.integer();
                    Radius.Attr o = q.get(Radius.ACCT_OUTPUT_OCTETS); if (o != null) x.out = o.integer();
                    Radius.Attr c = q.get(Radius.ACCT_TERMINATE_CAUSE); if (c != null) x.cause = Radius.cause(c.integer());
                    break;
                default: break;
            }
            while (acct.size() > 40) acct.remove(acct.keySet().iterator().next());
        }
        Radius.Packet r = new Radius.Packet(Radius.ACCOUNTING_RESPONSE, q.id);
        r.auth = Radius.responseAuth(r, q.auth, secret);
        return r.encode();
    }

    private static String text(Radius.Packet q, int type) { Radius.Attr a = q.get(type); return a == null ? "" : a.text(); }

    public synchronized String json() {
        List<String> us = new ArrayList<>();
        for (Map.Entry<String, Account> e : users.entrySet()) us.add(Json.obj("user", e.getKey(), "priv", e.getValue().priv));
        List<String> ac = new ArrayList<>();
        for (Acct x : acct.values()) {
            List<String> cs = new ArrayList<>(); for (String c : x.commands) cs.add(Json.str(c));
            ac.add(Json.obj("id", x.id, "user", x.user, "nas", x.nas, "client", x.client, "port", x.port, "authentic", x.authentic,
                    "start", x.start, "stop", x.stop, "seconds", x.seconds, "in", x.in, "out", x.out, "cause", x.cause, "commands", Json.raw(Json.arr(cs))));
        }
        return Json.obj("authPort", authPort, "acctPort", acctPort, "online", online, "users", Json.raw(Json.arr(us)), "accounting", Json.raw(Json.arr(ac)),
                "accessRequests", accessRequests, "accepts", accepts, "rejects", rejects, "acctRequests", acctRequests, "dropped", dropped, "badAuthenticator", badAuthenticator);
    }
}

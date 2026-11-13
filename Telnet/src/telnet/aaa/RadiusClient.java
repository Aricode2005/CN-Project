package telnet.aaa;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import telnet.core.Hub;
import telnet.core.Json;
import telnet.server.DeviceConfig;
import telnet.server.RemoteAuth;
import telnet.server.SessionEvents;
import telnet.server.TelnetSession;

/**
 * The router's side of AAA (the "NAS", network access server): asks the RADIUS server at login, and sends accounting
 * records for each exec session (Start, an Interim-Update per command, Stop).
 *
 * UDP gives no delivery guarantee, so the client retransmits the same packet (same Identifier and authenticator)
 * after 1 s, three times. It accepts an answer only if its Response Authenticator proves the server knows the secret.
 */
public final class RadiusClient implements RemoteAuth, SessionEvents {

    static final int TIMEOUT_MS = 1000, TRIES = 3;
    /** The process's RADIUS client and server, for the dashboard. */
    public static volatile RadiusClient I;
    public static volatile RadiusServer SERVER;

    private final DeviceConfig cfg;
    private final SecureRandom rnd = new SecureRandom();
    private final AtomicInteger ids = new AtomicInteger(new SecureRandom().nextInt(256));
    private final ExecutorService acctQ = Executors.newSingleThreadExecutor(r -> { Thread t = new Thread(r, "radius-acct"); t.setDaemon(true); return t; });
    private final Map<Integer, String> acctIds = new ConcurrentHashMap<>();
    private final List<String> log = new ArrayList<>();
    public volatile long requests, retransmits, accepts, rejects, timeouts, badResponses, acctSent, acctAcked;
    public volatile double lastRttMs = -1;

    public RadiusClient(DeviceConfig cfg) { this.cfg = cfg; }

    // ================================================================== authentication

    @Override
    public Answer authenticate(String user, String password, TelnetSession s) {
        Radius.Packet q = new Radius.Packet(Radius.ACCESS_REQUEST, ids.incrementAndGet() & 0xFF);
        rnd.nextBytes(q.auth);                                       // Request Authenticator: 16 random octets
        byte[] key = cfg.radiusKey.getBytes(StandardCharsets.UTF_8);
        q.add(Radius.USER_NAME, user)
         .add(Radius.USER_PASSWORD, Radius.hidePassword(password, key, q.auth))
         .add(Radius.NAS_IP_ADDRESS, new byte[]{127, 0, 0, 1})
         .addInt(Radius.NAS_PORT, s.line)
         .addInt(Radius.NAS_PORT_TYPE, 5)
         .add(Radius.CALLING_STATION_ID, s.clientIp())
         .add(Radius.NAS_IDENTIFIER, cfg.hostname);
        requests++;
        Radius.Packet r = exchange(q, cfg.radiusAuthPort, key);
        if (r == null) { timeouts++; return new Answer(false, true, 0, "no answer"); }
        Radius.Attr msg = r.get(Radius.REPLY_MESSAGE);
        String m = msg == null ? "" : msg.text();
        if (r.code == Radius.ACCESS_ACCEPT) {
            accepts++;
            int priv = 1;
            Radius.Attr st = r.get(Radius.SERVICE_TYPE);
            if (st != null && st.integer() == Radius.SERVICE_ADMINISTRATIVE) priv = 15;
            for (String p : r.ciscoPairs()) if (p.startsWith("shell:priv-lvl=")) try { priv = Integer.parseInt(p.substring(15).trim()); } catch (NumberFormatException ignored) { }
            return new Answer(true, false, priv, m);
        }
        rejects++;
        return new Answer(false, false, 0, m.isEmpty() ? "Access-Reject" : m);
    }

    /** Send, wait 1 s, retransmit the identical packet up to 3 times; verify the Response Authenticator. */
    private Radius.Packet exchange(Radius.Packet q, int port, byte[] key) {
        byte[] wire = q.encode();
        note("NAS → server", q, wire, "");
        try (DatagramSocket s = new DatagramSocket()) {
            s.setSoTimeout(TIMEOUT_MS);
            InetAddress to = InetAddress.getByName(cfg.radiusHost);
            byte[] b = new byte[4096];
            for (int t = 1; t <= TRIES; t++) {
                long t0 = System.nanoTime();
                s.send(new DatagramPacket(wire, wire.length, to, port));
                if (t > 1) { retransmits++; noteText("retransmission " + t + "/" + TRIES + " of " + Radius.codeName(q.code) + " id " + q.id + " (no answer within " + TIMEOUT_MS + " ms)"); }
                long deadline = System.currentTimeMillis() + TIMEOUT_MS;
                while (System.currentTimeMillis() < deadline) {
                    DatagramPacket p = new DatagramPacket(b, b.length);
                    try { s.receive(p); } catch (SocketTimeoutException e) { break; }
                    Radius.Packet r;
                    try { r = Radius.decode(p.getData(), p.getLength()); } catch (IllegalArgumentException e) { badResponses++; continue; }
                    if (r.id != q.id) continue;
                    byte[] got = java.util.Arrays.copyOf(p.getData(), p.getLength());
                    if (!MessageDigest.isEqual(r.auth, Radius.responseAuth(r, q.auth, key))) {
                        badResponses++;
                        note("server → NAS", r, got, "Response Authenticator does NOT match: wrong shared secret or forged reply. Discarded.");
                        continue;
                    }
                    lastRttMs = (System.nanoTime() - t0) / 1e6;
                    note("server → NAS", r, got, String.format("Response Authenticator verified · %.2f ms", lastRttMs));
                    return r;
                }
            }
        } catch (IOException e) { noteText("socket error: " + e.getMessage()); }
        noteText("no answer from " + cfg.radiusHost + ":" + port + " after " + TRIES + " tries");
        return null;
    }

    // ================================================================== accounting (RFC 2866)

    @Override public void loggedIn(TelnetSession s, boolean resumed) {
        if (!cfg.aaaRadius) return;
        String id = String.format("%08X", (int) (System.currentTimeMillis() ^ (s.id * 2654435761L)));
        acctIds.put(s.id, id);
        Radius.Packet q = acctBase(s, id, Radius.STATUS_START);
        q.addInt(Radius.ACCT_AUTHENTIC, "RADIUS".equals(s.authBy) ? 1 : 2);
        if (resumed) q.addCisco("cmd=(session resumed on another node)");
        sendAcct(q);
    }

    @Override public void command(TelnetSession s, String line) {
        String id = acctIds.get(s.id);
        if (id == null || !cfg.aaaRadius) return;
        Radius.Packet q = acctBase(s, id, Radius.STATUS_INTERIM);
        q.addCisco("cmd=" + line);                                    // which command was run (a Cisco AV-pair)
        sendAcct(q);
    }

    @Override public void closed(TelnetSession s, String why) {
        String id = acctIds.remove(s.id);
        if (id == null) return;
        Radius.Packet q = acctBase(s, id, Radius.STATUS_STOP);
        q.addInt(Radius.ACCT_SESSION_TIME, (System.currentTimeMillis() - s.startedAt) / 1000)
         .addInt(Radius.ACCT_INPUT_OCTETS, s.bytesIn).addInt(Radius.ACCT_OUTPUT_OCTETS, s.bytesOut)
         .addInt(Radius.ACCT_TERMINATE_CAUSE, why.equals("exit") || why.equals("logout") || why.equals("quit") || why.equals("Ctrl-D") ? 1
                 : why.equals("exec-timeout") ? 4 : why.equals("node crashed") ? 9 : 2);
        sendAcct(q);
    }

    private Radius.Packet acctBase(TelnetSession s, String id, int status) {
        return new Radius.Packet(Radius.ACCOUNTING_REQUEST, ids.incrementAndGet() & 0xFF)
                .addInt(Radius.ACCT_STATUS_TYPE, status).add(Radius.ACCT_SESSION_ID, id).add(Radius.USER_NAME, s.user)
                .add(Radius.NAS_IP_ADDRESS, new byte[]{127, 0, 0, 1}).addInt(Radius.NAS_PORT, s.line).addInt(Radius.NAS_PORT_TYPE, 5)
                .add(Radius.CALLING_STATION_ID, s.clientIp()).add(Radius.NAS_IDENTIFIER, cfg.hostname);
    }

    private void sendAcct(Radius.Packet q) {
        byte[] key = cfg.radiusKey.getBytes(StandardCharsets.UTF_8);
        q.auth = Radius.accountingRequestAuth(q, key);
        acctSent++;
        acctQ.submit(() -> { if (exchange(q, cfg.radiusAcctPort, key) != null) acctAcked++; });
    }

    // ================================================================== log + status

    private synchronized void note(String dir, Radius.Packet p, byte[] wire, String verdict) {
        log.add(Json.obj("t", now(), "dir", dir, "verdict", verdict, "packet", Json.raw(Radius.dissect(p, wire))));
        while (log.size() > 50) log.remove(0);
        Hub.I.log("[AAA] " + dir + " " + Radius.codeName(p.code) + " id " + p.id + " (" + wire.length + " bytes)" + (verdict.isEmpty() ? "" : " · " + verdict));
    }

    private synchronized void noteText(String s) {
        log.add(Json.obj("t", now(), "dir", "note", "verdict", s));
        while (log.size() > 50) log.remove(0);
        Hub.I.log("[AAA] " + s);
    }

    private static String now() { return new SimpleDateFormat("HH:mm:ss.SSS").format(new Date()); }

    @Override
    public String status() {
        return String.format("RADIUS: id 1 priority 1 using %s\n  auth-port %d, acct-port %d, key ********\n  State: current UP, timeout %d ms, %d tries\n"
                + "  Authen: request %d, retransmit %d, accept %d, reject %d, timeouts %d, bad responses %d\n  Account: request %d, response %d\n  Last round trip: %s\n",
                cfg.radiusHost, cfg.radiusAuthPort, cfg.radiusAcctPort, TIMEOUT_MS, TRIES, requests, retransmits, accepts, rejects, timeouts, badResponses,
                acctSent, acctAcked, lastRttMs < 0 ? "-" : String.format("%.2f ms", lastRttMs));
    }

    public synchronized String json() {
        return Json.obj("aaa", cfg.aaaRadius, "host", cfg.radiusHost, "authPort", cfg.radiusAuthPort, "acctPort", cfg.radiusAcctPort,
                "requests", requests, "retransmits", retransmits, "accepts", accepts, "rejects", rejects, "timeouts", timeouts, "badResponses", badResponses,
                "acctSent", acctSent, "acctAcked", acctAcked, "lastRtt", lastRttMs, "log", Json.raw(Json.arr(log)));
    }
}

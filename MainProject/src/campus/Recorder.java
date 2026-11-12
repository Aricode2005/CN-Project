package campus;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Records what really happened on the wire during one story step, so the dashboard can replay it as animation:
 *   dhcp   DISCOVER / OFFER / REQUEST / ACK / DECLINE, from the DHCP module's own send and receive log lines
 *   arp    every ARP frame that entered the ARP lab's switch (port, MACs, broadcast?, dropped by DAI?), from its frame capture
 *   tel    every chunk of the Telnet TCP session through the LAN relay, decoded into NVT tokens (data vs IAC commands)
 */
public final class Recorder {

    public static final class Rec {
        final long seq, t; final String json;
        Rec(long seq, long t, String json) { this.seq = seq; this.t = t; this.json = json; }
    }

    private final List<Rec> recs = new ArrayList<>();
    private long seq, frameMark;
    private final String clientMac, clientName;
    private volatile int lastNode = -1;
    // a run of Telnet chunks in the same direction is merged into one record
    private StringBuilder telText; private List<String> telTokens; private boolean telDir; private long telT; private int telBytes, telPort; private boolean telTls;

    public Recorder(String clientMac, String clientName) { this.clientMac = clientMac.toUpperCase(); this.clientName = clientName; }

    private synchronized void add(long t, String json) { recs.add(new Rec(++seq, t, json)); if (recs.size() > 5000) recs.remove(0); }

    // ------------------------------------------------------------------ DHCP: parse the module's own log lines
    private static final Pattern DISCOVER = Pattern.compile("Sent DHCPDISCOVER \\(xid=(0x[0-9a-f]+)\\)");
    private static final Pattern OFFER_RX = Pattern.compile("Received DHCPOFFER: IP=(\\S+) from Server=(\\S+)");
    private static final Pattern REQUEST = Pattern.compile("Sent DHCPREQUEST for IP=(\\S+) \\(serverId=(\\S+)\\)");
    private static final Pattern DONE = Pattern.compile("DORA COMPLETE \\(DHCPACK\\): Assigned IP=(\\S+), Mask=(\\S+), GW=(\\S+), DNS=(\\S+), Lease=(\\d+)s");
    private static final Pattern NODE = Pattern.compile("^\\[DHCP-Node-(\\d)\\] (DHCPOFFER|DHCPACK|DHCPDECLINE)\\s*-> (?:Marked IP )?(\\S+)");
    private static final Pattern DECLINE = Pattern.compile("Sent DHCPDECLINE \\(ARP Conflict reported for IP (\\S+)\\)");
    private volatile String xid = "";

    public void dhcpLog(String line, int hashedNode) {
        long t = System.currentTimeMillis();
        Matcher m;
        boolean mine = line.contains(clientName) || line.toUpperCase().contains(clientMac);
        if (!mine) return;
        if ((m = DISCOVER.matcher(line)).find()) {
            xid = m.group(1); lastNode = hashedNode;
            add(t, Json.obj("kind", "dhcp", "msg", "DISCOVER", "dir", "up", "node", hashedNode, "xid", xid, "src", "0.0.0.0:68", "dst", "255.255.255.255:67", "bcast", true,
                "fields", Json.raw(fields("op", "1 BOOTREQUEST", "xid", xid, "ciaddr", "0.0.0.0", "yiaddr", "0.0.0.0", "chaddr", clientMac, "option 53", "1 = DISCOVER", "option 12", clientName))));
        } else if ((m = NODE.matcher(line)).find()) {
            int node = Integer.parseInt(m.group(1)); String what = m.group(2), ip = m.group(3);
            if (what.equals("DHCPDECLINE")) {
                add(t, Json.obj("kind", "dhcp", "msg", "DECLINE-SEEN", "dir", "srv", "node", node, "ip", ip, "fields", Json.raw(fields("server", "DHCP-Node-" + node, "action", ip + " marked DECLINED, never offered again"))));
                return;
            }
            String msg = what.equals("DHCPOFFER") ? "OFFER" : "ACK";
            lastNode = node;
            add(t, Json.obj("kind", "dhcp", "msg", msg, "dir", "down", "node", node, "xid", xid, "ip", ip, "src", "server:67", "dst", "255.255.255.255:68", "bcast", true,
                "fields", Json.raw(fields("op", "2 BOOTREPLY", "xid", xid, "yiaddr", ip + "  (your address)", "chaddr", clientMac, "option 53", (msg.equals("OFFER") ? "2 = OFFER" : "5 = ACK"),
                    "option 1 / 3 / 6", "mask 255.255.255.0 · router 192.168.1.1 · DNS 192.168.1.1", "option 51", "lease 120 s", "server", "DHCP-Node-" + node + " (chosen by consistent hashing of the MAC)"))));
        } else if ((m = REQUEST.matcher(line)).find()) {
            add(t, Json.obj("kind", "dhcp", "msg", "REQUEST", "dir", "up", "node", lastNode, "xid", xid, "ip", m.group(1), "src", "0.0.0.0:68", "dst", "255.255.255.255:67", "bcast", true,
                "fields", Json.raw(fields("op", "1 BOOTREQUEST", "xid", xid + "  (same transaction)", "ciaddr", "0.0.0.0  (not configured yet)", "option 50", m.group(1) + "  (requested IP)",
                    "option 54", m.group(2) + "  (server identifier: tells the other servers they lost)", "option 53", "3 = REQUEST"))));
        } else if ((m = DONE.matcher(line)).find()) {
            add(t, Json.obj("kind", "dhcp", "msg", "BOUND", "dir", "client", "ip", m.group(1),
                "fields", Json.raw(fields("address", m.group(1), "mask", m.group(2), "gateway", m.group(3), "DNS", m.group(4), "lease", m.group(5) + " s (renew at T1 = 50%)"))));
        } else if ((m = DECLINE.matcher(line)).find()) {
            add(t, Json.obj("kind", "dhcp", "msg", "DECLINE", "dir", "up", "node", lastNode, "ip", m.group(1), "src", "0.0.0.0:68", "dst", "255.255.255.255:67", "bcast", true,
                "fields", Json.raw(fields("op", "1 BOOTREQUEST", "option 53", "4 = DECLINE", "option 50", m.group(1) + "  (the address that is already in use)", "why", "the ARP check found another owner"))));
        } else if ((m = OFFER_RX.matcher(line)).find()) {
            /* the client-side receive of the OFFER: the node line above already represents it */
        }
    }

    // ------------------------------------------------------------------ ARP: frames the ARP lab's switch captured at ingress
    public synchronized void pollFrames() {
        for (arp.core.Hub.CapturedFrame f : arp.core.Hub.I.framesSince(frameMark)) {
            frameMark = f.seq;
            if (!f.isArp) continue;                               // IPv4 frames are the Telnet chunks, recorded separately
            byte[] r = f.rawBytes;
            int off = (r.length > 13 && (r[12] & 0xff) == 0x81 && r[13] == 0) ? 18 : 14;
            String op = "?", sha = "", spa = "", tha = "", tpa = "";
            if (r.length >= off + 28) {
                int o = ((r[off + 6] & 0xff) << 8) | (r[off + 7] & 0xff);
                op = o == 1 ? "REQUEST" : o == 2 ? "REPLY" : o == 3 ? "RARP REQUEST" : o == 4 ? "RARP REPLY" : String.valueOf(o);
                sha = mac(r, off + 8); spa = ip(r, off + 14); tha = mac(r, off + 18); tpa = ip(r, off + 24);
            }
            String kind = spa.equals("0.0.0.0") ? "PROBE" : (op.equals("REQUEST") && spa.equals(tpa)) || (op.equals("REPLY") && f.isBroadcast && spa.equals(tpa)) ? "GRATUITOUS" : op;
            add(f.timestampMs, Json.obj("kind", "arp", "op", op, "type", kind, "port", f.port, "src", f.srcMac, "dst", f.dstMac, "bcast", f.isBroadcast, "blocked", f.blockedByDai,
                "sha", sha, "spa", spa, "tha", tha, "tpa", tpa,
                "fields", Json.raw(fields("Ethernet dst", f.dstMac + (f.isBroadcast ? "  (broadcast: every port)" : "  (unicast)"), "Ethernet src", f.srcMac, "EtherType", "0x0806 ARP",
                    "operation", (op.equals("REQUEST") ? "1 = request" : op.equals("REPLY") ? "2 = reply" : op), "sender MAC / IP", sha + "  /  " + spa, "target MAC / IP", tha + "  /  " + tpa,
                    "switch", f.blockedByDai ? "DROPPED by Dynamic ARP Inspection (no matching DHCP-snooping binding)" : "forwarded"))));
        }
    }
    private static String mac(byte[] b, int o) { StringBuilder s = new StringBuilder(); for (int i = 0; i < 6; i++) { if (i > 0) s.append(':'); s.append(String.format("%02X", b[o + i] & 0xff)); } return s.toString(); }
    private static String ip(byte[] b, int o) { return (b[o] & 0xff) + "." + (b[o + 1] & 0xff) + "." + (b[o + 2] & 0xff) + "." + (b[o + 3] & 0xff); }

    // ------------------------------------------------------------------ Telnet: chunks through the LAN relay, as NVT tokens
    public synchronized void telnet(boolean toRouter, byte[] b, int n, boolean tls, int framePort, String clientIp) {
        long t = System.currentTimeMillis();
        if (telText != null && (telDir != toRouter || t - telT > 60 || telTokens.size() > 14)) flushTel(clientIp);
        if (telText == null) { telText = new StringBuilder(); telTokens = new ArrayList<>(); telDir = toRouter; telT = t; telBytes = 0; telPort = framePort; telTls = tls; }
        telBytes += n; telT = t;
        if (tls) { telTokens.add(Json.obj("k", "tls", "t", "TLS record (" + n + " bytes)")); return; }
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < n; i++) {
            int c = b[i] & 0xff;
            if (c == 255 && i + 1 < n) {
                if (text.length() > 0) { telTokens.add(Json.obj("k", "data", "t", text.toString())); telText.append(text); text.setLength(0); }
                int cmd = b[i + 1] & 0xff;
                if (cmd >= 251 && cmd <= 254 && i + 2 < n) { telTokens.add(Json.obj("k", "iac", "t", "IAC " + telnet.protocol.Telnet.cmdName(cmd) + " " + telnet.protocol.Telnet.optName(b[i + 2] & 0xff), "hex", String.format("FF %02X %02X", cmd, b[i + 2] & 0xff))); i += 2; }
                else if (cmd == 250) { int j = i + 2; while (j + 1 < n && !((b[j] & 0xff) == 255 && (b[j + 1] & 0xff) == 240)) j++; telTokens.add(Json.obj("k", "iac", "t", "IAC SB " + (i + 2 < n ? telnet.protocol.Telnet.optName(b[i + 2] & 0xff) : "") + " … IAC SE", "hex", "FF FA … FF F0")); i = j + 1; }
                else if (cmd == 255) { text.append('ÿ'); i++; }
                else { telTokens.add(Json.obj("k", "iac", "t", "IAC " + telnet.protocol.Telnet.cmdName(cmd), "hex", String.format("FF %02X", cmd))); i++; }
            } else if (c == '\r') text.append('⏎');
            else if (c == '\n' || c == 0) { /* CR LF / CR NUL: the NVT end of line */ }
            else if (c >= 0x20 && c < 0x7f) text.append((char) c);
        }
        if (text.length() > 0) { telTokens.add(Json.obj("k", "data", "t", text.toString())); telText.append(text); }
    }

    private void flushTel(String clientIp) {
        if (telText == null) return;
        String preview = telText.length() > 90 ? telText.substring(0, 90) + "…" : telText.toString();
        add(telT, Json.obj("kind", "tel", "dir", telDir ? "up" : "down", "tls", telTls, "bytes", telBytes, "port", telPort, "text", preview, "tokens", Json.raw(Json.arr(telTokens)),
            "fields", Json.raw(fields("TCP", (telDir ? clientIp + ":client → 192.168.1.1:23" : "192.168.1.1:23 → " + clientIp), "bytes", String.valueOf(telBytes),
                "Ethernet dst", telPort == 5 ? "66:66:66:66:66:66  (the attacker: the ARP cache is poisoned!)" : telDir ? "00:1A:2B:00:01:01  (the router)" : "the laptop", "content", telTls ? "encrypted TLS records" : "NVT text + IAC commands"))));
        telText = null; telTokens = null;
    }

    // ------------------------------------------------------------------ the replay of one step
    public synchronized long mark() { pollFrames(); flushTel(""); return seq; }

    public synchronized List<String> since(long mark, String clientIp) {
        pollFrames(); flushTel(clientIp == null ? "the laptop" : clientIp);
        List<Rec> l = new ArrayList<>();
        for (Rec r : recs) if (r.seq > mark) l.add(r);
        l.sort((a, b) -> a.t != b.t ? Long.compare(a.t, b.t) : Long.compare(a.seq, b.seq));
        List<String> out = new ArrayList<>();
        for (Rec r : l) out.add(r.json);
        return out;
    }

    private static String fields(String... kv) {
        List<String> l = new ArrayList<>();
        for (int i = 0; i + 1 < kv.length; i += 2) l.add(Json.obj("k", kv[i], "v", kv[i + 1]));
        return Json.arr(l);
    }

    static List<String> empty() { return Collections.emptyList(); }
}

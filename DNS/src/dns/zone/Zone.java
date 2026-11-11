package dns.zone;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import dns.wire.Message;
import dns.wire.Message.RR;

/**
 * One authoritative zone (everything at and below {@link #origin}, except delegated sub-zones).
 * Implements the authoritative half of RFC 1034 §4.3.2: answer, CNAME, referral with glue,
 * NXDOMAIN and NODATA (both carrying the SOA so resolvers can cache the negative answer).
 */
public final class Zone {

    public final String origin;            // "" = the root zone
    public final List<RR> records = new CopyOnWriteArrayList<>();

    public Zone(String origin) { this.origin = origin.toLowerCase(); }

    public Zone add(String name, int type, long ttl, String data) {
        String n = name.equals("@") ? origin : name.toLowerCase();
        records.add(new RR(n, type, ttl, data));
        return this;
    }

    public boolean remove(String name, int type, String data) {
        return records.removeIf(r -> r.name.equals(name.toLowerCase()) && r.type == type && (data == null || r.data.equalsIgnoreCase(data)));
    }

    public boolean contains(String qname) { return under(qname.toLowerCase(), origin); }

    public static boolean under(String name, String zone) { return zone.isEmpty() || name.equals(zone) || name.endsWith("." + zone); }

    public RR soa() { for (RR r : records) if (r.type == Message.SOA && r.name.equals(origin)) return r; return null; }

    /** Negative-caching TTL: min(SOA TTL, SOA MINIMUM) — RFC 2308. */
    public RR negativeSoa() {
        RR s = soa(); if (s == null) return null;
        String[] p = s.data.split("\\s+");
        return s.withTtl(Math.min(s.ttl, Long.parseLong(p[6])));
    }

    List<RR> at(String name, int type) {
        List<RR> l = new ArrayList<>();
        for (RR r : records) if (r.name.equals(name) && (type == Message.ANY || r.type == type)) l.add(r);
        return l;
    }
    boolean exists(String name) {
        for (RR r : records) if (r.name.equals(name) || r.name.endsWith("." + name)) return true;   // incl. empty non-terminals
        return false;
    }

    /** Build the authoritative server's response to {@code q}. */
    public Message answer(Message q) {
        Message r = q.reply();
        if (q.qd.isEmpty()) { r.rcode = Message.FORMERR; return r; }
        String qn = q.qd.get(0).name.toLowerCase();
        int qt = q.qd.get(0).type;
        if (!contains(qn)) { r.rcode = Message.REFUSED; return r; }

        // 1. delegation? walk from just below the origin down to the name
        String[] ql = qn.isEmpty() ? new String[0] : qn.split("\\.");
        int ol = origin.isEmpty() ? 0 : origin.split("\\.").length;
        for (int k = ol + 1; k <= ql.length; k++) {
            String cut = join(ql, ql.length - k);
            List<RR> nsr = at(cut, Message.NS);
            if (!nsr.isEmpty()) {
                r.ns.addAll(nsr);
                for (RR n : nsr) glue(n.target(), r.ar);
                return r;                                   // referral: AA=0, no answer
            }
        }

        // 2. authoritative data
        r.aa = true;
        String name = qn;
        for (int hop = 0; hop < 8; hop++) {
            List<RR> match = at(name, qt);
            if (!match.isEmpty()) {
                r.an.addAll(match);
                for (RR m : match) if (m.type == Message.MX || m.type == Message.NS) glue(m.target(), r.ar);
                return r;
            }
            List<RR> cn = at(name, Message.CNAME);
            if (!cn.isEmpty() && qt != Message.CNAME) {
                r.an.add(cn.get(0));
                name = cn.get(0).target();
                if (!contains(name)) return r;              // target lives elsewhere: resolver follows it
                continue;
            }
            if (hop == 0) {
                if (!exists(name)) r.rcode = Message.NXDOMAIN; // the name does not exist at all
                RR s = negativeSoa(); if (s != null) r.ns.add(s); // else NODATA: name exists, type does not
            }
            return r;
        }
        return r;
    }

    private void glue(String host, List<RR> into) {
        if (host == null) return;
        for (RR r : records) if (r.name.equals(host) && (r.type == Message.A || r.type == Message.AAAA)) into.add(r);
    }

    private static String join(String[] l, int from) {
        StringBuilder b = new StringBuilder();
        for (int i = from; i < l.length; i++) b.append(i > from ? "." : "").append(l[i]);
        return b.toString();
    }

    /** BIND-style zone file text. */
    public String zoneFile() {
        StringBuilder b = new StringBuilder("$ORIGIN ").append(Message.fq(origin)).append('\n');
        RR s = soa();
        if (s != null) {
            String[] p = s.data.split("\\s+");
            b.append(String.format("@\t%d\tIN\tSOA\t%s. %s. (\n\t\t\t\t%s ; serial\n\t\t\t\t%s ; refresh\n\t\t\t\t%s ; retry\n\t\t\t\t%s ; expire\n\t\t\t\t%s ) ; negative-cache TTL\n",
                    s.ttl, p[0], p[1], p[2], p[3], p[4], p[5], p[6]));
        }
        for (RR r : records) {
            if (r.type == Message.SOA) continue;
            String rel = r.name.equals(origin) ? "@" : origin.isEmpty() ? r.name + "." : r.name.endsWith("." + origin) ? r.name.substring(0, r.name.length() - origin.length() - 1) : r.name + ".";
            String data = r.data;
            if (r.type == Message.NS || r.type == Message.CNAME || r.type == Message.PTR) data = data + ".";
            if (r.type == Message.MX) data = data + ".";
            b.append(String.format("%-14s\t%d\tIN\t%-5s\t%s\n", rel, r.ttl, Message.typeName(r.type), data));
        }
        return b.toString();
    }
}

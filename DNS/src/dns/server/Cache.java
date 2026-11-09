package dns.server;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import dns.core.Json;
import dns.wire.Message;
import dns.wire.Message.RR;

/**
 * The resolver's cache. Each RRset lives for its TTL; records handed out carry the remaining TTL
 * (that is why a second lookup shows a smaller number). Negative answers (NXDOMAIN / NODATA) are
 * cached for the SOA minimum (RFC 2308). Two views keep the lab hierarchy and the real Internet apart.
 */
public final class Cache {

    public static final long MAX_TTL = 86400;

    public static final class Entry {
        public final String view, name; public final int type; public final List<RR> rrs; public final int rcode;
        public final long stored, expires, ttl; public final String source;
        Entry(String view, String name, int type, List<RR> rrs, int rcode, long ttl, String source) {
            this.view = view; this.name = name; this.type = type; this.rrs = rrs; this.rcode = rcode; this.ttl = ttl; this.source = source;
            this.stored = System.currentTimeMillis(); this.expires = stored + ttl * 1000;
        }
        public boolean negative() { return rrs.isEmpty(); }
        public long left() { return Math.max(0, (expires - System.currentTimeMillis() + 999) / 1000); }
        public String json() {
            List<String> d = new ArrayList<>(); for (RR r : rrs) d.add(Json.str(r.data));
            return Json.obj("view", view, "name", name, "type", Message.typeName(type), "data", Json.raw("[" + String.join(",", d) + "]"),
                    "rcode", Message.rcodeName(rcode), "ttl", ttl, "left", left(), "negative", negative(), "source", source, "age", (System.currentTimeMillis() - stored) / 1000);
        }
    }

    private final Map<String, Entry> map = new ConcurrentHashMap<>();
    public volatile long hits, misses;

    private static String key(String view, String name, int type) { return view + "|" + name.toLowerCase() + "|" + type; }

    public void put(String view, String name, int type, List<RR> rrs, String source) {
        if (rrs.isEmpty()) return;
        long ttl = MAX_TTL; for (RR r : rrs) ttl = Math.min(ttl, r.ttl);
        map.put(key(view, name, type), new Entry(view, name.toLowerCase(), type, new ArrayList<>(rrs), 0, ttl, source));
    }

    public void putNegative(String view, String name, int type, int rcode, long ttl, String source) {
        map.put(key(view, name, type), new Entry(view, name.toLowerCase(), type, new ArrayList<>(), rcode, Math.min(ttl, 3600), source));
    }

    /** A live entry, with each record's TTL reduced to what is left; null if absent or expired. */
    public Entry get(String view, String name, int type) {
        String k = key(view, name, type);
        Entry e = map.get(k);
        if (e == null) return null;
        long left = e.left();
        if (left <= 0) { map.remove(k); return null; }
        List<RR> rr = new ArrayList<>(); for (RR r : e.rrs) rr.add(r.withTtl(left));
        Entry c = new Entry(e.view, e.name, e.type, rr, e.rcode, e.ttl, e.source);
        return c;
    }
    public Entry raw(String view, String name, int type) { return map.get(key(view, name, type)); }

    public List<Entry> list() {
        List<Entry> l = new ArrayList<>();
        for (Map.Entry<String, Entry> me : map.entrySet()) { if (me.getValue().left() <= 0) map.remove(me.getKey()); else l.add(me.getValue()); }
        l.sort(Comparator.comparing((Entry e) -> e.view).thenComparing(e -> rev(e.name)).thenComparing(e -> e.type));
        return l;
    }
    private static String rev(String n) { String[] p = n.split("\\."); StringBuilder b = new StringBuilder(); for (int i = p.length - 1; i >= 0; i--) b.append(p[i]).append('.'); return b.toString(); }

    public void flush() { map.clear(); hits = 0; misses = 0; }
    public void removeName(String name) { String n = name.toLowerCase(); map.values().removeIf(e -> e.name.equals(n)); }
    public int size() { return map.size(); }
}

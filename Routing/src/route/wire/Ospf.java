package route.wire;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * OSPFv2 Link State Update packets carrying Router-LSAs (RFC 2328 §A.3.1, §A.3.5, §A.4.1, §A.4.2).
 * Real OSPF runs directly on IP (protocol 89); Java has no raw sockets, so the lab carries the same bytes inside UDP.
 *
 *   OSPF header (24): version 2 · type 4 (LS Update) · length · router ID · area ID · checksum · AuType · authentication(8)
 *   #LSAs (4)
 *   Router-LSA header (20): LS age · options · LS type 1 · link state ID · advertising router · LS sequence number · LS checksum (Fletcher) · length
 *   Router-LSA body: flags · 0 · #links, then per link: link ID · link data · type 1 (point-to-point) · #TOS 0 · metric
 */
public final class Ospf {
    private Ospf() { }

    public static final int INITIAL_SEQ = 0x80000001;

    public static final class Lsa {
        public final int origin; public final int seq; public final int[][] links;   // links[i] = {neighbour, cost}
        public int age;
        public Lsa(int origin, int seq, int[][] links) { this.origin = origin; this.seq = seq; this.links = links; }
    }

    public static int routerId(int node) { return (10 << 24) | (255 << 16) | (node + 1); }   // 10.255.0.N
    public static int nodeOf(int rid) { return (rid & 0xff) - 1; }
    static int ifaceAddr(int a, int b) { return (10 << 24) | (254 << 16) | ((Math.min(a, b) + 1) << 8) | ((Math.max(a, b) + 1) * 10 + (a < b ? 1 : 2)); }

    public static byte[] lsa(Lsa l) {
        int len = 20 + 4 + 12 * l.links.length;
        ByteBuffer b = ByteBuffer.allocate(len);
        b.putShort((short) l.age).put((byte) 0x02).put((byte) 1).putInt(routerId(l.origin)).putInt(routerId(l.origin)).putInt(l.seq).putShort((short) 0).putShort((short) len);
        b.put((byte) 0).put((byte) 0).putShort((short) l.links.length);
        for (int[] k : l.links) b.putInt(routerId(k[0])).putInt(ifaceAddr(l.origin, k[0])).put((byte) 1).put((byte) 0).putShort((short) k[1]);
        byte[] a = b.array();
        int ck = fletcher(a, 2, len - 2, 14);
        a[16] = (byte) (ck >> 8); a[17] = (byte) ck;
        return a;
    }

    /** ISO 8473 / RFC 905 Fletcher checksum, as OSPF uses it for LSAs (LS age excluded). */
    public static int fletcher(byte[] buf, int off, int len, int ckPos) {
        int c0 = 0, c1 = 0;
        for (int i = 0; i < len; i++) {
            int v = (i == ckPos || i == ckPos + 1) ? 0 : buf[off + i] & 0xff;
            c0 = (c0 + v) % 255; c1 = (c1 + c0) % 255;
        }
        int x = ((len - ckPos - 1) * c0 - c1) % 255; if (x <= 0) x += 255;
        int y = 510 - c0 - x; if (y > 255) y -= 255;
        return (x << 8) | y;
    }

    public static boolean fletcherOk(byte[] lsa) {
        int c0 = 0, c1 = 0;
        for (int i = 2; i < lsa.length; i++) { c0 = (c0 + (lsa[i] & 0xff)) % 255; c1 = (c1 + c0) % 255; }
        return c0 == 0 && c1 == 0;
    }

    public static byte[] update(int fromNode, List<Lsa> lsas) {
        List<byte[]> bodies = new ArrayList<>(); int n = 0;
        for (Lsa l : lsas) { byte[] x = lsa(l); bodies.add(x); n += x.length; }
        int len = 24 + 4 + n;
        ByteBuffer b = ByteBuffer.allocate(len);
        b.put((byte) 2).put((byte) 4).putShort((short) len).putInt(routerId(fromNode)).putInt(0).putShort((short) 0).putShort((short) 0).putLong(0);
        b.putInt(lsas.size());
        for (byte[] x : bodies) b.put(x);
        byte[] a = b.array();
        int ck = ipChecksum(a);
        a[12] = (byte) (ck >> 8); a[13] = (byte) ck;
        return a;
    }

    public static int ipChecksum(byte[] a) {
        long s = 0;
        for (int i = 0; i + 1 < a.length; i += 2) s += ((a[i] & 0xff) << 8) | (a[i + 1] & 0xff);
        if ((a.length & 1) == 1) s += (a[a.length - 1] & 0xff) << 8;
        while ((s >> 16) != 0) s = (s & 0xffff) + (s >> 16);
        return (int) (~s & 0xffff);
    }

    public static List<Lsa> parse(byte[] p) {
        ByteBuffer b = ByteBuffer.wrap(p);
        if (b.get() != 2 || b.get() != 4) throw new IllegalArgumentException("not an OSPFv2 LS Update");
        if (ipChecksum(p) != 0) throw new IllegalArgumentException("bad OSPF packet checksum");
        b.position(24);
        int count = b.getInt();
        List<Lsa> out = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            int start = b.position();
            int age = b.getShort() & 0xffff; b.get(); b.get(); b.getInt(); int adv = b.getInt(); int seq = b.getInt(); b.getShort(); int len = b.getShort() & 0xffff;
            byte[] raw = new byte[len]; System.arraycopy(p, start, raw, 0, len);
            if (!fletcherOk(raw)) throw new IllegalArgumentException("bad LSA checksum");
            b.get(); b.get(); int nl = b.getShort() & 0xffff;
            int[][] links = new int[nl][];
            for (int k = 0; k < nl; k++) { int id = b.getInt(); b.getInt(); b.get(); b.get(); int m = b.getShort() & 0xffff; links[k] = new int[] { nodeOf(id), m }; }
            Lsa l = new Lsa(nodeOf(adv), seq, links); l.age = age; out.add(l);
        }
        return out;
    }

    public static List<String[]> fields(byte[] p, String[] names) {
        List<String[]> f = new ArrayList<>();
        ByteBuffer b = ByteBuffer.wrap(p);
        f.add(new String[] { "0", "1", "version", "2 = OSPFv2" });
        f.add(new String[] { "1", "1", "type", "4 = Link State Update" });
        f.add(new String[] { "2", "2", "packet length", "" + (b.getShort(2) & 0xffff) });
        f.add(new String[] { "4", "4", "router ID", Rip.ip(b.getInt(4)) + "  (" + name(names, nodeOf(b.getInt(4))) + ")" });
        f.add(new String[] { "8", "4", "area ID", "0.0.0.0  (backbone)" });
        f.add(new String[] { "12", "2", "checksum", String.format("0x%04x  (one's complement, like IP)", b.getShort(12) & 0xffff) });
        f.add(new String[] { "14", "2", "AuType", "0 = no authentication" });
        f.add(new String[] { "16", "8", "authentication", "0" });
        f.add(new String[] { "24", "4", "# LSAs", "" + b.getInt(24) });
        int o = 28, n = b.getInt(24);
        for (int i = 0; i < n; i++) {
            int len = b.getShort(o + 18) & 0xffff;
            f.add(new String[] { "" + o, "2", "LSA " + (i + 1) + ": LS age", (b.getShort(o) & 0xffff) + " s" });
            f.add(new String[] { "" + (o + 2), "1", "options", "0x02 (E-bit)" });
            f.add(new String[] { "" + (o + 3), "1", "LS type", "1 = Router-LSA" });
            f.add(new String[] { "" + (o + 4), "4", "link state ID", Rip.ip(b.getInt(o + 4)) });
            f.add(new String[] { "" + (o + 8), "4", "advertising router", Rip.ip(b.getInt(o + 8)) + "  (" + name(names, nodeOf(b.getInt(o + 8))) + ")" });
            f.add(new String[] { "" + (o + 12), "4", "LS sequence number", String.format("0x%08x  (higher = newer)", b.getInt(o + 12)) });
            f.add(new String[] { "" + (o + 16), "2", "LS checksum", String.format("0x%04x  (Fletcher, age excluded)", b.getShort(o + 16) & 0xffff) });
            f.add(new String[] { "" + (o + 18), "2", "length", "" + len });
            int nl = b.getShort(o + 22) & 0xffff;
            f.add(new String[] { "" + (o + 20), "4", "flags · #links", nl + " link" + (nl == 1 ? "" : "s") });
            for (int k = 0; k < nl; k++) {
                int lo = o + 24 + 12 * k;
                f.add(new String[] { "" + lo, "12", "  link " + (k + 1), "to " + name(names, nodeOf(b.getInt(lo))) + " (" + Rip.ip(b.getInt(lo)) + "), point-to-point, metric " + (b.getShort(lo + 10) & 0xffff) });
            }
            o += len;
        }
        return f;
    }
    static String name(String[] n, int i) { return i >= 0 && i < n.length ? n[i] : "?"; }
}

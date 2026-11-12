package route.wire;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * RIP version 2 messages (RFC 2453 §4). Sent over UDP port 520.
 *
 *   command(1)=2 response · version(1)=2 · must-be-zero(2)
 *   then up to 25 route entries of 20 bytes:
 *   AFI(2)=2 · route tag(2) · IP address(4) · subnet mask(4) · next hop(4) · metric(4, 1..16, 16 = unreachable)
 */
public final class Rip {
    private Rip() { }

    public static final int INFINITY = 16;

    public static final class Entry {
        public final int dest; public final int metric;
        public Entry(int dest, int metric) { this.dest = dest; this.metric = metric; }
    }

    /** Each lab router "owns" one destination network: router i ↔ 10.0.(i+1).0/24. */
    public static int network(int node) { return (10 << 24) | ((node + 1) << 8); }
    public static int nodeOf(int network) { return ((network >> 8) & 0xff) - 1; }

    public static byte[] response(List<Entry> entries) {
        ByteBuffer b = ByteBuffer.allocate(4 + 20 * entries.size());
        b.put((byte) 2).put((byte) 2).putShort((short) 0);
        for (Entry e : entries) {
            b.putShort((short) 2).putShort((short) 0).putInt(network(e.dest)).putInt(0xffffff00).putInt(0).putInt(e.metric);
        }
        return b.array();
    }

    public static List<Entry> parse(byte[] p) {
        ByteBuffer b = ByteBuffer.wrap(p);
        if (b.get() != 2 || b.get() != 2) throw new IllegalArgumentException("not a RIPv2 response");
        b.getShort();
        List<Entry> l = new ArrayList<>();
        while (b.remaining() >= 20) {
            b.getShort(); b.getShort();
            int net = b.getInt(); b.getInt(); b.getInt(); int metric = b.getInt();
            l.add(new Entry(nodeOf(net), metric));
        }
        return l;
    }

    /** Field-by-field description for the packet inspector. */
    public static List<String[]> fields(byte[] p, String[] names) {
        List<String[]> f = new ArrayList<>();
        f.add(new String[] { "0", "1", "command", "2 = response (a routing update)" });
        f.add(new String[] { "1", "1", "version", "2 = RIPv2" });
        f.add(new String[] { "2", "2", "must be zero", "0" });
        ByteBuffer b = ByteBuffer.wrap(p); b.position(4);
        int i = 0;
        while (b.remaining() >= 20) {
            int o = 4 + 20 * i;
            b.getShort(); b.getShort(); int net = b.getInt(); int mask = b.getInt(); b.getInt(); int metric = b.getInt();
            int node = nodeOf(net);
            f.add(new String[] { "" + o, "2", "entry " + (i + 1) + ": AFI", "2 = IPv4" });
            f.add(new String[] { "" + (o + 2), "2", "route tag", "0" });
            f.add(new String[] { "" + (o + 4), "4", "IP address", ip(net) + "  (router " + (node >= 0 && node < names.length ? names[node] : "?") + "'s network)" });
            f.add(new String[] { "" + (o + 8), "4", "subnet mask", ip(mask) + "  (/24)" });
            f.add(new String[] { "" + (o + 12), "4", "next hop", "0.0.0.0  (= send it to me)" });
            f.add(new String[] { "" + (o + 16), "4", "metric", metric + (metric >= INFINITY ? "  (16 = infinity: unreachable)" : "") });
            i++;
        }
        return f;
    }

    public static String ip(int a) { return ((a >>> 24) & 0xff) + "." + ((a >>> 16) & 0xff) + "." + ((a >>> 8) & 0xff) + "." + (a & 0xff); }
}

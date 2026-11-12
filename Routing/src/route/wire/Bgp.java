package route.wire;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * BGP-4 messages (RFC 4271 §4). Carried over TCP port 179.
 *
 *   header (19): marker 16 × 0xFF · length(2) · type(1): 1 OPEN, 2 UPDATE, 3 NOTIFICATION, 4 KEEPALIVE
 *   OPEN: version 4 · my AS(2) · hold time(2) · BGP identifier(4) · opt-param length(1)
 *   UPDATE: withdrawn-routes length(2) · withdrawn prefixes · path-attribute length(2) · attributes · NLRI prefixes
 *           attributes used: ORIGIN (1), AS_PATH (2, one AS_SEQUENCE segment of 2-byte AS numbers), NEXT_HOP (3)
 */
public final class Bgp {
    private Bgp() { }

    public static final int PREFIX = (10 << 24) | (4 << 16), PREFIX_LEN = 16;     // 10.4.0.0/16, the network AS 400 originates

    public static byte[] header(int type, int bodyLen) {
        ByteBuffer b = ByteBuffer.allocate(19 + bodyLen);
        for (int i = 0; i < 16; i++) b.put((byte) 0xff);
        b.putShort((short) (19 + bodyLen)).put((byte) type);
        return b.array();
    }

    public static byte[] open(int as, int id) {
        byte[] a = header(1, 10);
        ByteBuffer.wrap(a, 19, 10).put((byte) 4).putShort((short) as).putShort((short) 180).putInt(id).put((byte) 0);
        return a;
    }

    public static byte[] keepalive() { return header(4, 0); }

    /** An announcement of 10.4.0.0/16 with the given AS_PATH, or (path == null) a withdrawal. */
    public static byte[] update(List<Integer> path, int nextHop) {
        if (path == null) {
            byte[] a = header(2, 2 + 3 + 2);
            ByteBuffer.wrap(a, 19, 7).putShort((short) 3).put((byte) PREFIX_LEN).put((byte) 10).put((byte) 4).putShort((short) 0);
            return a;
        }
        int asPathLen = 2 + 2 * path.size();
        int attrs = (3 + 1) + (3 + asPathLen) + (3 + 4);
        int body = 2 + 2 + attrs + 3;
        byte[] a = header(2, body);
        ByteBuffer b = ByteBuffer.wrap(a, 19, body);
        b.putShort((short) 0).putShort((short) attrs);
        b.put((byte) 0x40).put((byte) 1).put((byte) 1).put((byte) 0);                        // ORIGIN = IGP
        b.put((byte) 0x40).put((byte) 2).put((byte) asPathLen).put((byte) 2).put((byte) path.size());
        for (int as : path) b.putShort((short) as);                                            // AS_PATH: AS_SEQUENCE
        b.put((byte) 0x40).put((byte) 3).put((byte) 4).putInt(nextHop);                       // NEXT_HOP
        b.put((byte) PREFIX_LEN).put((byte) 10).put((byte) 4);                                // NLRI: 10.4.0.0/16
        return a;
    }

    /** Parsed UPDATE: path == null means the route was withdrawn. */
    public static final class Update { public List<Integer> path; public boolean withdraw; public int nextHop; }

    public static int type(byte[] m) { return m[18] & 0xff; }

    public static Update parseUpdate(byte[] m) {
        for (int i = 0; i < 16; i++) if (m[i] != (byte) 0xff) throw new IllegalArgumentException("bad marker");
        if (type(m) != 2) throw new IllegalArgumentException("not an UPDATE");
        ByteBuffer b = ByteBuffer.wrap(m); b.position(19);
        Update u = new Update();
        int wl = b.getShort() & 0xffff;
        if (wl > 0) { b.position(b.position() + wl); u.withdraw = true; }
        int al = b.getShort() & 0xffff, end = b.position() + al;
        while (b.position() < end) {
            int flags = b.get() & 0xff, type = b.get() & 0xff;
            int len = (flags & 0x10) != 0 ? b.getShort() & 0xffff : b.get() & 0xff;
            int start = b.position();
            if (type == 2) {
                List<Integer> p = new ArrayList<>();
                while (b.position() < start + len) { b.get(); int n = b.get() & 0xff; for (int i = 0; i < n; i++) p.add(b.getShort() & 0xffff); }
                u.path = p;
            } else if (type == 3) u.nextHop = b.getInt();
            b.position(start + len);
        }
        if (b.remaining() > 0 && u.path != null) u.withdraw = false;
        return u;
    }

    public static List<String[]> fields(byte[] m) {
        List<String[]> f = new ArrayList<>();
        ByteBuffer b = ByteBuffer.wrap(m);
        f.add(new String[] { "0", "16", "marker", "ff × 16" });
        f.add(new String[] { "16", "2", "length", "" + (b.getShort(16) & 0xffff) });
        int t = type(m);
        f.add(new String[] { "18", "1", "type", t + (t == 1 ? " = OPEN" : t == 2 ? " = UPDATE" : t == 4 ? " = KEEPALIVE" : "") });
        if (t == 1) {
            f.add(new String[] { "19", "1", "version", "4" });
            f.add(new String[] { "20", "2", "my AS", "" + (b.getShort(20) & 0xffff) });
            f.add(new String[] { "22", "2", "hold time", (b.getShort(22) & 0xffff) + " s" });
            f.add(new String[] { "24", "4", "BGP identifier", Rip.ip(b.getInt(24)) });
            f.add(new String[] { "28", "1", "opt. param length", "0" });
        } else if (t == 2) {
            int wl = b.getShort(19) & 0xffff;
            f.add(new String[] { "19", "2", "withdrawn routes length", "" + wl });
            if (wl > 0) f.add(new String[] { "21", "" + wl, "withdrawn routes", "10.4.0.0/16  (no longer reachable through me)" });
            int ao = 21 + wl, al = b.getShort(ao) & 0xffff;
            f.add(new String[] { "" + ao, "2", "total path attribute length", "" + al });
            int o = ao + 2;
            while (o < ao + 2 + al) {
                int type = b.get(o + 1) & 0xff, len = b.get(o + 2) & 0xff;
                String v;
                if (type == 1) v = "ORIGIN = IGP";
                else if (type == 2) { StringBuilder s = new StringBuilder("AS_PATH = AS_SEQUENCE ["); int n = b.get(o + 4) & 0xff; for (int i = 0; i < n; i++) s.append(i > 0 ? " " : "").append(b.getShort(o + 5 + 2 * i) & 0xffff); v = s.append("]").toString(); }
                else if (type == 3) v = "NEXT_HOP = " + Rip.ip(b.getInt(o + 3));
                else v = "type " + type;
                f.add(new String[] { "" + o, "" + (3 + len), "path attribute", v + "  (flags 0x40 = well-known transitive)" });
                o += 3 + len;
            }
            if (o < m.length) f.add(new String[] { "" + o, "" + (m.length - o), "NLRI", "10.4.0.0/16  (reachable through me)" });
        }
        return f;
    }
}

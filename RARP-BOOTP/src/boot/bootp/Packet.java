package boot.bootp;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import boot.core.Field;

/**
 * A BOOTP message (RFC 951, 1985; relay rules RFC 1542; vendor extensions RFC 1497). Always 300 bytes:
 *
 *   op(1) htype(1) hlen(1) hops(1) | xid(4) | secs(2) flags(2) | ciaddr yiaddr siaddr giaddr (4 each)
 *   chaddr(16) | sname(64) | file(128) | vend(64) = magic cookie 99.130.83.99 + options
 *
 * DHCP (1993) later reused exactly this layout, which is why DHCP servers still answer BOOTP clients.
 */
public final class Packet {

    public static final int SIZE = 300, BOOTREQUEST = 1, BOOTREPLY = 2;
    public static final byte[] COOKIE = {99, (byte) 130, 83, 99};
    public static final int OPT_PAD = 0, OPT_MASK = 1, OPT_ROUTER = 3, OPT_DNS = 6, OPT_HOST = 12, OPT_END = 255;

    public int op = BOOTREQUEST, hops, secs, flags;
    public long xid;
    public String ciaddr = "0.0.0.0", yiaddr = "0.0.0.0", siaddr = "0.0.0.0", giaddr = "0.0.0.0", chaddr = "00:00:00:00:00:00", sname = "", file = "";
    public final Map<Integer, byte[]> options = new LinkedHashMap<>();

    public byte[] encode() {
        byte[] b = new byte[SIZE];
        b[0] = (byte) op; b[1] = 1; b[2] = 6; b[3] = (byte) hops;
        b[4] = (byte) (xid >> 24); b[5] = (byte) (xid >> 16); b[6] = (byte) (xid >> 8); b[7] = (byte) xid;
        b[8] = (byte) (secs >> 8); b[9] = (byte) secs; b[10] = (byte) (flags >> 8); b[11] = (byte) flags;
        put(b, 12, Field.ipBytes(ciaddr)); put(b, 16, Field.ipBytes(yiaddr)); put(b, 20, Field.ipBytes(siaddr)); put(b, 24, Field.ipBytes(giaddr));
        put(b, 28, Field.macBytes(chaddr));
        str(b, 44, 64, sname); str(b, 108, 128, file);
        put(b, 236, COOKIE);
        int p = 240;
        for (Map.Entry<Integer, byte[]> o : options.entrySet()) {
            if (p + 2 + o.getValue().length >= SIZE) break;
            b[p++] = (byte) (int) o.getKey(); b[p++] = (byte) o.getValue().length; put(b, p, o.getValue()); p += o.getValue().length;
        }
        b[p] = (byte) OPT_END;
        return b;
    }
    private static void put(byte[] b, int o, byte[] v) { System.arraycopy(v, 0, b, o, v.length); }
    private static void str(byte[] b, int o, int max, String s) { byte[] v = s.getBytes(StandardCharsets.US_ASCII); System.arraycopy(v, 0, b, o, Math.min(v.length, max - 1)); }
    private static String cstr(byte[] b, int o, int max) { int e = o; while (e < o + max && b[e] != 0) e++; return new String(b, o, e - o, StandardCharsets.US_ASCII); }

    public static Packet decode(byte[] b, int len) {
        if (len < 240) throw new IllegalArgumentException("BOOTP packet shorter than 240 bytes");
        Packet p = new Packet();
        p.op = b[0] & 0xFF; p.hops = b[3] & 0xFF; p.xid = Field.u32(b, 4); p.secs = Field.u16(b, 8); p.flags = Field.u16(b, 10);
        p.ciaddr = Field.ip(b, 12); p.yiaddr = Field.ip(b, 16); p.siaddr = Field.ip(b, 20); p.giaddr = Field.ip(b, 24);
        p.chaddr = Field.mac(b, 28); p.sname = cstr(b, 44, 64); p.file = cstr(b, 108, 128);
        if (len > 240 && b[236] == 99 && (b[237] & 0xFF) == 130 && b[238] == 83 && b[239] == 99) {
            int i = 240;
            while (i < len) {
                int c = b[i] & 0xFF;
                if (c == OPT_END) break;
                if (c == OPT_PAD) { i++; continue; }
                if (i + 1 >= len) break;
                int l = b[i + 1] & 0xFF;
                if (i + 2 + l > len) break;
                byte[] v = new byte[l]; System.arraycopy(b, i + 2, v, 0, l);
                p.options.put(c, v); i += 2 + l;
            }
        }
        return p;
    }

    public static String optName(int c) {
        switch (c) { case OPT_MASK: return "Subnet mask"; case OPT_ROUTER: return "Router"; case OPT_DNS: return "DNS server"; case OPT_HOST: return "Host name"; default: return "Option " + c; }
    }
    public static String optValue(int c, byte[] v) {
        if (c == OPT_HOST) return new String(v, StandardCharsets.US_ASCII);
        if (v.length % 4 == 0 && (c == OPT_MASK || c == OPT_ROUTER || c == OPT_DNS)) { StringBuilder s = new StringBuilder(); for (int i = 0; i < v.length; i += 4) s.append(i > 0 ? ", " : "").append(Field.ip(v, i)); return s.toString(); }
        return Field.hex(v);
    }

    /** Every field's byte span and meaning, for the dashboard's packet view. */
    public static List<Field> dissect(byte[] b) {
        Packet p = decode(b, b.length);
        List<Field> f = new ArrayList<>();
        f.add(new Field(0, 1, "header", "op", p.op + (p.op == 1 ? " = BOOTREQUEST (client → server)" : " = BOOTREPLY (server → client)")));
        f.add(new Field(1, 1, "header", "htype", (b[1] & 0xFF) + " = Ethernet"));
        f.add(new Field(2, 1, "header", "hlen", (b[2] & 0xFF) + " = MAC length"));
        f.add(new Field(3, 1, "header", "hops", p.hops + (p.hops > 0 ? " (incremented by each relay agent on the way)" : " (0 = sent on the client's own LAN)")));
        f.add(new Field(4, 4, "header", "xid", String.format("0x%08x: random transaction ID, matches the reply to the request", p.xid)));
        f.add(new Field(8, 2, "header", "secs", p.secs + " s since the client started booting"));
        f.add(new Field(10, 2, "header", "flags", String.format("0x%04x (unused in RFC 951; RFC 1542 broadcast bit)", p.flags)));
        f.add(new Field(12, 4, "addresses", "ciaddr", p.ciaddr + "  client IP if it already knows it"));
        f.add(new Field(16, 4, "addresses", "yiaddr", p.yiaddr + (p.op == 2 ? "  ← \"your\" IP: the answer" : "  (filled in by the server)")));
        f.add(new Field(20, 4, "addresses", "siaddr", p.siaddr + (p.op == 2 ? "  boot server IP (where to fetch the boot file by TFTP)" : "")));
        f.add(new Field(24, 4, "addresses", "giaddr", p.giaddr + (p.giaddr.equals("0.0.0.0") ? "  (no relay agent)" : "  ← set by the relay agent: the client's LAN, and where to send the reply")));
        f.add(new Field(28, 16, "addresses", "chaddr", p.chaddr + "  client MAC (+10 bytes padding)"));
        f.add(new Field(44, 64, "names", "sname", p.sname.isEmpty() ? "(empty) optional server host name" : p.sname));
        f.add(new Field(108, 128, "names", "file", p.file.isEmpty() ? "(empty) boot file name" : p.file + "  ← boot image to download with TFTP"));
        f.add(new Field(236, 4, "vend", "magic cookie", "99.130.83.99: the vendor area holds RFC 1497 options"));
        int i = 240;
        while (i < b.length) {
            int c = b[i] & 0xFF;
            if (c == OPT_END) { f.add(new Field(i, 1, "vend", "end", "255 = end of options")); i++; break; }
            if (c == OPT_PAD) { i++; continue; }
            int l = b[i + 1] & 0xFF; byte[] v = new byte[l]; System.arraycopy(b, i + 2, v, 0, l);
            f.add(new Field(i, 2 + l, "vend", optName(c), "code " + c + ", len " + l + ": " + optValue(c, v)));
            i += 2 + l;
        }
        if (i < SIZE) f.add(new Field(i, SIZE - i, "pad", "padding", (SIZE - i) + " zero bytes: a BOOTP message is always 300 bytes"));
        return f;
    }

    public String summary() {
        return (op == 1 ? "BOOTREQUEST" : "BOOTREPLY") + String.format(" xid=0x%08x chaddr=%s", xid, chaddr)
                + (op == 2 ? " yiaddr=" + yiaddr + " siaddr=" + siaddr + " file=" + file : "")
                + (giaddr.equals("0.0.0.0") ? "" : " giaddr=" + giaddr) + (hops > 0 ? " hops=" + hops : "");
    }
}

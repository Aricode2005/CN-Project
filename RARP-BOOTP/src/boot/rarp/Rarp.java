package boot.rarp;

import java.util.ArrayList;
import java.util.List;
import boot.core.Field;

/**
 * RARP (RFC 903, 1984) inside an Ethernet II frame.
 *
 *  Ethernet: dst MAC (6) | src MAC (6) | EtherType 0x8035 (2)
 *  RARP:     HTYPE 1 (2) | PTYPE 0x0800 (2) | HLEN 6 | PLEN 4 | OPER (2)
 *            SHA (6) | SPA (4) | THA (6) | TPA (4)            = 28 bytes, the same layout as ARP
 *  padded to the 60-byte Ethernet minimum.
 *
 * ARP uses EtherType 0x0806 and opcodes 1/2 ("what MAC has this IP?");
 * RARP uses 0x8035 and opcodes 3/4 ("what IP belongs to my MAC?").
 */
public final class Rarp {

    public static final int ETH_ARP = 0x0806, ETH_RARP = 0x8035;
    public static final int REQUEST = 3, REPLY = 4;
    public static final String BROADCAST = "ff:ff:ff:ff:ff:ff";

    public static byte[] frame(String dst, String src, int op, String sha, String spa, String tha, String tpa) {
        byte[] f = new byte[60];                                 // zero padding to 60 bytes
        System.arraycopy(Field.macBytes(dst), 0, f, 0, 6);
        System.arraycopy(Field.macBytes(src), 0, f, 6, 6);
        f[12] = (byte) (ETH_RARP >> 8); f[13] = (byte) ETH_RARP;
        f[14] = 0; f[15] = 1;                                     // HTYPE 1 = Ethernet
        f[16] = 0x08; f[17] = 0x00;                               // PTYPE 0x0800 = IPv4
        f[18] = 6; f[19] = 4;                                     // HLEN, PLEN
        f[20] = 0; f[21] = (byte) op;
        System.arraycopy(Field.macBytes(sha), 0, f, 22, 6);
        System.arraycopy(Field.ipBytes(spa), 0, f, 28, 4);
        System.arraycopy(Field.macBytes(tha), 0, f, 32, 6);
        System.arraycopy(Field.ipBytes(tpa), 0, f, 38, 4);
        return f;
    }

    public static final class Decoded {
        public String dst, src, sha, spa, tha, tpa; public int type, op;
        public final List<Field> fields = new ArrayList<>();
    }

    public static Decoded decode(byte[] f) {
        Decoded d = new Decoded();
        d.dst = Field.mac(f, 0); d.src = Field.mac(f, 6); d.type = Field.u16(f, 12);
        d.op = Field.u16(f, 20);
        d.sha = Field.mac(f, 22); d.spa = Field.ip(f, 28); d.tha = Field.mac(f, 32); d.tpa = Field.ip(f, 38);
        List<Field> x = d.fields;
        x.add(new Field(0, 6, "ethernet", "Destination MAC", d.dst + (d.dst.equals(BROADCAST) ? "  (broadcast: every station on the LAN reads it)" : "  (unicast)")));
        x.add(new Field(6, 6, "ethernet", "Source MAC", d.src));
        x.add(new Field(12, 2, "ethernet", "EtherType", String.format("0x%04x = %s", d.type, d.type == ETH_RARP ? "RARP (not IP: RARP sits directly on Ethernet)" : d.type == ETH_ARP ? "ARP" : "?")));
        x.add(new Field(14, 2, "rarp", "HTYPE", Field.u16(f, 14) + " = Ethernet"));
        x.add(new Field(16, 2, "rarp", "PTYPE", String.format("0x%04x = IPv4", Field.u16(f, 16))));
        x.add(new Field(18, 1, "rarp", "HLEN", (f[18] & 0xFF) + " bytes per hardware address"));
        x.add(new Field(19, 1, "rarp", "PLEN", (f[19] & 0xFF) + " bytes per protocol address"));
        x.add(new Field(20, 2, "rarp", "OPER", d.op + (d.op == REQUEST ? " = reverse request (\"what is MY IP?\")" : d.op == REPLY ? " = reverse reply" : d.op == 1 ? " = ARP request" : " = ARP reply")));
        x.add(new Field(22, 6, "rarp", "Sender MAC (SHA)", d.sha));
        x.add(new Field(28, 4, "rarp", "Sender IP (SPA)", d.spa + (d.spa.equals("0.0.0.0") ? "  (unknown: that is the whole problem)" : "")));
        x.add(new Field(32, 6, "rarp", "Target MAC (THA)", d.tha + (d.op == REQUEST ? "  (= my own MAC: \"look this one up\")" : "")));
        x.add(new Field(38, 4, "rarp", "Target IP (TPA)", d.tpa + (d.op == REPLY ? "  ← the answer: the requester's IP" : "  (unknown, filled in by the server)")));
        x.add(new Field(42, 18, "pad", "Padding", "18 zero bytes: Ethernet frames are at least 60 bytes (+4-byte FCS on the wire)"));
        return d;
    }
}

package dns.wire;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import dns.core.Json;

/**
 * A DNS message (RFC 1035 §4): 12-byte header, question, answer, authority and additional sections.
 * Encodes with name compression (§4.1.4) and decodes while recording every field's byte span,
 * so the dashboard can draw the packet byte by byte.
 */
public final class Message {

    public static final int A = 1, NS = 2, CNAME = 5, SOA = 6, PTR = 12, MX = 15, TXT = 16, AAAA = 28, ANY = 255;
    public static final int NOERROR = 0, FORMERR = 1, SERVFAIL = 2, NXDOMAIN = 3, NOTIMP = 4, REFUSED = 5;

    public static String typeName(int t) {
        switch (t) {
            case A: return "A"; case NS: return "NS"; case CNAME: return "CNAME"; case SOA: return "SOA"; case PTR: return "PTR";
            case MX: return "MX"; case TXT: return "TXT"; case AAAA: return "AAAA"; case ANY: return "ANY"; default: return "TYPE" + t;
        }
    }
    public static int typeOf(String s) {
        switch (s.toUpperCase()) {
            case "A": return A; case "NS": return NS; case "CNAME": return CNAME; case "SOA": return SOA; case "PTR": return PTR;
            case "MX": return MX; case "TXT": return TXT; case "AAAA": return AAAA; case "ANY": return ANY;
            default: return s.toUpperCase().startsWith("TYPE") ? Integer.parseInt(s.substring(4)) : A;
        }
    }
    public static String rcodeName(int r) {
        switch (r) { case 0: return "NOERROR"; case 1: return "FORMERR"; case 2: return "SERVFAIL"; case 3: return "NXDOMAIN"; case 4: return "NOTIMP"; case 5: return "REFUSED"; default: return "RCODE" + r; }
    }

    // ------------------------------------------------------------------ model
    public int id, opcode, rcode;
    public boolean qr, aa, tc, rd, ra;
    public final List<Question> qd = new ArrayList<>();
    public final List<RR> an = new ArrayList<>(), ns = new ArrayList<>(), ar = new ArrayList<>();

    public static final class Question {
        public final String name; public final int type, cls;
        public Question(String name, int type) { this(name, type, 1); }
        public Question(String name, int type, int cls) { this.name = name; this.type = type; this.cls = cls; }
        @Override public String toString() { return fq(name) + " " + typeName(type); }
    }

    public static final class RR {
        public final String name; public final int type, cls; public final long ttl; public final String data;
        public RR(String name, int type, long ttl, String data) { this(name, type, 1, ttl, data); }
        public RR(String name, int type, int cls, long ttl, String data) { this.name = name; this.type = type; this.cls = cls; this.ttl = ttl; this.data = data; }
        public RR withTtl(long t) { return new RR(name, type, cls, t, data); }
        /** zone-file style: www.cse.myuniv.edu.  120  IN  A  192.168.151.4 */
        @Override public String toString() { return fq(name) + "  " + ttl + "  IN  " + typeName(type) + "  " + data; }
        public String json() { return Json.obj("name", name, "type", typeName(type), "ttl", ttl, "data", data); }
        /** For NS / CNAME / PTR / MX: the host name the record points to. */
        public String target() {
            if (type == NS || type == CNAME || type == PTR) return data.toLowerCase();
            if (type == MX) return data.substring(data.indexOf(' ') + 1).toLowerCase();
            return null;
        }
    }

    /** One decoded field: where it sits in the packet and what it means. */
    public static final class Field {
        public final int off, len; public final String section, kind, label, value;
        Field(int off, int len, String section, String kind, String label, String value) { this.off = off; this.len = len; this.section = section; this.kind = kind; this.label = label; this.value = value; }
        public String json() { return Json.obj("off", off, "len", len, "section", section, "kind", kind, "label", label, "value", value); }
    }

    public static String fq(String n) { return n.isEmpty() ? "." : n + "."; }

    public Message reply() {
        Message r = new Message();
        r.id = id; r.qr = true; r.opcode = opcode; r.rd = rd;
        r.qd.addAll(qd);
        return r;
    }

    public static Message query(int id, String name, int type, boolean rd) {
        Message m = new Message(); m.id = id; m.rd = rd; m.qd.add(new Question(name, type)); return m;
    }

    public int flags() {
        return (qr ? 0x8000 : 0) | (opcode & 0xF) << 11 | (aa ? 0x400 : 0) | (tc ? 0x200 : 0) | (rd ? 0x100 : 0) | (ra ? 0x80 : 0) | (rcode & 0xF);
    }

    /** One-line description used in the ledger. */
    public String summary() {
        String q = qd.isEmpty() ? "" : qd.get(0).name + " " + typeName(qd.get(0).type);
        if (!qr) return String.format("query id=0x%04x %s?%s", id, q, rd ? " RD" : "");
        StringBuilder b = new StringBuilder(String.format("response id=0x%04x %s %s", id, rcodeName(rcode), q));
        if (aa) b.append(" AA"); if (tc) b.append(" TC"); if (ra) b.append(" RA");
        b.append(String.format(" [an=%d ns=%d ar=%d]", an.size(), ns.size(), ar.size()));
        if (!an.isEmpty()) { b.append(" → "); for (int i = 0; i < Math.min(3, an.size()); i++) b.append(i > 0 ? ", " : "").append(typeName(an.get(i).type)).append(' ').append(an.get(i).data); if (an.size() > 3) b.append(" …"); }
        else if (!ns.isEmpty() && ns.get(0).type == NS) b.append(" → referral to ").append(fq(ns.get(0).name));
        return b.toString();
    }

    // ================================================================== encode
    public byte[] encode() {
        W w = new W();
        w.u16(id); w.u16(flags()); w.u16(qd.size()); w.u16(an.size()); w.u16(ns.size()); w.u16(ar.size());
        for (Question q : qd) { w.name(q.name, true); w.u16(q.type); w.u16(q.cls); }
        for (List<RR> sec : List.of(an, ns, ar)) for (RR r : sec) w.rr(r);
        return w.out.toByteArray();
    }

    private static final class W {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final Map<String, Integer> ptr = new HashMap<>();
        void u8(int v) { out.write(v & 0xFF); }
        void u16(int v) { u8(v >> 8); u8(v); }
        void u32(long v) { u16((int) (v >> 16)); u16((int) v); }
        int pos() { return out.size(); }
        void name(String n, boolean compress) {
            String rest = n;
            while (!rest.isEmpty()) {
                Integer p = compress ? ptr.get(rest.toLowerCase()) : null;
                if (p != null) { u16(0xC000 | p); return; }
                if (pos() < 0x3FFF) ptr.putIfAbsent(rest.toLowerCase(), pos());
                int dot = rest.indexOf('.');
                String label = dot < 0 ? rest : rest.substring(0, dot);
                byte[] b = label.getBytes(StandardCharsets.US_ASCII);
                if (b.length > 63) throw new IllegalArgumentException("label longer than 63 bytes: " + label);
                u8(b.length); out.write(b, 0, b.length);
                rest = dot < 0 ? "" : rest.substring(dot + 1);
            }
            u8(0);
        }
        void rr(RR r) {
            name(r.name, true); u16(r.type); u16(r.cls); u32(r.ttl);
            int lenAt = pos(); u16(0);
            int start = pos();
            rdata(r);
            int len = pos() - start;
            byte[] all = out.toByteArray();
            all[lenAt] = (byte) (len >> 8); all[lenAt + 1] = (byte) len;
            out.reset(); out.write(all, 0, all.length);
        }
        void rdata(RR r) {
            String d = r.data.trim();
            try {
                switch (r.type) {
                    case A: case AAAA: { byte[] a = InetAddress.getByName(d).getAddress(); out.write(a, 0, a.length); break; }
                    case NS: case CNAME: case PTR: name(d, true); break;
                    case MX: { String[] p = d.split("\\s+"); u16(Integer.parseInt(p[0])); name(p[1], true); break; }
                    case SOA: {
                        String[] p = d.split("\\s+");
                        name(p[0], true); name(p[1], true);
                        for (int i = 2; i < 7; i++) u32(Long.parseLong(p[i]));
                        break;
                    }
                    case TXT: for (String s : txtStrings(d)) { byte[] b = s.getBytes(StandardCharsets.UTF_8); u8(b.length); out.write(b, 0, b.length); } break;
                    default: { for (int i = 0; i + 1 < d.length(); i += 2) u8(Integer.parseInt(d.substring(i, i + 2), 16)); }
                }
            } catch (IOException e) { throw new IllegalArgumentException(e); }
        }
    }

    /** "a" "b c" → [a, b c]; unquoted text → chunks of 255 bytes. */
    public static List<String> txtStrings(String d) {
        List<String> l = new ArrayList<>();
        if (d.startsWith("\"")) {
            int i = 0;
            while ((i = d.indexOf('"', i)) >= 0) { int j = d.indexOf('"', i + 1); if (j < 0) break; l.add(d.substring(i + 1, j)); i = j + 1; }
        } else for (int i = 0; i < d.length(); i += 255) l.add(d.substring(i, Math.min(d.length(), i + 255)));
        if (l.isEmpty()) l.add("");
        return l;
    }

    // ================================================================== decode
    public static Message decode(byte[] b, int len) throws IOException { return decode(b, len, null); }

    /** Decode a packet. If {@code fields} is not null, every field's byte span is recorded. */
    public static Message decode(byte[] b, int len, List<Field> fields) throws IOException {
        R r = new R(b, len, fields);
        Message m = new Message();
        if (len < 12) throw new IOException("packet shorter than the 12-byte header");
        m.id = r.u16(); r.f(0, 2, "header", "id", "ID", String.format("0x%04x (%d): matches a response to its query", m.id, m.id));
        int fl = r.u16();
        m.qr = (fl & 0x8000) != 0; m.opcode = fl >> 11 & 0xF; m.aa = (fl & 0x400) != 0; m.tc = (fl & 0x200) != 0;
        m.rd = (fl & 0x100) != 0; m.ra = (fl & 0x80) != 0; m.rcode = fl & 0xF;
        r.f(2, 2, "header", "flags", "Flags", String.format("0x%04x: QR=%d OPCODE=%d AA=%d TC=%d RD=%d RA=%d RCODE=%d (%s)",
                fl, m.qr ? 1 : 0, m.opcode, m.aa ? 1 : 0, m.tc ? 1 : 0, m.rd ? 1 : 0, m.ra ? 1 : 0, m.rcode, rcodeName(m.rcode)));
        int qn = r.u16(), anc = r.u16(), nsc = r.u16(), arc = r.u16();
        r.f(4, 2, "header", "count", "QDCOUNT", qn + " question(s)");
        r.f(6, 2, "header", "count", "ANCOUNT", anc + " answer record(s)");
        r.f(8, 2, "header", "count", "NSCOUNT", nsc + " authority record(s)");
        r.f(10, 2, "header", "count", "ARCOUNT", arc + " additional record(s)");
        for (int i = 0; i < qn; i++) {
            String name = r.name("question", true);
            int t0 = r.p; int type = r.u16(); r.f(t0, 2, "question", "type", "QTYPE", typeName(type) + " (" + type + ")");
            int c0 = r.p; int cls = r.u16(); r.f(c0, 2, "question", "class", "QCLASS", cls == 1 ? "IN (1) = Internet" : String.valueOf(cls));
            m.qd.add(new Question(name, type, cls));
        }
        r.section(m.an, anc, "answer"); r.section(m.ns, nsc, "authority"); r.section(m.ar, arc, "additional");
        return m;
    }

    private static final class R {
        final byte[] b; final int len; final List<Field> fields; int p;
        R(byte[] b, int len, List<Field> fields) { this.b = b; this.len = len; this.fields = fields; }
        int u8() throws IOException { if (p >= len) throw new IOException("truncated packet"); return b[p++] & 0xFF; }
        int u16() throws IOException { return u8() << 8 | u8(); }
        long u32() throws IOException { return (long) u16() << 16 | u16(); }
        void f(int off, int l, String sec, String kind, String label, String value) { if (fields != null) fields.add(new Field(off, l, sec, kind, label, value)); }

        /** Read a (possibly compressed) name at the cursor; record label / pointer fields when {@code record}. */
        String name(String sec, boolean record) throws IOException {
            StringBuilder sb = new StringBuilder();
            int pos = p, jumps = 0; boolean jumped = false;
            while (true) {
                if (pos >= len) throw new IOException("name runs past the end of the packet");
                int l = b[pos] & 0xFF;
                if ((l & 0xC0) == 0xC0) {
                    if (pos + 1 >= len) throw new IOException("bad pointer");
                    int target = (l & 0x3F) << 8 | b[pos + 1] & 0xFF;
                    if (!jumped && record) f(pos, 2, sec, "ptr", "Pointer", String.format("0xC0%02X → offset %d: the rest of this name is \"%s\"", target & 0xFF, target, peek(target)));
                    if (!jumped) p = pos + 2;
                    jumped = true; pos = target;
                    if (++jumps > 20) throw new IOException("compression loop");
                    continue;
                }
                if (l == 0) {
                    if (!jumped) { if (record) f(pos, 1, sec, "end", "Root", "0: end of name"); p = pos + 1; }
                    break;
                }
                if (pos + 1 + l > len) throw new IOException("label runs past the end of the packet");
                String label = new String(b, pos + 1, l, StandardCharsets.US_ASCII);
                if (!jumped && record) f(pos, 1 + l, sec, "label", "Label", l + " + \"" + label + "\"");
                if (sb.length() > 0) sb.append('.');
                sb.append(label);
                pos += 1 + l;
                if (sb.length() > 255) throw new IOException("name too long");
            }
            return sb.toString();
        }
        String peek(int at) { int save = p; try { p = at; return fq(name(null, false)); } catch (IOException e) { return "?"; } finally { p = save; } }

        void section(List<RR> into, int n, String sec) throws IOException {
            for (int i = 0; i < n; i++) {
                String name = name(sec, true);
                int t0 = p; int type = u16(); f(t0, 2, sec, "type", "TYPE", typeName(type));
                int c0 = p; int cls = u16(); f(c0, 2, sec, "class", "CLASS", cls == 1 ? "IN" : String.valueOf(cls));
                int l0 = p; long ttl = u32(); f(l0, 4, sec, "ttl", "TTL", ttl + " s: how long a resolver may cache this");
                int d0 = p; int rdl = u16(); f(d0, 2, sec, "rdlen", "RDLENGTH", rdl + " bytes of data follow");
                int start = p, end = p + rdl;
                if (end > len) throw new IOException("record data runs past the end of the packet");
                String data = rdata(type, rdl);
                p = end;
                f(start, rdl, sec, "rdata", "RDATA", typeName(type) + " " + data);
                into.add(new RR(name, type, cls, ttl, data));
            }
        }
        String rdata(int type, int rdl) throws IOException {
            switch (type) {
                case A: return (b[p] & 0xFF) + "." + (b[p + 1] & 0xFF) + "." + (b[p + 2] & 0xFF) + "." + (b[p + 3] & 0xFF);
                case AAAA: { byte[] a = new byte[16]; System.arraycopy(b, p, a, 0, 16); return InetAddress.getByAddress(a).getHostAddress(); }
                case NS: case CNAME: case PTR: return name(null, false);
                case MX: { int pref = u16(); return pref + " " + name(null, false); }
                case SOA: {
                    String mn = name(null, false), rn = name(null, false);
                    return mn + " " + rn + " " + u32() + " " + u32() + " " + u32() + " " + u32() + " " + u32();
                }
                case TXT: {
                    StringBuilder sb = new StringBuilder(); int end = p + rdl;
                    while (p < end) { int l = u8(); sb.append(sb.length() > 0 ? " " : "").append('"').append(new String(b, p, l, StandardCharsets.UTF_8)).append('"'); p += l; }
                    return sb.toString();
                }
                default: { StringBuilder sb = new StringBuilder(); for (int i = 0; i < rdl; i++) sb.append(String.format("%02x", b[p + i])); return sb.toString(); }
            }
        }
    }
}

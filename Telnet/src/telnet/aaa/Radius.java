package telnet.aaa;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import telnet.core.Json;

/**
 * RADIUS packets (RFC 2865 authentication, RFC 2866 accounting).
 *
 * <pre>
 *  Code (1) | Identifier (1) | Length (2) | Authenticator (16) | Attributes: Type (1) Length (1) Value ...
 * </pre>
 *
 * Security in RADIUS rests on a shared secret S between the NAS (our router) and the server:
 *  - User-Password is hidden:  c1 = p1 XOR MD5(S + RequestAuthenticator),  ci = pi XOR MD5(S + c(i-1))
 *  - Response Authenticator =  MD5(Code + ID + Length + RequestAuthenticator + Attributes + S)
 *  - Accounting-Request Authenticator = MD5(Code + ID + Length + 16 zero octets + Attributes + S)
 */
public final class Radius {
    public static final int ACCESS_REQUEST = 1, ACCESS_ACCEPT = 2, ACCESS_REJECT = 3, ACCOUNTING_REQUEST = 4, ACCOUNTING_RESPONSE = 5;
    public static final int USER_NAME = 1, USER_PASSWORD = 2, NAS_IP_ADDRESS = 4, NAS_PORT = 5, SERVICE_TYPE = 6, REPLY_MESSAGE = 18,
            VENDOR_SPECIFIC = 26, CALLING_STATION_ID = 31, NAS_IDENTIFIER = 32, ACCT_STATUS_TYPE = 40, ACCT_INPUT_OCTETS = 42,
            ACCT_OUTPUT_OCTETS = 43, ACCT_SESSION_ID = 44, ACCT_AUTHENTIC = 45, ACCT_SESSION_TIME = 46, ACCT_TERMINATE_CAUSE = 49, NAS_PORT_TYPE = 61;
    public static final int VENDOR_CISCO = 9, CISCO_AVPAIR = 1;
    public static final int STATUS_START = 1, STATUS_STOP = 2, STATUS_INTERIM = 3;
    public static final int SERVICE_ADMINISTRATIVE = 6, SERVICE_NAS_PROMPT = 7;

    public static final class Attr {
        public final int type; public final byte[] value;
        public Attr(int type, byte[] value) { this.type = type; this.value = value; }
        public String text() { return new String(value, StandardCharsets.UTF_8); }
        public int integer() { int v = 0; for (byte b : value) v = (v << 8) | (b & 0xFF); return v; }
    }

    public static final class Packet {
        public int code, id; public byte[] auth = new byte[16]; public final List<Attr> attrs = new ArrayList<>();
        public Packet(int code, int id) { this.code = code; this.id = id; }
        public Packet add(int type, byte[] v) { attrs.add(new Attr(type, v)); return this; }
        public Packet add(int type, String s) { return add(type, s.getBytes(StandardCharsets.UTF_8)); }
        public Packet addInt(int type, long v) { return add(type, new byte[]{(byte) (v >> 24), (byte) (v >> 16), (byte) (v >> 8), (byte) v}); }
        public Packet addCisco(String avpair) {
            byte[] s = avpair.getBytes(StandardCharsets.UTF_8);
            byte[] v = new byte[6 + s.length];
            v[0] = 0; v[1] = 0; v[2] = 0; v[3] = (byte) VENDOR_CISCO; v[4] = (byte) CISCO_AVPAIR; v[5] = (byte) (2 + s.length);
            System.arraycopy(s, 0, v, 6, s.length);
            return add(VENDOR_SPECIFIC, v);
        }
        public Attr get(int type) { for (Attr a : attrs) if (a.type == type) return a; return null; }
        public List<String> ciscoPairs() {
            List<String> l = new ArrayList<>();
            for (Attr a : attrs) if (a.type == VENDOR_SPECIFIC && a.value.length > 6 && a.value[3] == VENDOR_CISCO && a.value[4] == CISCO_AVPAIR)
                l.add(new String(a.value, 6, a.value.length - 6, StandardCharsets.UTF_8));
            return l;
        }
        public byte[] attributeBytes() {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            for (Attr a : attrs) { b.write(a.type); b.write(a.value.length + 2); b.write(a.value, 0, a.value.length); }
            return b.toByteArray();
        }
        /** The packet with the given authenticator field. */
        public byte[] encode() {
            byte[] at = attributeBytes();
            int len = 20 + at.length;
            byte[] p = new byte[len];
            p[0] = (byte) code; p[1] = (byte) id; p[2] = (byte) (len >> 8); p[3] = (byte) len;
            System.arraycopy(auth, 0, p, 4, 16);
            System.arraycopy(at, 0, p, 20, at.length);
            return p;
        }
    }

    public static Packet decode(byte[] b, int len) {
        if (len < 20) throw new IllegalArgumentException("RADIUS packet shorter than 20 bytes");
        int plen = ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
        if (plen < 20 || plen > len || plen > 4096) throw new IllegalArgumentException("bad RADIUS length " + plen);
        Packet p = new Packet(b[0] & 0xFF, b[1] & 0xFF);
        System.arraycopy(b, 4, p.auth, 0, 16);
        int i = 20;
        while (i + 2 <= plen) {
            int t = b[i] & 0xFF, l = b[i + 1] & 0xFF;
            if (l < 2 || i + l > plen) throw new IllegalArgumentException("bad attribute length at offset " + i);
            byte[] v = new byte[l - 2];
            System.arraycopy(b, i + 2, v, 0, l - 2);
            p.attrs.add(new Attr(t, v));
            i += l;
        }
        return p;
    }

    // ================================================================== the shared-secret operations

    public static byte[] md5(byte[]... parts) {
        try { MessageDigest m = MessageDigest.getInstance("MD5"); for (byte[] x : parts) m.update(x); return m.digest(); }
        catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    /** RFC 2865 §5.2 User-Password hiding. */
    public static byte[] hidePassword(String password, byte[] secret, byte[] requestAuth) {
        byte[] p = password.getBytes(StandardCharsets.UTF_8);
        int n = Math.max(16, (p.length + 15) / 16 * 16);
        byte[] padded = new byte[n];
        System.arraycopy(p, 0, padded, 0, p.length);
        byte[] out = new byte[n], prev = requestAuth;
        for (int i = 0; i < n; i += 16) {
            byte[] b = md5(secret, prev);
            for (int j = 0; j < 16; j++) out[i + j] = (byte) (padded[i + j] ^ b[j]);
            prev = java.util.Arrays.copyOfRange(out, i, i + 16);
        }
        return out;
    }

    public static String unhidePassword(byte[] hidden, byte[] secret, byte[] requestAuth) {
        byte[] out = new byte[hidden.length], prev = requestAuth;
        for (int i = 0; i + 16 <= hidden.length; i += 16) {
            byte[] b = md5(secret, prev);
            for (int j = 0; j < 16; j++) out[i + j] = (byte) (hidden[i + j] ^ b[j]);
            prev = java.util.Arrays.copyOfRange(hidden, i, i + 16);
        }
        int n = out.length; while (n > 0 && out[n - 1] == 0) n--;
        return new String(out, 0, n, StandardCharsets.UTF_8);
    }

    /** Authenticator of a response (Access-Accept/Reject, Accounting-Response): MD5(Code+ID+Length+RequestAuth+Attributes+Secret). */
    public static byte[] responseAuth(Packet resp, byte[] requestAuth, byte[] secret) {
        byte[] saved = resp.auth; resp.auth = requestAuth;
        byte[] p = resp.encode(); resp.auth = saved;
        return md5(p, secret);
    }

    /** Authenticator of an Accounting-Request: MD5(Code+ID+Length+16 zero octets+Attributes+Secret). */
    public static byte[] accountingRequestAuth(Packet req, byte[] secret) {
        byte[] saved = req.auth; req.auth = new byte[16];
        byte[] p = req.encode(); req.auth = saved;
        return md5(p, secret);
    }

    // ================================================================== names, for the dashboard and the logs

    public static String codeName(int c) {
        switch (c) {
            case ACCESS_REQUEST: return "Access-Request"; case ACCESS_ACCEPT: return "Access-Accept"; case ACCESS_REJECT: return "Access-Reject";
            case ACCOUNTING_REQUEST: return "Accounting-Request"; case ACCOUNTING_RESPONSE: return "Accounting-Response"; case 11: return "Access-Challenge";
            default: return "code " + c;
        }
    }

    public static String attrName(int t) {
        switch (t) {
            case USER_NAME: return "User-Name"; case USER_PASSWORD: return "User-Password"; case NAS_IP_ADDRESS: return "NAS-IP-Address";
            case NAS_PORT: return "NAS-Port"; case SERVICE_TYPE: return "Service-Type"; case REPLY_MESSAGE: return "Reply-Message";
            case VENDOR_SPECIFIC: return "Vendor-Specific"; case CALLING_STATION_ID: return "Calling-Station-Id"; case NAS_IDENTIFIER: return "NAS-Identifier";
            case ACCT_STATUS_TYPE: return "Acct-Status-Type"; case ACCT_INPUT_OCTETS: return "Acct-Input-Octets"; case ACCT_OUTPUT_OCTETS: return "Acct-Output-Octets";
            case ACCT_SESSION_ID: return "Acct-Session-Id"; case ACCT_AUTHENTIC: return "Acct-Authentic"; case ACCT_SESSION_TIME: return "Acct-Session-Time";
            case ACCT_TERMINATE_CAUSE: return "Acct-Terminate-Cause"; case NAS_PORT_TYPE: return "NAS-Port-Type";
            default: return "attribute " + t;
        }
    }

    static String attrValue(Attr a) {
        switch (a.type) {
            case USER_NAME: case REPLY_MESSAGE: case CALLING_STATION_ID: case NAS_IDENTIFIER: case ACCT_SESSION_ID: return "\"" + a.text() + "\"";
            case USER_PASSWORD: return hex(a.value) + "  (hidden: XOR with MD5(secret + authenticator))";
            case NAS_IP_ADDRESS: return (a.value[0] & 0xFF) + "." + (a.value[1] & 0xFF) + "." + (a.value[2] & 0xFF) + "." + (a.value[3] & 0xFF);
            case SERVICE_TYPE: return a.integer() + (a.integer() == SERVICE_ADMINISTRATIVE ? " (Administrative-User)" : a.integer() == SERVICE_NAS_PROMPT ? " (NAS-Prompt-User)" : "");
            case ACCT_STATUS_TYPE: return a.integer() + (a.integer() == 1 ? " (Start)" : a.integer() == 2 ? " (Stop)" : a.integer() == 3 ? " (Interim-Update)" : "");
            case ACCT_AUTHENTIC: return a.integer() + (a.integer() == 1 ? " (RADIUS)" : a.integer() == 2 ? " (Local)" : "");
            case NAS_PORT_TYPE: return a.integer() + (a.integer() == 5 ? " (Virtual: a VTY line)" : "");
            case ACCT_TERMINATE_CAUSE: return a.integer() + " (" + cause(a.integer()) + ")";
            case ACCT_SESSION_TIME: return a.integer() + " s";
            case VENDOR_SPECIFIC:
                if (a.value.length > 6 && a.value[3] == VENDOR_CISCO) return "Cisco (9) AV-pair \"" + new String(a.value, 6, a.value.length - 6, StandardCharsets.UTF_8) + "\"";
                return hex(a.value);
            default: return a.value.length == 4 ? String.valueOf(a.integer()) : hex(a.value);
        }
    }

    public static String cause(int c) {
        switch (c) { case 1: return "User-Request"; case 2: return "Lost-Carrier"; case 4: return "Idle-Timeout"; case 9: return "NAS-Error"; case 11: return "NAS-Reboot"; default: return "cause " + c; }
    }

    public static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (int i = 0; i < b.length; i++) { if (i > 0) s.append(' '); s.append(String.format("%02X", b[i])); } return s.toString(); }

    /** Field-by-field JSON of a packet for the dashboard. */
    public static String dissect(Packet p, byte[] wire) {
        List<String> at = new ArrayList<>();
        for (Attr a : p.attrs) at.add(Json.obj("type", a.type, "name", attrName(a.type), "len", a.value.length + 2, "value", attrValue(a)));
        return Json.obj("code", p.code, "name", codeName(p.code), "id", p.id, "length", wire.length, "authenticator", hex(p.auth),
                "attrs", Json.raw(Json.arr(at)), "hex", hex(wire));
    }
}

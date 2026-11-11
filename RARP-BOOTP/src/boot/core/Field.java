package boot.core;

/** One field of a packet: where it sits (byte offset + length), which part it belongs to and what it means. */
public final class Field {
    public final int off, len; public final String part, label, value;
    public Field(int off, int len, String part, String label, String value) { this.off = off; this.len = len; this.part = part; this.label = label; this.value = value; }
    public String json() { return Json.obj("off", off, "len", len, "part", part, "label", label, "value", value); }

    public static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format("%02x", x)); return s.toString(); }
    public static String mac(byte[] b, int o) { return String.format("%02x:%02x:%02x:%02x:%02x:%02x", b[o], b[o + 1], b[o + 2], b[o + 3], b[o + 4], b[o + 5]); }
    public static String ip(byte[] b, int o) { return (b[o] & 0xFF) + "." + (b[o + 1] & 0xFF) + "." + (b[o + 2] & 0xFF) + "." + (b[o + 3] & 0xFF); }
    public static byte[] macBytes(String m) { String[] p = m.split(":"); byte[] b = new byte[6]; for (int i = 0; i < 6; i++) b[i] = (byte) Integer.parseInt(p[i], 16); return b; }
    public static byte[] ipBytes(String s) { if (s == null || s.isEmpty()) return new byte[4]; String[] p = s.split("\\."); byte[] b = new byte[4]; for (int i = 0; i < 4; i++) b[i] = (byte) Integer.parseInt(p[i]); return b; }
    public static int u16(byte[] b, int o) { return (b[o] & 0xFF) << 8 | b[o + 1] & 0xFF; }
    public static long u32(byte[] b, int o) { return (long) u16(b, o) << 16 | u16(b, o + 2); }
}

package dhcp.protocol;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Full RFC 2131 Compliant DHCP Packet Parser & Serializer.
 *
 * Structure:
 * - Fixed 236-byte BOOTP header (op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file)
 * - 4-byte Magic Cookie: 99.130.83.99 (0x63, 0x82, 0x53, 0x63)
 * - Variable-length TLV (Type-Length-Value) DHCP Options terminated by 0xFF (Option 255)
 */
public class DhcpPacket {

    public static final byte BOOTREQUEST = 1;
    public static final byte BOOTREPLY = 2;
    public static final byte HTYPE_ETHER = 1;
    public static final byte HLEN_ETHER = 6;

    public static final byte[] MAGIC_COOKIE = new byte[]{99, (byte) 130, 83, 99};

    // Standard RFC 2132 DHCP Option Codes
    public static final byte OPT_SUBNET_MASK = 1;
    public static final byte OPT_ROUTER = 3;
    public static final byte OPT_DNS_SERVER = 6;
    public static final byte OPT_HOSTNAME = 12;
    public static final byte OPT_DOMAIN_NAME = 15;
    public static final byte OPT_REQUESTED_IP = 50;
    public static final byte OPT_LEASE_TIME = 51;
    public static final byte OPT_MESSAGE_TYPE = 53;
    public static final byte OPT_SERVER_ID = 54;
    public static final byte OPT_PARAM_REQ_LIST = 55;
    public static final byte OPT_MESSAGE = 56;
    public static final byte OPT_CLIENT_PORT = (byte) 224; // Private option for simulated client return port on single host
    public static final byte OPT_SYNC_PAYLOAD = (byte) 225; // Private option for cluster state replication payload
    public static final byte OPT_END = (byte) 255;

    private byte op = BOOTREQUEST;
    private byte htype = HTYPE_ETHER;
    private byte hlen = HLEN_ETHER;
    private byte hops = 0;
    private int xid;
    private short secs = 0;
    private short flags = (short) 0x8000; // Broadcast flag

    private String ciaddr = "0.0.0.0"; // Client IP
    private String yiaddr = "0.0.0.0"; // 'Your' (Client) offered/assigned IP
    private String siaddr = "0.0.0.0"; // Next Server IP
    private String giaddr = "0.0.0.0"; // Relay Agent / Load Balancer IP

    private String chaddr = "00:00:00:00:00:00"; // Client MAC address

    private final Map<Byte, byte[]> options = new LinkedHashMap<>();

    public DhcpPacket() {
    }

    public byte[] toBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        buffer.put(op);
        buffer.put(htype);
        buffer.put(hlen);
        buffer.put(hops);
        buffer.putInt(xid);
        buffer.putShort(secs);
        buffer.putShort(flags);

        buffer.put(ipToBytes(ciaddr));
        buffer.put(ipToBytes(yiaddr));
        buffer.put(ipToBytes(siaddr));
        buffer.put(ipToBytes(giaddr));

        // 16-byte chaddr field
        byte[] macBytes = macToBytes(chaddr);
        byte[] chaddrField = new byte[16];
        System.arraycopy(macBytes, 0, chaddrField, 0, Math.min(macBytes.length, 16));
        buffer.put(chaddrField);

        // 64-byte sname + 128-byte file (zeros)
        buffer.put(new byte[64]);
        buffer.put(new byte[128]);

        // 4-byte Magic Cookie
        buffer.put(MAGIC_COOKIE);

        // TLV Options
        for (Map.Entry<Byte, byte[]> entry : options.entrySet()) {
            byte code = entry.getKey();
            byte[] val = entry.getValue();
            if (code == OPT_END) continue;
            buffer.put(code);
            buffer.put((byte) (val.length & 0xFF));
            buffer.put(val);
        }

        // End Option (255)
        buffer.put(OPT_END);

        byte[] result = new byte[buffer.position()];
        buffer.flip();
        buffer.get(result);
        return result;
    }

    public static DhcpPacket fromBytes(byte[] data, int length) {
        if (length < 240) {
            throw new IllegalArgumentException("Packet too short to be a valid RFC 2131 DHCP packet (" + length + " bytes)");
        }
        ByteBuffer buffer = ByteBuffer.wrap(data, 0, length);
        DhcpPacket packet = new DhcpPacket();

        packet.op = buffer.get();
        packet.htype = buffer.get();
        packet.hlen = buffer.get();
        packet.hops = buffer.get();
        packet.xid = buffer.getInt();
        packet.secs = buffer.getShort();
        packet.flags = buffer.getShort();

        byte[] ipBuf = new byte[4];
        buffer.get(ipBuf);
        packet.ciaddr = bytesToIp(ipBuf);
        buffer.get(ipBuf);
        packet.yiaddr = bytesToIp(ipBuf);
        buffer.get(ipBuf);
        packet.siaddr = bytesToIp(ipBuf);
        buffer.get(ipBuf);
        packet.giaddr = bytesToIp(ipBuf);

        byte[] chaddrField = new byte[16];
        buffer.get(chaddrField);
        packet.chaddr = bytesToMac(Arrays.copyOf(chaddrField, 6));

        // Skip sname (64) and file (128)
        buffer.position(buffer.position() + 192);

        // Verify Magic Cookie
        byte[] cookie = new byte[4];
        buffer.get(cookie);
        if (!Arrays.equals(cookie, MAGIC_COOKIE)) {
            throw new IllegalArgumentException("Invalid DHCP Magic Cookie");
        }

        // Parse TLV Options
        while (buffer.hasRemaining()) {
            byte code = buffer.get();
            if (code == 0) {
                continue; // Pad option
            }
            if (code == OPT_END) {
                break;
            }
            if (!buffer.hasRemaining()) break;
            int optLen = buffer.get() & 0xFF;
            if (buffer.remaining() < optLen) break;
            byte[] val = new byte[optLen];
            buffer.get(val);
            packet.options.put(code, val);
        }

        return packet;
    }

    // Convenience Option Getters/Setters
    public void setMessageType(DhcpMessageType type) {
        options.put(OPT_MESSAGE_TYPE, new byte[]{type.getCode()});
    }

    public DhcpMessageType getMessageType() {
        byte[] val = options.get(OPT_MESSAGE_TYPE);
        if (val == null || val.length == 0) return null;
        return DhcpMessageType.fromCode(val[0]);
    }

    public void setOptionIp(byte code, String ip) {
        options.put(code, ipToBytes(ip));
    }

    public String getOptionIp(byte code) {
        byte[] val = options.get(code);
        return (val != null && val.length == 4) ? bytesToIp(val) : null;
    }

    public void setOptionInt(byte code, int value) {
        ByteBuffer b = ByteBuffer.allocate(4);
        b.putInt(value);
        options.put(code, b.array());
    }

    public Integer getOptionInt(byte code) {
        byte[] val = options.get(code);
        if (val == null || val.length != 4) return null;
        return ByteBuffer.wrap(val).getInt();
    }

    public void setOptionString(byte code, String text) {
        if (text != null) {
            options.put(code, text.getBytes(StandardCharsets.UTF_8));
        }
    }

    public String getOptionString(byte code) {
        byte[] val = options.get(code);
        return val != null ? new String(val, StandardCharsets.UTF_8) : null;
    }

    public static byte[] ipToBytes(String ip) {
        try {
            if (ip == null || ip.isEmpty()) return new byte[]{0, 0, 0, 0};
            String[] parts = ip.trim().split("\\.");
            if (parts.length != 4) return new byte[]{0, 0, 0, 0};
            byte[] res = new byte[4];
            for (int i = 0; i < 4; i++) {
                res[i] = (byte) (Integer.parseInt(parts[i]) & 0xFF);
            }
            return res;
        } catch (Exception e) {
            return new byte[]{0, 0, 0, 0};
        }
    }

    public static String bytesToIp(byte[] b) {
        return String.format("%d.%d.%d.%d",
                b[0] & 0xFF, b[1] & 0xFF, b[2] & 0xFF, b[3] & 0xFF);
    }

    public static byte[] macToBytes(String mac) {
        String[] hex = mac.split("[:-]");
        byte[] bytes = new byte[6];
        for (int i = 0; i < Math.min(6, hex.length); i++) {
            bytes[i] = (byte) Integer.parseInt(hex[i], 16);
        }
        return bytes;
    }

    public static String bytesToMac(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02X", b[i] & 0xFF));
        }
        return sb.toString();
    }

    public byte getOp() { return op; }
    public void setOp(byte op) { this.op = op; }
    public byte getHops() { return hops; }
    public void setHops(byte hops) { this.hops = hops; }
    public int getXid() { return xid; }
    public void setXid(int xid) { this.xid = xid; }
    public short getFlags() { return flags; }
    public void setFlags(short flags) { this.flags = flags; }
    public String getCiaddr() { return ciaddr; }
    public void setCiaddr(String ciaddr) { this.ciaddr = ciaddr; }
    public String getYiaddr() { return yiaddr; }
    public void setYiaddr(String yiaddr) { this.yiaddr = yiaddr; }
    public String getSiaddr() { return siaddr; }
    public void setSiaddr(String siaddr) { this.siaddr = siaddr; }
    public String getGiaddr() { return giaddr; }
    public void setGiaddr(String giaddr) { this.giaddr = giaddr; }
    public String getChaddr() { return chaddr; }
    public void setChaddr(String chaddr) { this.chaddr = chaddr.toUpperCase(); }
    public Map<Byte, byte[]> getOptions() { return Collections.unmodifiableMap(options); }

    @Override
    public String toString() {
        return String.format("DhcpPacket[type=%s, xid=0x%08X, chaddr=%s, ciaddr=%s, yiaddr=%s, giaddr=%s]",
                getMessageType(), xid, chaddr, ciaddr, yiaddr, giaddr);
    }
}

package dhcp.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

public final class PcapRecorder {

    private static final int MAX_PACKETS = 50_000;
    private static final int LINKTYPE_ETHERNET = 1;
    private static final long START_MICROS = System.currentTimeMillis() * 1000L;
    private static final long START_NANOS = System.nanoTime();

    private static final ArrayDeque<Record> buffer = new ArrayDeque<>();
    private static final AtomicLong totalCaptured = new AtomicLong();
    private static final AtomicLong dhcpCaptured = new AtomicLong();
    private static volatile boolean enabled = true;
    private static volatile byte[] defaultLocalIp = detectLocalIp();

    private PcapRecorder() {}

    private static final class Record {
        final long micros;
        final byte[] srcIp;
        final int srcPort;
        final byte[] dstIp;
        final int dstPort;
        final byte[] payload;
        final byte msgType;

        Record(long micros, byte[] srcIp, int srcPort, byte[] dstIp, int dstPort, byte[] payload, byte msgType) {
            this.micros = micros;
            this.srcIp = srcIp;
            this.srcPort = srcPort;
            this.dstIp = dstIp;
            this.dstPort = dstPort;
            this.payload = payload;
            this.msgType = msgType;
        }

        boolean isHeartbeat() {
            int code = msgType & 0xFF;
            return code == 102 || code == 103;
        }
    }

    public static void send(DatagramSocket socket, DatagramPacket packet) throws IOException {
        socket.send(packet);
        recordOutbound(socket, packet);
    }

    public static void recordReceived(DatagramSocket socket, DatagramPacket packet, String localIpFallback) {
        if (!enabled) return;
        try {
            InetAddress src = packet.getAddress();
            if (!(src instanceof Inet4Address) || src.isLoopbackAddress()) {
                return;
            }
            InetAddress local = socket.getLocalAddress();
            byte[] dstIp;
            if (local instanceof Inet4Address && !local.isAnyLocalAddress()) {
                dstIp = local.getAddress();
            } else if (localIpFallback != null && !localIpFallback.isEmpty()) {
                dstIp = InetAddress.getByName(localIpFallback).getAddress();
            } else {
                dstIp = defaultLocalIp;
            }
            byte[] payload = new byte[packet.getLength()];
            System.arraycopy(packet.getData(), packet.getOffset(), payload, 0, packet.getLength());
            appendRecord(src.getAddress(), packet.getPort(), dstIp, socket.getLocalPort(), payload);
        } catch (Exception ignored) {
        }
    }

    private static void recordOutbound(DatagramSocket socket, DatagramPacket packet) {
        if (!enabled) return;
        try {
            InetAddress dst = packet.getAddress();
            if (!(dst instanceof Inet4Address)) return;

            InetAddress local = socket.getLocalAddress();
            byte[] srcIp;
            if (local instanceof Inet4Address && !local.isAnyLocalAddress()) {
                srcIp = local.getAddress();
            } else if (dst.isLoopbackAddress()) {
                srcIp = new byte[]{127, 0, 0, 1};
            } else {
                srcIp = defaultLocalIp;
            }

            byte[] payload = new byte[packet.getLength()];
            System.arraycopy(packet.getData(), packet.getOffset(), payload, 0, packet.getLength());
            appendRecord(srcIp, socket.getLocalPort(), dst.getAddress(), packet.getPort(), payload);
        } catch (Exception ignored) {
        }
    }

    private static void appendRecord(byte[] srcIp, int srcPort, byte[] dstIp, int dstPort, byte[] payload) {
        long micros = START_MICROS + (System.nanoTime() - START_NANOS) / 1000L;
        byte msgType = extractDhcpMessageType(payload);
        Record r = new Record(micros, srcIp, srcPort, dstIp, dstPort, payload, msgType);
        synchronized (buffer) {
            buffer.addLast(r);
            if (buffer.size() > MAX_PACKETS) buffer.removeFirst();
        }
        totalCaptured.incrementAndGet();
        if (!r.isHeartbeat()) {
            dhcpCaptured.incrementAndGet();
        }
    }

    private static byte extractDhcpMessageType(byte[] payload) {
        if (payload == null || payload.length < 243) return 0;
        if (payload[236] != 99 || payload[237] != (byte) 130 || payload[238] != 83 || payload[239] != 99) {
            return 0;
        }
        int idx = 240;
        while (idx < payload.length) {
            int code = payload[idx++] & 0xFF;
            if (code == 0) continue;
            if (code == 255 || idx >= payload.length) break;
            int len = payload[idx++] & 0xFF;
            if (code == 53 && len >= 1 && idx < payload.length) {
                return payload[idx];
            }
            idx += len;
        }
        return 0;
    }

    public static void setLocalIp(String ip) {
        try {
            InetAddress a = InetAddress.getByName(ip);
            if (a instanceof Inet4Address) defaultLocalIp = a.getAddress();
        } catch (Exception ignored) {
        }
    }

    public static void setEnabled(boolean on) { enabled = on; }
    public static boolean isEnabled() { return enabled; }
    public static long getTotalCaptured() { return totalCaptured.get(); }
    public static long getDhcpCaptured() { return dhcpCaptured.get(); }

    public static int getBufferedCount() {
        synchronized (buffer) {
            return buffer.size();
        }
    }

    public static void clear() {
        synchronized (buffer) {
            buffer.clear();
        }
        totalCaptured.set(0);
        dhcpCaptured.set(0);
    }

    public static byte[] exportPcap() {
        return exportPcap(true);
    }

    public static byte[] exportPcap(boolean includeHeartbeats) {
        List<Record> snapshot;
        synchronized (buffer) {
            snapshot = new ArrayList<>(buffer);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(24 + snapshot.size() * 380);

        ByteBuffer gh = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        gh.putInt(0xa1b2c3d4);
        gh.putShort((short) 2);
        gh.putShort((short) 4);
        gh.putInt(0);
        gh.putInt(0);
        gh.putInt(65535);
        gh.putInt(LINKTYPE_ETHERNET);
        out.write(gh.array(), 0, 24);

        int ipId = 1;
        for (Record r : snapshot) {
            if (!includeHeartbeats && r.isHeartbeat()) continue;
            byte[] frame = buildEthernetIpv4Udp(r, ipId++ & 0xFFFF);
            ByteBuffer ph = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
            ph.putInt((int) (r.micros / 1_000_000L));
            ph.putInt((int) (r.micros % 1_000_000L));
            ph.putInt(frame.length);
            ph.putInt(frame.length);
            out.write(ph.array(), 0, 16);
            out.write(frame, 0, frame.length);
        }
        return out.toByteArray();
    }

    private static byte[] buildEthernetIpv4Udp(Record r, int ipId) {
        int udpLen = 8 + r.payload.length;
        int ipLen = 20 + udpLen;
        int frameLen = 14 + ipLen;
        ByteBuffer b = ByteBuffer.allocate(frameLen).order(ByteOrder.BIG_ENDIAN);

        byte[] srcMac = deriveMac(r.srcIp, r.srcPort, r.payload, true);
        byte[] dstMac = deriveMac(r.dstIp, r.dstPort, r.payload, false);
        b.put(dstMac);
        b.put(srcMac);
        b.putShort((short) 0x0800);

        b.put((byte) 0x45);
        b.put((byte) 0);
        b.putShort((short) ipLen);
        b.putShort((short) ipId);
        b.putShort((short) 0x4000);
        b.put((byte) 64);
        b.put((byte) 17);
        b.putShort((short) 0);
        b.put(r.srcIp);
        b.put(r.dstIp);

        int srcPort = normalizeDhcpPort(r.srcPort, r.dstPort, true);
        int dstPort = normalizeDhcpPort(r.srcPort, r.dstPort, false);

        b.putShort((short) srcPort);
        b.putShort((short) dstPort);
        b.putShort((short) udpLen);
        b.putShort((short) 0);
        b.put(r.payload);

        byte[] frame = b.array();
        int ipSum = checksum(frame, 14, 20, 0);
        frame[24] = (byte) (ipSum >> 8);
        frame[25] = (byte) ipSum;

        long pseudo = 0;
        pseudo += ((r.srcIp[0] & 0xFF) << 8) | (r.srcIp[1] & 0xFF);
        pseudo += ((r.srcIp[2] & 0xFF) << 8) | (r.srcIp[3] & 0xFF);
        pseudo += ((r.dstIp[0] & 0xFF) << 8) | (r.dstIp[1] & 0xFF);
        pseudo += ((r.dstIp[2] & 0xFF) << 8) | (r.dstIp[3] & 0xFF);
        pseudo += 17;
        pseudo += udpLen;
        int udpSum = checksum(frame, 34, udpLen, pseudo);
        if (udpSum == 0) udpSum = 0xFFFF;
        frame[40] = (byte) (udpSum >> 8);
        frame[41] = (byte) udpSum;
        return frame;
    }

    private static int normalizeDhcpPort(int srcPort, int dstPort, boolean isSrc) {
        if (srcPort == 67 || dstPort == 67 || srcPort == 68 || dstPort == 68) {
            return isSrc ? srcPort : dstPort;
        }
        if (dstPort == 6700) {
            return isSrc ? srcPort : 67;
        }
        if (srcPort == 6700) {
            return isSrc ? 67 : dstPort;
        }
        if (dstPort >= 6701 && dstPort <= 6703 && srcPort != 67) {
            return isSrc ? 67 : dstPort;
        }
        if (srcPort >= 6701 && srcPort <= 6703 && dstPort != 67) {
            return isSrc ? srcPort : 68;
        }
        return isSrc ? srcPort : dstPort;
    }

    private static byte[] deriveMac(byte[] ip, int port, byte[] payload, boolean isSrc) {
        if ((ip[0] & 0xFF) == 255 && (ip[3] & 0xFF) == 255) {
            return new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
        }
        if (payload != null && payload.length >= 34) {
            boolean isBootRequest = payload[0] == 1;
            if ((isSrc && isBootRequest && port != 67 && port != 6700)
                    || (!isSrc && !isBootRequest && port != 67 && port != 6700 && (port < 6701 || port > 6703))) {
                byte[] chaddr = new byte[6];
                System.arraycopy(payload, 28, chaddr, 0, 6);
                if ((chaddr[0] | chaddr[1] | chaddr[2] | chaddr[3] | chaddr[4] | chaddr[5]) != 0) {
                    return chaddr;
                }
            }
        }
        return new byte[]{0x02, 0x42, ip[0], ip[1], ip[2], (byte) ((ip[3] ^ (port & 0xFF)) & 0xFF)};
    }

    private static int checksum(byte[] data, int off, int len, long initial) {
        long sum = initial;
        int i = off;
        int end = off + len;
        while (i + 1 < end) {
            sum += ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF);
            i += 2;
        }
        if (i < end) sum += (data[i] & 0xFF) << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (int) (~sum & 0xFFFF);
    }

    private static byte[] detectLocalIp() {
        try {
            InetAddress a = InetAddress.getLocalHost();
            if (a instanceof Inet4Address) return a.getAddress();
        } catch (Exception ignored) {
        }
        return new byte[]{127, 0, 0, 1};
    }
}

package arp.protocol;

import arp.model.IpAddress;
import arp.model.MacAddress;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Full RFC 826 / RFC 5227 Address Resolution Protocol (ARP) Packet Parser & Serializer.
 *
 * Binary Layout (28 bytes for Ethernet + IPv4):
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        Hardware Type          |        Protocol Type          |  (HTYPE=1, PTYPE=0x0800)
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  HW Addr Len  | Proto Addr Len|          Operation            |  (HLEN=6, PLEN=4, OPER=1/2)
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     Sender Hardware Address (bytes 0-3)       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Sender HW (4-5)              |  Sender Protocol Addr (0-1)   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Sender Proto Addr (2-3)      |  Target Hardware Addr (0-1)   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     Target Hardware Address (bytes 2-5)       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     Target Protocol Address (bytes 0-3)       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
public final class ArpPacket {

    public static final int ARP_HEADER_LENGTH = 28;
    public static final int HTYPE_ETHERNET = 1;
    public static final int PTYPE_IPV4 = 0x0800;
    public static final int HLEN_ETHERNET = 6;
    public static final int PLEN_IPV4 = 4;

    private final int hardwareType;
    private final int protocolType;
    private final int hardwareLength;
    private final int protocolLength;
    private final ArpOperation operation;
    private final MacAddress senderHardwareAddress;
    private final IpAddress senderProtocolAddress;
    private final MacAddress targetHardwareAddress;
    private final IpAddress targetProtocolAddress;

    public ArpPacket(
            int hardwareType,
            int protocolType,
            int hardwareLength,
            int protocolLength,
            ArpOperation operation,
            MacAddress senderHardwareAddress,
            IpAddress senderProtocolAddress,
            MacAddress targetHardwareAddress,
            IpAddress targetProtocolAddress) {
        this.hardwareType = hardwareType;
        this.protocolType = protocolType;
        this.hardwareLength = hardwareLength;
        this.protocolLength = protocolLength;
        this.operation = operation;
        this.senderHardwareAddress = senderHardwareAddress;
        this.senderProtocolAddress = senderProtocolAddress;
        this.targetHardwareAddress = targetHardwareAddress;
        this.targetProtocolAddress = targetProtocolAddress;
    }

    // ------------------------------------------------------------------ Factory methods

    /** Standard ARP Request: Who has targetIp? Tell senderIp */
    public static ArpPacket createRequest(MacAddress senderMac, IpAddress senderIp, IpAddress targetIp) {
        return new ArpPacket(
                HTYPE_ETHERNET, PTYPE_IPV4, HLEN_ETHERNET, PLEN_IPV4,
                ArpOperation.REQUEST,
                senderMac, senderIp,
                MacAddress.ZERO, targetIp
        );
    }

    /** Standard ARP Reply: senderIp is at senderMac */
    public static ArpPacket createReply(MacAddress senderMac, IpAddress senderIp, MacAddress targetMac, IpAddress targetIp) {
        return new ArpPacket(
                HTYPE_ETHERNET, PTYPE_IPV4, HLEN_ETHERNET, PLEN_IPV4,
                ArpOperation.REPLY,
                senderMac, senderIp,
                targetMac, targetIp
        );
    }

    /**
     * Gratuitous ARP Announcement (RFC 5227):
     * Updates neighbor caches and switch CAM tables when an interface comes up or changes IP.
     * senderProtocolAddress == targetProtocolAddress == myIp.
     */
    public static ArpPacket createGratuitousAnnouncement(MacAddress senderMac, IpAddress ip) {
        return new ArpPacket(
                HTYPE_ETHERNET, PTYPE_IPV4, HLEN_ETHERNET, PLEN_IPV4,
                ArpOperation.REQUEST,
                senderMac, ip,
                MacAddress.BROADCAST, ip
        );
    }

    /**
     * ARP Probe (RFC 5227 Address Conflict Detection):
     * Tests whether candidateIp is already in use without polluting existing ARP caches.
     * senderProtocolAddress is set to 0.0.0.0.
     */
    public static ArpPacket createProbe(MacAddress senderMac, IpAddress candidateIp) {
        return new ArpPacket(
                HTYPE_ETHERNET, PTYPE_IPV4, HLEN_ETHERNET, PLEN_IPV4,
                ArpOperation.REQUEST,
                senderMac, IpAddress.ANY,
                MacAddress.ZERO, candidateIp
        );
    }

    // ------------------------------------------------------------------ Getters

    public int getHardwareType() { return hardwareType; }
    public int getProtocolType() { return protocolType; }
    public int getHardwareLength() { return hardwareLength; }
    public int getProtocolLength() { return protocolLength; }
    public ArpOperation getOperation() { return operation; }
    public MacAddress getSenderHardwareAddress() { return senderHardwareAddress; }
    public IpAddress getSenderProtocolAddress() { return senderProtocolAddress; }
    public MacAddress getTargetHardwareAddress() { return targetHardwareAddress; }
    public IpAddress getTargetProtocolAddress() { return targetProtocolAddress; }

    /** True if this is an RFC 5227 Gratuitous ARP Announcement (SPA == TPA and SPA is not 0.0.0.0) */
    public boolean isGratuitous() {
        return senderProtocolAddress.equals(targetProtocolAddress) && !senderProtocolAddress.isAny();
    }

    /** True if this is an RFC 5227 ARP Probe (SPA == 0.0.0.0) */
    public boolean isProbe() {
        return senderProtocolAddress.isAny() && operation == ArpOperation.REQUEST;
    }

    // ------------------------------------------------------------------ Serialization

    public byte[] toBytes() {
        ByteBuffer buf = ByteBuffer.allocate(ARP_HEADER_LENGTH);
        buf.putShort((short) hardwareType);
        buf.putShort((short) protocolType);
        buf.put((byte) hardwareLength);
        buf.put((byte) protocolLength);
        buf.putShort((short) operation.getCode());
        buf.put(senderHardwareAddress.getBytes());
        buf.put(senderProtocolAddress.getBytes());
        buf.put(targetHardwareAddress.getBytes());
        buf.put(targetProtocolAddress.getBytes());
        return buf.array();
    }

    public static ArpPacket fromBytes(byte[] data) {
        return fromBytes(data, 0, data.length);
    }

    public static ArpPacket fromBytes(byte[] data, int offset, int length) {
        if (length < ARP_HEADER_LENGTH) {
            throw new IllegalArgumentException("Payload too short for ARP packet (" + length + " bytes)");
        }
        ByteBuffer buf = ByteBuffer.wrap(data, offset, length);

        int htype = buf.getShort() & 0xFFFF;
        int ptype = buf.getShort() & 0xFFFF;
        int hlen = buf.get() & 0xFF;
        int plen = buf.get() & 0xFF;
        int opCode = buf.getShort() & 0xFFFF;

        byte[] shaBytes = new byte[6];
        buf.get(shaBytes);
        byte[] spaBytes = new byte[4];
        buf.get(spaBytes);
        byte[] thaBytes = new byte[6];
        buf.get(thaBytes);
        byte[] tpaBytes = new byte[4];
        buf.get(tpaBytes);

        return new ArpPacket(
                htype, ptype, hlen, plen,
                ArpOperation.fromCode(opCode),
                new MacAddress(shaBytes),
                new IpAddress(spaBytes),
                new MacAddress(thaBytes),
                new IpAddress(tpaBytes)
        );
    }

    /**
     * Encapsulates this ARP packet in an Ethernet II frame ready for physical transmission.
     */
    public EthernetFrame toFrame() {
        MacAddress dst = (operation == ArpOperation.REQUEST) ? MacAddress.BROADCAST : targetHardwareAddress;
        return new EthernetFrame(dst, senderHardwareAddress, EthernetFrame.ETHERTYPE_ARP, toBytes());
    }

    public String toDetailedString() {
        if (isProbe()) {
            return String.format("[ARP PROBE] ACD Check for %s by MAC %s", targetProtocolAddress, senderHardwareAddress);
        }
        if (isGratuitous()) {
            return String.format("[GARP ANNOUNCE] %s is at %s (Broadcast update)", senderProtocolAddress, senderHardwareAddress);
        }
        if (operation == ArpOperation.REQUEST) {
            return String.format("[ARP REQUEST] Who has %s? Tell %s (%s)", targetProtocolAddress, senderProtocolAddress, senderHardwareAddress);
        }
        return String.format("[ARP REPLY] %s is at %s -> unicast to %s (%s)",
                senderProtocolAddress, senderHardwareAddress, targetProtocolAddress, targetHardwareAddress);
    }

    @Override
    public String toString() {
        return toDetailedString();
    }
}

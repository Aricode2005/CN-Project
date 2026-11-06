package arp.protocol;

import arp.model.MacAddress;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * IEEE 802.3 / Ethernet II Frame Encoder and Decoder.
 *
 * Layout:
 * - Destination MAC: 6 bytes
 * - Source MAC:      6 bytes
 * - EtherType:       2 bytes (0x0806 = ARP, 0x0800 = IPv4, 0x8035 = RARP)
 * - Payload:         46 to 1500 bytes (padded with 0s if payload < 46 bytes)
 * (FCS / CRC-32 is handled at physical layer; omitted in logical L2 simulation)
 */
public final class EthernetFrame {

    public static final int HEADER_LENGTH = 14;
    public static final int MIN_PAYLOAD_LENGTH = 46;
    public static final int MIN_FRAME_LENGTH = HEADER_LENGTH + MIN_PAYLOAD_LENGTH; // 60 bytes
    public static final int MAX_FRAME_LENGTH = 1514;

    public static final int ETHERTYPE_ARP = 0x0806;
    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_RARP = 0x8035;

    private final MacAddress destinationMac;
    private final MacAddress sourceMac;
    private final int etherType;
    private final byte[] payload;

    public EthernetFrame(MacAddress destinationMac, MacAddress sourceMac, int etherType, byte[] payload) {
        if (destinationMac == null || sourceMac == null) {
            throw new IllegalArgumentException("MAC addresses cannot be null");
        }
        this.destinationMac = destinationMac;
        this.sourceMac = sourceMac;
        this.etherType = etherType & 0xFFFF;
        this.payload = payload != null ? Arrays.copyOf(payload, payload.length) : new byte[0];
    }

    public MacAddress getDestinationMac() {
        return destinationMac;
    }

    public MacAddress getSourceMac() {
        return sourceMac;
    }

    public int getEtherType() {
        return etherType;
    }

    public byte[] getPayload() {
        return Arrays.copyOf(payload, payload.length);
    }

    public boolean isBroadcast() {
        return destinationMac.isBroadcast();
    }

    public boolean isArp() {
        return etherType == ETHERTYPE_ARP;
    }

    public boolean isIpv4() {
        return etherType == ETHERTYPE_IPV4;
    }

    /**
     * Serializes this Ethernet frame into a wire-ready byte array.
     * Automatically applies Ethernet padding if payload is shorter than 46 bytes.
     */
    public byte[] toBytes() {
        int payloadLen = Math.max(payload.length, MIN_PAYLOAD_LENGTH);
        ByteBuffer buf = ByteBuffer.allocate(HEADER_LENGTH + payloadLen);

        buf.put(destinationMac.getBytes());
        buf.put(sourceMac.getBytes());
        buf.putShort((short) etherType);
        buf.put(payload);

        // Zero-padding up to 46 bytes
        if (payload.length < MIN_PAYLOAD_LENGTH) {
            buf.put(new byte[MIN_PAYLOAD_LENGTH - payload.length]);
        }

        return buf.array();
    }

    /**
     * Parses an Ethernet II frame from raw bytes.
     */
    public static EthernetFrame fromBytes(byte[] data) {
        return fromBytes(data, 0, data.length);
    }

    public static EthernetFrame fromBytes(byte[] data, int offset, int length) {
        if (length < HEADER_LENGTH) {
            throw new IllegalArgumentException("Data too short for Ethernet header (" + length + " bytes)");
        }
        ByteBuffer buf = ByteBuffer.wrap(data, offset, length);

        byte[] dstMac = new byte[6];
        buf.get(dstMac);
        byte[] srcMac = new byte[6];
        buf.get(srcMac);
        int type = buf.getShort() & 0xFFFF;

        byte[] payload = new byte[buf.remaining()];
        buf.get(payload);

        return new EthernetFrame(new MacAddress(dstMac), new MacAddress(srcMac), type, payload);
    }

    public String toHexDump() {
        byte[] raw = toBytes();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < raw.length; i++) {
            if (i > 0 && i % 16 == 0) sb.append("\n");
            else if (i > 0 && i % 8 == 0) sb.append("  ");
            else if (i > 0) sb.append(" ");
            sb.append(String.format("%02X", raw[i] & 0xFF));
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        String typeStr = (etherType == ETHERTYPE_ARP) ? "ARP" : (etherType == ETHERTYPE_IPV4) ? "IPv4" : String.format("0x%04X", etherType);
        return String.format("[Ethernet II] %s -> %s | Type: %s | Payload: %d bytes",
                sourceMac, destinationMac, typeStr, payload.length);
    }
}

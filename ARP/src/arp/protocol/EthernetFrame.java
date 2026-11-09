package arp.protocol;

import arp.model.MacAddress;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * IEEE 802.3 / Ethernet II Frame Encoder and Decoder.
 * Supports standard untagged frames as well as IEEE 802.1Q VLAN-tagged frames.
 *
 * Untagged Layout:
 * - Destination MAC: 6 bytes
 * - Source MAC:      6 bytes
 * - EtherType:       2 bytes (0x0806 = ARP, 0x0800 = IPv4, 0x8035 = RARP)
 * - Payload:         46 to 1500 bytes (padded with 0s if payload < 46 bytes)
 *
 * IEEE 802.1Q Tagged Layout:
 * - Destination MAC: 6 bytes
 * - Source MAC:      6 bytes
 * - TPID:            2 bytes (0x8100)
 * - TCI:             2 bytes (PCP + DEI + VID)
 * - EtherType:       2 bytes (Inner protocol type)
 * - Payload:         42 to 1500 bytes (min 60-byte wire frame)
 */
public final class EthernetFrame {

    public static final int HEADER_LENGTH_UNTAGGED = 14;
    public static final int HEADER_LENGTH_TAGGED = 18;
    public static final int MIN_PAYLOAD_LENGTH = 46;
    public static final int MIN_FRAME_LENGTH = 60; // minimum Ethernet wire length
    public static final int MAX_FRAME_LENGTH = 1518;

    public static final int ETHERTYPE_ARP = 0x0806;
    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_RARP = 0x8035;
    public static final int ETHERTYPE_8021Q = 0x8100;

    private final MacAddress destinationMac;
    private final MacAddress sourceMac;
    private final int etherType;
    private final byte[] payload;
    private final Dot1qHeader vlanTag; // null if untagged

    /** Standard untagged Ethernet II frame constructor */
    public EthernetFrame(MacAddress destinationMac, MacAddress sourceMac, int etherType, byte[] payload) {
        this(destinationMac, sourceMac, etherType, payload, null);
    }

    /** 802.1Q VLAN-tagged Ethernet frame constructor */
    public EthernetFrame(MacAddress destinationMac, MacAddress sourceMac, int etherType, byte[] payload, Dot1qHeader vlanTag) {
        if (destinationMac == null || sourceMac == null) {
            throw new IllegalArgumentException("MAC addresses cannot be null");
        }
        this.destinationMac = destinationMac;
        this.sourceMac = sourceMac;
        this.etherType = etherType & 0xFFFF;
        this.payload = payload != null ? Arrays.copyOf(payload, payload.length) : new byte[0];
        this.vlanTag = vlanTag;
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

    public Dot1qHeader getVlanTag() {
        return vlanTag;
    }

    public boolean isTagged() {
        return vlanTag != null && vlanTag.getVlanId() > 0;
    }

    public int getVlanId() {
        return (vlanTag != null) ? vlanTag.getVlanId() : 1; // default VLAN 1
    }

    public boolean isBroadcast() {
        return destinationMac.isBroadcast();
    }

    public boolean isMulticast() {
        return destinationMac.isMulticast();
    }

    public boolean isArp() {
        return etherType == ETHERTYPE_ARP;
    }

    public boolean isRarp() {
        return etherType == ETHERTYPE_RARP;
    }

    public boolean isIpv4() {
        return etherType == ETHERTYPE_IPV4;
    }

    /** Creates a copy of this frame tagged with the specified VLAN ID */
    public EthernetFrame withVlan(int vlanId) {
        return new EthernetFrame(destinationMac, sourceMac, etherType, payload, new Dot1qHeader(vlanId));
    }

    /** Creates an untagged copy of this frame */
    public EthernetFrame withoutTag() {
        return new EthernetFrame(destinationMac, sourceMac, etherType, payload, null);
    }

    /**
     * Serializes this Ethernet frame into a wire-ready byte array.
     * Automatically applies Ethernet zero-padding if frame length is shorter than 60 bytes.
     */
    public byte[] toBytes() {
        int headerLen = isTagged() ? HEADER_LENGTH_TAGGED : HEADER_LENGTH_UNTAGGED;
        int totalWireLen = Math.max(headerLen + payload.length, MIN_FRAME_LENGTH);
        ByteBuffer buf = ByteBuffer.allocate(totalWireLen);

        buf.put(destinationMac.getBytes());
        buf.put(sourceMac.getBytes());

        if (isTagged()) {
            buf.putShort((short) ETHERTYPE_8021Q);
            int tci = ((vlanTag.getPriority() & 0x07) << 13)
                    | ((vlanTag.isDropEligible() ? 1 : 0) << 12)
                    | (vlanTag.getVlanId() & 0x0FFF);
            buf.putShort((short) tci);
            buf.putShort((short) etherType);
        } else {
            buf.putShort((short) etherType);
        }

        buf.put(payload);

        // Zero-padding up to 60 bytes
        int written = headerLen + payload.length;
        if (written < MIN_FRAME_LENGTH) {
            buf.put(new byte[MIN_FRAME_LENGTH - written]);
        }

        return buf.array();
    }

    /**
     * Parses an Ethernet II frame from raw bytes, detecting both untagged and 802.1Q tagged frames.
     */
    public static EthernetFrame fromBytes(byte[] data) {
        return fromBytes(data, 0, data.length);
    }

    public static EthernetFrame fromBytes(byte[] data, int offset, int length) {
        if (length < HEADER_LENGTH_UNTAGGED) {
            throw new IllegalArgumentException("Data too short for Ethernet header (" + length + " bytes)");
        }
        ByteBuffer buf = ByteBuffer.wrap(data, offset, length);

        byte[] dstMac = new byte[6];
        buf.get(dstMac);
        byte[] srcMac = new byte[6];
        buf.get(srcMac);

        int typeOrTpid = buf.getShort() & 0xFFFF;
        Dot1qHeader tag = null;
        int etherType;

        if (typeOrTpid == ETHERTYPE_8021Q) {
            // 802.1Q tagged frame
            if (buf.remaining() < 4) {
                throw new IllegalArgumentException("Truncated 802.1Q header");
            }
            int tci = buf.getShort() & 0xFFFF;
            tag = Dot1qHeader.fromTci(tci);
            etherType = buf.getShort() & 0xFFFF;
        } else {
            etherType = typeOrTpid;
        }

        byte[] payload = new byte[buf.remaining()];
        buf.get(payload);

        return new EthernetFrame(new MacAddress(dstMac), new MacAddress(srcMac), etherType, payload, tag);
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
        String typeStr = (etherType == ETHERTYPE_ARP) ? "ARP"
                : (etherType == ETHERTYPE_RARP) ? "RARP"
                : (etherType == ETHERTYPE_IPV4) ? "IPv4"
                : String.format("0x%04X", etherType);
        String tagStr = isTagged() ? String.format(" [VLAN %d]", getVlanId()) : "";
        return String.format("[Ethernet II%s] %s -> %s | Type: %s | Payload: %d bytes",
                tagStr, sourceMac, destinationMac, typeStr, payload.length);
    }
}

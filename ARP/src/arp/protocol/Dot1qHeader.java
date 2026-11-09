package arp.protocol;

/**
 * IEEE 802.1Q Virtual Local Area Network (VLAN) Tag Header.
 *
 * Layout (4 bytes):
 * - TPID (Tag Protocol Identifier): 0x8100 (2 bytes)
 * - TCI (Tag Control Information):  2 bytes
 *     - PCP (Priority Code Point):  3 bits (0-7, IEEE 802.1p Quality of Service)
 *     - DEI (Drop Eligible Indicator): 1 bit (0 or 1)
 *     - VID (VLAN Identifier):      12 bits (1 - 4094)
 */
public final class Dot1qHeader {

    public static final int TPID_8021Q = 0x8100;
    public static final int HEADER_LENGTH = 4;
    public static final int DEFAULT_VLAN = 1;

    private final int priority;     // 3 bits (0-7)
    private final boolean dropEligible; // 1 bit
    private final int vlanId;       // 12 bits (1-4094)

    public Dot1qHeader(int vlanId) {
        this(0, false, vlanId);
    }

    public Dot1qHeader(int priority, boolean dropEligible, int vlanId) {
        if (vlanId < 0 || vlanId > 4095) {
            throw new IllegalArgumentException("VLAN ID must be in range [0, 4095], got: " + vlanId);
        }
        this.priority = priority & 0x07;
        this.dropEligible = dropEligible;
        this.vlanId = vlanId & 0x0FFF;
    }

    public int getPriority() { return priority; }
    public boolean isDropEligible() { return dropEligible; }
    public int getVlanId() { return vlanId; }

    /**
     * Serializes this 802.1Q tag into 4 bytes (TPID + TCI).
     */
    public byte[] toBytes() {
        byte[] b = new byte[4];
        b[0] = (byte) ((TPID_8021Q >> 8) & 0xFF);
        b[1] = (byte) (TPID_8021Q & 0xFF);

        int tci = ((priority & 0x07) << 13) | ((dropEligible ? 1 : 0) << 12) | (vlanId & 0x0FFF);
        b[2] = (byte) ((tci >> 8) & 0xFF);
        b[3] = (byte) (tci & 0xFF);
        return b;
    }

    public static Dot1qHeader fromTci(int tci) {
        int pri = (tci >> 13) & 0x07;
        boolean dei = ((tci >> 12) & 0x01) == 1;
        int vid = tci & 0x0FFF;
        return new Dot1qHeader(pri, dei, vid);
    }

    @Override
    public String toString() {
        return String.format("[802.1Q VLAN %d | PCP=%d | DEI=%d]", vlanId, priority, dropEligible ? 1 : 0);
    }
}

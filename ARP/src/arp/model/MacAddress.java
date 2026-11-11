package arp.model;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable representation of a 48-bit (6-byte) IEEE 802 MAC (Media Access Control) address.
 */
public final class MacAddress implements Comparable<MacAddress> {

    public static final int LENGTH = 6;
    public static final MacAddress BROADCAST = new MacAddress(new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF});
    public static final MacAddress ZERO = new MacAddress(new byte[]{0, 0, 0, 0, 0, 0});

    private static final Map<String, String> OUI_VENDORS = new HashMap<>();
    static {
        OUI_VENDORS.put("00:1A:2B", "Cisco Systems");
        OUI_VENDORS.put("00:50:56", "VMware Virtual NIC");
        OUI_VENDORS.put("08:00:27", "Oracle VirtualBox");
        OUI_VENDORS.put("AA:AA:AA", "Simulated-Node A");
        OUI_VENDORS.put("BB:BB:BB", "Simulated-Node B");
        OUI_VENDORS.put("CC:CC:CC", "Simulated-Node C");
        OUI_VENDORS.put("66:66:66", "Kali Rogue NIC");
        OUI_VENDORS.put("F0:18:98", "Apple Inc.");
        OUI_VENDORS.put("3C:52:82", "Intel Corporate");
        OUI_VENDORS.put("52:54:00", "QEMU Virtual NIC");
    }

    private final byte[] bytes;
    private final String formatted;

    public MacAddress(byte[] bytes) {
        if (bytes == null || bytes.length != LENGTH) {
            throw new IllegalArgumentException("MAC address must be exactly 6 bytes");
        }
        this.bytes = Arrays.copyOf(bytes, LENGTH);
        this.formatted = String.format("%02X:%02X:%02X:%02X:%02X:%02X",
                this.bytes[0] & 0xFF, this.bytes[1] & 0xFF, this.bytes[2] & 0xFF,
                this.bytes[3] & 0xFF, this.bytes[4] & 0xFF, this.bytes[5] & 0xFF);
    }

    public static MacAddress parse(String str) {
        if (str == null) throw new IllegalArgumentException("MAC string cannot be null");
        String clean = str.trim().replaceAll("[:-]", "").replace(".", "");
        if (clean.length() != 12) {
            throw new IllegalArgumentException("Invalid MAC address representation: " + str);
        }
        byte[] b = new byte[6];
        for (int i = 0; i < 6; i++) {
            int high = Character.digit(clean.charAt(i * 2), 16);
            int low = Character.digit(clean.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("Invalid hex character in MAC: " + str);
            }
            b[i] = (byte) ((high << 4) | low);
        }
        return new MacAddress(b);
    }

    public byte[] getBytes() {
        return Arrays.copyOf(bytes, LENGTH);
    }

    public boolean isBroadcast() {
        return this.equals(BROADCAST);
    }

    public boolean isMulticast() {
        return !isBroadcast() && ((bytes[0] & 0x01) != 0);
    }

    public boolean isUnicast() {
        return !isBroadcast() && !isMulticast();
    }

    public boolean isZero() {
        return this.equals(ZERO);
    }

    public String getOuiPrefix() {
        return String.format("%02X:%02X:%02X", bytes[0] & 0xFF, bytes[1] & 0xFF, bytes[2] & 0xFF);
    }

    public String getVendor() {
        String vendor = OUI_VENDORS.get(getOuiPrefix());
        return vendor != null ? vendor : "Generic / Private NIC";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof MacAddress)) return false;
        MacAddress that = (MacAddress) o;
        return Arrays.equals(this.bytes, that.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public String toString() {
        return formatted;
    }

    @Override
    public int compareTo(MacAddress o) {
        for (int i = 0; i < LENGTH; i++) {
            int a = this.bytes[i] & 0xFF;
            int b = o.bytes[i] & 0xFF;
            if (a != b) return Integer.compare(a, b);
        }
        return 0;
    }
}

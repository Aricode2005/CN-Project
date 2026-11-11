package arp.model;

import java.util.Arrays;

/**
 * Immutable representation of a 32-bit (4-byte) IPv4 address.
 */
public final class IpAddress implements Comparable<IpAddress> {

    public static final int LENGTH = 4;
    public static final IpAddress ANY = new IpAddress(new byte[]{0, 0, 0, 0});
    public static final IpAddress BROADCAST = new IpAddress(new byte[]{(byte) 255, (byte) 255, (byte) 255, (byte) 255});

    private final byte[] bytes;
    private final String formatted;
    private final int intVal;

    public IpAddress(byte[] bytes) {
        if (bytes == null || bytes.length != LENGTH) {
            throw new IllegalArgumentException("IPv4 address must be exactly 4 bytes");
        }
        this.bytes = Arrays.copyOf(bytes, LENGTH);
        this.formatted = String.format("%d.%d.%d.%d",
                this.bytes[0] & 0xFF, this.bytes[1] & 0xFF,
                this.bytes[2] & 0xFF, this.bytes[3] & 0xFF);
        this.intVal = ((this.bytes[0] & 0xFF) << 24)
                | ((this.bytes[1] & 0xFF) << 16)
                | ((this.bytes[2] & 0xFF) << 8)
                | (this.bytes[3] & 0xFF);
    }

    public static IpAddress parse(String str) {
        if (str == null) throw new IllegalArgumentException("IP string cannot be null");
        String[] parts = str.trim().split("\\.");
        if (parts.length != 4) {
            throw new IllegalArgumentException("Invalid IPv4 address format: " + str);
        }
        byte[] b = new byte[4];
        for (int i = 0; i < 4; i++) {
            int val = Integer.parseInt(parts[i].trim());
            if (val < 0 || val > 255) {
                throw new IllegalArgumentException("Octet out of range [0-255]: " + val);
            }
            b[i] = (byte) val;
        }
        return new IpAddress(b);
    }

    public byte[] getBytes() {
        return Arrays.copyOf(bytes, LENGTH);
    }

    public int toInt() {
        return intVal;
    }

    public boolean isAny() {
        return this.equals(ANY);
    }

    public boolean isBroadcast() {
        return this.equals(BROADCAST);
    }

    public boolean isInSameSubnet(IpAddress other, IpAddress netmask) {
        return (this.intVal & netmask.intVal) == (other.intVal & netmask.intVal);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof IpAddress)) return false;
        IpAddress ipAddress = (IpAddress) o;
        return this.intVal == ipAddress.intVal;
    }

    @Override
    public int hashCode() {
        return intVal;
    }

    @Override
    public String toString() {
        return formatted;
    }

    @Override
    public int compareTo(IpAddress o) {
        return Integer.compareUnsigned(this.intVal, o.intVal);
    }
}

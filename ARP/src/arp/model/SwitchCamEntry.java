package arp.model;

import arp.core.Json;

/**
 * An entry in an L2 Ethernet Switch's CAM (Content Addressable Memory) / MAC Address Table.
 */
public final class SwitchCamEntry {

    private final MacAddress mac;
    private volatile int port;
    private final boolean isStatic;
    private volatile long lastSeenMs;
    private final int ttlSeconds;

    public SwitchCamEntry(MacAddress mac, int port, boolean isStatic, int ttlSeconds) {
        this.mac = mac;
        this.port = port;
        this.isStatic = isStatic;
        this.ttlSeconds = ttlSeconds;
        this.lastSeenMs = System.currentTimeMillis();
    }

    public static SwitchCamEntry dynamicEntry(MacAddress mac, int port, int ttlSeconds) {
        return new SwitchCamEntry(mac, port, false, ttlSeconds);
    }

    public static SwitchCamEntry staticEntry(MacAddress mac, int port) {
        return new SwitchCamEntry(mac, port, true, 0);
    }

    public MacAddress getMac() { return mac; }
    public int getPort() { return port; }
    public boolean isStatic() { return isStatic; }
    public long getLastSeenMs() { return lastSeenMs; }
    public int getTtlSeconds() { return ttlSeconds; }

    public void refresh(int newPort) {
        this.port = newPort;
        this.lastSeenMs = System.currentTimeMillis();
    }

    public long getAgeSeconds() {
        return Math.max(0, (System.currentTimeMillis() - lastSeenMs) / 1000);
    }

    public long getRemainingTtlSeconds() {
        if (isStatic) return Long.MAX_VALUE;
        long elapsed = (System.currentTimeMillis() - lastSeenMs) / 1000;
        return Math.max(0, ttlSeconds - elapsed);
    }

    public boolean isExpired() {
        if (isStatic) return false;
        return getRemainingTtlSeconds() <= 0;
    }

    public String json() {
        return Json.obj(
                "mac", mac.toString(),
                "port", port,
                "isStatic", isStatic,
                "ageSec", getAgeSeconds(),
                "ttlRemainingSec", isStatic ? -1 : getRemainingTtlSeconds(),
                "vendor", mac.getVendor()
        );
    }

    @Override
    public String toString() {
        return String.format("Port %d: %s (%s, Age: %ds)",
                port, mac, isStatic ? "STATIC" : "DYNAMIC", getAgeSeconds());
    }
}

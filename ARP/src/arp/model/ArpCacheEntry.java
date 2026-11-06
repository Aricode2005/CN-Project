package arp.model;

import arp.core.Json;

/**
 * An entry in a host or router's ARP Cache table.
 */
public final class ArpCacheEntry {

    public enum State {
        INCOMPLETE("Incomplete", "Awaiting ARP reply"),
        REACHABLE("Reachable", "Confirmed valid entry"),
        STALE("Stale", "Aged past active freshness"),
        STATIC("Static", "Permanently configured VIP"),
        POISONED("Poisoned", "Compromised by ARP Spoofing attack");

        private final String label;
        private final String desc;
        State(String label, String desc) { this.label = label; this.desc = desc; }
        public String getLabel() { return label; }
        public String getDesc() { return desc; }
    }

    private final IpAddress ip;
    private volatile MacAddress mac;
    private volatile State state;
    private final boolean isStatic;
    private final long createdTimeMs;
    private volatile long lastUpdatedTimeMs;
    private final int ttlSeconds;

    public ArpCacheEntry(IpAddress ip, MacAddress mac, State state, boolean isStatic, int ttlSeconds) {
        this.ip = ip;
        this.mac = mac != null ? mac : MacAddress.ZERO;
        this.state = state;
        this.isStatic = isStatic;
        this.ttlSeconds = ttlSeconds;
        this.createdTimeMs = System.currentTimeMillis();
        this.lastUpdatedTimeMs = this.createdTimeMs;
    }

    public static ArpCacheEntry dynamicEntry(IpAddress ip, MacAddress mac, int ttlSeconds) {
        return new ArpCacheEntry(ip, mac, State.REACHABLE, false, ttlSeconds);
    }

    public static ArpCacheEntry staticEntry(IpAddress ip, MacAddress mac) {
        return new ArpCacheEntry(ip, mac, State.STATIC, true, 0);
    }

    public static ArpCacheEntry incomplete(IpAddress ip, int timeoutSeconds) {
        return new ArpCacheEntry(ip, MacAddress.ZERO, State.INCOMPLETE, false, timeoutSeconds);
    }

    public IpAddress getIp() { return ip; }
    public MacAddress getMac() { return mac; }
    public State getState() { return state; }
    public boolean isStatic() { return isStatic; }
    public long getCreatedTimeMs() { return createdTimeMs; }
    public long getLastUpdatedTimeMs() { return lastUpdatedTimeMs; }
    public int getTtlSeconds() { return ttlSeconds; }

    public void update(MacAddress newMac, State newState) {
        this.mac = newMac;
        this.state = newState;
        this.lastUpdatedTimeMs = System.currentTimeMillis();
    }

    public void setState(State state) {
        this.state = state;
    }

    public long getAgeSeconds() {
        return Math.max(0, (System.currentTimeMillis() - lastUpdatedTimeMs) / 1000);
    }

    public long getRemainingTtlSeconds() {
        if (isStatic || state == State.STATIC) return Long.MAX_VALUE;
        long elapsed = (System.currentTimeMillis() - lastUpdatedTimeMs) / 1000;
        return Math.max(0, ttlSeconds - elapsed);
    }

    public boolean isExpired() {
        if (isStatic || state == State.STATIC) return false;
        return getRemainingTtlSeconds() <= 0;
    }

    public String json() {
        return Json.obj(
                "ip", ip.toString(),
                "mac", mac.toString(),
                "state", state.name(),
                "stateLabel", state.getLabel(),
                "isStatic", isStatic,
                "ageSec", getAgeSeconds(),
                "ttlRemainingSec", (isStatic || state == State.STATIC) ? -1 : getRemainingTtlSeconds(),
                "vendor", mac.getVendor()
        );
    }

    @Override
    public String toString() {
        return String.format("%-15s -> %-17s [%-10s] TTL: %3ds (%s)",
                ip, mac, state.getLabel(),
                (isStatic || state == State.STATIC) ? -1 : getRemainingTtlSeconds(),
                isStatic ? "STATIC" : "DYNAMIC");
    }
}

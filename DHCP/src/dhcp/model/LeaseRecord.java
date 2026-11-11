package dhcp.model;

public class LeaseRecord {

    public enum State {
        OFFERED,
        ACTIVE,
        EXPIRED,
        DECLINED
    }

    private final String ipAddress;
    private final String macAddress;
    private final String hostname;
    private final State state;
    private final String allocatedByNode;
    private final long expiresAtEpochMs;
    private final boolean staticReservation;
    private final long lastUpdatedEpochMs;

    public LeaseRecord(
            String ipAddress,
            String macAddress,
            String hostname,
            State state,
            String allocatedByNode,
            long expiresAtEpochMs,
            boolean staticReservation) {
        this.ipAddress = ipAddress;
        this.macAddress = macAddress.toUpperCase();
        this.hostname = hostname != null ? hostname : "client-" + macAddress.substring(Math.max(0, macAddress.length() - 5)).replace(":", "");
        this.state = state;
        this.allocatedByNode = allocatedByNode;
        this.expiresAtEpochMs = expiresAtEpochMs;
        this.staticReservation = staticReservation;
        this.lastUpdatedEpochMs = System.currentTimeMillis();
    }

    public String getIpAddress() { return ipAddress; }
    public String getMacAddress() { return macAddress; }
    public String getHostname() { return hostname; }
    public State getState() { return state; }
    public String getAllocatedByNode() { return allocatedByNode; }
    public long getExpiresAtEpochMs() { return expiresAtEpochMs; }
    public boolean isStaticReservation() { return staticReservation; }
    public long getLastUpdatedEpochMs() { return lastUpdatedEpochMs; }

    public long getRemainingSeconds() {
        long diff = (expiresAtEpochMs - System.currentTimeMillis()) / 1000;
        return Math.max(0, diff);
    }

    public boolean isExpired() {
        return !staticReservation && System.currentTimeMillis() > expiresAtEpochMs;
    }

    public String serialize() {
        return String.join("|",
                ipAddress,
                macAddress,
                hostname.replace("|", "_"),
                state.name(),
                allocatedByNode,
                String.valueOf(expiresAtEpochMs),
                String.valueOf(staticReservation));
    }

    public static LeaseRecord deserialize(String line) {
        String[] parts = line.split("\\|");
        if (parts.length < 7) {
            throw new IllegalArgumentException("Invalid serialized LeaseRecord: " + line);
        }
        return new LeaseRecord(
                parts[0],
                parts[1],
                parts[2],
                State.valueOf(parts[3]),
                parts[4],
                Long.parseLong(parts[5]),
                Boolean.parseBoolean(parts[6])
        );
    }

    @Override
    public String toString() {
        return String.format("Lease[ip=%s, mac=%s, host=%s, state=%s, node=%s, ttl=%ds, static=%s]",
                ipAddress, macAddress, hostname, state, allocatedByNode, getRemainingSeconds(), staticReservation);
    }
}

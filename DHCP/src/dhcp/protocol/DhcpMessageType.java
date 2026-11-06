package dhcp.protocol;

/**
 * RFC 2131 DHCP Message Types (Option 53) plus internal distributed cluster control message types.
 */
public enum DhcpMessageType {
    DHCPDISCOVER((byte) 1),
    DHCPOFFER((byte) 2),
    DHCPREQUEST((byte) 3),
    DHCPDECLINE((byte) 4),
    DHCPACK((byte) 5),
    DHCPNAK((byte) 6),
    DHCPRELEASE((byte) 7),
    DHCPINFORM((byte) 8),

    // Distributed Systems / Internal Cluster Control Messages
    CLUSTER_PEER_SYNC((byte) 101),
    CLUSTER_HEALTH_PING((byte) 102),
    CLUSTER_HEALTH_PONG((byte) 103);

    private final byte code;

    DhcpMessageType(byte code) {
        this.code = code;
    }

    public byte getCode() {
        return code;
    }

    public static DhcpMessageType fromCode(byte code) {
        for (DhcpMessageType type : values()) {
            if (type.code == code) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown DHCP Message Type code: " + code);
    }
}

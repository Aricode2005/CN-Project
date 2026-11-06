package arp.protocol;

/**
 * Standard ARP Operation codes as defined in RFC 826, RFC 903, and RFC 2390.
 */
public enum ArpOperation {
    REQUEST(1, "ARP Request", "Who has target IP? Tell sender"),
    REPLY(2, "ARP Reply", "Sender IP is at sender MAC"),
    RARP_REQUEST(3, "RARP Request", "Who has target MAC? Tell IP (RFC 903)"),
    RARP_REPLY(4, "RARP Reply", "Sender MAC is at sender IP (RFC 903)"),
    INARP_REQUEST(8, "InARP Request", "Inverse ARP Request (RFC 2390)"),
    INARP_REPLY(9, "InARP Reply", "Inverse ARP Reply (RFC 2390)");

    private final int code;
    private final String title;
    private final String description;

    ArpOperation(int code, String title, String description) {
        this.code = code;
        this.title = title;
        this.description = description;
    }

    public int getCode() {
        return code;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    public static ArpOperation fromCode(int code) {
        for (ArpOperation op : values()) {
            if (op.code == code) {
                return op;
            }
        }
        throw new IllegalArgumentException("Unknown ARP operation code: " + code);
    }
}

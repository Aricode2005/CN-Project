package arp.model;

/**
 * RFC 5227 IPv4 Address Conflict Detection (ACD) State Machine.
 */
public enum AcdState {
    IDLE("Idle", "Interface uninitialized or static configuration"),
    PROBING("Probing", "Transmitting RFC 5227 ARP Probes (SPA=0.0.0.0) with backoff"),
    ANNOUNCING("Announcing", "Candidate IP clean; broadcasting Gratuitous ARP announcements"),
    CONFIGURED("Configured", "Address verified and actively bound to interface"),
    DEFENDING("Defending", "Conflict detected while configured; defensive GARP transmitted"),
    CONFLICTED("Conflicted", "Address conflict unresolved; address yielded / disabled");

    private final String label;
    private final String description;

    AcdState(String label, String description) {
        this.label = label;
        this.description = description;
    }

    public String getLabel() { return label; }
    public String getDescription() { return description; }
}

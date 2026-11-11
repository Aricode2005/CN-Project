package arp.security;

import arp.core.Hub;
import arp.core.Json;
import arp.model.ArpCacheEntry;
import arp.model.ArpTable;
import arp.model.IpAddress;
import arp.model.MacAddress;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Host-Side Passive ARP Defense & MAC Flip-Flop Monitor (Arpwatch Heuristics).
 *
 * Detects ARP Spoofing attacks locally on the end host:
 * - Detects unsolicited / sudden MAC changes for known IP addresses (Flip-Flop).
 * - Flags security alarms.
 * - In STRICT mode: Rejects unsolicited MAC flip-flops to safeguard the local ARP table.
 */
public final class HostArpDefender {

    public static final class Alert {
        public final long timestampMs;
        public final IpAddress ip;
        public final MacAddress oldMac;
        public final MacAddress newMac;
        public final boolean blocked;

        public Alert(IpAddress ip, MacAddress oldMac, MacAddress newMac, boolean blocked) {
            this.timestampMs = System.currentTimeMillis();
            this.ip = ip;
            this.oldMac = oldMac;
            this.newMac = newMac;
            this.blocked = blocked;
        }

        public String json() {
            return Json.obj(
                    "t", timestampMs,
                    "ip", ip.toString(),
                    "oldMac", oldMac.toString(),
                    "newMac", newMac.toString(),
                    "blocked", blocked
            );
        }
    }

    private final String hostname;
    private volatile boolean strictMode = false;
    private final AtomicInteger flipFlopCount = new AtomicInteger();
    private final List<Alert> alerts = Collections.synchronizedList(new ArrayList<>());

    public HostArpDefender(String hostname) {
        this.hostname = hostname;
    }

    public boolean isStrictMode() {
        return strictMode;
    }

    public void setStrictMode(boolean strictMode) {
        this.strictMode = strictMode;
    }

    public int getFlipFlopCount() {
        return flipFlopCount.get();
    }

    public List<Alert> getAlerts() {
        synchronized (alerts) {
            return new ArrayList<>(alerts);
        }
    }

    /**
     * Inspects an incoming ARP mapping update before applying it to the host ARP table.
     *
     * @param table Current host ARP table
     * @param ip Sender IP address
     * @param newMac Sender MAC address
     * @return true if mapping is safe to accept; false if rejected by strict policy
     */
    public boolean checkUpdate(ArpTable table, IpAddress ip, MacAddress newMac) {
        ArpCacheEntry existing = table.lookup(ip);
        if (existing == null || existing.getMac().isZero()) {
            return true; // First time learning or completing pending resolution
        }

        if (existing.isStatic() || existing.getState() == ArpCacheEntry.State.STATIC) {
            Hub.I.log(String.format("[%s DEFENDER] REJECTED ARP update for Static VIP %s (Attempted overwrite by %s)",
                    hostname, ip, newMac));
            return false;
        }

        if (!existing.getMac().equals(newMac)) {
            // Flip-Flop detected!
            int count = flipFlopCount.incrementAndGet();
            boolean block = strictMode;
            Hub.I.log(String.format("[ARPWATCH ALARM on %s] MAC FLIP-FLOP DETECTED for %s! Old: %s -> New Rogue: %s (%s)",
                    hostname, ip, existing.getMac(), newMac, block ? "BLOCKED" : "LOGGED ONLY"));

            Alert alert = new Alert(ip, existing.getMac(), newMac, block);
            synchronized (alerts) {
                alerts.add(0, alert);
                if (alerts.size() > 30) alerts.remove(alerts.size() - 1);
            }

            if (block) {
                return false;
            }
        }

        return true;
    }

    public String json() {
        List<String> aJsons = new ArrayList<>();
        for (Alert a : getAlerts()) aJsons.add(a.json());
        return Json.obj(
                "strictMode", strictMode,
                "flipFlops", flipFlopCount.get(),
                "alerts", Json.arr(aJsons)
        );
    }
}

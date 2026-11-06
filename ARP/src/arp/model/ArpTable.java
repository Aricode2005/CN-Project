package arp.model;

import arp.core.Json;
import arp.protocol.EthernetFrame;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe ARP Cache Table maintained by every network node.
 * Supports:
 * - RFC 826 lookup and dynamic resolution
 * - Pending packet queueing during INCOMPLETE state
 * - Cache entry aging and expiration
 * - Static VIP protection against spoofing
 */
public final class ArpTable {

    private final String ownerName;
    private final Map<IpAddress, ArpCacheEntry> table = new ConcurrentHashMap<>();
    private final Map<IpAddress, List<EthernetFrame>> pendingPackets = new ConcurrentHashMap<>();

    public ArpTable(String ownerName) {
        this.ownerName = ownerName;
    }

    public ArpCacheEntry lookup(IpAddress ip) {
        ArpCacheEntry entry = table.get(ip);
        if (entry != null && entry.isExpired()) {
            table.remove(ip);
            return null;
        }
        return entry;
    }

    public MacAddress lookupMac(IpAddress ip) {
        ArpCacheEntry entry = lookup(ip);
        if (entry != null && (entry.getState() == ArpCacheEntry.State.REACHABLE
                || entry.getState() == ArpCacheEntry.State.STATIC
                || entry.getState() == ArpCacheEntry.State.POISONED)) {
            return entry.getMac();
        }
        return null;
    }

    public ArpCacheEntry putDynamic(IpAddress ip, MacAddress mac, int ttlSeconds) {
        ArpCacheEntry existing = table.get(ip);
        if (existing != null && (existing.isStatic() || existing.getState() == ArpCacheEntry.State.STATIC)) {
            // Protected static VIP entry: reject dynamic overwrite
            return existing;
        }
        if (existing != null) {
            existing.update(mac, ArpCacheEntry.State.REACHABLE);
            return existing;
        } else {
            ArpCacheEntry newEntry = ArpCacheEntry.dynamicEntry(ip, mac, ttlSeconds);
            table.put(ip, newEntry);
            return newEntry;
        }
    }

    public ArpCacheEntry putStatic(IpAddress ip, MacAddress mac) {
        ArpCacheEntry entry = ArpCacheEntry.staticEntry(ip, mac);
        table.put(ip, entry);
        return entry;
    }

    public ArpCacheEntry markIncomplete(IpAddress ip, int timeoutSeconds) {
        ArpCacheEntry existing = table.get(ip);
        if (existing != null && (existing.isStatic() || existing.getState() == ArpCacheEntry.State.STATIC)) {
            return existing;
        }
        ArpCacheEntry entry = ArpCacheEntry.incomplete(ip, timeoutSeconds);
        table.put(ip, entry);
        return entry;
    }

    public void markPoisoned(IpAddress ip, MacAddress rogueMac) {
        ArpCacheEntry existing = table.get(ip);
        if (existing != null && (existing.isStatic() || existing.getState() == ArpCacheEntry.State.STATIC)) {
            return; // Static entry is immune
        }
        ArpCacheEntry entry = new ArpCacheEntry(ip, rogueMac, ArpCacheEntry.State.POISONED, false, 45);
        table.put(ip, entry);
    }

    public void queuePendingPacket(IpAddress ip, EthernetFrame frame) {
        pendingPackets.computeIfAbsent(ip, k -> Collections.synchronizedList(new ArrayList<>())).add(frame);
    }

    public List<EthernetFrame> drainPendingPackets(IpAddress ip) {
        List<EthernetFrame> frames = pendingPackets.remove(ip);
        return frames != null ? new ArrayList<>(frames) : Collections.emptyList();
    }

    public void reap() {
        for (Map.Entry<IpAddress, ArpCacheEntry> entry : table.entrySet()) {
            ArpCacheEntry e = entry.getValue();
            if (e.isExpired()) {
                if (e.getState() == ArpCacheEntry.State.REACHABLE) {
                    e.setState(ArpCacheEntry.State.STALE);
                } else {
                    table.remove(entry.getKey());
                    pendingPackets.remove(entry.getKey());
                }
            }
        }
    }

    public void clearDynamic() {
        table.entrySet().removeIf(e -> !e.getValue().isStatic() && e.getValue().getState() != ArpCacheEntry.State.STATIC);
        pendingPackets.clear();
    }

    public void remove(IpAddress ip) {
        table.remove(ip);
        pendingPackets.remove(ip);
    }

    public List<ArpCacheEntry> getEntries() {
        List<ArpCacheEntry> list = new ArrayList<>(table.values());
        Collections.sort(list, (a, b) -> a.getIp().compareTo(b.getIp()));
        return list;
    }

    public int size() {
        return table.size();
    }

    public String getOwnerName() {
        return ownerName;
    }

    public String json() {
        List<String> entryJsons = new ArrayList<>();
        for (ArpCacheEntry e : getEntries()) {
            entryJsons.add(e.json());
        }
        return Json.arr(entryJsons);
    }
}

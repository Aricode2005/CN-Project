package dhcp.cluster;

import dhcp.model.LeaseRecord;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class LeaseManager {

    private final String subnetPrefix;
    private final int startHost;
    private final int endHost;
    private final int defaultLeaseSeconds;
    private final File persistenceFile;

    private final List<String> ipPool = new ArrayList<>();
    private final ConcurrentHashMap<String, LeaseRecord> leasesByIp = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> ipByMac = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> staticReservations = new ConcurrentHashMap<>();

    private final ScheduledExecutorService reaperExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "Lease-Expiration-Reaper");
        t.setDaemon(true);
        return t;
    });

    public LeaseManager(String subnetPrefix, int startHost, int endHost, int defaultLeaseSeconds, File persistenceFile) {
        this.subnetPrefix = subnetPrefix.endsWith(".") ? subnetPrefix : subnetPrefix + ".";
        this.startHost = startHost;
        this.endHost = endHost;
        this.defaultLeaseSeconds = defaultLeaseSeconds;
        this.persistenceFile = persistenceFile;

        for (int i = startHost; i <= endHost; i++) {
            ipPool.add(this.subnetPrefix + i);
        }

        addStaticReservation("00:1A:2B:3C:4D:01", this.subnetPrefix + "5", "gateway-admin-vip");
        addStaticReservation("00:1A:2B:3C:4D:02", this.subnetPrefix + "6", "prod-db-primary");

        loadFromDisk();

        reaperExecutor.scheduleAtFixedRate(this::reapExpiredLeases, 2, 2, TimeUnit.SECONDS);
    }

    public synchronized void addStaticReservation(String mac, String ip, String hostname) {
        String normalizedMac = mac.toUpperCase();
        staticReservations.put(normalizedMac, ip);
        LeaseRecord staticRecord = new LeaseRecord(
                ip,
                normalizedMac,
                hostname,
                LeaseRecord.State.ACTIVE,
                "STATIC-VIP",
                Long.MAX_VALUE,
                true
        );
        leasesByIp.put(ip, staticRecord);
        ipByMac.put(normalizedMac, ip);
    }

    public synchronized LeaseRecord offerLease(String mac, String hostname, String requestedIp, String nodeId) {
        String normalizedMac = mac.toUpperCase();

        if (staticReservations.containsKey(normalizedMac)) {
            String staticIp = staticReservations.get(normalizedMac);
            LeaseRecord record = new LeaseRecord(
                    staticIp, normalizedMac, hostname,
                    LeaseRecord.State.OFFERED, nodeId,
                    System.currentTimeMillis() + (defaultLeaseSeconds * 1000L), true
            );
            leasesByIp.put(staticIp, record);
            ipByMac.put(normalizedMac, staticIp);
            return record;
        }

        String existingIp = ipByMac.get(normalizedMac);
        if (existingIp != null) {
            LeaseRecord existing = leasesByIp.get(existingIp);
            if (existing != null && existing.getState() != LeaseRecord.State.DECLINED) {
                LeaseRecord refreshed = new LeaseRecord(
                        existingIp, normalizedMac, hostname,
                        LeaseRecord.State.OFFERED, nodeId,
                        System.currentTimeMillis() + 30_000L,
                        false
                );
                leasesByIp.put(existingIp, refreshed);
                return refreshed;
            }
        }

        if (requestedIp != null && ipPool.contains(requestedIp)) {
            LeaseRecord current = leasesByIp.get(requestedIp);
            if (current == null || current.isExpired()) {
                return createOffer(requestedIp, normalizedMac, hostname, nodeId);
            }
        }

        for (String candidateIp : ipPool) {
            if (staticReservations.containsValue(candidateIp)) continue;
            LeaseRecord current = leasesByIp.get(candidateIp);
            if (current == null || current.isExpired() || current.getState() == LeaseRecord.State.EXPIRED) {
                return createOffer(candidateIp, normalizedMac, hostname, nodeId);
            }
        }

        return null;
    }

    private LeaseRecord createOffer(String ip, String mac, String hostname, String nodeId) {
        LeaseRecord offer = new LeaseRecord(
                ip, mac, hostname,
                LeaseRecord.State.OFFERED, nodeId,
                System.currentTimeMillis() + 30_000L,
                false
        );
        leasesByIp.put(ip, offer);
        ipByMac.put(mac, ip);
        return offer;
    }

    public synchronized LeaseRecord commitLease(String mac, String requestedIp, String hostname, String nodeId, int leaseTimeSec) {
        String normalizedMac = mac.toUpperCase();
        int durationSec = leaseTimeSec > 0 ? leaseTimeSec : defaultLeaseSeconds;

        String targetIp = requestedIp;
        if (targetIp == null || targetIp.equals("0.0.0.0")) {
            targetIp = ipByMac.get(normalizedMac);
        }
        if (targetIp == null || !targetIp.startsWith(subnetPrefix)) {
            return null;
        }

        LeaseRecord existing = leasesByIp.get(targetIp);
        if (existing != null && !existing.isExpired()
                && existing.getState() != LeaseRecord.State.EXPIRED
                && !existing.getMacAddress().equalsIgnoreCase(normalizedMac)) {
            return null;
        }

        boolean isStatic = staticReservations.containsKey(normalizedMac);
        LeaseRecord active = new LeaseRecord(
                targetIp,
                normalizedMac,
                hostname != null ? hostname : (existing != null ? existing.getHostname() : null),
                LeaseRecord.State.ACTIVE,
                nodeId,
                System.currentTimeMillis() + (durationSec * 1000L),
                isStatic
        );

        leasesByIp.put(targetIp, active);
        ipByMac.put(normalizedMac, targetIp);
        saveToDisk();
        return active;
    }

    public synchronized boolean releaseLease(String mac, String nodeId) {
        String normalizedMac = mac.toUpperCase();
        String ip = ipByMac.remove(normalizedMac);
        if (ip != null) {
            if (staticReservations.containsKey(normalizedMac)) {
                return false;
            }
            LeaseRecord removed = leasesByIp.remove(ip);
            saveToDisk();
            return removed != null;
        }
        return false;
    }

    public synchronized LeaseRecord declineLease(String mac, String declinedIp, String nodeId) {
        String normalizedMac = mac.toUpperCase();
        ipByMac.remove(normalizedMac);
        if (declinedIp != null) {
            LeaseRecord declined = new LeaseRecord(
                    declinedIp, "CONFLICT-" + normalizedMac, "arp-conflict",
                    LeaseRecord.State.DECLINED, nodeId,
                    System.currentTimeMillis() + 120_000L, false
            );
            leasesByIp.put(declinedIp, declined);
            saveToDisk();
            return declined;
        }
        return null;
    }

    public synchronized void applyPeerSync(LeaseRecord incoming) {
        if (incoming.getState() == LeaseRecord.State.EXPIRED) {
            leasesByIp.remove(incoming.getIpAddress());
            ipByMac.remove(incoming.getMacAddress());
        } else {
            leasesByIp.put(incoming.getIpAddress(), incoming);
            ipByMac.put(incoming.getMacAddress(), incoming.getIpAddress());
        }
    }

    public synchronized int reapExpiredLeases() {
        int reaped = 0;
        for (Map.Entry<String, LeaseRecord> entry : leasesByIp.entrySet()) {
            LeaseRecord record = entry.getValue();
            if (record.isExpired() && record.getState() != LeaseRecord.State.EXPIRED) {
                leasesByIp.remove(entry.getKey());
                ipByMac.remove(record.getMacAddress(), entry.getKey());
                reaped++;
            }
        }
        if (reaped > 0) {
            saveToDisk();
        }
        return reaped;
    }

    private synchronized void saveToDisk() {
        if (persistenceFile == null) return;
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(persistenceFile, false))) {
            for (LeaseRecord record : leasesByIp.values()) {
                if (!record.isExpired()) {
                    writer.write(record.serialize());
                    writer.newLine();
                }
            }
        } catch (IOException ignored) {
        }
    }

    private synchronized void loadFromDisk() {
        if (persistenceFile == null || !persistenceFile.exists()) return;
        try (BufferedReader reader = new BufferedReader(new FileReader(persistenceFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                try {
                    LeaseRecord rec = LeaseRecord.deserialize(line);
                    if (!rec.isExpired() && rec.getIpAddress().startsWith(this.subnetPrefix)) {
                        leasesByIp.put(rec.getIpAddress(), rec);
                        ipByMac.put(rec.getMacAddress(), rec.getIpAddress());
                    }
                } catch (Exception ignored) {
                }
            }
        } catch (IOException ignored) {
        }
    }

    public List<LeaseRecord> getAllLeases() {
        List<LeaseRecord> list = new ArrayList<>(leasesByIp.values());
        list.sort(Comparator.comparing(LeaseRecord::getIpAddress));
        return list;
    }

    public int getTotalPoolSize() {
        return ipPool.size() + staticReservations.size();
    }

    public int getActiveLeaseCount() {
        return leasesByIp.size();
    }

    public int getDefaultLeaseSeconds() {
        return defaultLeaseSeconds;
    }

    public void shutdown() {
        reaperExecutor.shutdownNow();
    }
}

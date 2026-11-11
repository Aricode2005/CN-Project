package arp.security;

import arp.core.Json;
import arp.model.IpAddress;
import arp.model.MacAddress;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * DHCP Snooping Database / Trusted IP-to-MAC Binding Table.
 *
 * Used by Cisco / Enterprise Switches to enforce Dynamic ARP Inspection (DAI).
 * Automatically imports leases from the sibling DHCP module (../DHCP/data/leases_node*.db)
 * or maintains manual trusted bindings.
 */
public final class DhcpSnoopingTable {

    public static final class Binding {
        public final IpAddress ip;
        public final MacAddress mac;
        public final int port;
        public final String hostname;
        public final long timestampMs;

        public Binding(IpAddress ip, MacAddress mac, int port, String hostname) {
            this.ip = ip;
            this.mac = mac;
            this.port = port;
            this.hostname = hostname;
            this.timestampMs = System.currentTimeMillis();
        }

        public String json() {
            return Json.obj(
                    "ip", ip.toString(),
                    "mac", mac.toString(),
                    "port", port,
                    "hostname", hostname
            );
        }
    }

    private final Map<IpAddress, Binding> bindings = new ConcurrentHashMap<>();

    public DhcpSnoopingTable() {
    }

    public void addBinding(IpAddress ip, MacAddress mac, int port, String hostname) {
        bindings.put(ip, new Binding(ip, mac, port, hostname));
    }

    public boolean isValid(IpAddress ip, MacAddress mac) {
        Binding b = bindings.get(ip);
        if (b == null) return false;
        return b.mac.equals(mac);
    }

    public Binding getBinding(IpAddress ip) {
        return bindings.get(ip);
    }

    public List<Binding> getBindings() {
        List<Binding> list = new ArrayList<>(bindings.values());
        Collections.sort(list, (a, b) -> a.ip.compareTo(b.ip));
        return list;
    }

    /**
     * Attempts to import active leases from the sibling DHCP cluster (if available).
     */
    public int importFromDhcpDataDir(File dataDir) {
        int imported = 0;
        if (dataDir == null || !dataDir.exists() || !dataDir.isDirectory()) {
            return 0;
        }
        File[] dbFiles = dataDir.listFiles((dir, name) -> name.startsWith("leases_") && name.endsWith(".db"));
        if (dbFiles == null) return 0;

        for (File db : dbFiles) {
            try (BufferedReader br = new BufferedReader(new FileReader(db))) {
                String line;
                while ((line = br.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) continue;
                    // Format: ip,mac,hostname,leaseTime,...
                    String[] parts = line.split("[,|]");
                    if (parts.length >= 2) {
                        try {
                            IpAddress ip = IpAddress.parse(parts[0].trim());
                            MacAddress mac = MacAddress.parse(parts[1].trim());
                            String host = parts.length >= 3 ? parts[2].trim() : "dhcp-host";
                            addBinding(ip, mac, 1, host);
                            imported++;
                        } catch (Exception ignored) {
                        }
                    }
                }
            } catch (Exception ignored) {
            }
        }
        return imported;
    }

    public String json() {
        List<String> bJsons = new ArrayList<>();
        for (Binding b : getBindings()) {
            bJsons.add(b.json());
        }
        return Json.arr(bJsons);
    }
}

package boot;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import boot.core.Json;

/**
 * The lab network used by both protocols:
 *
 *   LAN A 10.0.1.0/24 : WS-1, WS-2, WS-3 (not registered), the boot server (RARP + BOOTP) 10.0.1.5, router eth0 10.0.1.1
 *   LAN B 10.0.2.0/24 : WS-4, router eth1 10.0.2.1  (the router also runs the BOOTP relay agent)
 *
 * The workstations are diskless: they know their MAC (burned into the network card) and nothing else.
 */
public final class Topology {

    public static final class Station {
        public final String name, mac, segment, role; public final String fixedIp;
        Station(String name, String mac, String segment, String role, String fixedIp) { this.name = name; this.mac = mac; this.segment = segment; this.role = role; this.fixedIp = fixedIp; }
        public String json() { return Json.obj("name", name, "mac", mac, "segment", segment, "role", role, "ip", fixedIp); }
    }

    public static final class Entry {
        public final String mac, ip, host, file;
        public Entry(String mac, String ip, String host, String file) { this.mac = mac.toLowerCase(); this.ip = ip; this.host = host; this.file = file; }
        public String json() { return Json.obj("mac", mac, "ip", ip, "host", host, "file", file); }
    }

    public static final String SERVER_IP = "10.0.1.5", SERVER_NAME = "bootsrv", SERVER_MAC = "08:00:20:0a:01:05";
    public static final String ROUTER_A_IP = "10.0.1.1", ROUTER_B_IP = "10.0.2.1", ROUTER_A_MAC = "00:00:0c:01:00:01", ROUTER_B_MAC = "00:00:0c:01:00:02";
    public static final String MASK = "255.255.255.0", DNS = "10.0.1.53";

    public final List<Station> stations = new ArrayList<>();
    /** The boot server's database: /etc/ethers for RARP, /etc/bootptab for BOOTP (one table here). */
    public final Map<String, Entry> table = new ConcurrentHashMap<>();

    public Topology() {
        stations.add(new Station("WS-1", "08:00:20:0a:01:01", "A", "diskless workstation", null));
        stations.add(new Station("WS-2", "08:00:20:0a:01:02", "A", "diskless workstation", null));
        stations.add(new Station("WS-3", "08:00:20:0a:01:03", "A", "diskless workstation (not registered)", null));
        stations.add(new Station("SERVER", SERVER_MAC, "A", "RARP + BOOTP server", SERVER_IP));
        stations.add(new Station("ROUTER", ROUTER_A_MAC, "A", "router eth0 (+ BOOTP relay agent)", ROUTER_A_IP));
        stations.add(new Station("ROUTER-B", ROUTER_B_MAC, "B", "router eth1", ROUTER_B_IP));
        stations.add(new Station("WS-4", "08:00:20:0a:02:04", "B", "diskless workstation (other LAN)", null));
        reg("08:00:20:0a:01:01", "10.0.1.21", "ws1", "/tftpboot/sunos-ws1.img");
        reg("08:00:20:0a:01:02", "10.0.1.22", "ws2", "/tftpboot/sunos-ws2.img");
        reg("08:00:20:0a:02:04", "10.0.2.24", "ws4", "/tftpboot/sunos-ws4.img");
    }

    public void reg(String mac, String ip, String host, String file) { table.put(mac.toLowerCase(), new Entry(mac, ip, host, file)); }

    public Station station(String name) { for (Station s : stations) if (s.name.equalsIgnoreCase(name)) return s; return null; }

    public String json() {
        List<String> s = new ArrayList<>(); for (Station x : stations) s.add(x.json());
        List<String> t = new ArrayList<>(); for (Entry e : table.values()) t.add(e.json());
        t.sort(String::compareTo);
        return Json.obj("stations", Json.raw("[" + String.join(",", s) + "]"), "table", Json.raw("[" + String.join(",", t) + "]"));
    }
}

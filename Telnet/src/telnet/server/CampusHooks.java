package telnet.server;

/**
 * Bridge to the other two main-project modules (DHCP and ARP).
 *
 * The Telnet module compiles and runs on its own, so it cannot reference their classes directly.
 * When all three run together (MainProject), the launcher installs an implementation here, and the
 * router's CLI then shows live DHCP bindings, the LAN's ARP and MAC tables, and can switch
 * Dynamic ARP Inspection on and off, exactly like the matching Cisco IOS commands.
 */
public interface CampusHooks {

    /** Installed by MainProject; null when the Telnet lab runs alone. */
    final class Holder { private Holder() { } public static volatile CampusHooks hooks; }

    String showDhcpBinding();          // show ip dhcp binding
    String showIpArp();                // show ip arp
    String showMacTable();             // show mac address-table
    String showArpInspection();        // show ip arp inspection
    String setArpInspection(boolean on);   // [no] ip arp inspection vlan 1
    String clearArpCache();            // clear arp-cache
}

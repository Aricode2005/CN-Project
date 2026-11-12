package campus;

import java.util.ArrayList;
import java.util.List;
import arp.model.IpAddress;
import telnet.client.TelnetClient;

/**
 * The campus story: one laptop joins the LAN and each of the three protocols does its part.
 * Every step performs real actions (UDP DORA, frames on the simulated switch, a TCP Telnet session);
 * the dashboard runs one step per Forward ▶.
 */
public final class Story {

    public static final int PLAIN_RELAY = 2325, TLS_RELAY = 9925;

    public static final class Step {
        public final String title, lead; final Act act;
        Step(String title, String lead, Act act) { this.title = title; this.lead = lead; this.act = act; }
    }
    public interface Act { Result run() throws Exception; }
    public static final class Result {
        public final String say, mood;
        Result(String say, String mood) { this.say = say; this.mood = mood; }
    }

    private final Bus bus; private final boolean tlsAvailable;
    public final List<Step> steps = new ArrayList<>();
    private int next;
    private String firstOffer, lease;
    public volatile String lastSay = "", lastMood = "";

    public Story(Bus bus, boolean tlsAvailable) {
        this.bus = bus; this.tlsAvailable = tlsAvailable;
        steps.add(new Step("A laptop asks for an address", "DHCP · Discover → Offer → Request → Ack", this::dora1));
        steps.add(new Step("Is that address really free?", "ARP probe (RFC 5227) → DHCP Decline", this::probe1));
        steps.add(new Step("Second lease, clean probe", "DHCP again → probe → gratuitous ARP → snooping binding", this::dora2));
        steps.add(new Step("Find the gateway", "ARP request (broadcast) → ARP reply (unicast)", this::arpGateway));
        steps.add(new Step("The admin telnets into the router", "Telnet over TCP · live DHCP and ARP tables from the CLI", this::telnet1));
        steps.add(new Step("An attacker poisons the ARP caches", "forged ARP replies · inspection is off", this::poison));
        steps.add(new Step("The next login is sniffed", "the Telnet frames now go to the attacker's MAC", this::telnetSniffed));
        steps.add(new Step("Fix it from the router", "ip arp inspection vlan 1 · bindings come from DHCP", this::enableDai));
        steps.add(new Step("Log in again: nothing leaks", "the forged ARP was dropped at the switch port", this::telnetSafe));
        steps.add(new Step("Defence in depth: Telnet over TLS", "even on a poisoned LAN, the sniffer sees only ciphertext", this::telnetTls));
    }

    public synchronized int index() { return next; }
    public synchronized boolean done() { return next >= steps.size(); }

    public synchronized Result forward() {
        if (done()) return new Result("The story is finished. Restart to run it again.", "ok");
        Step s = steps.get(next);
        bus.ev("STORY", "── step " + (next + 1) + " of " + steps.size() + ": " + s.title + " ──");
        Result r;
        try { r = s.act.run(); } catch (Exception e) { r = new Result("This step failed: " + e.getClass().getSimpleName() + ": " + e.getMessage(), "alarm"); }
        next++;
        lastSay = r.say; lastMood = r.mood;
        return r;
    }

    public synchronized void restart() throws Exception { bus.reset(); next = 0; firstOffer = lease = null; lastSay = ""; lastMood = ""; }

    // ------------------------------------------------------------------ the steps
    private Result dora1() {
        firstOffer = bus.dora();
        if (firstOffer == null) return new Result("The DHCP cluster did not answer.", "alarm");
        return new Result("The laptop (" + Bus.ADMIN_MAC + ") has no address, so it broadcasts DHCPDISCOVER. The load balancer hashes its MAC to one cluster node, which offers " + firstOffer
            + "; Request and Ack complete the lease. Before using the address, a careful client checks that nobody else already has it.", "");
    }

    private Result probe1() {
        boolean clean = bus.probe(firstOffer);
        if (clean) { lease = firstOffer; return new Result("The probe got no answer: " + firstOffer + " is free, and the laptop keeps it.", "ok"); }
        bus.decline(firstOffer);
        return new Result("Before using " + firstOffer + ", the laptop probes for it (ARP request with sender IP 0.0.0.0) and then announces it with a gratuitous ARP. "
            + "But Host-A was configured with " + firstOffer + " by hand, so it defends the address with its own gratuitous ARP (RFC 5227). The laptop sees the conflict, gives the address up "
            + "and sends DHCPDECLINE: the server marks " + firstOffer + " unusable. This is the ARP → DHCP link.", "alarm");
    }

    private Result dora2() throws Exception {
        if (lease == null) {
            for (int i = 0; i < 4 && lease == null; i++) {
                String ip = bus.dora();
                if (ip == null) break;
                if (bus.probe(ip)) lease = ip; else bus.decline(ip);
            }
        }
        if (lease == null) return new Result("No usable address could be leased.", "alarm");
        Thread.sleep(450); bus.syncLeases();
        return new Result("A new DORA gives " + lease + ". This time the probe is unanswered, so the laptop announces itself with a gratuitous ARP. "
            + "The lease is also copied into the switch's DHCP-snooping table (" + lease + " ↔ " + Bus.ADMIN_MAC + "): that table is what Dynamic ARP Inspection will check against later. This is the DHCP → ARP link.", "ok");
    }

    private Result arpGateway() {
        bus.admin.ping(IpAddress.parse(Bus.GATEWAY), "hello-router");
        return new Result("To reach anything, the laptop needs the gateway's MAC. It broadcasts \"who has " + Bus.GATEWAY + "?\"; the router replies with a unicast, and the laptop caches "
            + Bus.GATEWAY + " → " + bus.router.getNic().getMac() + ". The switch has learned which port each MAC is on.", "ok");
    }

    private Result telnet1() throws Exception {
        String t = session(false, "show ip dhcp binding", "show ip arp");
        return new Result("The admin opens a Telnet session to the router (a real TCP connection). Each chunk also crosses the LAN as a frame addressed to the router's MAC, so only the router receives it. "
            + "From the CLI, 'show ip dhcp binding' reads the live DHCP cluster and 'show ip arp' reads the ARP lab: the three modules are now one network." + (t.contains(lease) ? "" : " (the lease was not found in the output!)"), "ok");
    }

    private Result poison() {
        bus.poison();
        boolean p = bus.poisoned();
        return new Result("The attacker sends forged ARP replies: it tells the laptop \"" + Bus.GATEWAY + " is at 66:66:66:66:66:66\" and tells the router the same about the laptop. "
            + "ARP has no authentication, so both believe it. " + (p ? "The laptop's cache now maps the gateway to the attacker's MAC." : "(The poisoning did not take effect.)"), p ? "alarm" : "");
    }

    private Result telnetSniffed() throws Exception {
        session(false, "show users");
        String s = bus.sniffed();
        boolean got = s.contains("cisco");
        return new Result("The admin logs in again. The laptop now sends its frames to the attacker's MAC, which reads them and forwards them on, so nothing looks wrong. "
            + (got ? "Telnet sends every keystroke in clear text: the attacker's notebook now holds the user name and the password." : "(Nothing was captured.)"), got ? "alarm" : "");
    }

    private Result enableDai() throws Exception {
        session(false, "configure terminal", "ip arp inspection vlan 1", "end", "clear arp-cache", "show ip arp inspection");
        bus.attacker.launchArpPoisoning();                            // the attacker keeps trying
        bus.admin.ping(IpAddress.parse(Bus.GATEWAY), "re-resolve");
        boolean p = bus.poisoned();
        return new Result("Over the same Telnet session the admin types 'ip arp inspection vlan 1' and clears the ARP caches. The switch now checks every ARP packet on an untrusted port against the DHCP-snooping table. "
            + "The attacker repeats its forged replies; the switch drops them (" + bus.dai.getDroppedCount() + " dropped so far), because DHCP never leased " + Bus.GATEWAY + " to that MAC. "
            + (p ? "(The cache is still poisoned!)" : "The laptop re-resolves the gateway and gets the real MAC."), p ? "alarm" : "ok");
    }

    private Result telnetSafe() throws Exception {
        String before = bus.sniffed();
        session(false, "show ip arp inspection");
        boolean leaked = bus.sniffed().length() > before.length();
        return new Result("Another login. The frames go straight to the router's MAC again, and the attacker's notebook gets " + (leaked ? "MORE text (unexpected!)." : "nothing new.")
            + " All three protocols were needed: DHCP supplied the bindings, ARP inspection used them, and Telnet was both the tool that configured it and the traffic it protects.", leaked ? "alarm" : "ok");
    }

    private Result telnetTls() throws Exception {
        if (!tlsAvailable) return new Result("Telnet over TLS is not available on this machine (keytool was not found), so this step is skipped.", "");
        session(false, "configure terminal", "no ip arp inspection vlan 1", "end");
        bus.poison();
        String before = bus.sniffed();
        session(true, "show users");
        String got = bus.sniffed().substring(Math.min(before.length(), bus.sniffed().length()));
        boolean clear = got.contains("cisco") || got.contains("admin");
        session(true, "configure terminal", "ip arp inspection vlan 1", "end", "clear arp-cache");
        return new Result("Suppose a switch has no inspection: we turn it off and the attacker poisons the caches again. This time the admin connects with Telnet over TLS (port 992). "
            + "The attacker still receives every frame, but " + (clear ? "could read the login (unexpected!)." : "they contain only encrypted TLS records: no user name, no password.")
            + " Inspection is switched back on at the end.", clear ? "alarm" : "ok");
    }

    // ------------------------------------------------------------------ a scripted admin session through the LAN relay
    String session(boolean tls, String... commands) throws Exception {
        try (TelnetClient c = new TelnetClient("127.0.0.1", tls ? TLS_RELAY : PLAIN_RELAY, tls, telnet.Main.KEYSTORE, new String[] { "VT100" }, 110, 40, true, s -> { })) {
            long m = c.expect(0, "Username: ", 6000);
            if (m < 0) throw new IllegalStateException("no login prompt from the router");
            c.line("admin");
            m = c.expect(m, "Password: ", 4000); c.line("cisco");
            m = c.expect(m, "JU-Main-R", 5000);
            if (m < 0) throw new IllegalStateException("login failed");
            for (String cmd : commands) {
                long mark = c.mark();
                c.line(cmd);
                if (cmd.equals("enable")) { long p = c.expect(mark, "Password: ", 3000); c.line("class"); c.expect(p, "#", 3000); }
                else c.expect(mark + cmd.length(), "JU-Main-R", 4000);
                Thread.sleep(120);
            }
            Thread.sleep(250);
            String t = c.since(0).replace("\r", "");
            c.line("exit");
            Thread.sleep(150);
            bus.lastTranscript = (tls ? "[Telnet over TLS, port 992]\n" : "[plain Telnet, port 23]\n") + t;
            bus.ev("TELNET", "session closed: " + commands.length + " command" + (commands.length == 1 ? "" : "s") + " run as admin" + (tls ? " (over TLS)" : ""));
            return t;
        }
    }
}

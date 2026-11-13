package telnet.server;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import telnet.core.Hub;
import telnet.protocol.Telnet;

/**
 * Cisco IOS-style command interpreter for a VTY session:
 *  - commands may be abbreviated to any unique prefix ("sh us" = "show users")
 *  - '?' lists what can come next, Tab completes the current word
 *  - errors point at the bad word with a '^' marker, like IOS
 *  - user EXEC (>) / privileged EXEC (#) / global configuration ((config)#) modes
 */
final class CommandShell {

    private interface Handler { void run(List<String> args, String rest); }

    private static final class Spec {
        final String[] tok; final int minPriv; final boolean config; final String help; final Handler h;
        Spec(String pattern, int minPriv, boolean config, String help, Handler h) {
            this.tok = pattern.split(" "); this.minPriv = minPriv; this.config = config; this.help = help; this.h = h;
        }
    }

    private static final Map<String, String> WORD_HELP = new LinkedHashMap<>();
    static {
        WORD_HELP.put("show", "Show running system information");
        WORD_HELP.put("configure", "Enter configuration mode");
        WORD_HELP.put("debug", "Debugging functions");
        WORD_HELP.put("no", "Negate a command or set its defaults");
        WORD_HELP.put("undebug", "Disable debugging functions");
        WORD_HELP.put("clear", "Reset functions");
        WORD_HELP.put("monitor", "Monitoring different system events");
        WORD_HELP.put("send", "Send a message to other tty lines");
        WORD_HELP.put("write", "Write running configuration to memory");
        WORD_HELP.put("username", "Establish User Name Authentication");
        WORD_HELP.put("login", "Enable secure login checking");
        WORD_HELP.put("banner", "Define a login banner");
        WORD_HELP.put("enable", "Turn on privileged commands");
        WORD_HELP.put("do", "To run exec commands in config mode");
    }

    private final TelnetSession s;
    private final List<Spec> specs = new ArrayList<>();

    CommandShell(TelnetSession s) {
        this.s = s;
        // ---------------- EXEC
        add("show users", 1, false, "Display information about terminal lines", (a, r) -> showUsers());
        add("show telnet", 1, false, "Telnet option states of this session (RFC 1143)", (a, r) -> showTelnet());
        add("show terminal", 1, false, "Display terminal configuration parameters", (a, r) -> showTerminal());
        add("show version", 1, false, "System hardware and software status", (a, r) -> showVersion());
        add("show clock", 1, false, "Display the system clock", (a, r) -> out(new SimpleDateFormat("HH:mm:ss.SSS z EEE MMM d yyyy").format(new Date()) + "\n"));
        add("show history", 1, false, "Display the session command history", (a, r) -> { for (String h : s.history) out("  " + h + "\n"); });
        add("show login", 1, false, "Display login block-for status", (a, r) -> out(s.pool.guard.showLogin()));
        add("show dhcp leases", 1, false, "DHCP bindings from the DHCP cluster module", (a, r) -> showDhcp());
        add("show arp", 1, false, "ARP cache of this host (live from the OS)", (a, r) -> showArp());
        add("show ip dhcp binding", 1, false, "Live DHCP bindings (needs MainProject: DHCP cluster)", (a, r) -> campus(h -> h.showDhcpBinding()));
        add("show ip arp", 1, false, "ARP tables on the campus LAN (needs MainProject: ARP lab)", (a, r) -> campus(h -> h.showIpArp()));
        add("show mac address-table", 1, false, "The LAN switch's CAM table (needs MainProject)", (a, r) -> campus(h -> h.showMacTable()));
        add("show ip arp inspection", 1, false, "Dynamic ARP Inspection status and drops (needs MainProject)", (a, r) -> campus(h -> h.showArpInspection()));
        add("clear arp-cache", 15, false, "Flush dynamic ARP entries on the LAN (needs MainProject)", (a, r) -> campus(h -> h.clearArpCache()));
        add("show ip interface brief", 1, false, "Brief summary of IP status and configuration", (a, r) -> showIpBrief());
        add("show running-config", 15, false, "Current operating configuration", (a, r) -> out(s.pool.cfg.runningConfig(VtyPool.LINES, s.pool.plainPort)));
        add("show aaa servers", 1, false, "RADIUS server status and counters", (a, r) -> {
            RemoteAuth ra = s.pool.radius;
            out("Authentication: " + (s.pool.cfg.aaaRadius ? "group radius, then local" : "local only") + "\n" + (ra == null ? "% No RADIUS client in this build\n" : ra.status()));
        });
        add("show session", 1, false, "This session: node, token, how it was authenticated", (a, r) -> out(
                "Session " + s.id + " on " + (s.pool.node.isEmpty() ? "stand-alone router" : "HA cluster node " + s.pool.node) + ", line vty " + s.line + "\n"
                + "Client " + s.clientIp() + ", user " + s.user + " (privilege " + s.priv + "), authenticated by " + s.authBy + "\n"
                + (s.token == null ? "No resume token (not on the HA cluster)\n" : "Resume token " + s.token + " : if the connection drops, reconnect and type  resume " + s.token + "\n")
                + "Input mode: " + (s.linemode ? "LINEMODE (RFC 1184, client edits locally)" : "character at a time (server echo)") + "\n"));
        add("dir", 1, false, "List files in flash:", (a, r) -> dir());
        add("cat <file>", 1, false, "Show a file (try: cat file1)", (a, r) -> cat(a.get(0)));
        add("who", 1, false, "List active sessions", (a, r) -> showUsers());
        add("whoami", 1, false, "Info on the current tty line", (a, r) -> out(s.user + " on vty " + s.line + " from " + s.from + " via " + s.transport + ", privilege " + s.priv + "\n"));
        add("tmping", 1, false, "Measure RTT with Telnet TIMING-MARK (RFC 860)", (a, r) -> s.tmping(5));
        add("tmping <count>", 1, false, "Number of probes", (a, r) -> s.tmping(Math.max(1, Math.min(20, num(a.get(0), 5)))));
        add("top", 1, false, "Full-screen live view of all VTY lines (needs ANSI + NAWS)", (a, r) -> s.startTop());
        add("send * <text>", 1, false, "Send a message to all tty lines", (a, r) -> broadcast(r));
        add("send <line> <text>", 1, false, "Send a message to one vty line", (a, r) -> sendOne(a.get(0), r));
        add("enable", 1, false, "Turn on privileged commands", (a, r) -> s.startEnable());
        add("disable", 1, false, "Turn off privileged commands", (a, r) -> { s.priv = 1; });
        add("exit", 1, false, "Exit from the EXEC", (a, r) -> s.close("exit"));
        add("logout", 1, false, "Exit from the EXEC", (a, r) -> s.close("logout"));
        add("quit", 1, false, "Exit from the EXEC", (a, r) -> s.close("quit"));
        add("debug telnet", 15, false, "Print Telnet negotiation events of all lines", (a, r) -> { s.setDebug(true); out("Telnet negotiation debugging is on\n"); });
        add("no debug telnet", 15, false, "Turn off Telnet debugging", (a, r) -> { s.setDebug(false); out("Telnet negotiation debugging is off\n"); });
        add("undebug all", 15, false, "Disable all debugging", (a, r) -> { s.setDebug(false); out("All possible debugging has been turned off\n"); });
        add("monitor line <line>", 15, false, "Shadow another vty line (read-only)", (a, r) -> shadow(a.get(0)));
        add("clear line <line>", 15, false, "Reset a terminal line", (a, r) -> clearLine(a.get(0)));
        add("clear login", 15, false, "Leave quiet mode (login block-for)", (a, r) -> { s.pool.guard.unblock(); out("[OK]\n"); });
        add("configure terminal", 15, false, "Configure from the terminal", (a, r) -> { out("Enter configuration commands, one per line.  End with CNTL/Z.\n"); s.mode = TelnetSession.Mode.CONFIG; });
        add("write memory", 15, false, "Write to NV memory", (a, r) -> writeMem());
        // ---------------- CONFIG
        add("hostname <name>", 15, true, "Set system's network name", (a, r) -> hostname(a.get(0)));
        add("banner motd <text>", 15, true, "Set Message of the Day banner", (a, r) -> banner(r));
        add("username <name> secret <password>", 15, true, "Add a privilege-1 user (stored as PBKDF2 hash)", (a, r) -> { s.pool.cfg.putUser(a.get(0), 1, a.get(1)); });
        add("username <name> privilege <level> secret <password>", 15, true, "Add a user with a privilege level", (a, r) -> s.pool.cfg.putUser(a.get(0), num(a.get(1), 1) >= 15 ? 15 : 1, a.get(2)));
        add("no username <name>", 15, true, "Remove a user", (a, r) -> { if (!s.pool.cfg.removeUser(a.get(0))) out("% User not found\n"); });
        add("enable secret <password>", 15, true, "Set the enable secret", (a, r) -> s.pool.cfg.setEnable(a.get(0)));
        add("exec-timeout <minutes>", 15, true, "Idle timeout for VTY sessions", (a, r) -> { s.pool.cfg.execTimeoutMin = Math.max(1, num(a.get(0), 5)); });
        add("login block-for <seconds> attempts <tries> within <seconds>", 15, true, "Block logins after repeated failures",
                (a, r) -> { s.pool.cfg.blockForSec = num(a.get(0), 30); s.pool.cfg.blockAttempts = num(a.get(1), 3); s.pool.cfg.blockWithinSec = num(a.get(2), 60); });
        add("ip arp inspection vlan <id>", 15, true, "Enable Dynamic ARP Inspection on the LAN switch", (a, r) -> campus(h -> h.setArpInspection(true)));
        add("no ip arp inspection vlan <id>", 15, true, "Disable Dynamic ARP Inspection", (a, r) -> campus(h -> h.setArpInspection(false)));
        add("do <text>", 15, true, "Run an EXEC command from configuration mode", (a, r) -> {
            TelnetSession.Mode m = s.mode; s.mode = TelnetSession.Mode.EXEC; execute(r); if (s.mode == TelnetSession.Mode.EXEC) s.mode = m;
        });
        // ---------------- AAA (RADIUS, RFC 2865 / 2866)
        add("aaa authentication login default group radius local", 15, true, "Log in through the RADIUS server; local users only if it does not answer",
                (a, r) -> { s.pool.cfg.aaaRadius = true; out("% AAA: logins now go to RADIUS " + s.pool.cfg.radiusHost + ":" + s.pool.cfg.radiusAuthPort + ", accounting to :" + s.pool.cfg.radiusAcctPort + "\n"); });
        add("aaa authentication login default local", 15, true, "Log in with the local user database only", (a, r) -> s.pool.cfg.aaaRadius = false);
        add("no aaa authentication login default", 15, true, "Back to local logins", (a, r) -> s.pool.cfg.aaaRadius = false);
        add("radius server host <ip> key <secret>", 15, true, "RADIUS server address and shared secret",
                (a, r) -> { s.pool.cfg.radiusHost = a.get(0); s.pool.cfg.radiusKey = a.get(1); });
        add("end", 15, true, "Exit from configure mode", (a, r) -> s.mode = TelnetSession.Mode.EXEC);
        add("exit", 15, true, "Exit from configure mode", (a, r) -> s.mode = TelnetSession.Mode.EXEC);
    }

    /** Commands that reach into the DHCP and ARP modules; they only work when MainProject runs all three together. */
    private void campus(java.util.function.Function<CampusHooks, String> f) {
        CampusHooks h = CampusHooks.Holder.hooks;
        if (h == null) { out("% Not available here: start MainProject/run.bat to run ARP + DHCP + Telnet as one network.\n"); return; }
        try { String t = f.apply(h); out(t.endsWith("\n") ? t : t + "\n"); } catch (RuntimeException e) { out("% " + e.getMessage() + "\n"); }
    }

    private void add(String p, int priv, boolean cfg, String help, Handler h) { specs.add(new Spec(p, priv, cfg, help, h)); }

    private void out(String t) { s.print(t); }

    private static int num(String x, int def) { try { return Integer.parseInt(x); } catch (NumberFormatException e) { return def; } }

    // ================================================================== parsing

    private static final class Tok { final String w; final int start; Tok(String w, int start) { this.w = w; this.start = start; } }

    private static List<Tok> tokenize(String line) {
        List<Tok> t = new ArrayList<>();
        int i = 0;
        while (i < line.length()) {
            while (i < line.length() && line.charAt(i) == ' ') i++;
            int st = i;
            while (i < line.length() && line.charAt(i) != ' ') i++;
            if (i > st) t.add(new Tok(line.substring(st, i), st));
        }
        return t;
    }

    private List<Spec> available() {
        List<Spec> l = new ArrayList<>();
        boolean cfg = s.mode == TelnetSession.Mode.CONFIG;
        for (Spec sp : specs) if (sp.config == cfg && s.priv >= sp.minPriv) l.add(sp);
        return l;
    }

    private static boolean isVar(String t) { return t.startsWith("<"); }

    /** FULL = matches; INCOMPLETE = input is a proper prefix; otherwise index of the first bad token. */
    private static final int FULL = -1, INCOMPLETE = -2;

    private static int match(Spec sp, List<Tok> in) {
        for (int i = 0; i < sp.tok.length; i++) {
            String p = sp.tok[i];
            if (i >= in.size()) return INCOMPLETE;
            if (p.equals("<text>")) return FULL;               // swallows the rest of the line
            if (isVar(p)) continue;
            if (!p.startsWith(in.get(i).w.toLowerCase())) return i;
        }
        return in.size() == sp.tok.length ? FULL : sp.tok.length;
    }

    void execute(String line) {
        List<Tok> in = tokenize(line);
        if (in.isEmpty()) return;
        List<Spec> full = new ArrayList<>();
        boolean incomplete = false;
        int worst = -1;
        for (Spec sp : available()) {
            int m = match(sp, in);
            if (m == FULL) full.add(sp);
            else if (m == INCOMPLETE) incomplete = true;
            else worst = Math.max(worst, m);
        }
        if (full.size() > 1) {   // prefer the spec whose literal words match exactly, then fewer variables
            List<Spec> exact = new ArrayList<>();
            for (Spec sp : full) {
                boolean ok = true;
                for (int i = 0; i < sp.tok.length && i < in.size(); i++) if (!isVar(sp.tok[i]) && !sp.tok[i].equalsIgnoreCase(in.get(i).w)) ok = false;
                if (ok) exact.add(sp);
            }
            if (exact.size() >= 1) full = exact;
            if (full.size() > 1) {
                Spec best = null; int bestLit = -1; boolean tie = false;
                for (Spec sp : full) {
                    int lit = 0; for (String t : sp.tok) if (!isVar(t)) lit++;
                    if (lit > bestLit) { best = sp; bestLit = lit; tie = false; } else if (lit == bestLit) tie = true;
                }
                if (tie) { out("% Ambiguous command:  \"" + line.trim() + "\"\n"); return; }
                List<Spec> one = new ArrayList<>(); one.add(best); full = one;
            }
        }
        if (full.size() == 1) {
            Spec sp = full.get(0);
            List<String> args = new ArrayList<>();
            String rest = "";
            for (int i = 0; i < sp.tok.length; i++) {
                if (sp.tok[i].equals("<text>")) { rest = line.substring(in.get(i).start).trim(); break; }
                if (isVar(sp.tok[i])) args.add(in.get(i).w);
            }
            try { sp.h.run(args, rest); } catch (RuntimeException e) { out("% Error: " + e.getMessage() + "\n"); }
            return;
        }
        if (incomplete) { out("% Incomplete command.\n\n"); return; }
        int pos = Math.max(0, Math.min(worst, in.size() - 1));
        int col = s.prompt().length() + in.get(pos).start;
        StringBuilder caret = new StringBuilder();
        for (int i = 0; i < col; i++) caret.append(' ');
        out(caret + "^\n% Invalid input detected at '^' marker.\n\n");
    }

    // ================================================================== ? and Tab

    /** Words that may come at position `pos`, given the earlier words. */
    private Map<String, String> nextWords(List<Tok> before, int pos, String prefix) {
        Map<String, String> m = new TreeMap<>();
        boolean cr = false;
        for (Spec sp : available()) {
            boolean ok = true;
            for (int i = 0; i < pos; i++) {
                if (i >= sp.tok.length) { ok = false; break; }
                if (sp.tok[i].equals("<text>")) break;
                if (!isVar(sp.tok[i]) && !sp.tok[i].startsWith(before.get(i).w.toLowerCase())) { ok = false; break; }
            }
            if (!ok) continue;
            if (pos >= sp.tok.length) { cr = true; continue; }
            if (pos > 0 && sp.tok[pos - 1].equals("<text>")) continue;
            String w = sp.tok[pos];
            if (!w.startsWith(prefix.toLowerCase()) && !isVar(w)) continue;
            String help = pos == 0 && WORD_HELP.containsKey(w) && sp.tok.length > 1 ? WORD_HELP.get(w) : (pos == sp.tok.length - 1 || isVar(w) ? sp.help : WORD_HELP.getOrDefault(w, sp.help));
            m.putIfAbsent(w, help);
        }
        if (cr && prefix.isEmpty()) m.put("<cr>", "");
        return m;
    }

    void help(String line) {
        List<Tok> t = tokenize(line);
        boolean midWord = !line.isEmpty() && !line.endsWith(" ");
        int pos = midWord ? t.size() - 1 : t.size();
        String prefix = midWord ? t.get(t.size() - 1).w : "";
        Map<String, String> m = nextWords(t, pos, prefix);
        if (m.isEmpty()) { out("% Unrecognized command\n"); return; }
        if (midWord) {   // IOS lists matching keywords on one line
            StringBuilder b = new StringBuilder();
            for (String w : m.keySet()) if (!isVar(w)) b.append(w).append("  ");
            out(b.toString().trim() + "\n\n");
            return;
        }
        for (Map.Entry<String, String> e : m.entrySet()) out(String.format("  %-22s %s\n", e.getKey(), e.getValue()));
        out("\n");
    }

    void complete(StringBuilder buf) {
        String line = buf.toString();
        if (line.isEmpty() || line.endsWith(" ")) return;
        List<Tok> t = tokenize(line);
        String prefix = t.get(t.size() - 1).w;
        Set<String> words = new LinkedHashSet<>();
        for (String w : nextWords(t, t.size() - 1, prefix).keySet()) if (!isVar(w) && !w.equals("<cr>")) words.add(w);
        if (words.size() == 1) {
            String w = words.iterator().next();
            s.replaceBuffer(line.substring(0, t.get(t.size() - 1).start) + w + " ", false);
        } else if (words.size() > 1) {
            String common = null;
            for (String w : words) { if (common == null) common = w; else { int i = 0; while (i < common.length() && i < w.length() && common.charAt(i) == w.charAt(i)) i++; common = common.substring(0, i); } }
            if (common != null && common.length() > prefix.length()) s.replaceBuffer(line.substring(0, t.get(t.size() - 1).start) + common, false);
            else { out("\n" + String.join("  ", words) + "\n"); s.replaceBuffer(line, true); }
        }
    }

    // ================================================================== command bodies

    private static final Map<String, String> FILES = new LinkedHashMap<>();
    static {
        FILES.put("file1", "This is file1 on flash: of JU-Main-R.\n"
                + "If you see this after typing 'cat filea' + IAC EC + '1', the server applied the\n"
                + "Telnet Erase Character command (IAC EC = 255 247) before running the command:\n"
                + "  received   c a t _ f i l e a [IAC EC] 1\n"
                + "  executed   cat file1\n");
        FILES.put("readme.txt", "Telnet VTY lab. Commands are IOS-style: abbreviate them, press ? for help, Tab to complete.\n");
        FILES.put("vlan.dat", "(binary file: 616 bytes)\n");
        FILES.put("startup-config", null);
    }

    private void dir() {
        out("Directory of flash:/\n\n");
        int i = 1;
        for (Map.Entry<String, String> e : FILES.entrySet()) {
            int size = e.getValue() == null ? s.pool.cfg.runningConfig(VtyPool.LINES, s.pool.plainPort).length() : e.getValue().length();
            out(String.format("%4d  -rw-  %8d   <no date>  %s\n", i++, size, e.getKey()));
        }
        out("\n64016384 bytes total (63987712 bytes free)\n");
    }

    private void cat(String f) {
        if (!FILES.containsKey(f)) { out("%Error opening flash:/" + f + " (No such file or directory)\n"); return; }
        String c = FILES.get(f);
        out(c == null ? s.pool.cfg.runningConfig(VtyPool.LINES, s.pool.plainPort) : c);
    }

    private void showUsers() {
        out("    Line       User       Host(s)              Idle       Location\n");
        for (TelnetSession x : s.pool.sessions()) {
            long idle = (System.currentTimeMillis() - x.lastInput) / 1000;
            out(String.format("%s %3d vty %-3d %-10s %-20s %02d:%02d:%02d   %s (%s)\n", x == s ? "*" : " ", x.line + 2, x.line,
                    x.user.isEmpty() ? "-" : x.user, x.mode == TelnetSession.Mode.TOP ? "top" : x.mode == TelnetSession.Mode.SHADOW ? "monitor" : "idle",
                    idle / 3600, (idle / 60) % 60, idle % 60, x.from, x.transport));
        }
        out("\n  Interface    User               Mode         Idle     Peer Address\n\n");
    }

    private void showTelnet() {
        out("Telnet options for line vty " + s.line + " (" + s.transport + ", RFC 1143 Q-method states)\n\n");
        out(String.format("  %-24s %-9s %-14s %-14s\n", "Option", "RFC", "Server (us)", "Client (him)"));
        int[] opts = {Telnet.OPT_BINARY, Telnet.OPT_ECHO, Telnet.OPT_SGA, Telnet.OPT_STATUS, Telnet.OPT_TIMING_MARK, Telnet.OPT_TTYPE, Telnet.OPT_TSPEED, Telnet.OPT_NAWS, Telnet.OPT_LINEMODE};
        for (int o : opts) {
            out(String.format("  %-24s %-9s %-14s %-14s\n", Telnet.optName(o) + " (" + o + ")", Telnet.optRfc(o), s.neg.usState(o), s.neg.himState(o)));
        }
        out("\n  Terminal types offered (RFC 1091 cycle): " + (s.ttypes.isEmpty() ? "none" : String.join(", ", s.ttypes)) + "\n");
        out("  Window size (RFC 1073 NAWS): " + s.cols + " columns x " + s.rows + " rows\n");
        out("  Terminal speed (RFC 1079): " + (s.tspeed.isEmpty() ? "not reported" : s.tspeed + " bps (transmit,receive)") + "\n");
        out("  Character mode: " + (s.neg.isLocal(Telnet.OPT_ECHO) && s.neg.isLocal(Telnet.OPT_SGA) ? "yes (server echoes, no go-ahead)" : "no (client line mode / local echo)") + "\n");
        double r = s.lastRtt();
        out("  Last TIMING-MARK round trip: " + (r < 0 ? "not measured yet" : String.format("%.3f ms", r)) + "\n");
        out("  Negotiation messages sent by server: " + s.neg.messagesSent() + "\n\n");
    }

    private void showTerminal() {
        out("Line " + (s.line + 2) + ", Location: \"" + s.from + "\", Type: \"" + s.terminalType() + "\"\n");
        out("Length: " + s.rows + " lines, Width: " + s.cols + " columns\n");
        out("Status: " + (s.priv >= 15 ? "Privileged" : "Ready") + ", Active, " + (s.ansi() ? "ANSI capable" : "no ANSI") + "\n");
        out("Capabilities: Character mode, " + (s.debugging() ? "Debug on, " : "") + "Transport " + s.transport + "\n");
        out("Timeouts:      Idle EXEC    Idle Session   Modem Answer  Session   Dispatch\n");
        out("               " + String.format("%02d:%02d:00", s.pool.cfg.execTimeoutMin / 60, s.pool.cfg.execTimeoutMin % 60) + "        never                        none     not set\n");
        out("Allowed input transports are telnet telnets.\n");
    }

    private void showVersion() {
        long up = (System.currentTimeMillis() - s.pool.bootTime) / 1000;
        out("JU Telnet VTY Software (Java), Version 2.0, RELEASE SOFTWARE\n");
        out("Implements RFC 854, 855, 857, 858, 860, 1073, 1091, 1143; TLS listener for telnets\n\n");
        out(s.pool.cfg.hostname + " uptime is " + up / 3600 + " hours, " + (up / 60) % 60 + " minutes, " + up % 60 + " seconds\n");
        out("Java " + System.getProperty("java.version") + " on " + System.getProperty("os.name") + " " + System.getProperty("os.arch") + "\n");
        out(VtyPool.LINES + " Virtual terminal line(s) (line vty 0 " + (VtyPool.LINES - 1) + ")\n");
        out("Listeners: telnet TCP " + s.pool.plainPort + (s.pool.tlsPort > 0 ? ", telnets (TLS) TCP " + s.pool.tlsPort : "") + "\n");
    }

    private void showIpBrief() {
        out("Interface              IP-Address      OK? Method Status                Protocol\n");
        out("FastEthernet0/0        192.168.148.1   YES manual up                    up\n");
        out("FastEthernet0/1        unassigned      YES unset  administratively down down\n");
        out("Serial0/0/0            192.168.150.1   YES manual up                    up\n");
        out("Serial0/0/1            unassigned      YES unset  administratively down down\n");
        out(String.format("Vty0-%d                 %-15s YES manual up                    up      (TCP %d)\n",
                VtyPool.LINES - 1, "127.0.0.1", s.pool.plainPort));
        out("! interfaces mirror JU-Main-R from Assignment 6 Q5; the VTY lines are real\n");
    }

    private void showDhcp() {
        File dir = s.pool.dhcpDataDir;
        File[] files = dir.listFiles((d, n) -> n.startsWith("leases_") && n.endsWith(".db"));
        if (files == null || files.length == 0) {
            out("% No DHCP bindings: lease files not found in " + dir.getAbsolutePath() + "\n% Start the DHCP module (..\\DHCP\\run.bat) first.\n");
            return;
        }
        Map<String, String[]> best = new TreeMap<>((x, y) -> ipKey(x).compareTo(ipKey(y)));
        int read = 0;
        for (File f : files) {
            try (BufferedReader r = new BufferedReader(new FileReader(f))) {
                String l;
                while ((l = r.readLine()) != null) {
                    String[] p = l.split("\\|");
                    if (p.length < 7) continue;
                    read++;
                    String[] old = best.get(p[0]);
                    if (old == null || "ACTIVE".equals(p[3]) && !"ACTIVE".equals(old[3]) || parseL(p[5]) > parseL(old[5]) && p[3].equals(old[3])) best.put(p[0], p);
                }
            } catch (IOException e) { out("% cannot read " + f.getName() + "\n"); }
        }
        out("Bindings from the DHCP cluster: " + files.length + " replica file(s), " + read + " records, " + best.size() + " unique addresses\n\n");
        out(String.format("%-16s %-27s %-20s %-9s %-12s %s\n", "IP address", "Client-ID/Hardware address", "Hostname", "State", "Server", "Lease expiration"));
        SimpleDateFormat f = new SimpleDateFormat("MMM dd yyyy HH:mm:ss");
        for (String[] p : best.values()) {
            long exp = parseL(p[5]);
            String e = exp >= Long.MAX_VALUE / 2 ? "Infinite" : f.format(new Date(exp));
            out(String.format("%-16s %-27s %-20s %-9s %-12s %s\n", p[0], p[1].toLowerCase(), p[2], p[3], p[4], e));
        }
    }

    private static long parseL(String x) { try { return Long.parseLong(x); } catch (NumberFormatException e) { return 0; } }

    private static String ipKey(String ip) {
        StringBuilder b = new StringBuilder();
        for (String p : ip.split("\\.")) { String q = "000" + p; b.append(q.substring(q.length() - 3)); }
        return b.toString();
    }

    private void showArp() {
        out("Host ARP cache, read live from the operating system ('arp -a'):\n\n");
        try {
            Process p = new ProcessBuilder("arp", "-a").redirectErrorStream(true).start();
            StringBuilder b = new StringBuilder();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String l; int n = 0;
                while ((l = r.readLine()) != null && n++ < 60) b.append(l).append('\n');
            }
            p.waitFor(3, TimeUnit.SECONDS);
            out(b.toString());
            out("\n! Telnet runs over TCP/IP: before the first SYN reached this router, the client's\n! ARP resolved the next-hop MAC - the entries above are that mechanism at work.\n");
        } catch (Exception e) {
            out("% arp not available: " + e.getMessage() + "\n");
        }
    }

    private void broadcast(String msg) {
        int n = 0;
        for (TelnetSession x : s.pool.sessions()) {
            if (x.mode == TelnetSession.Mode.EXEC || x.mode == TelnetSession.Mode.CONFIG) {
                x.notifyAsync("\n***\n***\n*** Message from vty" + s.line + " to all terminals (" + s.user + "):\n*** " + msg + "\n***\n");
                n++;
            }
        }
        Hub.I.log("[VTY" + s.line + "] send * \"" + msg + "\" -> " + n + " line(s)");
    }

    private void sendOne(String lineNo, String msg) {
        TelnetSession x = s.pool.byLine(num(lineNo, -1));
        if (x == null) { out("% No such line\n"); return; }
        x.notifyAsync("\n***\n*** Message from vty" + s.line + " (" + s.user + "):\n*** " + msg + "\n***\n");
    }

    private void shadow(String lineNo) {
        TelnetSession x = s.pool.byLine(num(lineNo, -1));
        if (x == null) { out("% No such line\n"); return; }
        if (x == s) { out("% Cannot monitor your own line\n"); return; }
        s.startShadow(x);
        x.notifyAsync("% Note: your session is being monitored from vty " + s.line + " (" + s.user + ")");
    }

    private void clearLine(String lineNo) {
        TelnetSession x = s.pool.byLine(num(lineNo, -1));
        if (x == null) { out("% No such line\n"); return; }
        if (x == s) { out("% Use 'exit' to end your own session\n"); return; }
        x.print("\n% Line cleared by " + s.user + " on vty " + s.line + "\n");
        x.close("clear line");
        out("[confirm]\n [OK]\n");
    }

    private void writeMem() {
        try { s.pool.cfg.save(); out("Building configuration...\n[OK]\n"); }
        catch (IOException e) { out("% Write failed: " + e.getMessage() + "\n"); }
    }

    private void hostname(String n) {
        if (!n.matches("[A-Za-z][A-Za-z0-9-]{0,30}")) { out("% Hostname must start with a letter: letters, digits, '-'\n"); return; }
        s.pool.cfg.hostname = n;
    }

    private void banner(String text) {
        String t = text;
        if (t.length() >= 2 && t.charAt(0) == t.charAt(t.length() - 1) && !Character.isLetterOrDigit(t.charAt(0))) t = t.substring(1, t.length() - 1);
        s.pool.cfg.banner = t;
    }
}

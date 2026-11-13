package telnet;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import telnet.aaa.Radius;
import telnet.aaa.RadiusClient;
import telnet.aaa.RadiusServer;
import telnet.client.TelnetClient;
import telnet.cluster.Cluster;
import telnet.lab.ModeLab;
import telnet.core.Hub;
import telnet.dashboard.DashboardServer;
import telnet.protocol.LoopExperiment;
import telnet.protocol.OptionNegotiator;
import telnet.protocol.Telnet;
import telnet.protocol.TelnetCodec;
import telnet.server.TelnetSession;
import telnet.server.VtyPool;

/** Automated end-to-end verification ("run.bat --verify"). */
final class Verify {

    private static int pass, fail;

    private static void check(String name, boolean ok, String detail) {
        if (ok) pass++; else fail++;
        System.out.printf("  [%s] %-62s %s%n", ok ? "PASS" : "FAIL", name, detail == null ? "" : detail);
    }

    static int run(VtyPool pool, DashboardServer.Ports p, File keystore) throws Exception {
        System.out.println("\n--- 1. RFC 854 codec -------------------------------------------------------");
        codecTests();
        System.out.println("\n--- 2. RFC 1143 option negotiation ---------------------------------------");
        negotiationTests();
        System.out.println("\n--- 3. Server end to end (through the wire tap) --------------------------");
        serverTests(pool, p);
        System.out.println("\n--- 4. Security: sniffing, TLS, brute force, VTY limit -------------------");
        securityTests(pool, p, keystore);
        System.out.println("\n--- 5. HA cluster: load balancer, failover, session resume --------------");
        clusterTests();
        System.out.println("\n--- 6. AAA: RADIUS authentication and accounting (RFC 2865 / 2866) ------");
        radiusTests(pool, p);
        System.out.println("\n--- 7. LINEMODE vs character mode vs Nagle (measured) --------------------");
        modeTests(p);
        System.out.println("\n============================================================================");
        System.out.printf("  %d passed, %d failed%n", pass, fail);
        System.out.println("============================================================================");
        return fail;
    }

    // ------------------------------------------------------------------ 1

    private static void codecTests() {
        byte[] enc = TelnetCodec.encodeData(new byte[]{'a', (byte) 255, 'b', '\r', 'c'});
        check("0xFF in data is doubled, bare CR becomes CR NUL", Telnet.hex(enc).equals("61 FF FF 62 0D 00 63"), Telnet.hex(enc));

        // A stream with data, a command, two negotiations and a subnegotiation containing an escaped 255
        byte[] stream = concat("hi".getBytes(), new byte[]{(byte) 255, (byte) 246}, Telnet.negotiation(Telnet.DO, Telnet.OPT_NAWS),
                Telnet.negotiation(Telnet.WILL, Telnet.OPT_TTYPE), Telnet.subnegotiation(Telnet.OPT_NAWS, new byte[]{0, (byte) 255, 0, 24}),
                new byte[]{(byte) 255, (byte) 255}, "!".getBytes());
        String whole = decode(stream, new int[]{stream.length});
        check("decoder recognises data, AYT, DO, WILL, SB with escaped 255", whole.equals("D:h D:i C:AYT N:DO NAWS N:WILL TERMINAL-TYPE S:NAWS[0,255,0,24] D:255 D:!"), whole);

        // Fuzz: split the same stream at random places (TCP has no message boundaries)
        Random r = new Random(1143);
        boolean ok = true;
        for (int t = 0; t < 2000 && ok; t++) {
            List<Integer> cuts = new ArrayList<>();
            int left = stream.length;
            while (left > 0) { int c = 1 + r.nextInt(Math.min(left, 4)); cuts.add(c); left -= c; }
            int[] arr = new int[cuts.size()];
            for (int i = 0; i < arr.length; i++) arr[i] = cuts.get(i);
            ok = decode(stream, arr).equals(whole);
        }
        check("fuzz: 2000 random TCP segmentations decode identically", ok, "");
    }

    private static String decode(byte[] s, int[] chunks) {
        final StringBuilder out = new StringBuilder();
        TelnetCodec c = new TelnetCodec(new TelnetCodec.Listener() {
            public void onData(int b) { out.append(b >= 32 && b < 127 ? "D:" + (char) b : "D:" + b).append(' '); }
            public void onCommand(int x) { out.append("C:").append(Telnet.cmdName(x)).append(' '); }
            public void onNegotiation(int v, int o) { out.append("N:").append(Telnet.cmdName(v)).append(' ').append(Telnet.optName(o)).append(' '); }
            public void onSubnegotiation(int o, byte[] p) {
                out.append("S:").append(Telnet.optName(o)).append('[');
                for (int i = 0; i < p.length; i++) out.append(i > 0 ? "," : "").append(p[i] & 255);
                out.append("] ");
            }
        });
        int off = 0;
        for (int n : chunks) { c.feed(s, off, n); off += n; }
        return out.toString().trim();
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0; for (byte[] b : parts) n += b.length;
        byte[] r = new byte[n]; int o = 0;
        for (byte[] b : parts) { System.arraycopy(b, 0, r, o, b.length); o += b.length; }
        return r;
    }

    // ------------------------------------------------------------------ 2

    private static void negotiationTests() {
        LoopExperiment.Result naive = LoopExperiment.naive(), q = LoopExperiment.qMethod();
        check("naive negotiation loops forever (stopped at the cap)", naive.looped, naive.trace.size() + " messages");
        check("Q-method converges, both ends agree", !q.looped && q.finalState.contains("agree"), q.finalState);

        List<int[]> sent = new ArrayList<>();
        OptionNegotiator n = new OptionNegotiator((v, o, m) -> sent.add(new int[]{v, o}), new OptionNegotiator.Policy() {
            public boolean acceptLocal(int o) { return o == Telnet.OPT_ECHO; }
            public boolean acceptRemote(int o) { return false; }
        });
        n.receive(Telnet.DO, Telnet.OPT_ECHO);
        n.receive(Telnet.DO, Telnet.OPT_ECHO);
        check("DO ECHO answered once with WILL; a repeat DO gets no reply", sent.size() == 1 && sent.get(0)[0] == Telnet.WILL && n.isLocal(Telnet.OPT_ECHO), sent.size() + " reply");
        n.receive(Telnet.DO, Telnet.OPT_LINEMODE);
        check("unsupported option (LINEMODE) refused with WONT", sent.size() == 2 && sent.get(1)[0] == Telnet.WONT, "");
        n.receive(Telnet.WILL, Telnet.OPT_NEW_ENVIRON);
        check("peer offer we don't want (NEW-ENVIRON) refused with DONT", sent.size() == 3 && sent.get(2)[0] == Telnet.DONT, "");
    }

    // ------------------------------------------------------------------ 3

    private static void serverTests(VtyPool pool, DashboardServer.Ports p) throws Exception {
        TelnetClient c = new TelnetClient("127.0.0.1", p.tap, false, null, new String[]{"XTERM-256COLOR", "XTERM", "VT100"}, 120, 30, true, null);
        long m = c.expect(0, "Username: ", 5000);
        check("banner and Username prompt after negotiation", m > 0, "");
        TelnetSession s = pool.sessions().isEmpty() ? null : pool.sessions().get(0);
        check("server ECHO + SUPPRESS-GO-AHEAD on (character mode)", s != null && s.neg.isLocal(Telnet.OPT_ECHO) && s.neg.isLocal(Telnet.OPT_SGA), "");
        check("TERMINAL-TYPE cycled until repeat (RFC 1091)", s != null && s.ttypes.size() == 3, s == null ? "" : s.ttypes.toString());
        check("NAWS window size received (RFC 1073)", s != null && s.cols == 120 && s.rows == 30, s == null ? "" : s.cols + "x" + s.rows);

        c.line("student");
        long pw = c.expect(m, "Password: ", 3000);
        c.line("wrong");
        long inv = c.expect(pw, "% Login invalid", 3000);
        check("wrong password rejected", inv > 0, "");
        m = c.expect(inv, "Username: ", 3000);
        c.line("student");
        pw = c.expect(m, "Password: ", 3000);
        c.line("ju2026");
        long ok = c.expect(pw, "JU-Main-R>", 4000);
        check("student logs in to user EXEC (>)", ok > 0, "");
        String echoed = c.since(pw);
        check("password was not echoed back by the server", !echoed.contains("ju2026"), "");

        c.line("sh us");
        long u = c.expect(ok, "vty", 3000);
        check("IOS abbreviation 'sh us' = show users", u > 0, "");
        c.line("show running-config");
        long inv2 = c.expect(u, "Invalid input", 3000);
        check("privilege 1 cannot see running-config (% Invalid input)", inv2 > 0, "");
        c.line("enable");
        long ep = c.expect(inv2, "Password: ", 3000);
        c.line("class");
        long en = c.expect(ep, "JU-Main-R#", 3000);
        check("enable with enable secret -> privileged EXEC (#)", en > 0, "");
        c.line("configure terminal");
        c.line("hostname LAB-R1");
        c.line("end");
        long hn = c.expect(en, "LAB-R1#", 3000);
        check("configure terminal / hostname changes the prompt", hn > 0, "");
        c.line("show telnet");
        long st = c.expect(hn, "NAWS", 3000);
        check("show telnet lists RFC 1143 option states", st > 0, "");
        c.line("tmping 3");
        long tm = c.expect(st, "Success rate is 100 percent (3/3)", 5000);
        check("tmping: 3 RTT measurements via TIMING-MARK (RFC 860)", tm > 0, "");
        c.type("sh ver?");
        long q = c.expect(tm, "version", 3000);
        check("'?' context help lists completions", q > 0, "");
        c.type("\u0015");      // Ctrl-U clears the line
        c.command(Telnet.AYT);
        long ay = c.expect(q, "[LAB-R1: yes]", 3000);
        check("IAC AYT answered with a visible [host: yes]", ay > 0, "");
        c.embedEraseDemo();
        long em = c.expect(ay, "executed   cat file1", 3000);
        check("textbook embedding: 'cat filea' IAC EC '1' runs 'cat file1'", em > 0, "");
        check("TERMINAL-SPEED reported (RFC 1079)", s != null && "38400,38400".equals(s.tspeed), s == null ? "" : s.tspeed);
        boolean st2 = c.requestStatus();
        Thread.sleep(300);
        boolean gotStatus = false;
        synchronized (c) { for (String l : c.negLog) if (l.contains("SB STATUS IS")) gotStatus = true; }
        check("STATUS (RFC 859): SB STATUS SEND answered with SB STATUS IS", st2 && gotStatus, "");
        boolean meaning = false;
        for (Hub.NegEvent e : Hub.I.negFor(s == null ? -1 : s.id))
            if (e.text.equals("IAC DO ECHO") && e.meaning.equals("Approving an offer to enable")) meaning = true;
        check("client's DO ECHO labelled 'Approving an offer to enable'", meaning, "");
        c.line("configure terminal");
        c.line("hostname JU-Main-R");
        c.line("end");
        c.line("exit");
        Thread.sleep(400);
        check("exit closes the VTY line", pool.sessions().isEmpty(), pool.sessions().size() + " open");
        c.close();
    }

    // ------------------------------------------------------------------ 4

    private static void securityTests(VtyPool pool, DashboardServer.Ports p, File ks) throws Exception {
        Hub.I.captures.clear();
        TelnetClient c = new TelnetClient("127.0.0.1", p.tap, false, null, new String[]{"VT100"}, 80, 24, true, null);
        long m = c.expect(0, "Username: ", 5000);
        for (char ch : "admin\r".toCharArray()) c.type(String.valueOf(ch));          // char-at-a-time, like a real client
        long pw = c.expect(m, "Password: ", 3000);
        for (char ch : "cisco\r".toCharArray()) c.type(String.valueOf(ch));
        c.expect(pw, "JU-Main-R#", 4000);
        Thread.sleep(200);
        boolean sniffed = false;
        for (Hub.Capture x : Hub.I.captures) if (x.user.equals("admin") && x.pass.equals("cisco")) sniffed = true;
        check("wire tap sniffs admin/cisco from plaintext Telnet", sniffed, "");
        c.line("exit");
        c.close();

        if (p.tls > 0) {
            Hub.I.captures.clear();
            TelnetClient t = new TelnetClient("127.0.0.1", p.tlsTap, true, ks, new String[]{"VT100"}, 80, 24, true, null);
            long tm = t.expect(0, "Username: ", 6000);
            t.line("admin");
            long tp = t.expect(tm, "Password: ", 3000);
            t.line("cisco");
            long ok = t.expect(tp, "JU-Main-R#", 4000);
            Thread.sleep(200);
            check("telnets: TLS login works through the tap", ok > 0, "");
            check("telnets: the tap captured NO credentials", Hub.I.captures.isEmpty(), "");
            t.line("exit");
            t.close();
        } else {
            check("telnets listener available", false, "keytool missing");
        }

        // VTY limit: 5 lines
        List<TelnetClient> held = new ArrayList<>();
        for (int i = 0; i < 5; i++) held.add(new TelnetClient("127.0.0.1", p.telnet, false, null, new String[]{"VT100"}, 80, 24, true, null));
        Thread.sleep(300);
        TelnetClient sixth = new TelnetClient("127.0.0.1", p.telnet, false, null, new String[]{"VT100"}, 80, 24, true, null);
        long busy = sixth.expect(0, "All VTY lines are busy", 3000);
        check("6th connection refused: all 5 VTY lines busy", busy > 0, "");
        sixth.close();
        for (TelnetClient h : held) h.close();
        Thread.sleep(500);

        // Brute force: 3 failures within 60 s -> quiet mode
        TelnetClient b = new TelnetClient("127.0.0.1", p.telnet, false, null, new String[]{"BOT"}, 80, 24, true, null);
        long bm = b.expect(0, "Username: ", 5000);
        for (String guess : new String[]{"123456", "password", "admin"}) {
            b.line("admin");
            long bp = b.expect(bm, "Password: ", 3000);
            b.line(guess);
            bm = b.expect(bp, "% Login invalid", 3000);
        }
        long q = b.expect(bm, "blocked", 3000);
        check("3 failed logins -> login block-for (quiet mode)", q > 0 && pool.guard.quietSecondsLeft() > 0, pool.guard.quietSecondsLeft() + " s left");
        b.close();
        TelnetClient d = new TelnetClient("127.0.0.1", p.telnet, false, null, new String[]{"BOT"}, 80, 24, true, null);
        long r = d.expect(0, "quiet mode", 3000);
        check("next connection refused while in quiet mode", r > 0, "");
        d.close();
        pool.guard.unblock();
        check("clear login leaves quiet mode", pool.guard.quietSecondsLeft() == 0, "");
    }

    // ------------------------------------------------------------------ 5

    private static void clusterTests() throws Exception {
        Cluster cl = Cluster.I;
        if (cl == null) { check("HA cluster is running", false, "not started"); return; }
        Thread.sleep(1200);                                            // first heartbeats
        TelnetClient c = new TelnetClient("127.0.0.1", Cluster.LB_PORT, false, null, new String[]{"XTERM"}, 80, 24, true, null);
        long m = c.expect(0, "Username: ", 6000);
        Matcher nm = Pattern.compile("cluster node (R\\d)").matcher(c.since(0));
        String node = nm.find() ? nm.group(1) : "?";
        check("load balancer hands the connection to a cluster node", m > 0 && !node.equals("?"), node);
        c.line("admin"); long pw = c.expect(m, "Password: ", 3000); c.line("cisco");
        long t = c.expect(pw, "Session token", 4000);
        Matcher tm = Pattern.compile("Session token ([A-Z0-9]{4}-[A-Z0-9]{4})").matcher(c.since(pw));
        String tok = tm.find() ? tm.group(1) : "?";
        check("cluster login prints a resume token", t > 0 && !tok.equals("?"), tok);
        long pr = c.expect(t, "#", 3000);
        c.line("show clock"); pr = c.expect(pr, "#", 3000);
        c.line("configure terminal"); c.expect(pr, "(config)#", 3000);
        Thread.sleep(400);
        check("session snapshot replicated to all three nodes (UDP)", cl.replicaCount(tok) == 3, cl.replicaCount(tok) + " copies");
        cl.control("kill", node, "");
        long end = System.currentTimeMillis() + 3000;
        while (!c.isClosed() && System.currentTimeMillis() < end) Thread.sleep(50);
        check("killing the node drops the client's TCP connection", c.isClosed(), "");
        Thread.sleep(2000);
        check("no heartbeat for 1.5 s: the balancer takes the node out", !cl.healthy(node), node);
        TelnetClient c2 = new TelnetClient("127.0.0.1", Cluster.LB_PORT, false, null, new String[]{"XTERM"}, 80, 24, true, null);
        long m2 = c2.expect(0, "Username: ", 6000);
        Matcher nm2 = Pattern.compile("cluster node (R\\d)").matcher(c2.since(0));
        String node2 = nm2.find() ? nm2.group(1) : "?";
        check("reconnect lands on a surviving node", m2 > 0 && !node2.equals(node) && !node2.equals("?"), node + " -> " + node2);
        c2.line("resume");
        long rs = c2.expect(m2, "(config)#", 4000);
        check("'resume' continues the session in configuration mode", rs > 0 && c2.since(m2).contains("RESUMED"), "");
        c2.line("do show history");
        long h = c2.expect(rs, "(config)#", 3000);
        String hist = c2.since(rs);
        check("command history survived the failover", h > 0 && hist.contains("show clock") && hist.contains("configure terminal"), "");
        c2.line("end"); c2.expect(h, "#", 3000);
        c2.line("exit"); Thread.sleep(600);
        check("logout deletes the snapshot on every node", cl.replicaCount(tok) == 0, cl.replicaCount(tok) + " copies left");
        c2.close();
        cl.control("revive", node, "");
        Thread.sleep(1500);
        check("revived node rejoins the rotation", cl.healthy(node), node);
    }

    // ------------------------------------------------------------------ 6

    private static void radiusTests(VtyPool pool, DashboardServer.Ports p) throws Exception {
        byte[] secret = "testing123".getBytes(), ra = new byte[16];
        new Random(2865).nextBytes(ra);
        byte[] hidden = Radius.hidePassword("a-long-password-of-21", secret, ra);
        check("User-Password hiding: 32 bytes, and it reverses with the secret", hidden.length == 32 && Radius.unhidePassword(hidden, secret, ra).equals("a-long-password-of-21"), "");
        check("...but not with the wrong secret", !Radius.unhidePassword(hidden, "wrong".getBytes(), ra).equals("a-long-password-of-21"), "");
        RadiusServer srv = RadiusClient.SERVER; RadiusClient cli = RadiusClient.I;
        if (srv == null || cli == null) { check("RADIUS server is running", false, ""); return; }
        pool.cfg.aaaRadius = true;
        String out = login(p.telnet, "netops", "radius123", "#");
        check("RADIUS-only user logs in with the privilege from Access-Accept", out.contains("Authenticated by RADIUS") && out.contains("privilege 15"), "");
        out = login(p.telnet, "admin", "not-the-password", "Username: ");
        check("wrong password -> Access-Reject (no fallback to local)", out.contains("Wrong password") && out.contains("Login invalid"), "");
        srv.online = false;
        long to = cli.timeouts;
        out = login(p.telnet, "admin", "cisco", "#");
        check("server silent: 3 tries, then fall back to local users", cli.timeouts > to && out.contains("local (RADIUS unreachable)"), "");
        out = login(p.telnet, "netops", "radius123", "Username: ");
        check("server silent: a RADIUS-only user cannot log in", out.contains("Login invalid"), "");
        srv.online = true;
        pool.cfg.radiusKey = "wrong-secret";
        long bad = cli.badResponses;
        login(p.telnet, "admin", "cisco", "#");
        check("wrong shared secret: reply fails the Response Authenticator check", cli.badResponses > bad, "");
        pool.cfg.radiusKey = "testing123";
        Thread.sleep(1500);                                            // accounting is asynchronous
        String acct = srv.json();
        check("accounting Start and Stop recorded on the server", acct.contains("\"user\":\"netops\"") && Pattern.compile("\"user\":\"netops\".*?\"stop\":[1-9]").matcher(acct).find(), "");
        check("accounting Interim-Update recorded the command", Pattern.compile("\"user\":\"netops\".*?\"commands\":\\[\"show users\"").matcher(acct).find(), "");
        pool.cfg.aaaRadius = false;
    }

    /** Log in, run "show users", log out; returns everything the server printed. */
    private static String login(int port, String user, String pass, String until) throws Exception {
        TelnetClient c = new TelnetClient("127.0.0.1", port, false, null, new String[]{"VT100"}, 80, 24, true, null);
        long m = c.expect(0, "Username: ", 6000);
        c.line(user); long pw = c.expect(m, "Password: ", 3000); c.line(pass);
        long r = c.expect(pw, until, 9000);
        if (until.equals("#") && r > 0) { c.line("show users"); r = c.expect(r, "#", 3000); c.line("exit"); Thread.sleep(300); }
        String s = c.since(0);
        c.close();
        return s;
    }

    // ------------------------------------------------------------------ 7

    private static void modeTests(DashboardServer.Ports p) {
        String j = ModeLab.run(p.telnet, 200, 60);
        Matcher mm = Pattern.compile("\"mode\":\"(\\w+)\",\"keys\":(\\d+),\"segC2S\":(\\d+).*?\"echoAvg\":([\\d.]+)").matcher(j);
        java.util.Map<String, double[]> r = new java.util.HashMap<>();
        while (mm.find()) r.put(mm.group(1), new double[]{Double.parseDouble(mm.group(2)), Double.parseDouble(mm.group(3)), Double.parseDouble(mm.group(4))});
        check("experiment ran in all three modes", r.size() == 3, r.keySet().toString());
        if (r.size() < 3) return;
        double[] ch = r.get("char"), ng = r.get("nagle"), ln = r.get("line");
        check("character mode: one client segment per keystroke", ch[1] >= ch[0] * 0.95, (int) ch[1] + " segments / " + (int) ch[0] + " keys");
        check("Nagle's rule sends fewer segments than character mode", ng[1] < ch[1] * 0.75, (int) ng[1] + " vs " + (int) ch[1]);
        check("...but makes the echo slower", ng[2] > ch[2], ng[2] + " ms vs " + ch[2] + " ms");
        check("LINEMODE: one segment per command line", ln[1] <= ModeLab.SCRIPT.length + 1, (int) ln[1] + " segments");
    }
}

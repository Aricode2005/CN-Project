package telnet;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.List;
import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import telnet.client.TelnetClient;
import telnet.core.Hub;
import telnet.dashboard.DashboardServer;
import telnet.server.DeviceConfig;
import telnet.server.VtyPool;
import telnet.tap.WireTap;

/**
 * Telnet Remote-Management Lab.
 *
 *   TCP 2323  Telnet server (plaintext, RFC 854)       - 5 VTY lines like "line vty 0 4"
 *   TCP 2324  Wire tap -> 2323 (shows what a sniffer sees)
 *   TCP 9923  Telnet over TLS ("telnets", real port 992)
 *   TCP 9924  Wire tap -> 9923 (shows that TLS hides everything)
 *   HTTP 8081 Dashboard (the DHCP module uses 8080, so both run side by side)
 *
 * Usage:  run.bat               start everything + console menu
 *         run.bat --verify      run the automated test suite
 *         run.bat client [port] [--tls]   console Telnet client
 */
public final class Main {

    static final int TELNET = 2323, TAP = 2324, TLS = 9923, TLS_TAP = 9924, HTTP = 8081;
    static final File DATA = new File("data");
    static final File KEYSTORE = new File(DATA, "telnet-tls.p12");

    public static void main(String[] args) throws Exception {
        List<String> a = Arrays.asList(args);
        if (!a.isEmpty() && a.get(0).equals("client")) { cliClient(args); return; }
        boolean verify = a.contains("--verify");

        System.out.println("==============================================================================");
        System.out.println("   TELNET REMOTE-MANAGEMENT LAB  -  RFC 854/855/857/858/860/1073/1091/1143     ");
        System.out.println("==============================================================================");
        DATA.mkdirs();
        Hub.I.quiet = verify;

        DeviceConfig cfg = new DeviceConfig(new File(DATA, verify ? "startup-config.verify" : "startup-config.properties"));
        VtyPool pool = new VtyPool(cfg, new File(System.getProperty("dhcp.data", "../DHCP/data")));
        pool.listen(TELNET, ServerSocketFactory.getDefault(), "telnet");
        new WireTap(TAP, TELNET, false).start();

        boolean tls = ensureKeystore();
        if (tls) {
            pool.listen(TLS, tlsFactory(), "telnets");
            new WireTap(TLS_TAP, TLS, true).start();
        } else {
            Hub.I.log("[TLS] keytool not available: telnets listener disabled");
        }

        DashboardServer.Ports p = new DashboardServer.Ports();
        p.telnet = TELNET; p.tap = TAP; p.tls = tls ? TLS : 0; p.tlsTap = tls ? TLS_TAP : 0; p.http = HTTP;
        DashboardServer dash = new DashboardServer(p, pool, new File("web"), KEYSTORE);
        dash.start();
        Hub.I.log("[DASHBOARD] http://localhost:" + HTTP);

        if (verify) {
            int failed = Verify.run(pool, p, KEYSTORE);
            dash.stop(); pool.shutdown();
            System.exit(failed == 0 ? 0 : 1);
        }

        System.out.println();
        System.out.println("  Dashboard ........ http://localhost:" + HTTP);
        System.out.println("  Telnet ........... telnet localhost " + TELNET + "     (or PuTTY: Telnet, port " + TELNET + ")");
        System.out.println("  Via wire tap ..... telnet localhost " + TAP + "     (passwords appear in the sniffer)");
        if (tls) System.out.println("  Telnet over TLS .. run.bat client " + TLS_TAP + " --tls");
        System.out.println("  Logins ........... admin / cisco (privilege 15), student / ju2026, enable secret: class");
        System.out.println();
        System.out.println("  Commands: [s] sessions  [l] loop experiment  [u] unblock logins  [q] quit");
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = in.readLine()) != null) {
            line = line.trim();
            if (line.equals("q")) break;
            if (line.equals("s")) for (telnet.server.TelnetSession s : pool.sessions())
                System.out.println("  vty" + s.line + " " + (s.user.isEmpty() ? "-" : s.user) + " " + s.from + " " + s.transport + " " + s.terminalType() + " " + s.cols + "x" + s.rows + " " + s.mode);
            if (line.equals("l")) {
                for (telnet.protocol.LoopExperiment.Result r : new telnet.protocol.LoopExperiment.Result[]{telnet.protocol.LoopExperiment.naive(), telnet.protocol.LoopExperiment.qMethod()}) {
                    System.out.println("  " + r.name + ": " + r.finalState + (r.looped ? "  <-- LOOP (stopped at cap)" : ""));
                }
            }
            if (line.equals("u")) pool.guard.unblock();
        }
        dash.stop();
        pool.shutdown();
        System.exit(0);
    }

    // ------------------------------------------------------------------ TLS

    /** Create a self-signed certificate for the TLS listener with the JDK's keytool. */
    static boolean ensureKeystore() {
        if (KEYSTORE.exists()) return true;
        String exe = System.getProperty("java.home") + File.separator + "bin" + File.separator + "keytool";
        try {
            Process p = new ProcessBuilder(exe, "-genkeypair", "-alias", "telnets", "-keyalg", "RSA", "-keysize", "2048",
                    "-validity", "3650", "-keystore", KEYSTORE.getPath(), "-storetype", "PKCS12", "-storepass", "changeit",
                    "-keypass", "changeit", "-dname", "CN=JU-Main-R, OU=CSE, O=Jadavpur University, C=IN", "-noprompt")
                    .redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            p.waitFor();
            if (KEYSTORE.exists()) Hub.I.log("[TLS] generated self-signed certificate " + KEYSTORE.getPath());
            return KEYSTORE.exists();
        } catch (Exception e) {
            return false;
        }
    }

    static ServerSocketFactory tlsFactory() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream f = new FileInputStream(KEYSTORE)) { ks.load(f, "changeit".toCharArray()); }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "changeit".toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        return ctx.getServerSocketFactory();
    }

    // ------------------------------------------------------------------ console client

    /** Line-mode console client. It refuses server ECHO (the console echoes locally) and hides the password itself. */
    static void cliClient(String[] args) throws Exception {
        int port = args.length > 1 && !args[1].startsWith("--") ? Integer.parseInt(args[1]) : TAP;
        boolean tls = Arrays.asList(args).contains("--tls");
        Hub.I.quiet = true;
        final StringBuilder tail = new StringBuilder();
        TelnetClient c = new TelnetClient("127.0.0.1", port, tls, KEYSTORE, new String[]{"VT100"}, 100, 30, false, s -> {
            System.out.print(s.replace("\r", ""));
            System.out.flush();
            synchronized (tail) { tail.append(s); if (tail.length() > 30) tail.delete(0, tail.length() - 30); }
        });
        System.out.println("Connected to 127.0.0.1:" + port + (tls ? " over TLS" : "") + ". Ctrl+C to quit.");
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        while (!c.isClosed()) {
            boolean pw;
            synchronized (tail) { pw = tail.toString().endsWith("Password: "); }
            String line;
            if (pw && System.console() != null) line = new String(System.console().readPassword());
            else line = in.readLine();
            if (line == null) break;
            c.line(line);
        }
        c.close();
    }
}

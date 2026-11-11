package mail;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Collections;
import java.util.Properties;
import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import mail.client.LineClient;
import mail.client.SmtpClient;
import mail.core.Hub;
import mail.dashboard.DashboardServer;
import mail.server.ImapSession;
import mail.server.Pop3Session;
import mail.server.Session;
import mail.server.SmtpSession;
import mail.store.MailStore;

/**
 * JU Mail Lab — our own SMTP, POP3 and IMAP4 servers + clients + dashboard.
 *
 *            plain   TLS (implicit)        real-world ports
 *   SMTP     2525    2465                  25 / 587 (STARTTLS) / 465
 *   POP3     1110    2995                  110 / 995
 *   IMAP     1143    2993                  143 / 993
 *   Dashboard http://localhost:8083       (DHCP 8080, Telnet 8081, ARP 8082)
 *
 * The plain ports also offer STARTTLS / STLS. Domain: cse.myuniv.edu (as in Assignment 6 Q7).
 */
public final class Main {

    public static final int SMTP = 2525, SMTPS = 2465, POP3 = 1110, POP3S = 2995, IMAP = 1143, IMAPS = 2993, HTTP = 8083;
    static final File DATA = new File("data");
    static final File KEYSTORE = new File(DATA, "mail-tls.p12");
    public static final String DOMAIN = "cse.myuniv.edu";

    public static void main(String[] args) throws Exception {
        boolean verify = Arrays.asList(args).contains("--verify");
        System.out.println("==============================================================================");
        System.out.println("   JU MAIL LAB  -  SMTP (RFC 5321) · POP3 (RFC 1939) · IMAP4rev1 (RFC 3501)     ");
        System.out.println("==============================================================================");
        DATA.mkdirs();
        Hub.I.quiet = verify;

        File storeDir = new File(DATA, verify ? "mail-verify" : "mail");
        if (verify) deleteTree(storeDir);
        MailStore store = new MailStore(storeDir, DOMAIN);

        SSLSocketFactory tls = null;
        ServerSocketFactory tlsServer = null;
        if (ensureKeystore()) {
            SSLContext c = sslContext();
            tls = c.getSocketFactory();
            tlsServer = c.getServerSocketFactory();
            LineClient.localTrustStore = KEYSTORE;
        } else Hub.I.log("[TLS] keytool not found: STARTTLS and TLS ports disabled");

        Session.Context ctx = new Session.Context(store, tls, "mail." + DOMAIN);
        ServerSocketFactory plain = ServerSocketFactory.getDefault();
        Session.listen(SMTP, plain, "SMTP", s -> make(() -> new SmtpSession(ctx, s, false)));
        Session.listen(POP3, plain, "POP3", s -> make(() -> new Pop3Session(ctx, s, false)));
        Session.listen(IMAP, plain, "IMAP", s -> make(() -> new ImapSession(ctx, s, false)));
        if (tlsServer != null) {
            Session.listen(SMTPS, tlsServer, "SMTPS", s -> make(() -> new SmtpSession(ctx, s, true)));
            Session.listen(POP3S, tlsServer, "POP3S", s -> make(() -> new Pop3Session(ctx, s, true)));
            Session.listen(IMAPS, tlsServer, "IMAPS", s -> make(() -> new ImapSession(ctx, s, true)));
        }
        configureSmartHost();

        DashboardServer dash = new DashboardServer(HTTP, store, new File("web"), tlsServer != null);
        dash.start();
        Hub.I.log("[DASHBOARD] http://localhost:" + HTTP);

        if (verify) {
            int failed = Verify.run(store);
            dash.stop();
            System.exit(failed == 0 ? 0 : 1);
        }

        System.out.println();
        System.out.println("  Dashboard ...... http://localhost:" + HTTP);
        System.out.println("  Users .......... alice/alice123  bob/bob123  subham/ju2026   (@" + DOMAIN + ")");
        System.out.println("  Try by hand .... telnet localhost 2525  (SMTP)   1110 (POP3)   1143 (IMAP)");
        System.out.println("  Real clients ... Thunderbird/Outlook: IMAP localhost:1143, SMTP localhost:2525, user bob");
        System.out.println("  Interop test ... python interop_test.py   (Python's smtplib/poplib/imaplib against our servers)");
        System.out.println("  Press Enter to stop.");
        System.in.read();
        dash.stop();
        System.exit(0);
    }

    interface Maker { Session make() throws Exception; }
    private static Session make(Maker m) { try { return m.make(); } catch (Exception e) { Hub.I.log("[SERVER] " + e.getMessage()); return null; } }

    /**
     * Optional: relay mail for other domains through a real provider ("smart host").
     * data/smarthost.properties:  host=smtp.gmail.com  port=587  tls=STARTTLS  user=you@gmail.com  password=<app password>
     */
    private static void configureSmartHost() {
        File f = new File(DATA, "smarthost.properties");
        if (!f.exists()) return;
        Properties p = new Properties();
        try (FileInputStream in = new FileInputStream(f)) { p.load(in); } catch (Exception e) { return; }
        SmtpSession.relay = msg -> {
            try {
                SmtpClient c = new SmtpClient(p.getProperty("host"), Integer.parseInt(p.getProperty("port", "587")),
                        LineClient.Tls.valueOf(p.getProperty("tls", "STARTTLS")));
                if (c.extensions.isEmpty()) c.ehlo("mail." + DOMAIN);
                c.login(p.getProperty("user"), p.getProperty("password"));
                c.send(p.getProperty("user"), Collections.singletonList(msg[1]), msg[2]);
                c.quit();
            } catch (Exception e) { throw new RuntimeException(e.getMessage(), e); }
        };
        Hub.I.log("[SMTP] smart host configured: " + p.getProperty("host"));
    }

    static boolean ensureKeystore() {
        if (KEYSTORE.exists()) return true;
        String exe = System.getProperty("java.home") + File.separator + "bin" + File.separator + "keytool";
        try {
            Process pr = new ProcessBuilder(exe, "-genkeypair", "-alias", "mail", "-keyalg", "RSA", "-keysize", "2048", "-validity", "3650",
                    "-keystore", KEYSTORE.getPath(), "-storetype", "PKCS12", "-storepass", "changeit", "-keypass", "changeit",
                    "-dname", "CN=mail." + DOMAIN + ", OU=CSE, O=Jadavpur University, C=IN", "-ext", "SAN=dns:localhost,ip:127.0.0.1,dns:mail." + DOMAIN,
                    "-noprompt").redirectErrorStream(true).start();
            pr.getInputStream().readAllBytes();
            pr.waitFor();
            return KEYSTORE.exists();
        } catch (Exception e) { return false; }
    }

    static SSLContext sslContext() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream f = new FileInputStream(KEYSTORE)) { ks.load(f, "changeit".toCharArray()); }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "changeit".toCharArray());
        SSLContext c = SSLContext.getInstance("TLS");
        c.init(kmf.getKeyManagers(), null, null);
        return c;
    }

    static void deleteTree(File f) {
        File[] fs = f.listFiles();
        if (fs != null) for (File x : fs) deleteTree(x);
        f.delete();
    }
}

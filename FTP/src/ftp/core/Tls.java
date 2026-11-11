package ftp.core;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** A self-signed certificate (made once with keytool) for FTPS: AUTH TLS on the control connection, PROT P on data. */
public final class Tls {
    private Tls() { }
    public static final File KEYSTORE = new File("data", "ftp-tls.p12");
    private static SSLContext server, client;

    public static synchronized boolean init() {
        try {
            if (!KEYSTORE.exists()) {
                KEYSTORE.getParentFile().mkdirs();
                String exe = System.getProperty("java.home") + File.separator + "bin" + File.separator + "keytool";
                Process p = new ProcessBuilder(exe, "-genkeypair", "-alias", "ftp", "-keyalg", "RSA", "-keysize", "2048", "-validity", "3650",
                        "-keystore", KEYSTORE.getPath(), "-storetype", "PKCS12", "-storepass", "changeit", "-keypass", "changeit",
                        "-dname", "CN=ftp.cse.myuniv.edu, OU=CSE, O=Jadavpur University, C=IN", "-ext", "SAN=dns:localhost,ip:127.0.0.1,dns:ftp.cse.myuniv.edu",
                        "-noprompt").redirectErrorStream(true).start();
                p.getInputStream().readAllBytes(); p.waitFor();
            }
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (FileInputStream f = new FileInputStream(KEYSTORE)) { ks.load(f, "changeit".toCharArray()); }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, "changeit".toCharArray());
            server = SSLContext.getInstance("TLS"); server.init(kmf.getKeyManagers(), null, null);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);                                   // our client trusts the lab certificate
            client = SSLContext.getInstance("TLS"); client.init(null, tmf.getTrustManagers(), null);
            return true;
        } catch (Exception e) { Hub.I.log("[TLS] disabled: " + e.getMessage()); return false; }
    }
    public static SSLContext server() { return server; }
    /** For localhost: trust the lab certificate; for real servers: the JDK's normal trust store. */
    public static SSLContext clientFor(String host) {
        if (client != null && (host.equals("127.0.0.1") || host.equals("localhost"))) return client;
        try { return SSLContext.getDefault(); } catch (Exception e) { return client; }
    }
}

package telnet.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * The "router" configuration that the Telnet VTY lines protect, modelled on Cisco IOS:
 * hostname, MOTD banner, local users (secret 8 = PBKDF2-SHA256, never stored in clear),
 * enable secret, exec-timeout and "login block-for". Saved by "write memory".
 */
public final class DeviceConfig {

    public static final class User {
        public final String name; public final int privilege; public final String secret;
        User(String name, int privilege, String secret) { this.name = name; this.privilege = privilege; this.secret = secret; }
    }

    public volatile String hostname = "JU-Main-R";
    public volatile String banner = "Authorized access only. JU CSE network lab - all sessions are logged.";
    public volatile int execTimeoutMin = 5;
    public volatile int blockForSec = 30, blockAttempts = 3, blockWithinSec = 60;
    public volatile String enableSecret;
    public final Map<String, User> users = new LinkedHashMap<>();
    /** "aaa authentication login default group radius local" */
    public volatile boolean aaaRadius;
    /** "radius server host 127.0.0.1 auth-port 1812 acct-port 1813 key testing123" */
    public volatile String radiusHost = "127.0.0.1", radiusKey = "testing123";
    public volatile int radiusAuthPort = 1812, radiusAcctPort = 1813;
    private final File file;

    public DeviceConfig(File file) {
        this.file = file;
        enableSecret = hash("class");
        users.put("admin", new User("admin", 15, hash("cisco")));
        users.put("student", new User("student", 1, hash("ju2026")));
        load();
    }

    // ------------------------------------------------------------------ users / secrets

    public synchronized User authenticate(String user, String password) {
        User u = users.get(user);
        if (u == null) { hash(password); return null; }           // same work either way: no timing hint
        return verify(password, u.secret) ? u : null;
    }

    public synchronized void putUser(String name, int priv, String password) { users.put(name, new User(name, priv, hash(password))); }
    public synchronized boolean removeUser(String name) { return users.remove(name) != null; }
    public boolean checkEnable(String pw) { return verify(pw, enableSecret); }
    public void setEnable(String pw) { enableSecret = hash(pw); }

    /** "$8$salt$iterations$hash" (like Cisco type 8: PBKDF2 with SHA-256). */
    public static String hash(String password) {
        byte[] salt = new byte[10];
        new SecureRandom().nextBytes(salt);
        return "$8$" + b64(salt) + "$20000$" + b64(pbkdf2(password, salt, 20000));
    }

    public static boolean verify(String password, String stored) {
        try {
            String[] p = stored.split("\\$");
            byte[] salt = Base64.getDecoder().decode(p[2]);
            int it = Integer.parseInt(p[3]);
            byte[] want = Base64.getDecoder().decode(p[4]);
            return MessageDigest.isEqual(want, pbkdf2(password, salt, it));     // constant-time compare
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] pbkdf2(String pw, byte[] salt, int it) {
        try {
            KeySpec spec = new PBEKeySpec(pw.toCharArray(), salt, it, 256);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String b64(byte[] b) { return Base64.getEncoder().withoutPadding().encodeToString(b); }

    // ------------------------------------------------------------------ show running-config

    public synchronized String runningConfig(int vtyLines, int port) {
        StringBuilder s = new StringBuilder();
        s.append("Building configuration...\n\nCurrent configuration:\n!\n");
        s.append("hostname ").append(hostname).append("\n!\n");
        s.append("enable secret 8 ").append(enableSecret).append("\n!\n");
        for (User u : users.values()) {
            s.append("username ").append(u.name).append(" privilege ").append(u.privilege).append(" secret 8 ").append(u.secret).append('\n');
        }
        s.append("!\naaa new-model\n");
        s.append(aaaRadius ? "aaa authentication login default group radius local\naaa accounting exec default start-stop group radius\n"
                : "aaa authentication login default local\n");
        s.append("radius server host ").append(radiusHost).append(" auth-port ").append(radiusAuthPort).append(" acct-port ").append(radiusAcctPort)
                .append(" key 7 ").append(Base64.getEncoder().encodeToString(radiusKey.getBytes(java.nio.charset.StandardCharsets.UTF_8))).append('\n');
        s.append("!\nlogin block-for ").append(blockForSec).append(" attempts ").append(blockAttempts).append(" within ").append(blockWithinSec).append("\n!\n");
        s.append("banner motd ^C").append(banner).append("^C\n!\n");
        s.append("line vty 0 ").append(vtyLines - 1).append('\n');
        s.append(" exec-timeout ").append(execTimeoutMin).append(" 0\n");
        s.append(aaaRadius ? " login authentication default\n" : " login local\n").append(" transport input telnet\n");
        s.append(" ! listening on TCP ").append(port).append(" (23 needs admin rights)\n!\nend\n");
        return s.toString();
    }

    // ------------------------------------------------------------------ write memory

    public synchronized void save() throws IOException {
        Properties p = new Properties();
        p.setProperty("hostname", hostname);
        p.setProperty("banner", banner);
        p.setProperty("execTimeoutMin", String.valueOf(execTimeoutMin));
        p.setProperty("block", blockForSec + "," + blockAttempts + "," + blockWithinSec);
        p.setProperty("enable", enableSecret);
        StringBuilder u = new StringBuilder();
        for (User x : users.values()) u.append(x.name).append(':').append(x.privilege).append(':').append(x.secret).append(';');
        p.setProperty("users", u.toString());
        p.setProperty("aaaRadius", String.valueOf(aaaRadius));
        p.setProperty("radius", radiusHost + "," + radiusAuthPort + "," + radiusAcctPort + "," + radiusKey);
        file.getParentFile().mkdirs();
        try (OutputStream o = new FileOutputStream(file)) { p.store(o, "startup-config (write memory)"); }
    }

    private void load() {
        if (file == null || !file.exists()) return;
        Properties p = new Properties();
        try (InputStream i = new FileInputStream(file)) { p.load(i); } catch (IOException e) { return; }
        hostname = p.getProperty("hostname", hostname);
        banner = p.getProperty("banner", banner);
        execTimeoutMin = Integer.parseInt(p.getProperty("execTimeoutMin", "5"));
        String[] b = p.getProperty("block", "30,3,60").split(",");
        blockForSec = Integer.parseInt(b[0]); blockAttempts = Integer.parseInt(b[1]); blockWithinSec = Integer.parseInt(b[2]);
        enableSecret = p.getProperty("enable", enableSecret);
        aaaRadius = Boolean.parseBoolean(p.getProperty("aaaRadius", "false"));
        String[] r = p.getProperty("radius", "").split(",", 4);
        if (r.length == 4) { radiusHost = r[0]; radiusAuthPort = Integer.parseInt(r[1]); radiusAcctPort = Integer.parseInt(r[2]); radiusKey = r[3]; }
        String us = p.getProperty("users");
        if (us != null && !us.isEmpty()) {
            users.clear();
            for (String rec : us.split(";")) {
                if (rec.isEmpty()) continue;
                String[] f = rec.split(":", 3);
                users.put(f[0], new User(f[0], Integer.parseInt(f[1]), f[2]));
            }
        }
    }
}

package mail.store;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import mail.core.Hub;
import mail.mime.Mime;

/**
 * The mail store behind all three servers: users (PBKDF2 password hashes), each user's
 * folders, and messages with IMAP UIDs and flags. Persisted Maildir-style: one .eml file per
 * message under data/mail/&lt;user&gt;/&lt;folder&gt;/, plus a small meta file per folder.
 *
 * SMTP writes into INBOX; POP3 reads (and deletes from) INBOX only; IMAP sees every folder.
 */
public final class MailStore {

    // ================================================================== model

    public static final class Message {
        public final long uid;
        public final byte[] raw;
        public final long internalDate;
        public final Set<String> flags = new TreeSet<>();
        public boolean recent = true;
        Message(long uid, byte[] raw, long date) { this.uid = uid; this.raw = raw; this.internalDate = date; }
        public int size() { return raw.length; }
        public String header(String h) { return Mime.decodeWords(Mime.parse(raw).header(h)); }
    }

    public static final class Folder {
        public final String name;
        public final long uidValidity;
        long uidNext = 1;
        public volatile long version;                         // bumps on every change (IMAP sessions poll it)
        final List<Message> messages = new ArrayList<>();
        Folder(String name, long uidValidity) { this.name = name; this.uidValidity = uidValidity; }
        public synchronized List<Message> list() { return new ArrayList<>(messages); }
        public synchronized long uidNext() { return uidNext; }
        public synchronized int count() { return messages.size(); }
        public synchronized int unseen() { int n = 0; for (Message m : messages) if (!m.flags.contains("\\Seen")) n++; return n; }
        public synchronized int recent() { int n = 0; for (Message m : messages) if (m.recent) n++; return n; }
    }

    static final class User {
        final String name; final String hash;
        final Map<String, Folder> folders = new LinkedHashMap<>();
        volatile boolean popLocked;
        User(String name, String hash) { this.name = name; this.hash = hash; }
    }

    public final String domain;
    private final File root;
    private final Map<String, User> users = new ConcurrentHashMap<>();

    public MailStore(File root, String domain) {
        this.root = root;
        this.domain = domain;
        root.mkdirs();
        addUser("alice", "alice123");
        addUser("bob", "bob123");
        addUser("subham", "ju2026");
        for (User u : users.values()) load(u);
        if (folder("bob", "INBOX").count() == 0) seed();
    }

    // ================================================================== users

    private void addUser(String name, String password) {
        User u = new User(name, hash(password));
        for (String f : new String[]{"INBOX", "Sent", "Drafts", "Trash"}) u.folders.put(f, new Folder(f, uidValidity()));
        users.put(name, u);
    }

    public boolean userExists(String name) { return users.containsKey(name.toLowerCase()); }
    public Set<String> userNames() { return new TreeSet<>(users.keySet()); }

    public boolean authenticate(String user, String password) {
        User u = users.get(user == null ? "" : user.toLowerCase());
        if (u == null) { hash(password == null ? "" : password); return false; }
        return verify(password == null ? "" : password, u.hash);
    }

    /** POP3 needs an exclusive lock on the maildrop (RFC 1939). */
    public synchronized boolean lockPop(String user) {
        User u = users.get(user.toLowerCase());
        if (u == null || u.popLocked) return false;
        u.popLocked = true;
        return true;
    }
    public void unlockPop(String user) { User u = users.get(user.toLowerCase()); if (u != null) u.popLocked = false; }

    // ================================================================== folders

    public Folder folder(String user, String name) {
        User u = users.get(user.toLowerCase());
        if (u == null) return null;
        synchronized (u) {
            for (Map.Entry<String, Folder> e : u.folders.entrySet()) if (e.getKey().equalsIgnoreCase(name)) return e.getValue();
        }
        return null;
    }

    public List<String> folderNames(String user) {
        User u = users.get(user.toLowerCase());
        synchronized (u) { return new ArrayList<>(u.folders.keySet()); }
    }

    public synchronized boolean createFolder(String user, String name) {
        User u = users.get(user.toLowerCase());
        if (folder(user, name) != null || name.isEmpty()) return false;
        synchronized (u) { u.folders.put(name, new Folder(name, uidValidity())); }
        save(user, folder(user, name));
        Hub.I.event("FOLDER", user + " created folder " + name);
        return true;
    }

    public synchronized boolean deleteFolder(String user, String name) {
        if (name.equalsIgnoreCase("INBOX")) return false;
        User u = users.get(user.toLowerCase());
        Folder f = folder(user, name);
        if (f == null) return false;
        synchronized (u) { u.folders.remove(f.name); }
        deleteDir(new File(new File(root, user), safe(f.name)));
        return true;
    }

    public synchronized boolean renameFolder(String user, String from, String to) {
        User u = users.get(user.toLowerCase());
        Folder f = folder(user, from);
        if (f == null || folder(user, to) != null || from.equalsIgnoreCase("INBOX")) return false;
        Folder n = new Folder(to, uidValidity());
        synchronized (f) { for (Message m : f.messages) { Message c = new Message(n.uidNext++, m.raw, m.internalDate); c.flags.addAll(m.flags); n.messages.add(c); } }
        synchronized (u) { u.folders.remove(f.name); u.folders.put(to, n); }
        deleteDir(new File(new File(root, user), safe(f.name)));
        save(user, n);
        return true;
    }

    // ================================================================== messages

    /** Append a message (SMTP delivery, IMAP APPEND, COPY, sent copy). Returns the new UID. */
    public long append(String user, String folderName, byte[] raw, Set<String> flags) {
        Folder f = folder(user, folderName);
        if (f == null) return -1;
        Message m;
        synchronized (f) {
            m = new Message(f.uidNext++, raw, System.currentTimeMillis());
            if (flags != null) m.flags.addAll(flags);
            f.messages.add(m);
            f.version++;
        }
        save(user, f);
        return m.uid;
    }

    public void setFlags(String user, Folder f, Message m, Set<String> flags) {
        synchronized (f) { m.flags.clear(); m.flags.addAll(flags); f.version++; }
        save(user, f);
    }

    /** Remove all \Deleted messages; returns the removed UIDs in order. */
    public List<Long> expunge(String user, Folder f) {
        List<Long> gone = new ArrayList<>();
        synchronized (f) {
            f.messages.removeIf(m -> { if (m.flags.contains("\\Deleted")) { gone.add(m.uid); return true; } return false; });
            if (!gone.isEmpty()) f.version++;
        }
        if (!gone.isEmpty()) {
            for (long uid : gone) new File(dir(user, f), uid + ".eml").delete();
            save(user, f);
        }
        return gone;
    }

    /** Remove exactly these UIDs (IMAP MOVE / UID EXPUNGE). */
    public List<Long> expungeUids(String user, Folder f, Set<Long> uids) {
        List<Long> gone = new ArrayList<>();
        synchronized (f) {
            f.messages.removeIf(m -> { if (uids.contains(m.uid)) { gone.add(m.uid); return true; } return false; });
            if (!gone.isEmpty()) f.version++;
        }
        if (!gone.isEmpty()) {
            for (long uid : gone) new File(dir(user, f), uid + ".eml").delete();
            save(user, f);
        }
        return gone;
    }

    public void clearRecent(Folder f) { synchronized (f) { for (Message m : f.messages) m.recent = false; } }

    // ================================================================== persistence

    private File dir(String user, Folder f) { return new File(new File(root, user), safe(f.name)); }
    private static String safe(String n) { return n.replaceAll("[^A-Za-z0-9._-]", "_"); }

    private synchronized void save(String user, Folder f) {
        File d = dir(user, f);
        d.mkdirs();
        StringBuilder meta = new StringBuilder();
        meta.append("name=").append(f.name).append('\n');
        meta.append("uidvalidity=").append(f.uidValidity).append('\n');
        List<Message> ms;
        synchronized (f) { meta.append("uidnext=").append(f.uidNext).append('\n'); ms = new ArrayList<>(f.messages); }
        try {
            for (Message m : ms) {
                File e = new File(d, m.uid + ".eml");
                if (!e.exists()) Files.write(e.toPath(), m.raw);
                meta.append(m.uid).append(' ').append(m.internalDate).append(' ').append(String.join(",", m.flags)).append('\n');
            }
            Files.write(new File(d, "folder.meta").toPath(), meta.toString().getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            Hub.I.log("[STORE] save failed: " + e.getMessage());
        }
    }

    private void load(User u) {
        File ud = new File(root, u.name);
        File[] dirs = ud.listFiles(File::isDirectory);
        if (dirs == null) return;
        for (File d : dirs) {
            File metaF = new File(d, "folder.meta");
            if (!metaF.exists()) continue;
            try {
                List<String> lines = Files.readAllLines(metaF.toPath(), StandardCharsets.UTF_8);
                String name = lines.get(0).substring(5);
                Folder f = new Folder(name, Long.parseLong(lines.get(1).substring(12)));
                f.uidNext = Long.parseLong(lines.get(2).substring(8));
                for (int i = 3; i < lines.size(); i++) {
                    String[] p = lines.get(i).split(" ", 3);
                    if (p.length < 2) continue;
                    File e = new File(d, p[0] + ".eml");
                    if (!e.exists()) continue;
                    Message m = new Message(Long.parseLong(p[0]), Files.readAllBytes(e.toPath()), Long.parseLong(p[1]));
                    m.recent = false;
                    if (p.length > 2 && !p[2].isEmpty()) Collections.addAll(m.flags, p[2].split(","));
                    f.messages.add(m);
                }
                u.folders.put(name, f);
            } catch (Exception e) {
                Hub.I.log("[STORE] could not load " + d + ": " + e.getMessage());
            }
        }
    }

    private void seed() {
        String host = "mail." + domain;
        append("bob", "INBOX", Mime.build("Alice <alice@" + domain + ">", "Bob <bob@" + domain + ">", "Welcome to JU Mail",
                "Hi Bob,\n\nThis mailbox is served by our own SMTP, POP3 and IMAP4 servers.\nTry reading it with POP3 on one device and IMAP on another.\n\n- Alice", null, null, host).getBytes(StandardCharsets.UTF_8), null);
        append("bob", "INBOX", Mime.build("Subham <subham@" + domain + ">", "Bob <bob@" + domain + ">", "Lab schedule",
                "Assignment 6 viva is on Friday.\nBring the .pkt files.", null, null, host).getBytes(StandardCharsets.UTF_8), null);
        append("bob", "INBOX", Mime.build("Alice <alice@" + domain + ">", "Bob <bob@" + domain + ">", "Notes with attachment",
                "Notes attached (base64 inside a multipart/mixed message).", "notes.txt",
                "SMTP = push (port 25)\nPOP3 = pull + download (110)\nIMAP = pull + stay on server (143)\n".getBytes(StandardCharsets.UTF_8), host).getBytes(StandardCharsets.UTF_8), null);
    }

    private static void deleteDir(File d) {
        File[] fs = d.listFiles();
        if (fs != null) for (File f : fs) f.delete();
        d.delete();
    }

    private static long uidValidity() { return System.currentTimeMillis() / 1000 + new SecureRandom().nextInt(1000); }

    // ================================================================== password hashing

    static String hash(String pw) {
        byte[] salt = new byte[10];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt) + "$" + Base64.getEncoder().encodeToString(pbkdf2(pw, salt));
    }

    static boolean verify(String pw, String stored) {
        String[] p = stored.split("\\$");
        return MessageDigest.isEqual(Base64.getDecoder().decode(p[1]), pbkdf2(pw, Base64.getDecoder().decode(p[0])));
    }

    private static byte[] pbkdf2(String pw, byte[] salt) {
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec(pw.toCharArray(), salt, 20000, 256)).getEncoded();
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    /** Distinct helper for callers that need a stable ordered copy of flags. */
    public static Set<String> flagsOf(Message m) { synchronized (m.flags) { return new LinkedHashSet<>(m.flags); } }
}

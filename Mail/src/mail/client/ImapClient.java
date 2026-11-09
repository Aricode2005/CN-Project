package mail.client;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * IMAP4rev1 client: tagged commands, untagged responses, server literals {n}.
 * Enough for a real mail app: LIST, SELECT, SEARCH, FETCH headers/bodies/flags, STORE, COPY/MOVE,
 * EXPUNGE, APPEND and IDLE — against our server or imap.gmail.com:993.
 */
public final class ImapClient extends LineClient {

    /** One untagged response; literals are kept separately. */
    public static final class Untagged {
        public final String text;
        public final List<byte[]> literals = new ArrayList<>();
        Untagged(String t) { text = t; }
    }

    /** A summary row for a mailbox listing. */
    public static final class Summary {
        public long uid; public int seq; public String flags = "", subject = "", from = "", date = ""; public long size;
    }

    private int tagNo;
    public final String greeting;

    public ImapClient(String host, int port, Tls tls) throws IOException {
        super("IMAP", host, port, tls);
        greeting = readLine();
        if (tls == Tls.STARTTLS) { command("STARTTLS"); wrapTls(); }
    }

    public void login(String user, String pass) throws IOException {
        command("LOGIN " + q(user) + " " + q(pass), "LOGIN " + q(user) + " " + (maskSecrets ? "\"********\"" : q(pass)));
    }

    public List<String> list() throws IOException {
        List<String> out = new ArrayList<>();
        for (Untagged u : command("LIST \"\" \"*\"")) {
            Matcher m = Pattern.compile("^\\* LIST \\(([^)]*)\\) (\"[^\"]*\"|NIL) (.+)$").matcher(u.text);
            if (m.find()) {
                String name = u.literals.isEmpty() ? m.group(3) : new String(u.literals.get(0), StandardCharsets.UTF_8);
                out.add(name.replaceAll("^\"|\"$", ""));
            }
        }
        return out;
    }

    /** Returns EXISTS count. */
    public int select(String folder) throws IOException {
        int exists = 0;
        for (Untagged u : command("SELECT " + q(folder))) {
            Matcher m = Pattern.compile("^\\* (\\d+) EXISTS").matcher(u.text);
            if (m.find()) exists = Integer.parseInt(m.group(1));
        }
        return exists;
    }

    public List<Long> uidSearch(String criteria) throws IOException {
        List<Long> r = new ArrayList<>();
        for (Untagged u : command("UID SEARCH " + criteria))
            if (u.text.startsWith("* SEARCH")) for (String s : u.text.substring(8).trim().split(" ")) if (!s.isEmpty()) r.add(Long.parseLong(s));
        return r;
    }

    /** UID, FLAGS, size and the main headers (BODY.PEEK so nothing gets marked read). */
    public List<Summary> summaries(String uidSet) throws IOException {
        List<Summary> out = new ArrayList<>();
        for (Untagged u : command("UID FETCH " + uidSet + " (UID FLAGS RFC822.SIZE BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])")) {
            if (!u.text.contains(" FETCH ")) continue;
            Summary s = new Summary();
            Matcher m = Pattern.compile("^\\* (\\d+) FETCH").matcher(u.text); if (m.find()) s.seq = Integer.parseInt(m.group(1));
            m = Pattern.compile("UID (\\d+)").matcher(u.text); if (m.find()) s.uid = Long.parseLong(m.group(1));
            m = Pattern.compile("FLAGS \\(([^)]*)\\)").matcher(u.text); if (m.find()) s.flags = m.group(1);
            m = Pattern.compile("RFC822.SIZE (\\d+)").matcher(u.text); if (m.find()) s.size = Long.parseLong(m.group(1));
            if (!u.literals.isEmpty()) {
                String h = new String(u.literals.get(0), StandardCharsets.UTF_8);
                s.subject = header(h, "Subject"); s.from = header(h, "From"); s.date = header(h, "Date");
            }
            out.add(s);
        }
        return out;
    }

    /** Whole message (BODY[] — marks it \Seen, like opening it in a mail app). */
    public byte[] body(long uid, boolean peek) throws IOException {
        for (Untagged u : command("UID FETCH " + uid + " " + (peek ? "BODY.PEEK[]" : "BODY[]")))
            if (!u.literals.isEmpty()) return u.literals.get(0);
        return new byte[0];
    }

    public void store(long uid, String op, String flags) throws IOException { command("UID STORE " + uid + " " + op + " (" + flags + ")"); }
    public void move(long uid, String folder) throws IOException { command("UID MOVE " + uid + " " + q(folder)); }
    public void copy(long uid, String folder) throws IOException { command("UID COPY " + uid + " " + q(folder)); }
    public void expunge() throws IOException { command("EXPUNGE"); }
    public void noop() throws IOException { command("NOOP"); }
    public List<Untagged> lastUntagged = new ArrayList<>();

    public void append(String folder, String flags, byte[] msg) throws IOException {
        String tag = nextTag();
        String head = tag + " APPEND " + q(folder) + (flags.isEmpty() ? "" : " (" + flags + ")") + " {" + msg.length + "}";
        writeLine(head, null);
        String l = readLine();
        if (!l.startsWith("+")) throw new ProtocolException(l);
        writeRaw(msg, "(message literal: " + msg.length + " bytes)");
        writeLine("", "");
        finish(tag);
    }

    /** IDLE for up to `ms` milliseconds, reporting every pushed line. */
    public void idle(long ms, Consumer<String> onPush) throws IOException {
        String tag = nextTag();
        writeLine(tag + " IDLE", null);
        String l = readLine();
        if (!l.startsWith("+")) throw new ProtocolException(l);
        sock.setSoTimeout(250);
        long end = System.currentTimeMillis() + ms;
        try {
            while (System.currentTimeMillis() < end) {
                try { String p = readLine(); if (onPush != null) onPush.accept(p); }
                catch (java.net.SocketTimeoutException ignored) { }
            }
        } finally { sock.setSoTimeout(20000); }
        writeLine("DONE", null);
        finish(tag);
    }

    public void logout() throws IOException { try { command("LOGOUT"); } finally { close(); } }

    // ------------------------------------------------------------------ core

    public List<Untagged> command(String cmd) throws IOException { return command(cmd, null); }

    public List<Untagged> command(String cmd, String shown) throws IOException {
        String tag = nextTag();
        writeLine(tag + " " + cmd, shown == null ? null : tag + " " + shown);
        return finish(tag);
    }

    private List<Untagged> finish(String tag) throws IOException {
        List<Untagged> out = new ArrayList<>();
        while (true) {
            String l = readLine();
            if (l.startsWith(tag + " ")) {
                lastUntagged = out;
                String st = l.substring(tag.length() + 1);
                if (!st.startsWith("OK")) throw new ProtocolException(st);
                return out;
            }
            List<byte[]> lits = new ArrayList<>();
            StringBuilder text = new StringBuilder();
            while (true) {                                   // a response line may carry {n} literals
                Matcher m = Pattern.compile("\\{(\\d+)\\}$").matcher(l);
                if (!m.find()) { text.append(l); break; }
                text.append(l, 0, m.start()).append("{literal}");
                lits.add(readBytes(Integer.parseInt(m.group(1))));
                l = readLine();
            }
            Untagged u = new Untagged(text.toString());
            u.literals.addAll(lits);
            out.add(u);
        }
    }

    private String nextTag() { return "A" + String.format("%03d", ++tagNo); }

    private static String q(String s) { return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""; }

    private static String header(String block, String name) {
        Map<String, String> h = new LinkedHashMap<>();
        String cur = null;
        for (String l : block.split("\r?\n")) {
            if ((l.startsWith(" ") || l.startsWith("\t")) && cur != null) { h.put(cur, h.get(cur) + " " + l.trim()); continue; }
            int c = l.indexOf(':');
            if (c > 0) { cur = l.substring(0, c).trim().toLowerCase(); h.put(cur, l.substring(c + 1).trim()); }
        }
        String v = h.get(name.toLowerCase());
        return v == null ? "" : mail.mime.Mime.decodeWords(v);
    }
}

package mail.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import mail.core.Hub;
import mail.store.MailStore;

/**
 * POP3 server session (RFC 1939) — the message access agent that lets a client
 * DOWNLOAD mail from its INBOX.
 *
 *   AUTHORIZATION (USER/PASS) → TRANSACTION (STAT LIST UIDL RETR TOP DELE NOOP RSET) → QUIT → UPDATE
 *
 * The maildrop is locked for the whole session, DELE only marks messages, and the marked ones
 * are removed in the UPDATE state after QUIT. POP3 knows nothing about folders or flags.
 */
public final class Pop3Session extends Session {

    private enum State { AUTHORIZATION, TRANSACTION }

    private State state = State.AUTHORIZATION;
    private String user, pendingUser;
    private List<MailStore.Message> drop;                 // snapshot of INBOX taken at login
    private final Set<Integer> deleted = new HashSet<>();

    public Pop3Session(Context ctx, Socket s, boolean implicitTls) throws IOException { super(ctx, s, "POP3", implicitTls); }

    @Override
    protected void session() throws IOException {
        ok("JU-POP3 server ready", "greeting; we are in the AUTHORIZATION state");
        String line;
        while ((line = readLine()) != null) {
            String verb = line.split(" ", 2)[0].toUpperCase(Locale.ROOT);
            String arg = line.length() > verb.length() ? line.substring(verb.length()).trim() : "";
            logClient(verb.equals("PASS") ? "PASS " + arg : line, clientNote(verb, arg));
            if (verb.equals("QUIT")) { quit(); return; }
            if (verb.equals("CAPA")) { capa(); continue; }
            if (state == State.AUTHORIZATION) authorization(verb, arg);
            else transaction(verb, arg);
        }
    }

    private void authorization(String verb, String arg) throws IOException {
        switch (verb) {
            case "STLS":
                if (secure || ctx.tls == null) { err("TLS already active or not available"); return; }
                ok("Begin TLS negotiation", "client now starts the TLS handshake");
                upgradeTls();
                return;
            case "USER": pendingUser = arg; ok("User accepted, send PASS", "username recorded"); return;
            case "PASS":
                if (pendingUser == null) { err("USER first"); return; }
                if (!ctx.store.authenticate(pendingUser, arg)) { pendingUser = null; err("[AUTH] Invalid username or password"); return; }
                if (!ctx.store.lockPop(pendingUser)) { err("[IN-USE] Maildrop already locked by another POP3 session"); return; }
                user = pendingUser.toLowerCase(Locale.ROOT);
                drop = ctx.store.folder(user, "INBOX").list();
                state = State.TRANSACTION;
                ok("Logged in, " + drop.size() + " message(s) (" + octets() + " octets)", "maildrop locked; now in the TRANSACTION state");
                Hub.I.event("POP3", user + " logged in (" + drop.size() + " messages in INBOX)");
                return;
            default: err("Not allowed in AUTHORIZATION state");
        }
    }

    private void transaction(String verb, String arg) throws IOException {
        switch (verb) {
            case "STAT": ok(live() + " " + octets(), "number of messages and total size (excluding DELE-marked)"); return;
            case "LIST":
                if (!arg.isEmpty()) { int n = num(arg); if (valid(n)) ok(n + " " + drop.get(n - 1).size(), "message number and size"); return; }
                ok(live() + " messages", "scan listing follows, one line per message, ends with \".\"");
                for (int i = 1; i <= drop.size(); i++) if (!deleted.contains(i)) send(i + " " + drop.get(i - 1).size(), "");
                send(".", "end of multi-line response");
                return;
            case "UIDL":
                if (!arg.isEmpty()) { int n = num(arg); if (valid(n)) ok(n + " " + uidl(n), "unique id: stays the same across sessions"); return; }
                ok("unique-id listing follows", "lets a client in keep mode remember which messages it already has");
                for (int i = 1; i <= drop.size(); i++) if (!deleted.contains(i)) send(i + " " + uidl(i), "");
                send(".", "end of multi-line response");
                return;
            case "RETR": {
                int n = num(arg);
                if (!valid(n)) return;
                MailStore.Message m = drop.get(n - 1);
                ok(m.size() + " octets", "the whole message follows (dot-stuffed), ends with \".\"");
                sendBytes(stuff(m.raw, Integer.MAX_VALUE), "<message " + n + ": \"" + m.header("Subject") + "\">");
                send(".", "end of message");
                Hub.I.event("POP3", user + " downloaded message " + n + " \"" + m.header("Subject") + "\"");
                return;
            }
            case "TOP": {
                String[] p = arg.split(" ");
                int n = num(p[0]);
                if (!valid(n)) return;
                int k = p.length > 1 ? num(p[1]) : 0;
                ok("top of message follows", "headers + the first " + k + " body lines");
                sendBytes(stuff(drop.get(n - 1).raw, k), "<headers + " + k + " lines of message " + n + ">");
                send(".", "end of response");
                return;
            }
            case "DELE": {
                int n = num(arg);
                if (!valid(n)) return;
                deleted.add(n);
                ok("Message " + n + " marked for deletion", "not removed yet: happens only in the UPDATE state after QUIT (RSET undoes it)");
                return;
            }
            case "RSET": deleted.clear(); ok("Deletion marks removed", "undo every DELE of this session"); return;
            case "NOOP": ok("", "keep-alive"); return;
            default: err("Unknown command");
        }
    }

    private void quit() throws IOException {
        if (state == State.TRANSACTION) {
            MailStore.Folder inbox = ctx.store.folder(user, "INBOX");
            for (int n : deleted) {
                MailStore.Message m = drop.get(n - 1);
                java.util.Set<String> f = new java.util.TreeSet<>(m.flags);
                f.add("\\Deleted");
                ctx.store.setFlags(user, inbox, m, f);
            }
            int removed = ctx.store.expunge(user, inbox).size();
            ok("Bye: " + removed + " message(s) deleted", "UPDATE state: DELE-marked messages removed from the server, lock released");
            if (removed > 0) Hub.I.event("POP3", user + "'s POP3 session removed " + removed + " message(s) from the server");
        } else ok("Bye", "");
    }

    @Override
    protected void cleanup() {
        if (user != null) ctx.store.unlockPop(user);          // connection dropped without QUIT: no UPDATE, deletions discarded
    }

    private void capa() throws IOException {
        ok("Capability list follows", "");
        for (String c : new String[]{"USER", "UIDL", "TOP", "RESP-CODES", "PIPELINING", (!secure && ctx.tls != null) ? "STLS" : null, "IMPLEMENTATION JU-Mail"})
            if (c != null) send(c, "");
        send(".", "end of capability list");
    }

    // ------------------------------------------------------------------ helpers

    private boolean valid(int n) throws IOException {
        if (n < 1 || n > drop.size()) { err("No such message"); return false; }
        if (deleted.contains(n)) { err("Message " + n + " already deleted"); return false; }
        return true;
    }

    private int live() { return drop.size() - deleted.size(); }

    private long octets() {
        long s = 0;
        for (int i = 1; i <= drop.size(); i++) if (!deleted.contains(i)) s += drop.get(i - 1).size();
        return s;
    }

    private String uidl(int n) { return ctx.store.folder(user, "INBOX").uidValidity + "." + drop.get(n - 1).uid; }

    private static int num(String s) { try { return Integer.parseInt(s.trim()); } catch (Exception e) { return -1; } }

    /** Byte-stuff: a line starting with "." gets an extra "."; optionally only headers + k body lines. */
    private static byte[] stuff(byte[] raw, int bodyLines) {
        String s = new String(raw, StandardCharsets.UTF_8).replace("\r\n", "\n");
        if (s.endsWith("\n")) s = s.substring(0, s.length() - 1);
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        boolean inBody = false;
        int body = 0;
        for (String l : s.split("\n", -1)) {
            if (inBody && body++ >= bodyLines) break;
            if (!inBody && l.isEmpty()) inBody = true;
            if (l.startsWith(".")) l = "." + l;
            byte[] b = (l + "\r\n").getBytes(StandardCharsets.UTF_8);
            o.write(b, 0, b.length);
        }
        return o.toByteArray();                               // always ends with CRLF, so "." lands on its own line
    }

    private void ok(String text, String note) throws IOException { send("+OK" + (text.isEmpty() ? "" : " " + text), note); }
    private void err(String text) throws IOException { send("-ERR " + text, "error"); }

    private static String clientNote(String verb, String arg) {
        switch (verb) {
            case "USER": return "username";
            case "PASS": return "password in PLAIN TEXT (unless STLS was used)";
            case "STAT": return "how many messages, how big?";
            case "LIST": return "size of each message";
            case "UIDL": return "permanent unique id of each message";
            case "RETR": return "download message " + arg;
            case "TOP": return "headers + first lines only";
            case "DELE": return "mark message " + arg + " for deletion";
            case "RSET": return "unmark all deletions";
            case "QUIT": return "end session → UPDATE state";
            case "STLS": return "upgrade to TLS";
            case "CAPA": return "list server capabilities";
            default: return "";
        }
    }
}

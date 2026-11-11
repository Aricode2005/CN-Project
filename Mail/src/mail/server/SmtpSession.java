package mail.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;
import mail.core.Hub;
import mail.mime.Mime;

/**
 * SMTP server session (RFC 5321) — the MTA that receives mail.
 *
 *   220 greeting → EHLO → [STARTTLS → EHLO] → [AUTH] → MAIL FROM → RCPT TO (×n) → DATA → "." → QUIT
 *
 * Local recipients (@domain) are delivered to their INBOX. Mail for other domains is relayed
 * only for authenticated users (otherwise "554 Relay access denied" — no open relay); without a
 * configured smart host the relay attempt produces a bounce (DSN) to the sender, as real MTAs do.
 */
public final class SmtpSession extends Session {

    private static final int MAX_SIZE = 10 * 1024 * 1024;
    /** Optional outbound relay ("smart host"), e.g. a real provider; set by Main. */
    public static volatile Consumer<String[]> relay;   // {from, to, rawMessage}

    private String helo;
    private String authUser;
    private String from;
    private final List<String> local = new ArrayList<>();
    private final List<String> remote = new ArrayList<>();

    public SmtpSession(Context ctx, Socket s, boolean implicitTls) throws IOException { super(ctx, s, "SMTP", implicitTls); }

    @Override
    protected void session() throws IOException {
        reply("220 mail." + ctx.store.domain + " ESMTP JU-Mail ready");
        String line;
        while ((line = readLine()) != null) {
            String up = line.toUpperCase(Locale.ROOT);
            String verb = up.split(" ", 2)[0];
            String arg = line.length() > verb.length() ? line.substring(verb.length()).trim() : "";
            logClient(line, clientNote(verb));
            switch (verb) {
                case "EHLO": ehlo(arg); break;
                case "HELO": helo = arg; resetTxn(); reply("250 mail." + ctx.store.domain); break;
                case "STARTTLS": starttls(); break;
                case "AUTH": auth(arg); break;
                case "MAIL": mail(arg); break;
                case "RCPT": rcpt(arg); break;
                case "DATA": data(); break;
                case "RSET": resetTxn(); reply("250 2.0.0 OK"); break;
                case "NOOP": reply("250 2.0.0 OK"); break;
                case "VRFY": reply("252 2.1.5 Cannot VRFY user, but will accept message and attempt delivery"); break;
                case "HELP": reply("214 2.0.0 Commands: EHLO HELO STARTTLS AUTH MAIL RCPT DATA RSET NOOP VRFY QUIT"); break;
                case "QUIT": reply("221 2.0.0 mail." + ctx.store.domain + " closing connection"); return;
                default: reply("500 5.5.2 Syntax error, command unrecognized");
            }
        }
    }

    private void ehlo(String arg) throws IOException {
        if (arg.isEmpty()) { reply("501 5.5.4 EHLO needs a domain"); return; }
        helo = arg;
        resetTxn();
        List<String> ext = new ArrayList<>();
        ext.add("mail." + ctx.store.domain + " Hello " + arg + " [" + sock.getInetAddress().getHostAddress() + "]");
        ext.add("SIZE " + MAX_SIZE);
        ext.add("8BITMIME");
        ext.add("PIPELINING");
        if (!secure && ctx.tls != null) ext.add("STARTTLS");
        ext.add("AUTH PLAIN LOGIN");
        ext.add("ENHANCEDSTATUSCODES");
        ext.add("HELP");
        for (int i = 0; i < ext.size(); i++) reply("250" + (i < ext.size() - 1 ? "-" : " ") + ext.get(i));
    }

    private void starttls() throws IOException {
        if (secure || ctx.tls == null) { reply("503 5.5.1 TLS already active or not available"); return; }
        reply("220 2.0.0 Ready to start TLS");
        upgradeTls();
        helo = null; authUser = null; resetTxn();          // RFC 3207: forget everything learnt before TLS
    }

    private void auth(String arg) throws IOException {
        if (helo == null) { reply("503 5.5.1 EHLO first"); return; }
        if (authUser != null) { reply("503 5.5.1 Already authenticated"); return; }
        String[] p = arg.split(" ", 2);
        String mech = p[0].toUpperCase(Locale.ROOT);
        String user, pass;
        if (mech.equals("PLAIN")) {
            String resp = p.length > 1 ? p[1] : null;
            if (resp == null) { reply("334 "); resp = readSecret(); }
            String dec = b64(resp);
            String[] parts = dec.split("\u0000", -1);
            if (parts.length < 3) { reply("501 5.5.2 Bad AUTH PLAIN data"); return; }
            user = parts[1]; pass = parts[2];
        } else if (mech.equals("LOGIN")) {
            reply("334 VXNlcm5hbWU6");                       // base64("Username:")
            user = b64(readSecret());
            reply("334 UGFzc3dvcmQ6");                       // base64("Password:")
            pass = b64(readSecret());
        } else { reply("504 5.5.4 Unrecognized authentication type"); return; }
        if (user.contains("@")) user = user.substring(0, user.indexOf('@'));
        if (ctx.store.authenticate(user, pass)) { authUser = user; reply("235 2.7.0 Authentication successful"); }
        else reply("535 5.7.8 Authentication credentials invalid");
    }

    /** Read an AUTH continuation line and explain what base64 hides (nothing). */
    private String readSecret() throws IOException {
        String l = readLine();
        if (l == null) throw new IOException("eof");
        String dec = b64(l).replace("\u0000", "\\0");
        logClient(l, "base64 → \"" + dec + "\"  " + (secure ? "(inside TLS: encrypted on the wire)" : "(NOT encrypted: base64 is only an encoding — use STARTTLS)"));
        return l;
    }

    private static String b64(String s) {
        try { return new String(Base64.getDecoder().decode(s.trim()), StandardCharsets.UTF_8); }
        catch (IllegalArgumentException e) { return ""; }
    }

    private void mail(String arg) throws IOException {
        if (helo == null) { reply("503 5.5.1 Send EHLO/HELO first"); return; }
        if (from != null) { reply("503 5.5.1 Nested MAIL command"); return; }
        if (!arg.toUpperCase(Locale.ROOT).startsWith("FROM:")) { reply("501 5.5.4 Syntax: MAIL FROM:<address>"); return; }
        String rest = arg.substring(5).trim();
        String addr = angle(rest);
        int sz = rest.toUpperCase(Locale.ROOT).indexOf("SIZE=");
        if (sz >= 0) {
            try { if (Long.parseLong(rest.substring(sz + 5).split(" ")[0]) > MAX_SIZE) { reply("552 5.3.4 Message size exceeds fixed limit"); return; } }
            catch (NumberFormatException ignored) { }
        }
        from = addr;
        reply("250 2.1.0 Sender <" + addr + "> OK");
    }

    private void rcpt(String arg) throws IOException {
        if (from == null) { reply("503 5.5.1 Need MAIL before RCPT"); return; }
        if (!arg.toUpperCase(Locale.ROOT).startsWith("TO:")) { reply("501 5.5.4 Syntax: RCPT TO:<address>"); return; }
        String addr = angle(arg.substring(3).trim());
        int at = addr.indexOf('@');
        String user = at > 0 ? addr.substring(0, at) : addr;
        String dom = at > 0 ? addr.substring(at + 1) : ctx.store.domain;
        if (dom.equalsIgnoreCase(ctx.store.domain)) {
            if (!ctx.store.userExists(user)) { reply("550 5.1.1 <" + addr + ">: Recipient address rejected: User unknown"); return; }
            local.add(user.toLowerCase(Locale.ROOT));
            reply("250 2.1.5 Recipient <" + addr + "> OK");
        } else if (authUser != null) {
            remote.add(addr);
            reply("250 2.1.5 Recipient <" + addr + "> OK (will relay)");
        } else {
            reply("554 5.7.1 <" + addr + ">: Relay access denied");
        }
    }

    private void data() throws IOException {
        if (from == null) { reply("503 5.5.1 Need MAIL command"); return; }
        if (local.isEmpty() && remote.isEmpty()) { reply("554 5.5.1 No valid recipients"); return; }
        reply("354 End data with <CR><LF>.<CR><LF>");
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        int lines = 0;
        String l;
        while ((l = readLine()) != null) {
            if (l.equals(".")) break;
            if (l.startsWith("..")) l = l.substring(1);          // undo dot-stuffing
            if (body.size() < MAX_SIZE) body.write((l + "\r\n").getBytes(StandardCharsets.UTF_8));
            lines++;
        }
        logClient("(" + lines + " lines of message data)", "headers + blank line + body; dot-stuffed lines un-stuffed");
        logClient(".", "a line with only \".\" ends the message");
        if (body.size() >= MAX_SIZE) { reply("552 5.3.4 Message too big"); resetTxn(); return; }

        String qid = Long.toHexString(System.nanoTime()).toUpperCase(Locale.ROOT);
        String received = "Return-Path: <" + from + ">\r\n"
                + "Received: from " + helo + " (" + peer + ") by mail." + ctx.store.domain + " (JU-Mail) with "
                + (authUser != null ? "E" : "") + "SMTP" + (secure ? "S" : "") + (authUser != null ? "A" : "")
                + " id " + qid + "; " + Mime.rfc822Date(new Date()) + "\r\n";
        byte[] msg = (received + body.toString("UTF-8")).getBytes(StandardCharsets.UTF_8);
        String subject = Mime.parse(msg).header("Subject");
        for (String u : local) {
            ctx.store.append(u, "INBOX", msg, null);
            Hub.I.event("DELIVER", from + " → " + u + "@" + ctx.store.domain + "  \"" + Mime.decodeWords(subject) + "\" (" + msg.length + " B, id " + qid + ")");
        }
        for (String r : remote) relayOrBounce(r, msg, subject);
        reply("250 2.0.0 OK: queued as " + qid);
        resetTxn();
    }

    private void relayOrBounce(String rcpt, byte[] msg, String subject) {
        Consumer<String[]> r = relay;
        if (r != null) {
            try { r.accept(new String[]{from, rcpt, new String(msg, StandardCharsets.UTF_8)}); Hub.I.event("RELAY", from + " → " + rcpt + " via smart host"); return; }
            catch (RuntimeException e) { Hub.I.log("[SMTP] relay failed: " + e.getMessage()); }
        }
        // no relay configured: generate a delivery status notification for the (local) sender
        String sender = from.contains("@") ? from.substring(0, from.indexOf('@')) : from;
        if (ctx.store.userExists(sender)) {
            String dsn = Mime.build("Mail Delivery Subsystem <MAILER-DAEMON@" + ctx.store.domain + ">", from,
                    "Undelivered Mail Returned to Sender",
                    "This is the mail system at mail." + ctx.store.domain + ".\n\nYour message \"" + Mime.decodeWords(subject) + "\" to <" + rcpt + "> could not be delivered:\n"
                    + "this lab server has no route to external domains (no smart host configured).\n"
                    + "A real MTA would look up the MX record of the domain in DNS and connect to it on port 25.",
                    null, null, "mail." + ctx.store.domain);
            ctx.store.append(sender, "INBOX", dsn.getBytes(StandardCharsets.UTF_8), null);
            Hub.I.event("BOUNCE", "to " + rcpt + " (no smart host) → DSN to " + from);
        }
    }

    private void resetTxn() { from = null; local.clear(); remote.clear(); }

    private static String angle(String s) {
        int a = s.indexOf('<'), b = s.indexOf('>');
        return (a >= 0 && b > a ? s.substring(a + 1, b) : s.split(" ")[0]).trim();
    }

    private void reply(String line) throws IOException { send(line, replyNote(line)); }

    // ------------------------------------------------------------------ explanations for the transcript

    static String replyNote(String l) {
        if (l.length() < 3) return "";
        switch (l.substring(0, 3)) {
            case "220": return l.contains("TLS") ? "go ahead with the TLS handshake" : "service ready (greeting)";
            case "221": return "closing the connection";
            case "235": return "authentication succeeded";
            case "250": return l.charAt(3) == '-' ? "multi-line reply: one ESMTP extension per line" : "requested action OK";
            case "252": return "can't verify the user, but will try to deliver";
            case "334": return "server challenge (base64), waiting for the client";
            case "354": return "start mail input; end with a line containing only \".\"";
            case "214": return "help message";
            case "500": case "501": case "502": case "503": case "504": return "5xx permanent error: bad command or sequence";
            case "535": return "authentication failed";
            case "550": return "mailbox unavailable: no such user";
            case "552": return "message too large";
            case "554": return "transaction failed (here: we are not an open relay)";
            default: return "";
        }
    }

    static String clientNote(String verb) {
        switch (verb) {
            case "EHLO": return "extended hello: identify and ask for the server's extensions";
            case "HELO": return "basic hello (RFC 821)";
            case "STARTTLS": return "upgrade this TCP connection to TLS";
            case "AUTH": return "authenticate (credentials are base64 — encoding, not encryption)";
            case "MAIL": return "envelope sender (where bounces go)";
            case "RCPT": return "envelope recipient (decides delivery, not the To: header)";
            case "DATA": return "the message (headers + body) follows";
            case "RSET": return "abort the current transaction";
            case "QUIT": return "end the session";
            default: return "";
        }
    }
}

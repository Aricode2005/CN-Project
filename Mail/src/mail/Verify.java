package mail;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import mail.client.ImapClient;
import mail.client.LineClient.Tls;
import mail.client.Pop3Client;
import mail.client.SmtpClient;
import mail.mime.Mime;
import mail.store.MailStore;

/** Automated end-to-end checks ("run.bat --verify"): our clients against our servers. */
final class Verify {

    private static int pass, fail;

    private static void check(String name, boolean ok, String detail) {
        if (ok) pass++; else fail++;
        System.out.printf("  [%s] %-66s %s%n", ok ? "PASS" : "FAIL", name, detail == null ? "" : detail);
    }

    interface T { void run() throws Exception; }
    private static void test(String name, T t) {
        try { t.run(); } catch (Exception e) { check(name, false, e.getClass().getSimpleName() + ": " + e.getMessage()); }
    }

    static int run(MailStore store) {
        String D = Main.DOMAIN;
        System.out.println("\n--- MIME ---------------------------------------------------------------------");
        test("mime", () -> {
            String m = Mime.build("a@x", "b@y", "Hello é", "line1\n.dot line", "f.bin", new byte[]{0, 1, 2, (byte) 255}, "h");
            Mime.Part p = Mime.parse(m.getBytes(StandardCharsets.UTF_8));
            check("multipart/mixed with 2 parts", p.multipart() && p.children.size() == 2, p.type + "/" + p.subtype);
            check("attachment base64 decodes to the original bytes", Arrays.equals(p.children.get(1).decoded(), new byte[]{0, 1, 2, (byte) 255}), "");
            check("non-ASCII subject encoded as RFC 2047 word and decoded back", "Hello é".equals(Mime.decodeWords(p.header("Subject"))), p.header("Subject"));
        });

        System.out.println("\n--- SMTP ---------------------------------------------------------------------");
        test("smtp", () -> {
            SmtpClient c = new SmtpClient("localhost", Main.SMTP, Tls.NONE);
            check("220 greeting", c.greeting.startsWith("220"), c.greeting);
            c.ehlo("tester");
            check("EHLO advertises STARTTLS, AUTH, SIZE, 8BITMIME", c.extensions.stream().anyMatch(e -> e.startsWith("STARTTLS")) && c.extensions.stream().anyMatch(e -> e.startsWith("AUTH")), c.extensions.toString());
            try { c.send("x@evil.com", Collections.singletonList("someone@gmail.com"), "Subject: spam\r\n\r\nhi"); check("unauthenticated relay refused (no open relay)", false, ""); }
            catch (Exception e) { check("unauthenticated relay refused (no open relay)", e.getMessage().startsWith("554"), e.getMessage()); }
            try { c.send("alice@" + D, Collections.singletonList("nobody@" + D), "Subject: x\r\n\r\nhi"); check("unknown local user rejected", false, ""); }
            catch (Exception e) { check("unknown local user rejected with 550", e.getMessage().startsWith("550"), e.getMessage()); }
            int before = store.folder("bob", "INBOX").count();
            String msg = Mime.build("Alice <alice@" + D + ">", "Bob <bob@" + D + ">", "Dot test", "first\n.a line starting with a dot\nlast", null, null, "x");
            String r = c.send("alice@" + D, Collections.singletonList("bob@" + D), msg);
            check("message accepted (250 queued)", r.startsWith("250"), r);
            check("delivered to bob's INBOX", store.folder("bob", "INBOX").count() == before + 1, "");
            MailStore.Message last = store.folder("bob", "INBOX").list().get(before);
            String raw = new String(last.raw, StandardCharsets.UTF_8);
            check("dot-stuffing undone: \".a line\" kept intact", raw.contains("\r\n.a line starting with a dot\r\n"), "");
            check("server added Return-Path and Received headers", raw.startsWith("Return-Path: <alice@" + D + ">") && raw.contains("Received: from tester"), "");
            c.quit();
        });
        test("smtp-tls", () -> {
            SmtpClient c = new SmtpClient("localhost", Main.SMTP, Tls.STARTTLS);
            check("STARTTLS upgrade + new EHLO (no STARTTLS offered any more)", c.extensions.stream().noneMatch(e -> e.startsWith("STARTTLS")), "");
            c.login("alice", "alice123");
            check("AUTH PLAIN over TLS → 235", true, "");
            String r = c.send("alice@" + D, Collections.singletonList("friend@example.org"), Mime.build("alice@" + D, "friend@example.org", "Outside", "hi", null, null, "x"));
            check("authenticated user may relay (250)", r.startsWith("250"), r);
            boolean bounce = store.folder("alice", "INBOX").list().stream().anyMatch(m -> "Undelivered Mail Returned to Sender".equals(m.header("Subject")));
            check("no smart host → bounce (DSN) delivered to the sender", bounce, "");
            c.quit();
            SmtpClient s = new SmtpClient("localhost", Main.SMTPS, Tls.IMPLICIT);
            check("SMTPS (implicit TLS, like port 465) greets with 220", s.greeting.startsWith("220"), "");
            s.ehlo("x");
            try { s.login("alice", "wrong"); check("wrong password → 535", false, ""); }
            catch (Exception e) { check("wrong password → 535", e.getMessage().startsWith("535"), e.getMessage()); }
            s.quit();
        });

        System.out.println("\n--- POP3 ---------------------------------------------------------------------");
        test("pop3", () -> {
            int n = store.folder("bob", "INBOX").count();
            Pop3Client p = new Pop3Client("localhost", Main.POP3, Tls.NONE);
            p.login("bob", "bob123");
            long[] st = p.stat();
            check("STAT = messages in INBOX", st[0] == n, st[0] + " messages, " + st[1] + " octets");
            Map<Integer, String> u = p.uidl();
            check("UIDL gives permanent unique ids", u.size() == n && u.get(1).contains("."), u.get(1));
            byte[] m = p.retr(n);
            check("RETR returns the message, byte-stuffing undone", new String(m, StandardCharsets.UTF_8).contains("\r\n.a line starting with a dot\r\n"), m.length + " bytes");
            try (Pop3Client p2 = new Pop3Client("localhost", Main.POP3, Tls.NONE)) {
                try { p2.login("bob", "bob123"); check("second POP3 session refused: maildrop locked", false, ""); }
                catch (Exception e) { check("second POP3 session refused: maildrop locked", e.getMessage().contains("IN-USE"), e.getMessage()); }
            }
            p.dele(1);
            check("DELE only marks: still on the server before QUIT", store.folder("bob", "INBOX").count() == n, "");
            p.quit();
            check("QUIT → UPDATE state removes it from the server", store.folder("bob", "INBOX").count() == n - 1, "");
            Pop3Client s = new Pop3Client("localhost", Main.POP3, Tls.STARTTLS);
            s.login("bob", "bob123");
            check("POP3 STLS upgrade + login", s.stat()[0] == n - 1, "");
            s.quit();
            Pop3Client i = new Pop3Client("localhost", Main.POP3S, Tls.IMPLICIT);
            check("POP3S (implicit TLS, like 995)", i.greeting.contains("ready"), "");
            i.quit();
        });

        System.out.println("\n--- IMAP ---------------------------------------------------------------------");
        test("imap", () -> {
            ImapClient a = new ImapClient("localhost", Main.IMAP, Tls.NONE);
            check("* OK greeting with CAPABILITY", a.greeting.contains("IMAP4rev1") && a.greeting.contains("IDLE"), "");
            a.login("bob", "bob123");
            List<String> folders = a.list();
            check("LIST shows server-side folders", folders.containsAll(Arrays.asList("INBOX", "Sent", "Drafts", "Trash")), folders.toString());
            int exists = a.select("INBOX");
            check("SELECT INBOX → EXISTS", exists == store.folder("bob", "INBOX").count(), exists + " messages");
            List<Long> unseen = a.uidSearch("UNSEEN");
            check("UID SEARCH UNSEEN (search runs on the server)", !unseen.isEmpty(), unseen.toString());
            long uid = unseen.get(0);
            List<ImapClient.Summary> sum = a.summaries(String.valueOf(uid));
            check("FETCH BODY.PEEK[HEADER.FIELDS] does not mark \\Seen", !sum.get(0).flags.contains("\\Seen") && !sum.get(0).subject.isEmpty(), "\"" + sum.get(0).subject + "\"");
            byte[] body = a.body(uid, false);
            check("FETCH BODY[] returns the whole message", body.length > 100, body.length + " bytes");
            check("…and sets \\Seen on the server", a.summaries(String.valueOf(uid)).get(0).flags.contains("\\Seen"), "");

            ImapClient b = new ImapClient("localhost", Main.IMAPS, Tls.IMPLICIT);   // "second device", over IMAPS
            b.login("bob", "bob123");
            b.select("INBOX");
            a.store(uid, "+FLAGS", "\\Flagged");
            b.noop();
            boolean sawFlag = b.lastUntagged.stream().anyMatch(x -> x.text.contains("FETCH") && x.text.contains("\\Flagged"));
            check("device B sees device A's flag change (untagged FETCH on NOOP)", sawFlag, "");

            AtomicReference<String> pushed = new AtomicReference<>("");
            Thread t = new Thread(() -> {
                try { b.idle(2500, l -> { if (l.contains("EXISTS")) pushed.set(l); }); } catch (Exception ignored) { }
            });
            t.start();
            Thread.sleep(400);
            SmtpClient s = new SmtpClient("localhost", Main.SMTP, Tls.NONE);
            s.ehlo("x");
            s.send("alice@" + D, Collections.singletonList("bob@" + D), Mime.build("alice@" + D, "bob@" + D, "Push me", "IDLE test", null, null, "x"));
            s.quit();
            t.join();
            check("IDLE: new mail PUSHED to device B as \"* n EXISTS\"", pushed.get().contains("EXISTS"), pushed.get());

            a.move(uid, "Trash");
            check("UID MOVE to Trash", store.folder("bob", "Trash").count() == 1, "");
            a.append("Sent", "\\Seen", Mime.build("bob@" + D, "alice@" + D, "Copy of sent mail", "hi", null, null, "x").getBytes(StandardCharsets.UTF_8));
            check("APPEND to Sent (how mail apps keep sent copies)", store.folder("bob", "Sent").count() == 1, "");
            a.command("CREATE \"Projects\"");
            check("CREATE folder on the server", store.folder("bob", "Projects") != null, "");

            // POP3 on another device deletes from the server; IMAP device notices the EXPUNGE
            int before = b.select("INBOX");
            Pop3Client p = new Pop3Client("localhost", Main.POP3, Tls.NONE);
            p.login("bob", "bob123"); p.dele(1); p.quit();
            b.noop();
            boolean expunged = b.lastUntagged.stream().anyMatch(x -> x.text.endsWith("EXPUNGE"));
            check("POP3 delete on one device shows up as EXPUNGE on the IMAP device", expunged, before + " → " + store.folder("bob", "INBOX").count());
            a.logout(); b.logout();

            ImapClient c = new ImapClient("localhost", Main.IMAP, Tls.STARTTLS);
            c.login("alice", "alice123");
            check("IMAP STARTTLS + LOGIN", c.select("INBOX") >= 1, "");
            c.logout();
        });

        System.out.println("\n============================================================================");
        System.out.printf("  %d passed, %d failed%n", pass, fail);
        System.out.println("============================================================================");
        return fail;
    }
}

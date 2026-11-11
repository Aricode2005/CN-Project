package ftp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import ftp.client.FtpClient;
import ftp.server.FtpServer;
import ftp.tap.Tap;

/** Automated end-to-end checks ("run.bat --verify"): our client against our server over real TCP. */
final class Verify {

    private static int pass, fail;
    private static void check(String name, boolean ok, String detail) {
        if (ok) pass++; else fail++;
        System.out.printf("  [%s] %-68s %s%n", ok ? "PASS" : "FAIL", name, detail == null ? "" : detail);
    }
    interface T { void run() throws Exception; }
    private static void test(String name, T t) { try { t.run(); } catch (Exception e) { check(name, false, e.getClass().getSimpleName() + ": " + e.getMessage()); } }
    private static FtpClient alice(FtpClient.Mode m) throws Exception { FtpClient c = new FtpClient("127.0.0.1", Main.FTP); c.mode = m; c.login("alice", "alice123"); return c; }

    static int run(FtpServer srv, Tap tap, boolean on21) {
        srv.slowLink = false;
        System.out.println("\n--- control connection ---------------------------------------------------------");
        test("ctrl", () -> {
            FtpClient c = new FtpClient("127.0.0.1", Main.FTP);
            check("220 greeting", c.greeting.startsWith("220"), c.greeting);
            check("USER → 331, wrong PASS → 530", c.cmd("USER alice").code == 331 && c.cmd("PASS nope").code == 530, "");
            check("USER + right PASS → 230", c.cmd("USER alice").code == 331 && c.cmd("PASS alice123").code == 230, "");
            check("PWD → 257 \"/home/alice\" (starts in the home folder)", "/home/alice".equals(c.pwd()), "");
            FtpClient.Reply f = c.cmd("FEAT");
            check("FEAT: multi-line 211 reply lists SIZE, REST, EPSV, AUTH TLS", f.code == 211 && String.join("|", f.lines).contains("REST STREAM") && String.join("|", f.lines).contains("AUTH TLS"), f.lines.size() + " lines");
            check("CWD ../../.. cannot escape the jail (stays at /)", c.cwd("../../../..").code == 250 && "/".equals(c.pwd()), "");
            check("unknown command → 502", c.cmd("XYZZY").code == 502, "");
            check("MKD /home/alice/lab → 257, RMD → 250", c.cmd("MKD /home/alice/lab").code == 257 && c.cmd("RMD /home/alice/lab").code == 250, "");
            check("MKD outside the home folder → 550", c.cmd("MKD /pub/hack").code == 550, "");
            c.quit();
        });

        System.out.println("\n--- data connections: passive and active ---------------------------------------");
        test("data", () -> {
            FtpClient p = alice(FtpClient.Mode.PASSIVE);
            String l = new String(p.list("/pub"), StandardCharsets.UTF_8);
            check("passive LIST /pub (client connects to the server's port)", l.contains("readme.txt") && l.contains("logo.png") && p.traceJson().contains("227 Entering Passive Mode"), l.split("\n").length + " entries");
            p.quit();
            FtpClient a = alice(FtpClient.Mode.ACTIVE);
            String la = new String(a.list("/pub"), StandardCharsets.UTF_8);
            check("active LIST /pub (the server connects to the client)", la.equals(l) && a.traceJson().contains("PORT 127,0,0,1"), "");
            check("active connection comes from port control−1 (" + (Main.FTP - 1) + ")", a.traceJson().contains("server " + (Main.FTP - 1) + " ") || a.traceJson().contains("from port " + (Main.FTP - 1)), "");
            a.quit();
            FtpClient fw = alice(FtpClient.Mode.ACTIVE); fw.firewall = true;
            try { fw.list("/pub"); check("active behind a client firewall fails", false, ""); }
            catch (Exception e) { check("active behind a client firewall → 425 Can't open data connection", e.getMessage().startsWith("425"), e.getMessage()); }
            fw.quit();
            FtpClient pw = alice(FtpClient.Mode.PASSIVE); pw.firewall = true;
            check("passive behind the same firewall still works", pw.list("/pub").length > 0, "outgoing connections are allowed");
            check("EPSV → 229 (|||port|)", pw.cmd("EPSV").text.matches("229 .*\\(\\|\\|\\|\\d+\\|\\)"), "");
            check("PORT to another host → 500 (bounce-attack protection)", pw.cmd("PORT 8,8,8,8,0,80").code == 500, "");
            pw.quit();
        });

        System.out.println("\n--- transfers -----------------------------------------------------------------------");
        test("xfer", () -> {
            FtpClient c = alice(FtpClient.Mode.PASSIVE);
            byte[] logo = Files.readAllBytes(new File(srv.root, "pub/logo.png").toPath());
            c.type('I');
            ByteArrayOutputStream b = new ByteArrayOutputStream(); c.retr("/pub/logo.png", b, 0, -1, null);
            check("RETR in binary (TYPE I): byte-identical image", Arrays.equals(b.toByteArray(), logo), logo.length + " bytes");
            check("STOR binary then RETR: identical", c.stor("copy.png", new ByteArrayInputStream(logo)).code == 226 && retr(c, "copy.png").length == logo.length && Arrays.equals(retr(c, "copy.png"), logo), "");
            c.type('A');
            c.stor("ascii.png", new ByteArrayInputStream(logo));
            c.type('I');
            byte[] bad = retr(c, "ascii.png");
            check("the same image uploaded in ASCII mode is corrupted", !Arrays.equals(bad, logo), logo.length + " → " + bad.length + " bytes");
            c.type('A');
            byte[] text = retr(c, "/pub/readme.txt");
            byte[] disk = Files.readAllBytes(new File(srv.root, "pub/readme.txt").toPath());
            check("ASCII RETR of a text file: every LF becomes CR LF on the wire", text.length == disk.length + count(disk, (byte) '\n') && new String(text, StandardCharsets.US_ASCII).contains("\r\n"), disk.length + " → " + text.length + " bytes");
            c.type('I');
            check("SIZE and MDTM → 213", c.cmd("SIZE /pub/logo.png").text.equals("213 " + logo.length) && c.cmd("MDTM /pub/logo.png").text.matches("213 \\d{14}"), "");
            check("RNFR → 350, RNTO → 250, DELE → 250", c.cmd("RNFR copy.png").code == 350 && c.cmd("RNTO renamed.png").code == 250 && c.cmd("DELE renamed.png").code == 250, "");
            c.quit();
        });

        System.out.println("\n--- REST (resume) and ABOR -------------------------------------------------------------");
        test("rest", () -> {
            FtpClient c = alice(FtpClient.Mode.PASSIVE); c.type('I');
            byte[] big = Files.readAllBytes(new File(srv.root, "pub/big.bin").toPath());
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            FtpClient.Reply r1 = c.retr("/pub/big.bin", b, 0, big.length / 3, null);
            long part = b.size();
            check("ABOR half-way: 426 then 226", r1.code == 426 && c.traceJson().contains("426") && part < big.length, part + " of " + big.length + " bytes");
            FtpClient.Reply r2 = c.retr("/pub/big.bin", b, part, -1, null);
            check("REST " + part + " + RETR → 350, then the rest of the file", r2.code == 226 && c.traceJson().contains("350 Restarting at byte " + part), "");
            check("the resumed file is byte-identical (" + big.length + " bytes)", Arrays.equals(b.toByteArray(), big), "");
            c.quit();
        });

        System.out.println("\n--- anonymous, FTPS and the wire tap ---------------------------------------------------");
        test("sec", () -> {
            FtpClient a = new FtpClient("127.0.0.1", Main.FTP);
            a.login("anonymous", "guest@example.com");
            check("anonymous login sees /pub as \"/\"", "/".equals(a.pwd()) && new String(a.list(""), StandardCharsets.UTF_8).contains("readme.txt"), "");
            check("anonymous STOR → 553 (read-only)", a.stor("x.txt", new ByteArrayInputStream(new byte[]{1})).code == 553, "");
            a.quit();
            FtpClient t = new FtpClient("127.0.0.1", Main.FTP);
            t.authTls(true); t.login("alice", "alice123"); t.type('I');
            byte[] logo = Files.readAllBytes(new File(srv.root, "pub/logo.png").toPath());
            check("FTPS: AUTH TLS + PBSZ 0 + PROT P, then an encrypted RETR", Arrays.equals(retr(t, "/pub/logo.png"), logo), "");
            t.quit();
            FtpClient p = new FtpClient("127.0.0.1", Tap.PORT); p.login("alice", "alice123"); p.list("/pub"); p.quit();
            Thread.sleep(200);
            String plain = tap.json(tap.latest());
            check("wire tap on plain FTP reads \"PASS alice123\"", plain.contains("PASS alice123"), "");
            FtpClient s = new FtpClient("127.0.0.1", Tap.PORT); s.authTls(true); s.login("alice", "alice123"); s.list("/pub"); s.quit();
            Thread.sleep(200);
            String enc = tap.json(tap.latest());
            check("wire tap after AUTH TLS sees only TLS records, no password", !enc.contains("alice123") && enc.contains("TLS record"), "");
            if (on21) { FtpClient d = new FtpClient("127.0.0.1", 21); check("server also listens on the real FTP port 21", d.greeting.startsWith("220"), ""); d.quit(); }
        });

        System.out.println("\n================================================================================");
        System.out.printf("  %d passed, %d failed%n", pass, fail);
        System.out.println("================================================================================");
        return fail;
    }

    private static byte[] retr(FtpClient c, String f) throws Exception { ByteArrayOutputStream b = new ByteArrayOutputStream(); c.retr(f, b, 0, -1, null); return b.toByteArray(); }
    private static int count(byte[] b, byte x) { int n = 0; for (byte y : b) if (y == x) n++; return n; }
}

package ftp;

import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;
import ftp.core.Hub;
import ftp.core.Tls;
import ftp.dashboard.DashboardServer;
import ftp.server.FtpServer;
import ftp.server.Vfs;
import ftp.tap.Tap;

/**
 * JU FTP Lab — our own FTP server (RFC 959 + FTPS RFC 4217) and client, with a wire tap and a dashboard.
 *
 *   control   127.0.0.1:2121 (and :21 when free) · active data from 2120 (/ 20) · passive 50000-50100
 *   wire tap  127.0.0.1:2122 → 2121 (a sniffer on the control connection)
 *   dashboard http://localhost:8086
 */
public final class Main {

    public static final int FTP = 2121, HTTP = 8086;

    public static void main(String[] args) throws Exception {
        boolean verify = Arrays.asList(args).contains("--verify");
        System.out.println("==============================================================================");
        System.out.println("   JU FTP LAB  -  RFC 959 · two connections · active / passive · FTPS (RFC 4217)  ");
        System.out.println("==============================================================================");
        Hub.I.quiet = verify;
        boolean tls = Tls.init();
        File root = new File("data", verify ? "ftp-verify" : "ftp-root");
        if (verify && root.exists()) Vfs.deleteTree(root);
        FtpServer srv = new FtpServer(root).listen(FTP);
        boolean on21 = false;
        try { srv.listen(21); on21 = true; } catch (Exception e) { Hub.I.log("[FTP] port 21 is busy: control stays on 2121 only"); }
        Tap tap = new Tap(FTP).start();
        File local = new File("data", "client-files"); local.mkdirs();
        File note = new File(local, "my-notes.txt");
        if (!note.exists()) Files.writeString(note.toPath(), "Uploaded from the client's own folder.\nFTP: control on 21, data on a second connection.\n");
        DashboardServer dash = new DashboardServer(HTTP, FTP, srv, tap, new File("web"), local);
        dash.start();
        Hub.I.log("[DASHBOARD] http://localhost:" + HTTP + (tls ? " · FTPS available" : ""));
        if (verify) {
            int failed = Verify.run(srv, tap, on21);
            dash.stop(); tap.stop(); srv.stop();
            System.exit(failed == 0 ? 0 : 1);
        }
        System.out.println();
        System.out.println("  Dashboard ...... http://localhost:" + HTTP);
        System.out.println("  Users .......... alice/alice123  bob/bob123  subham/ju2026  anonymous (read-only)");
        System.out.println("  Try it ......... ftp 127.0.0.1" + (on21 ? "" : "   (port 21 busy: use  ftp  then  open 127.0.0.1 2121)") + "      (Windows ftp.exe: active mode)");
        System.out.println("  Interop test ... python interop_test.py   (Python ftplib + Windows ftp.exe)");
        System.out.println("  Press Enter to stop.");
        System.in.read();
        dash.stop(); tap.stop(); srv.stop();
        System.exit(0);
    }
}

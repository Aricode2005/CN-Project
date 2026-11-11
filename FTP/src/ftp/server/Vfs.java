package ftp.server;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

/**
 * The server's file system as a user sees it: a virtual "/" mapped onto a folder on disk (a chroot jail),
 * so "CWD ../../.." can never leave it. Named users see /pub and their own /home/<user> (writable);
 * anonymous users see only the public folder, read-only.
 */
public final class Vfs {

    public final File root; public final String user; public final boolean anonymous;

    public Vfs(File base, String user) {
        this.user = user; this.anonymous = user.equals("anonymous") || user.equals("ftp");
        this.root = anonymous ? new File(base, "pub") : base;
    }

    public String home() { return anonymous ? "/" : "/home/" + user; }

    /** Normalise a client path against the current directory; ".." can never climb above "/". */
    public static String resolve(String cwd, String arg) {
        String p = arg == null || arg.isEmpty() ? cwd : arg.startsWith("/") ? arg : (cwd.endsWith("/") ? cwd : cwd + "/") + arg;
        List<String> parts = new ArrayList<>();
        for (String s : p.split("/")) {
            if (s.isEmpty() || s.equals(".")) continue;
            if (s.equals("..")) { if (!parts.isEmpty()) parts.remove(parts.size() - 1); continue; }
            parts.add(s);
        }
        return "/" + String.join("/", parts);
    }

    public File file(String vpath) throws IOException {
        File f = new File(root, vpath.substring(1));
        Path r = root.getCanonicalFile().toPath(), c = f.getCanonicalFile().toPath();
        if (!c.startsWith(r)) throw new IOException("outside the jail");
        return f;
    }

    public boolean canWrite(String vpath) {
        if (anonymous) return false;
        String h = "/home/" + user;
        return vpath.equals(h) || vpath.startsWith(h + "/");
    }

    private static final SimpleDateFormat LS = new SimpleDateFormat("MMM dd HH:mm", Locale.US), MDTM = new SimpleDateFormat("yyyyMMddHHmmss");
    static { MDTM.setTimeZone(TimeZone.getTimeZone("UTC")); }

    /** One line of a Unix "ls -l" listing, the format almost every FTP server returns for LIST. */
    public String lsLine(File f, String vpath) {
        String owner = vpath.startsWith("/home/") && vpath.split("/").length > 2 ? vpath.split("/")[2] : "root";
        String perm = f.isDirectory() ? "drwxr-xr-x" : canWrite(vpath) ? "-rw-r--r--" : "-r--r--r--";
        synchronized (LS) { return String.format("%s 1 %-8s %-8s %10d %s %s", perm, owner, "ftp", f.isDirectory() ? 0 : f.length(), LS.format(new Date(f.lastModified())), f.getName()); }
    }
    public static String mdtm(File f) { synchronized (MDTM) { return MDTM.format(new Date(f.lastModified())); } }

    public static File[] children(File dir) {
        File[] l = dir.listFiles(); if (l == null) return new File[0];
        Arrays.sort(l, Comparator.comparing((File x) -> !x.isDirectory()).thenComparing(File::getName));
        return l;
    }

    public static void deleteTree(File f) throws IOException {
        if (f.isDirectory()) for (File c : children(f)) deleteTree(c);
        Files.deleteIfExists(f.toPath());
    }
}

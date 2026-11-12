package ftp.server;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * What FTP's replies and commands mean (RFC 959 §4.2). A reply code is three digits:
 *   1st: 1 preliminary (wait, more is coming) · 2 done · 3 send more · 4 failed, try again · 5 failed, don't
 *   2nd: 0 syntax · 1 information · 2 connections · 3 login · 5 file system
 */
public final class Codes {
    private Codes() { }

    private static final String[] FIRST = {"", "1 = preliminary: started, wait for another reply", "2 = completed", "3 = intermediate: send the next command",
            "4 = transient failure: try again later", "5 = permanent failure: don't repeat it"};
    private static final String[] SECOND = {"0 = syntax", "1 = information", "2 = connections", "3 = authentication", "4 = unspecified", "5 = file system"};

    private static final Map<String, String> CMD = new HashMap<>();
    static {
        String[][] c = {{"USER", "user name"}, {"PASS", "password, in plaintext unless AUTH TLS came first"}, {"ACCT", "account"}, {"CWD", "change working directory"},
                {"CDUP", "go to the parent directory"}, {"PWD", "print working directory"}, {"LIST", "detailed listing (sent on a DATA connection)"},
                {"NLST", "names only (on a DATA connection)"}, {"RETR", "retrieve = download a file (on a DATA connection)"}, {"STOR", "store = upload a file (on a DATA connection)"},
                {"APPE", "append to a file"}, {"DELE", "delete a file"}, {"MKD", "make a directory"}, {"RMD", "remove a directory"}, {"RNFR", "rename from…"}, {"RNTO", "…rename to"},
                {"TYPE", "A = ASCII (convert line endings), I = image/binary"}, {"MODE", "transfer mode: S = stream"}, {"STRU", "file structure: F = file"},
                {"PORT", "active mode: \"connect to ME at h1,h2,h3,h4,p1,p2\""}, {"PASV", "passive mode: \"open a port and I will connect to YOU\""},
                {"EPRT", "extended PORT (IPv6-ready)"}, {"EPSV", "extended PASV (IPv6-ready)"}, {"REST", "restart: the next RETR/STOR starts at this byte offset"},
                {"SIZE", "file size in bytes"}, {"MDTM", "file modification time"}, {"ABOR", "abort the transfer in progress"}, {"NOOP", "do nothing (keep-alive)"},
                {"SYST", "server operating system type"}, {"FEAT", "list extensions"}, {"STAT", "status"}, {"HELP", "list commands"}, {"QUIT", "log out and close"},
                {"AUTH", "AUTH TLS: switch the control connection to TLS (FTPS)"}, {"PBSZ", "protection buffer size (0 for TLS)"}, {"PROT", "data protection: P = encrypted, C = clear"}};
        for (String[] x : c) CMD.put(x[0], x[1]);
    }
    public static String command(String c) { return CMD.getOrDefault(c, ""); }

    public static String meaning(String line) {
        if (line.length() < 3 || !Character.isDigit(line.charAt(0)) || !Character.isDigit(line.charAt(1)) || !Character.isDigit(line.charAt(2))) return "";
        int a = line.charAt(0) - '0', b = line.charAt(1) - '0';
        String sep = line.length() > 3 && line.charAt(3) == '-' ? " · multi-line reply continues" : "";
        return (a >= 1 && a <= 5 ? FIRST[a] : "?") + " · " + (b <= 5 ? SECOND[b] : "?") + sep;
    }

    /** ASCII mode on the wire: every LF becomes CRLF (RFC 959 NVT-ASCII). */
    public static byte[] toCrlf(byte[] d) {
        ByteArrayOutputStream b = new ByteArrayOutputStream(d.length + d.length / 16);
        int prev = -1;
        for (byte x : d) { int c = x & 0xFF; if (c == '\n' && prev != '\r') b.write('\r'); b.write(c); prev = c; }
        return b.toByteArray();
    }
}

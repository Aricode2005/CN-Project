package telnet.protocol;

import java.util.HashMap;
import java.util.Map;

/**
 * Telnet constants from RFC 854 (commands) and the option RFCs, plus helpers that turn
 * raw bytes into readable names ("IAC DO NAWS") for logs, the CLI and the dashboard.
 */
public final class Telnet {

    private Telnet() { }

    // ---- RFC 854 commands (all introduced by IAC = 255) ----
    public static final int EOF = 236;   // end of file (RFC 1184)
    public static final int SUSP = 237;  // suspend process
    public static final int ABORT = 238; // abort process
    public static final int EOR = 239;   // end of record (RFC 885)
    public static final int SE = 240;    // end of subnegotiation
    public static final int NOP = 241;   // no operation
    public static final int DM = 242;    // data mark (Synch)
    public static final int BRK = 243;   // break
    public static final int IP = 244;    // interrupt process
    public static final int AO = 245;    // abort output
    public static final int AYT = 246;   // are you there
    public static final int EC = 247;    // erase character
    public static final int EL = 248;    // erase line
    public static final int GA = 249;    // go ahead
    public static final int SB = 250;    // start subnegotiation
    public static final int WILL = 251;
    public static final int WONT = 252;
    public static final int DO = 253;
    public static final int DONT = 254;
    public static final int IAC = 255;   // "interpret as command"

    // ---- options ----
    public static final int OPT_BINARY = 0;        // RFC 856
    public static final int OPT_ECHO = 1;          // RFC 857
    public static final int OPT_SGA = 3;           // RFC 858 suppress go-ahead
    public static final int OPT_STATUS = 5;        // RFC 859
    public static final int OPT_TIMING_MARK = 6;   // RFC 860
    public static final int OPT_TTYPE = 24;        // RFC 1091 terminal type
    public static final int OPT_NAWS = 31;         // RFC 1073 window size
    public static final int OPT_TSPEED = 32;       // RFC 1079
    public static final int OPT_LFLOW = 33;        // RFC 1372
    public static final int OPT_LINEMODE = 34;     // RFC 1184
    public static final int OPT_XDISPLOC = 35;     // RFC 1096
    public static final int OPT_ENVIRON = 36;      // RFC 1408
    public static final int OPT_NEW_ENVIRON = 39;  // RFC 1572

    // TTYPE subnegotiation codes (RFC 1091)
    public static final int TTYPE_IS = 0;
    public static final int TTYPE_SEND = 1;
    // STATUS / TSPEED subnegotiation codes (RFC 859, RFC 1079)
    public static final int SB_IS = 0;
    public static final int SB_SEND = 1;

    private static final Map<Integer, String> CMD = new HashMap<>();
    private static final Map<Integer, String> OPT = new HashMap<>();
    private static final Map<Integer, String> RFC = new HashMap<>();

    static {
        CMD.put(EOF, "EOF"); CMD.put(SUSP, "SUSP"); CMD.put(ABORT, "ABORT"); CMD.put(EOR, "EOR"); CMD.put(SE, "SE"); CMD.put(NOP, "NOP"); CMD.put(DM, "DM"); CMD.put(BRK, "BRK"); CMD.put(IP, "IP");
        CMD.put(AO, "AO"); CMD.put(AYT, "AYT"); CMD.put(EC, "EC"); CMD.put(EL, "EL"); CMD.put(GA, "GA");
        CMD.put(SB, "SB"); CMD.put(WILL, "WILL"); CMD.put(WONT, "WONT"); CMD.put(DO, "DO"); CMD.put(DONT, "DONT");
        CMD.put(IAC, "IAC");

        opt(OPT_BINARY, "BINARY", "RFC 856");
        opt(OPT_ECHO, "ECHO", "RFC 857");
        opt(OPT_SGA, "SUPPRESS-GO-AHEAD", "RFC 858");
        opt(OPT_STATUS, "STATUS", "RFC 859");
        opt(OPT_TIMING_MARK, "TIMING-MARK", "RFC 860");
        opt(OPT_TTYPE, "TERMINAL-TYPE", "RFC 1091");
        opt(OPT_NAWS, "NAWS", "RFC 1073");
        opt(OPT_TSPEED, "TERMINAL-SPEED", "RFC 1079");
        opt(OPT_LFLOW, "LFLOW", "RFC 1372");
        opt(OPT_LINEMODE, "LINEMODE", "RFC 1184");
        opt(OPT_XDISPLOC, "X-DISPLAY-LOCATION", "RFC 1096");
        opt(OPT_ENVIRON, "ENVIRON", "RFC 1408");
        opt(OPT_NEW_ENVIRON, "NEW-ENVIRON", "RFC 1572");
    }

    private static void opt(int code, String name, String rfc) {
        OPT.put(code, name);
        RFC.put(code, rfc);
    }

    public static String cmdName(int c) {
        String n = CMD.get(c);
        return n != null ? n : String.valueOf(c);
    }

    public static String optName(int o) {
        String n = OPT.get(o);
        return n != null ? n : "OPTION-" + o;
    }

    public static String optRfc(int o) {
        String r = RFC.get(o);
        return r != null ? r : "-";
    }

    /** {IAC, verb, option} */
    public static byte[] negotiation(int verb, int option) {
        return new byte[]{(byte) IAC, (byte) verb, (byte) option};
    }

    /** IAC SB option payload IAC SE, doubling any 255 inside the payload. */
    public static byte[] subnegotiation(int option, byte[] payload) {
        java.io.ByteArrayOutputStream b = new java.io.ByteArrayOutputStream();
        b.write(IAC); b.write(SB); b.write(option);
        for (byte x : payload) {
            b.write(x & 0xFF);
            if ((x & 0xFF) == IAC) b.write(IAC);
        }
        b.write(IAC); b.write(SE);
        return b.toByteArray();
    }

    public static String hex(byte[] b, int off, int len) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < len; i++) {
            if (i > 0) s.append(' ');
            s.append(String.format("%02X", b[off + i] & 0xFF));
        }
        return s.toString();
    }

    public static String hex(byte[] b) {
        return hex(b, 0, b.length);
    }

    /** "IAC DO NAWS" */
    public static String describeNegotiation(int verb, int option) {
        return "IAC " + cmdName(verb) + " " + optName(option);
    }
}

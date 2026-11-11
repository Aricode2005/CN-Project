package telnet.server;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import telnet.core.Hub;
import telnet.core.Json;
import telnet.protocol.OptionNegotiator;
import telnet.protocol.Telnet;
import telnet.protocol.TelnetCodec;

/**
 * One VTY line: an RFC 854 Network Virtual Terminal session.
 *
 * Layers inside one session:
 *   socket bytes -> TelnetCodec (IAC state machine) -> OptionNegotiator (RFC 1143)
 *                -> line editor (server-side echo, backspace, history, ?, Tab)
 *                -> login / enable / EXEC / config modes -> CommandShell
 *
 * The server negotiates "WILL ECHO" + "WILL SUPPRESS-GO-AHEAD": character-at-a-time mode,
 * where the client sends every keystroke and the server echoes it. That is what lets the
 * server hide the password (it simply doesn't echo) and offer Tab completion and '?' help.
 */
public final class TelnetSession implements Runnable {

    static final TelnetSession PLACEHOLDER = new TelnetSession();

    public enum Mode { NEGOTIATING, LOGIN_USER, LOGIN_PASS, ENABLE_PASS, EXEC, CONFIG, TOP, SHADOW, CLOSED }

    final VtyPool pool;
    final Socket sock;
    public final int line, id;
    public final String transport, from;
    public final long startedAt = System.currentTimeMillis();
    private final InputStream in;
    private final OutputStream out;
    private final TelnetCodec codec;
    public final OptionNegotiator neg;
    private final CommandShell shell;

    public volatile Mode mode = Mode.NEGOTIATING;
    public volatile String user = "";
    public volatile int priv;
    public volatile long lastInput = System.currentTimeMillis();
    public volatile long bytesIn, bytesOut;
    public volatile int cols = 80, rows = 24;
    public volatile String tspeed = "";
    public final List<String> ttypes = new CopyOnWriteArrayList<>();
    private volatile boolean ttypeDone;

    // line editor
    private final StringBuilder buf = new StringBuilder();
    final List<String> history = new ArrayList<>();
    private int histPos;
    private int esc;              // 0 none, 1 got ESC, 2 got ESC [
    private boolean lastCR;
    private int loginAttempts, enableAttempts;
    private String pendingUser = "";

    // features
    private final Deque<Long> tmSent = new ArrayDeque<>();
    public final Deque<Double> rtts = new ArrayDeque<>();
    private volatile int tmpingLeft;
    private final List<Double> tmpingResults = new ArrayList<>();
    final List<TelnetSession> shadows = new CopyOnWriteArrayList<>();
    volatile TelnetSession watching;
    private volatile Consumer<Hub.NegEvent> debugListener;
    private ScheduledFuture<?> topTask;
    private final StringBuilder recording = new StringBuilder("[");
    private int recEvents;

    private TelnetSession() {
        pool = null; sock = null; line = -1; id = -1; transport = ""; from = ""; in = null; out = null; codec = null; neg = null; shell = null;
    }

    TelnetSession(VtyPool pool, Socket sock, int line, int id, String transport) throws IOException {
        this.pool = pool;
        this.sock = sock;
        this.line = line;
        this.id = id;
        this.transport = transport;
        this.from = sock.getInetAddress().getHostAddress() + ":" + sock.getPort();
        this.in = sock.getInputStream();
        this.out = sock.getOutputStream();
        this.shell = new CommandShell(this);
        sock.setTcpNoDelay(true);   // send each keystroke echo immediately (no Nagle delay)

        this.neg = new OptionNegotiator((verb, opt, meaning) -> {
            byte[] b = Telnet.negotiation(verb, opt);
            rawWrite(b);
            Hub.I.neg(new Hub.NegEvent(id, "S>C", Telnet.describeNegotiation(verb, opt), Telnet.hex(b), "", "", meaning));
        }, new OptionNegotiator.Policy() {
            public boolean acceptLocal(int o) { return o == Telnet.OPT_ECHO || o == Telnet.OPT_SGA || o == Telnet.OPT_STATUS; }
            public boolean acceptRemote(int o) { return o == Telnet.OPT_TTYPE || o == Telnet.OPT_NAWS || o == Telnet.OPT_SGA || o == Telnet.OPT_TSPEED; }
        });
        this.neg.setObserver(new OptionNegotiator.Observer() {
            public void onStep(boolean received, int verb, int opt, boolean usSide, OptionNegotiator.Q before, OptionNegotiator.Q after, String meaning, String note) {
                String st = (usSide ? "us " : "him ") + Telnet.optName(opt) + ": " + before + (before == after ? " (unchanged)" : " -> " + after);
                if (received) Hub.I.neg(new Hub.NegEvent(id, "C>S", Telnet.describeNegotiation(verb, opt), Telnet.hex(Telnet.negotiation(verb, opt)), st, note, meaning));
                else Hub.I.neg(new Hub.NegEvent(id, "--", "request " + Telnet.cmdName(verb) + " " + Telnet.optName(opt), "", st, note, meaning));
            }
            public void onChange(boolean usSide, int opt, boolean enabled) {
                Hub.I.log("[VTY" + line + "] " + (usSide ? "server" : "client") + " " + Telnet.optName(opt) + " " + (enabled ? "ENABLED" : "disabled"));
                if (!usSide && opt == Telnet.OPT_TTYPE && enabled) askTerminalType();
                if (!usSide && opt == Telnet.OPT_TSPEED && enabled) {
                    byte[] b = Telnet.subnegotiation(Telnet.OPT_TSPEED, new byte[]{Telnet.SB_SEND});
                    rawWrite(b);
                    Hub.I.neg(new Hub.NegEvent(id, "S>C", "SB TERMINAL-SPEED SEND", Telnet.hex(b), "", "RFC 1079: what is your line speed?"));
                }
            }
        });
        this.codec = new TelnetCodec(new TelnetCodec.Listener() {
            public void onData(int b) { handleByte(b); }
            public void onCommand(int c) { handleCommand(c); }
            public void onNegotiation(int verb, int opt) { handleNegotiation(verb, opt); }
            public void onSubnegotiation(int opt, byte[] p) { handleSub(opt, p); }
        });
    }

    // ================================================================== main loop

    @Override
    public void run() {
        Hub.I.log("[VTY" + line + "] connection from " + from + " over " + transport);
        try {
            sock.setSoTimeout(250);
            // RFC 854: either side may start negotiating at once. We ask for character mode + terminal info.
            neg.requestLocal(Telnet.OPT_ECHO, true);
            neg.requestLocal(Telnet.OPT_SGA, true);
            neg.requestRemote(Telnet.OPT_SGA, true);
            neg.requestRemote(Telnet.OPT_TTYPE, true);
            neg.requestRemote(Telnet.OPT_NAWS, true);
            neg.requestRemote(Telnet.OPT_TSPEED, true);
            neg.requestLocal(Telnet.OPT_STATUS, true);
            long until = System.currentTimeMillis() + 700;     // let the answers arrive before the banner
            byte[] b = new byte[4096];
            while (System.currentTimeMillis() < until) {
                try { int n = in.read(b); if (n < 0) { close("peer closed"); return; } bytesIn += n; codec.feed(b, 0, n); }
                catch (SocketTimeoutException ignored) { }
            }
            print("\n" + pool.cfg.banner + "\n\n");
            startLogin();
            while (mode != Mode.CLOSED) {
                try {
                    int n = in.read(b);
                    if (n < 0) break;
                    bytesIn += n;
                    codec.feed(b, 0, n);
                } catch (SocketTimeoutException e) {
                    idleCheck();
                }
            }
        } catch (IOException e) {
            // connection reset
        } finally {
            close("disconnected");
        }
    }

    private void idleCheck() {
        if (mode == Mode.CLOSED || mode == Mode.TOP || mode == Mode.SHADOW) return;
        long idle = System.currentTimeMillis() - lastInput;
        if (idle > pool.cfg.execTimeoutMin * 60_000L) {
            print("\n% Session timed out: idle for " + pool.cfg.execTimeoutMin + " min (exec-timeout)\n");
            close("exec-timeout");
        }
    }

    public synchronized void close(String why) {
        if (mode == Mode.CLOSED) return;
        stopTop();
        if (watching != null) watching.shadows.remove(this);
        for (TelnetSession w : shadows) w.endShadow("% Shadowed line " + line + " closed.");
        if (debugListener != null) Hub.I.offNeg(debugListener);
        mode = Mode.CLOSED;
        try { sock.close(); } catch (IOException ignored) { }
        pool.release(this);
        if (recEvents > 0) Hub.I.recordings.add(new Hub.Recording(id, user.isEmpty() ? "(not logged in)" : user, from, startedAt, recording.toString() + "]"));
        Hub.I.log("[VTY" + line + "] session " + id + " closed (" + why + ")");
    }

    // ================================================================== output

    synchronized void rawWrite(byte[] b) {
        if (mode == Mode.CLOSED && sock != null && sock.isClosed()) return;
        try { out.write(b); out.flush(); bytesOut += b.length; } catch (IOException e) { /* closed */ }
    }

    /** Write text as NVT: "\n" becomes CR LF, 0xFF is escaped. Also recorded and mirrored to shadows. */
    public void print(String s) {
        String t = s.replace("\r\n", "\n").replace("\n", "\r\n");
        rawWrite(TelnetCodec.encodeData(t.getBytes(StandardCharsets.ISO_8859_1)));
        record(t);
        for (TelnetSession w : shadows) w.rawWrite(TelnetCodec.encodeData(t.getBytes(StandardCharsets.ISO_8859_1)));
    }

    private synchronized void record(String t) {
        if (recEvents > 6000) return;
        if (recEvents > 0) recording.append(',');
        recording.append('[').append(System.currentTimeMillis() - startedAt).append(',').append(Json.str(t)).append(']');
        recEvents++;
    }

    public synchronized String recordingJson() { return recording.toString() + "]"; }

    String prompt() {
        if (mode == Mode.CONFIG) return pool.cfg.hostname + "(config)#";
        return pool.cfg.hostname + (priv >= 15 ? "#" : ">");
    }

    void showPrompt() { print(prompt() + buf); }

    /** Print an asynchronous message (debug, broadcast) without destroying what the user is typing. */
    void notifyAsync(String msg) {
        if (mode == Mode.CLOSED || mode == Mode.TOP || mode == Mode.SHADOW) return;
        print("\n" + msg + (msg.endsWith("\n") ? "" : "\n"));
        if (mode == Mode.EXEC || mode == Mode.CONFIG) showPrompt();
    }

    private boolean echoOn() { return neg.isLocal(Telnet.OPT_ECHO); }

    // ================================================================== Telnet commands & options

    private void handleCommand(int c) {
        Hub.I.neg(new Hub.NegEvent(id, "C>S", "IAC " + Telnet.cmdName(c), Telnet.hex(new byte[]{(byte) 255, (byte) c}), "",
                c == Telnet.AYT ? "Are You There? -> visible reply" : c == Telnet.IP ? "Interrupt Process (like Ctrl-C)"
                : c == Telnet.EC ? "Erase Character: delete the last typed character" : c == Telnet.EL ? "Erase Line: delete the whole line"
                : c == Telnet.EOF ? "End Of File" : c == Telnet.EOR ? "End Of Record" : c == Telnet.NOP ? "No operation (keep-alive)" : c == Telnet.AO ? "Abort Output" : ""));
        switch (c) {
            case Telnet.AYT: print("\n[" + pool.cfg.hostname + ": yes]\n"); if (mode == Mode.EXEC || mode == Mode.CONFIG) showPrompt(); break;
            case Telnet.IP: case Telnet.BRK: handleByte(3); break;
            case Telnet.EC: handleByte(8); break;
            case Telnet.EL: handleByte(21); break;
            default: break;
        }
    }

    private void handleNegotiation(int verb, int opt) {
        if (opt == Telnet.OPT_TIMING_MARK) { timingMark(verb); return; }
        neg.receive(verb, opt);
    }

    private void handleSub(int opt, byte[] p) {
        String desc;
        if (opt == Telnet.OPT_NAWS && p.length >= 4) {
            cols = ((p[0] & 0xFF) << 8) | (p[1] & 0xFF);
            rows = ((p[2] & 0xFF) << 8) | (p[3] & 0xFF);
            desc = "SB NAWS " + cols + " x " + rows;
            if (mode == Mode.TOP) renderTop();
        } else if (opt == Telnet.OPT_TTYPE && p.length >= 1 && p[0] == Telnet.TTYPE_IS) {
            String name = new String(p, 1, p.length - 1, StandardCharsets.US_ASCII).toUpperCase();
            desc = "SB TERMINAL-TYPE IS \"" + name + "\"";
            boolean repeat = !ttypes.isEmpty() && ttypes.get(ttypes.size() - 1).equals(name);
            if (repeat || ttypes.contains(name) || ttypes.size() >= 6) ttypeDone = true;
            else { ttypes.add(name); askTerminalType(); }   // RFC 1091: keep asking until the list repeats
        } else if (opt == Telnet.OPT_TSPEED && p.length >= 1 && p[0] == Telnet.SB_IS) {
            tspeed = new String(p, 1, p.length - 1, StandardCharsets.US_ASCII);
            desc = "SB TERMINAL-SPEED IS \"" + tspeed + "\"";
        } else if (opt == Telnet.OPT_STATUS && p.length >= 1 && p[0] == Telnet.SB_SEND && neg.isLocal(Telnet.OPT_STATUS)) {
            desc = "SB STATUS SEND";
            sendStatus();
        } else {
            desc = "SB " + Telnet.optName(opt) + " (" + p.length + " bytes, ignored)";
        }
        byte[] wire = Telnet.subnegotiation(opt, p);
        Hub.I.neg(new Hub.NegEvent(id, "C>S", desc, Telnet.hex(wire), "", opt == Telnet.OPT_TTYPE && ttypeDone ? "list complete: " + ttypes : ""));
    }

    /** RFC 859: reply with every option currently enabled, as WILL x (our side) and DO x (the client's side). */
    private void sendStatus() {
        java.io.ByteArrayOutputStream b = new java.io.ByteArrayOutputStream();
        b.write(Telnet.SB_IS);
        StringBuilder d = new StringBuilder("SB STATUS IS");
        for (int o = 0; o < 256; o++) {
            if (neg.isLocal(o)) { b.write(Telnet.WILL); b.write(o); d.append(" WILL ").append(Telnet.optName(o)); }
            if (neg.isRemote(o)) { b.write(Telnet.DO); b.write(o); d.append(" DO ").append(Telnet.optName(o)); }
        }
        byte[] w = Telnet.subnegotiation(Telnet.OPT_STATUS, b.toByteArray());
        rawWrite(w);
        Hub.I.neg(new Hub.NegEvent(id, "S>C", d.toString(), Telnet.hex(w), "", "RFC 859: the server reports what it believes is enabled"));
    }

    private void askTerminalType() {
        if (ttypeDone) return;
        byte[] b = Telnet.subnegotiation(Telnet.OPT_TTYPE, new byte[]{Telnet.TTYPE_SEND});
        rawWrite(b);
        Hub.I.neg(new Hub.NegEvent(id, "S>C", "SB TERMINAL-TYPE SEND", Telnet.hex(b), "", "RFC 1091: tell me your terminal type"));
    }

    public String terminalType() { return ttypes.isEmpty() ? "UNKNOWN" : ttypes.get(0); }

    public boolean ansi() {
        for (String t : ttypes) if (t.contains("XTERM") || t.contains("ANSI") || t.contains("VT1") || t.contains("VT2") || t.contains("VTNT") || t.contains("LINUX") || t.contains("SCREEN")) return true;
        return false;
    }

    /** RFC 860 TIMING-MARK: "DO TIMING-MARK" makes the peer answer once everything before it is processed. */
    public void measureRtt(boolean visible) {
        if (mode == Mode.CLOSED || mode == Mode.NEGOTIATING) return;
        synchronized (tmSent) { tmSent.addLast(System.nanoTime()); }
        byte[] b = Telnet.negotiation(Telnet.DO, Telnet.OPT_TIMING_MARK);
        rawWrite(b);
        Hub.I.neg(new Hub.NegEvent(id, "S>C", "IAC DO TIMING-MARK", Telnet.hex(b), "", visible ? "tmping probe" : "RTT probe (every 5 s)"));
    }

    private void timingMark(int verb) {
        if (verb == Telnet.DO) {   // the client wants to synchronise with us: we have processed everything before it
            rawWrite(Telnet.negotiation(Telnet.WILL, Telnet.OPT_TIMING_MARK));
            return;
        }
        Long t0;
        synchronized (tmSent) { t0 = tmSent.pollFirst(); }
        if (t0 == null || (verb != Telnet.WILL && verb != Telnet.WONT)) return;
        double ms = (System.nanoTime() - t0) / 1e6;
        synchronized (rtts) { rtts.addLast(ms); if (rtts.size() > 60) rtts.removeFirst(); }
        Hub.I.neg(new Hub.NegEvent(id, "C>S", "IAC " + Telnet.cmdName(verb) + " TIMING-MARK", Telnet.hex(Telnet.negotiation(verb, 6)), "",
                String.format("round trip %.2f ms", ms)));
        if (tmpingLeft > 0) {
            tmpingResults.add(ms);
            print(String.format("Reply from %s via TIMING-MARK: seq=%d time=%.3f ms\n", from, tmpingResults.size(), ms));
            if (--tmpingLeft == 0) {
                double mn = 1e9, mx = 0, sum = 0;
                for (double x : tmpingResults) { mn = Math.min(mn, x); mx = Math.max(mx, x); sum += x; }
                print(String.format("Success rate is 100 percent (%d/%d), round-trip min/avg/max = %.3f/%.3f/%.3f ms\n",
                        tmpingResults.size(), tmpingResults.size(), mn, sum / tmpingResults.size(), mx));
                showPrompt();
            }
        }
    }

    void tmping(int count) {
        tmpingResults.clear();
        tmpingLeft = count;
        print("Type escape sequence to abort.\nSending " + count + " Telnet TIMING-MARK probes (RFC 860) to " + from + ":\n");
        for (int i = 0; i < count; i++) pool.timer.schedule(() -> measureRtt(true), 200L * i + 50, TimeUnit.MILLISECONDS);
        pool.timer.schedule(() -> {
            if (tmpingLeft > 0) { print("% " + tmpingLeft + " probe(s) unanswered: the client does not implement TIMING-MARK\n"); tmpingLeft = 0; showPrompt(); }
        }, 200L * count + 3000, TimeUnit.MILLISECONDS);
    }

    public double lastRtt() { synchronized (rtts) { return rtts.isEmpty() ? -1 : rtts.peekLast(); } }

    // ================================================================== line editor

    private void handleByte(int b) {
        lastInput = System.currentTimeMillis();
        if (mode == Mode.TOP) { if (b == 'q' || b == 'Q' || b == 3) stopTopAndPrompt(); return; }
        if (mode == Mode.SHADOW) { endShadow("% Shadowing stopped."); return; }
        if (mode == Mode.NEGOTIATING || mode == Mode.CLOSED) return;

        if (esc == 1) { esc = (b == '[' || b == 'O') ? 2 : 0; return; }
        if (esc == 2) {
            if (b >= '0' && b <= '9' || b == ';') return;
            esc = 0;
            if (b == 'A') historyMove(-1); else if (b == 'B') historyMove(1);
            return;
        }
        if (b == 27) { esc = 1; return; }

        if (b == '\r') { lastCR = true; submit(); return; }
        if (b == '\n') { if (lastCR) { lastCR = false; return; } submit(); return; }
        if (b == 0) return;          // CR NUL is the NVT carriage return: keep lastCR so a following LF is not a 2nd Enter
        lastCR = false;

        boolean visible = mode == Mode.LOGIN_USER || mode == Mode.EXEC || mode == Mode.CONFIG;
        boolean cli = mode == Mode.EXEC || mode == Mode.CONFIG;
        switch (b) {
            case 8: case 127:
                if (buf.length() > 0) { buf.setLength(buf.length() - 1); if (visible && echoOn()) print("\b \b"); }
                return;
            case 3:
                buf.setLength(0);
                print("^C\n");
                if (mode == Mode.LOGIN_PASS || mode == Mode.LOGIN_USER) startLogin();
                else if (mode == Mode.ENABLE_PASS) { mode = Mode.EXEC; showPrompt(); }
                else showPrompt();
                return;
            case 21:
                if (visible && echoOn()) { StringBuilder e = new StringBuilder(); for (int i = 0; i < buf.length(); i++) e.append("\b \b"); print(e.toString()); }
                buf.setLength(0);
                return;
            case 26:
                if (mode == Mode.CONFIG) { print("^Z\n"); buf.setLength(0); mode = Mode.EXEC; showPrompt(); }
                return;
            case 4:
                if (cli && buf.length() == 0) { print("logout\n"); close("Ctrl-D"); }
                return;
            case 9:
                if (cli) shell.complete(buf);
                return;
            case '?':
                if (cli) { print("?\n"); shell.help(buf.toString()); showPrompt(); return; }
                break;
            default:
                break;
        }
        if (b < 32 || b > 126) return;
        buf.append((char) b);
        if (visible && echoOn()) print(String.valueOf((char) b));
    }

    /** Called by the shell after Tab completion. */
    void replaceBuffer(String s, boolean redraw) {
        if (redraw) { buf.setLength(0); buf.append(s); showPrompt(); return; }
        String add = s.substring(buf.length());
        buf.setLength(0); buf.append(s);
        if (echoOn()) print(add);
    }

    private void historyMove(int d) {
        if (mode != Mode.EXEC && mode != Mode.CONFIG || history.isEmpty()) return;
        histPos = Math.max(0, Math.min(history.size(), histPos + d));
        String s = histPos < history.size() ? history.get(histPos) : "";
        StringBuilder e = new StringBuilder();
        for (int i = 0; i < buf.length(); i++) e.append("\b \b");
        buf.setLength(0); buf.append(s);
        print(e + s);
    }

    private void submit() {
        String lineText = buf.toString();
        buf.setLength(0);
        Mode m = mode;
        if (echoOn() || m == Mode.LOGIN_PASS || m == Mode.ENABLE_PASS) print("\n");
        switch (m) {
            case LOGIN_USER: loginUser(lineText.trim()); break;
            case LOGIN_PASS: loginPass(lineText); break;
            case ENABLE_PASS: enablePass(lineText); break;
            case EXEC: case CONFIG:
                if (!lineText.trim().isEmpty()) {
                    history.add(lineText.trim());
                    if (history.size() > 20) history.remove(0);
                }
                histPos = history.size();
                shell.execute(lineText);
                if ((mode == Mode.EXEC || mode == Mode.CONFIG) && tmpingLeft == 0) showPrompt();   // tmping prints the prompt when it finishes
                break;
            default: break;
        }
    }

    // ================================================================== login / enable

    private void startLogin() {
        if (pool.guard.blocked()) {
            print("% Login refused: the device is in quiet mode (login block-for).\n% Try again in " + pool.guard.quietSecondsLeft() + " seconds.\n");
            close("quiet mode");
            return;
        }
        if (loginAttempts == 0) print("User Access Verification\n\n");
        mode = Mode.LOGIN_USER;
        print("Username: ");
    }

    private void loginUser(String u) {
        if (u.isEmpty()) { print("Username: "); return; }
        pendingUser = u;
        mode = Mode.LOGIN_PASS;
        print("Password: ");    // not echoed: the server owns ECHO and simply doesn't echo here
    }

    private void loginPass(String pw) {
        DeviceConfig.User u = pool.cfg.authenticate(pendingUser, pw);
        if (u != null) {
            user = u.name;
            priv = u.privilege;
            pool.guard.success(user, from);
            mode = Mode.EXEC;
            print("\n% Welcome " + user + " (privilege " + priv + ") on line vty " + line + ", terminal " + terminalType()
                    + " " + cols + "x" + rows + ". Type ? for help, Tab to complete.\n\n");
            Hub.I.log("[VTY" + line + "] login OK: " + user + " from " + from);
            showPrompt();
            return;
        }
        loginAttempts++;
        boolean quiet = pool.guard.failure(pendingUser, from);
        print("% Login invalid\n\n");
        if (quiet) { print("% Too many failures: login is blocked for " + pool.cfg.blockForSec + " seconds.\n"); close("quiet mode"); return; }
        if (loginAttempts >= 3) { print("% Bad passwords\n"); close("3 failed logins"); return; }
        startLogin();
    }

    void startEnable() {
        if (priv >= 15) return;
        mode = Mode.ENABLE_PASS;
        print("Password: ");
    }

    private void enablePass(String pw) {
        if (pool.cfg.checkEnable(pw)) {
            priv = 15; enableAttempts = 0; mode = Mode.EXEC;
            Hub.I.log("[VTY" + line + "] " + user + " entered privileged EXEC (enable)");
        } else if (++enableAttempts >= 3) {
            print("% Bad secrets\n\n"); enableAttempts = 0; mode = Mode.EXEC;
        } else {
            print("% Access denied\n\n"); mode = Mode.EXEC;
        }
        showPrompt();
    }

    // ================================================================== debug telnet / broadcast / shadow

    void setDebug(boolean on) {
        if (on && debugListener == null) {
            debugListener = e -> {
                if (e.session == id && e.text.contains("TIMING-MARK")) return;   // don't spam our own RTT probes
                notifyAsync(String.format("TELNET%d: %s %-26s %s%s", e.session, e.dir, e.text,
                        e.state.isEmpty() ? "" : "[" + e.state + "] ", e.note));
            };
            Hub.I.onNeg(debugListener);
        } else if (!on && debugListener != null) {
            Hub.I.offNeg(debugListener);
            debugListener = null;
        }
    }

    boolean debugging() { return debugListener != null; }

    void startShadow(TelnetSession target) {
        mode = Mode.SHADOW;
        watching = target;
        print("% Shadowing line vty " + target.line + " (" + target.user + " from " + target.from + "). Read-only; press any key to stop.\n");
        print("%--------------------------------------------------------------------------\n");
        String rec = target.recentOutput(1200);
        if (!rec.isEmpty()) print(rec);
        target.shadows.add(this);
    }

    String recentOutput(int maxChars) {
        String r = recordingJson();
        StringBuilder text = new StringBuilder();
        // crude: pull the quoted strings back out of our own JSON
        int i = 0;
        while ((i = r.indexOf(",\"", i)) >= 0) {
            int j = i + 2; StringBuilder s = new StringBuilder();
            while (j < r.length() && r.charAt(j) != '"') {
                char c = r.charAt(j);
                if (c == '\\' && j + 1 < r.length()) {
                    char n = r.charAt(++j);
                    if (n == 'n') s.append('\n'); else if (n == 'r') s.append('\r'); else if (n == 'u') { s.append((char) Integer.parseInt(r.substring(j + 1, j + 5), 16)); j += 4; } else s.append(n);
                } else s.append(c);
                j++;
            }
            text.append(s); i = j;
        }
        String t = text.toString().replace("\r\n", "\n");
        return t.length() > maxChars ? t.substring(t.length() - maxChars) : t;
    }

    void endShadow(String msg) {
        if (mode != Mode.SHADOW) return;
        if (watching != null) watching.shadows.remove(this);
        watching = null;
        mode = Mode.EXEC;
        print("\n" + msg + "\n");
        showPrompt();
    }

    // ================================================================== top (full-screen, NAWS-aware)

    void startTop() {
        if (!ansi()) {
            print("% 'top' needs an ANSI/VT100 terminal, but TERMINAL-TYPE negotiation reported \"" + terminalType()
                    + "\".\n% This is exactly what RFC 1091 is for: the server must know what the screen can do.\n");
            return;
        }
        mode = Mode.TOP;
        print("\u001b[?25l\u001b[2J");
        topTask = pool.timer.scheduleAtFixedRate(this::renderTop, 0, 1, TimeUnit.SECONDS);
    }

    private void stopTop() {
        if (topTask != null) { topTask.cancel(false); topTask = null; }
    }

    private void stopTopAndPrompt() {
        stopTop();
        mode = Mode.EXEC;
        print("\u001b[2J\u001b[H\u001b[?25h");
        showPrompt();
    }

    synchronized void renderTop() {
        if (mode != Mode.TOP) return;
        int w = Math.max(40, cols), h = Math.max(12, rows);
        List<String> L = new ArrayList<>();
        long up = (System.currentTimeMillis() - pool.bootTime) / 1000;
        L.add(inverse(pad(" " + pool.cfg.hostname + " - VTY monitor   up " + up / 3600 + "h" + (up / 60) % 60 + "m" + up % 60 + "s   window " + w + "x" + h
                + " (from NAWS)   q = quit", w)));
        L.add("");
        L.add(String.format("%-5s %-9s %-22s %-8s %-14s %-8s %8s %8s %8s", "LINE", "USER", "FROM", "VIA", "TERMINAL", "SIZE", "IN", "OUT", "RTT ms"));
        long maxB = 1;
        List<TelnetSession> ss = pool.sessions();
        for (TelnetSession s : ss) maxB = Math.max(maxB, s.bytesIn + s.bytesOut);
        for (TelnetSession s : ss) {
            double r = s.lastRtt();
            L.add(String.format("%s%-4d %-9s %-22s %-8s %-14s %-8s %8d %8d %8s", s == this ? "*" : " ", s.line, s.user.isEmpty() ? "-" : s.user,
                    s.from, s.transport, s.terminalType(), s.cols + "x" + s.rows, s.bytesIn, s.bytesOut, r < 0 ? "-" : String.format("%.2f", r)));
        }
        for (int i = ss.size(); i < VtyPool.LINES; i++) L.add(String.format(" %-4d %-9s", i, "(free)"));
        L.add("");
        L.add("Traffic share (bytes in+out):");
        int bar = Math.max(10, w - 22);
        for (TelnetSession s : ss) {
            int n = (int) Math.round(bar * (double) (s.bytesIn + s.bytesOut) / maxB);
            L.add(String.format("  vty%-2d %-10s ", s.line, s.user.isEmpty() ? "-" : s.user) + repeat('#', n));
        }
        L.add("");
        L.add("This session's options:  server ECHO=" + neg.usState(Telnet.OPT_ECHO) + "  SGA=" + neg.usState(Telnet.OPT_SGA)
                + "  client TTYPE=" + neg.himState(Telnet.OPT_TTYPE) + "  NAWS=" + neg.himState(Telnet.OPT_NAWS));
        L.add("Security: " + (pool.guard.quietSecondsLeft() > 0 ? "QUIET MODE " + pool.guard.quietSecondsLeft() + "s" : "normal mode")
                + "   refused (lines busy): " + pool.refusedBusy.get());
        StringBuilder sb = new StringBuilder("\u001b[H");
        for (int i = 0; i < h - 1; i++) {
            String l = i < L.size() ? L.get(i) : "";
            sb.append(l.startsWith("\u001b[") ? l : clip(l, w)).append("\u001b[K");   // never cut an escape sequence in half
            if (i < h - 2) sb.append("\r\n");
        }
        sb.append("\r\n").append(inverse(pad(" Resize the terminal window: the client sends a new NAWS and this screen reflows to fit.", w)));
        rawWrite(TelnetCodec.encodeData(sb.toString().getBytes(StandardCharsets.ISO_8859_1)));
        record(sb.toString());
    }

    private static String inverse(String s) { return "\u001b[7m" + s + "\u001b[0m"; }
    private static String pad(String s, int w) { StringBuilder b = new StringBuilder(s.length() > w ? s.substring(0, w) : s); while (b.length() < w) b.append(' '); return b.toString(); }
    private static String clip(String s, int w) { return s.length() > w ? s.substring(0, w) : s; }
    private static String repeat(char c, int n) { StringBuilder b = new StringBuilder(); for (int i = 0; i < n; i++) b.append(c); return b.toString(); }

    // ================================================================== dashboard JSON

    public String json() {
        double r = lastRtt();
        StringBuilder rt = new StringBuilder("[");
        synchronized (rtts) { boolean f = true; for (double x : rtts) { if (!f) rt.append(','); rt.append(String.format(java.util.Locale.ROOT, "%.3f", x)); f = false; } }
        rt.append(']');
        int[] opts = {Telnet.OPT_BINARY, Telnet.OPT_ECHO, Telnet.OPT_SGA, Telnet.OPT_STATUS, Telnet.OPT_TIMING_MARK, Telnet.OPT_TTYPE, Telnet.OPT_NAWS, Telnet.OPT_TSPEED, Telnet.OPT_LINEMODE};
        List<String> o = new ArrayList<>();
        for (int x : opts) o.add(Json.obj("code", x, "name", Telnet.optName(x), "rfc", Telnet.optRfc(x),
                "us", neg.usState(x).name() + (neg.usQueued(x) ? "+OPP" : ""), "him", neg.himState(x).name() + (neg.himQueued(x) ? "+OPP" : "")));
        List<String> tt = new ArrayList<>();
        for (String t : ttypes) tt.add(Json.str(t));
        return Json.obj("id", id, "line", line, "user", user, "priv", priv, "from", from, "transport", transport, "mode", mode.name(),
                "prompt", mode == Mode.EXEC || mode == Mode.CONFIG ? prompt() : "", "ttype", terminalType(), "ttypes", Json.raw(Json.arr(tt)),
                "cols", cols, "rows", rows, "tspeed", tspeed, "in", bytesIn, "out", bytesOut, "idle", (System.currentTimeMillis() - lastInput) / 1000,
                "age", (System.currentTimeMillis() - startedAt) / 1000, "rtt", r, "rtts", Json.raw(rt.toString()),
                "debug", debugging(), "shadowedBy", shadows.size(), "options", Json.raw(Json.arr(o)));
    }
}

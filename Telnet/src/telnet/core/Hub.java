package telnet.core;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Shared telemetry for the whole system: logs, negotiation events, wire captures,
 * sniffed credentials and finished-session recordings. The dashboard reads everything from here.
 */
public final class Hub {

    public static final Hub I = new Hub();
    private Hub() { }

    public final long startedAt = System.currentTimeMillis();
    private final SimpleDateFormat fmt = new SimpleDateFormat("HH:mm:ss.SSS");

    // ------------------------------------------------------------------ logs
    private final Ring<String> logs = new Ring<>(400);
    private final List<Consumer<String>> logListeners = new CopyOnWriteArrayList<>();
    public volatile boolean quiet;

    public void log(String msg) {
        String line = fmt.format(new Date()) + " " + msg;
        logs.add(line);
        if (!quiet) System.out.println(line);
        for (Consumer<String> l : logListeners) l.accept(line);
    }

    public List<String> logs() { return logs.snapshot(); }

    // ------------------------------------------------------------------ negotiation events
    public static final class NegEvent {
        public long seq;
        public final int session;
        public final long t;
        public final String dir;      // "C>S", "S>C" or "--" (internal request)
        public final String text;     // "IAC DO NAWS"
        public final String hex;      // "FF FD 1F"
        public final String state;    // "him NAWS: WANTYES -> YES"
        public final String note;
        public final String meaning;  // textbook meaning, e.g. "Offering to enable"
        public NegEvent(int session, String dir, String text, String hex, String state, String note) {
            this(session, dir, text, hex, state, note, "");
        }
        public NegEvent(int session, String dir, String text, String hex, String state, String note, String meaning) {
            this.session = session; this.t = System.currentTimeMillis(); this.dir = dir;
            this.text = text; this.hex = hex; this.state = state; this.note = note; this.meaning = meaning;
        }
        public String json() {
            return Json.obj("seq", seq, "session", session, "t", t, "dir", dir, "text", text, "hex", hex, "state", state, "note", note, "meaning", meaning);
        }
    }

    private final Ring<NegEvent> neg = new Ring<>(3000);
    private long negSeq;
    private final List<Consumer<NegEvent>> negListeners = new CopyOnWriteArrayList<>();

    public void neg(NegEvent e) {
        synchronized (neg) { e.seq = ++negSeq; neg.add(e); }
        for (Consumer<NegEvent> l : negListeners) l.accept(e);
    }

    public List<NegEvent> negFor(int session) {
        List<NegEvent> out = new ArrayList<>();
        for (NegEvent e : neg.snapshot()) if (e.session == session) out.add(e);
        return out;
    }

    public void onNeg(Consumer<NegEvent> l) { negListeners.add(l); }
    public void offNeg(Consumer<NegEvent> l) { negListeners.remove(l); }

    // ------------------------------------------------------------------ wire frames (from the tap)
    public static final class WireFrame {
        public long seq;
        public final int conn;
        public final boolean c2s;
        public final long t;
        public final int len;
        public final String tokens;   // JSON array of decoded tokens
        public final boolean tls;
        public WireFrame(int conn, boolean c2s, int len, String tokens, boolean tls) {
            this.conn = conn; this.c2s = c2s; this.t = System.currentTimeMillis(); this.len = len; this.tokens = tokens; this.tls = tls;
        }
        public String json() {
            return Json.obj("seq", seq, "conn", conn, "dir", c2s ? "C>S" : "S>C", "t", t, "len", len, "tls", tls, "tokens", Json.raw(tokens));
        }
    }

    private final Ring<WireFrame> wire = new Ring<>(4000);
    private long wireSeq;

    public void wire(WireFrame f) { synchronized (wire) { f.seq = ++wireSeq; wire.add(f); } }

    public List<WireFrame> wireSince(long seq) {
        List<WireFrame> out = new ArrayList<>();
        for (WireFrame f : wire.snapshot()) if (f.seq > seq) out.add(f);
        return out;
    }

    // ------------------------------------------------------------------ sniffed credentials
    public static final class Capture {
        public final int conn; public final String user; public final String pass; public final long t;
        public Capture(int conn, String user, String pass) { this.conn = conn; this.user = user; this.pass = pass; this.t = System.currentTimeMillis(); }
        public String json() { return Json.obj("conn", conn, "user", user, "pass", pass, "t", t); }
    }
    public final List<Capture> captures = new CopyOnWriteArrayList<>();

    // ------------------------------------------------------------------ recordings of finished sessions
    public static final class Recording {
        public final int id; public final String user; public final String from; public final long start; public final String eventsJson;
        public Recording(int id, String user, String from, long start, String eventsJson) {
            this.id = id; this.user = user; this.from = from; this.start = start; this.eventsJson = eventsJson;
        }
    }
    public final Ring<Recording> recordings = new Ring<>(30);

    // ------------------------------------------------------------------ ring buffer
    public static final class Ring<T> {
        private final Object[] a; private int head, size;
        public Ring(int cap) { a = new Object[cap]; }
        public synchronized void add(T x) { a[(head + size) % a.length] = x; if (size < a.length) size++; else head = (head + 1) % a.length; }
        @SuppressWarnings("unchecked")
        public synchronized List<T> snapshot() {
            List<T> l = new ArrayList<>(size);
            for (int i = 0; i < size; i++) l.add((T) a[(head + i) % a.length]);
            return l;
        }
    }
}

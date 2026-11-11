package ftp.core;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Shared telemetry: server log + every protocol line exchanged on every session
 * (FTP control commands, replies and data-connection events).
 * The dashboard draws its ledger and hierarchy animation from here.
 */
public final class Hub {

    public static final Hub I = new Hub();
    private Hub() { }

    public volatile boolean quiet;
    private final SimpleDateFormat fmt = new SimpleDateFormat("HH:mm:ss.SSS");

    // ------------------------------------------------------------------ log
    private final Ring<String> logs = new Ring<>(500);
    public void log(String m) {
        String l = fmt.format(new Date()) + " " + m;
        logs.add(l);
        if (!quiet) System.out.println(l);
    }
    public List<String> logs() { return logs.snapshot(); }

    // ------------------------------------------------------------------ protocol lines
    public static final class Line {
        public long seq;
        public final String session;   // e.g. "ftp#3" or "client:ftp#2"
        public final String proto;     // FTP-CTRL / FTP-DATA
        public final boolean fromClient;
        public final String text;
        public final String note;      // explanation (what this message means)
        public final long t = System.currentTimeMillis();
        public Line(String session, String proto, boolean fromClient, String text, String note) {
            this.session = session; this.proto = proto; this.fromClient = fromClient; this.text = text; this.note = note;
        }
        public String json() {
            return Json.obj("seq", seq, "session", session, "proto", proto, "dir", fromClient ? "C" : "S", "text", text, "note", note, "t", t);
        }
    }

    private final Ring<Line> lines = new Ring<>(6000);
    private long lineSeq;
    public void line(Line l) { synchronized (lines) { l.seq = ++lineSeq; lines.add(l); } }
    public List<Line> linesSince(long seq) {
        List<Line> out = new ArrayList<>();
        for (Line l : lines.snapshot()) if (l.seq > seq) out.add(l);
        return out;
    }

    // ------------------------------------------------------------------ events (poisoning, cache flushes…)
    public static final class Event {
        public long seq;
        public final String kind, text;
        public final long t = System.currentTimeMillis();
        public Event(String kind, String text) { this.kind = kind; this.text = text; }
        public String json() { return Json.obj("seq", seq, "kind", kind, "text", text, "t", t); }
    }
    private final Ring<Event> events = new Ring<>(500);
    private long evSeq;
    private final List<Consumer<Event>> listeners = new CopyOnWriteArrayList<>();
    public void event(String kind, String text) {
        Event e = new Event(kind, text);
        synchronized (events) { e.seq = ++evSeq; events.add(e); }
        for (Consumer<Event> c : listeners) c.accept(e);
        log("[" + kind + "] " + text);
    }
    public List<Event> eventsSince(long seq) {
        List<Event> out = new ArrayList<>();
        for (Event e : events.snapshot()) if (e.seq > seq) out.add(e);
        return out;
    }

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

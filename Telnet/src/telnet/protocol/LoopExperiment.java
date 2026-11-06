package telnet.protocol;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/**
 * Experiment: two Telnet endpoints wired back to back in memory.
 *
 * Scenario: at the same instant both ends decide to turn ECHO on the server side
 * (the server sends WILL ECHO, the client sends DO ECHO). Then, before the answers arrive,
 * the server changes its mind (WONT ECHO).
 *
 *  - Naive endpoints answer every request, even ones that don't change anything, and do not
 *    remember outstanding requests. Their messages bounce forever (we stop at a cap).
 *  - RFC 1143 Q-method endpoints converge after a handful of messages, and both agree.
 */
public final class LoopExperiment {

    public static final class Msg {
        public final String from;
        public final String text;
        public Msg(String from, String text) { this.from = from; this.text = text; }
    }

    public static final class Result {
        public final String name;
        public final List<Msg> trace = new ArrayList<>();
        public boolean looped;
        public String finalState = "";
        Result(String name) { this.name = name; }
    }

    private static final int CAP = 40;

    /** A deliberately broken endpoint: always acknowledges, never remembers. */
    private static final class Naive {
        final String name;
        boolean usEcho;     // server side owns ECHO
        Naive peer;
        final Deque<int[]> inbox;
        final Result r;
        Naive(String name, Deque<int[]> inbox, Result r) { this.name = name; this.inbox = inbox; this.r = r; }
        void send(int verb) { r.trace.add(new Msg(name, Telnet.describeNegotiation(verb, Telnet.OPT_ECHO))); peer.inbox.add(new int[]{verb}); }
        void receive(int verb) {
            // "Always reply" rule, mirroring what was received
            if (verb == Telnet.DO) { usEcho = true; send(Telnet.WILL); }
            else if (verb == Telnet.DONT) { usEcho = false; send(Telnet.WONT); }
            else if (verb == Telnet.WILL) { send(Telnet.DO); }
            else if (verb == Telnet.WONT) { send(Telnet.DONT); }
        }
    }

    public static Result naive() {
        Result r = new Result("Naive (always acknowledge)");
        Deque<int[]> sIn = new ArrayDeque<>(), cIn = new ArrayDeque<>();
        Naive s = new Naive("Server", sIn, r), c = new Naive("Client", cIn, r);
        s.peer = c; c.peer = s;
        s.send(Telnet.WILL);   // server offers ECHO
        c.send(Telnet.DO);     // client asks for ECHO at the same instant
        s.send(Telnet.WONT);   // server changes its mind
        pump(r, s, c, sIn, cIn);
        r.finalState = "server thinks ECHO=" + (s.usEcho ? "on" : "off") + " | messages=" + r.trace.size();
        return r;
    }

    private static void pump(Result r, Naive s, Naive c, Deque<int[]> sIn, Deque<int[]> cIn) {
        while ((!sIn.isEmpty() || !cIn.isEmpty())) {
            if (r.trace.size() >= CAP) { r.looped = true; return; }
            if (!sIn.isEmpty()) s.receive(sIn.poll()[0]);
            if (!cIn.isEmpty()) c.receive(cIn.poll()[0]);
        }
    }

    public static Result qMethod() {
        final Result r = new Result("RFC 1143 Q-method");
        final Deque<int[]> toServer = new ArrayDeque<>(), toClient = new ArrayDeque<>();
        OptionNegotiator.Policy yes = new OptionNegotiator.Policy() {
            public boolean acceptLocal(int o) { return o == Telnet.OPT_ECHO; }
            public boolean acceptRemote(int o) { return o == Telnet.OPT_ECHO; }
        };
        OptionNegotiator server = new OptionNegotiator((v, o, m) -> {
            r.trace.add(new Msg("Server", Telnet.describeNegotiation(v, o))); toClient.add(new int[]{v, o});
        }, yes);
        OptionNegotiator client = new OptionNegotiator((v, o, m) -> {
            r.trace.add(new Msg("Client", Telnet.describeNegotiation(v, o))); toServer.add(new int[]{v, o});
        }, yes);
        server.requestLocal(Telnet.OPT_ECHO, true);
        client.requestRemote(Telnet.OPT_ECHO, true);
        server.requestLocal(Telnet.OPT_ECHO, false);
        while (!toServer.isEmpty() || !toClient.isEmpty()) {
            if (r.trace.size() >= CAP) { r.looped = true; break; }
            if (!toServer.isEmpty()) { int[] m = toServer.poll(); server.receive(m[0], m[1]); }
            if (!toClient.isEmpty()) { int[] m = toClient.poll(); client.receive(m[0], m[1]); }
        }
        r.finalState = "server us=" + server.usState(Telnet.OPT_ECHO) + ", client him=" + client.himState(Telnet.OPT_ECHO)
                + " | messages=" + r.trace.size()
                + (server.isLocal(Telnet.OPT_ECHO) == client.isRemote(Telnet.OPT_ECHO) ? " | both ends agree" : " | DISAGREE");
        return r;
    }
}

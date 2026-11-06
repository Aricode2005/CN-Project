package telnet.protocol;

/**
 * Telnet option negotiation using the RFC 1143 "Q method".
 *
 * Each option has two independent sides:
 *   us  = is the option enabled on OUR side?     (we say WILL / WONT, peer says DO / DONT)
 *   him = is the option enabled on the PEER side? (we say DO / DONT, peer says WILL / WONT)
 *
 * Each side is in one of four states, plus a one-bit queue:
 *   NO, YES, WANTNO, WANTYES   and   queue = EMPTY | OPPOSITE
 *
 * Every message is also labelled with its meaning from the textbook table
 * ("WILL = 1. offering to enable, 2. accepting a request to enable", ...). The same byte
 * means different things depending on the state it is sent in - the Q-method states are
 * exactly what disambiguates them.
 *
 * Why the Q-method matters: if both ends change their minds at the same time, simple
 * implementations either loop forever (WILL -> DO -> WILL -> DO ...) or end up disagreeing.
 * The WANT* states remember "I asked and haven't been answered yet", so every request gets
 * exactly one answer and the two ends always converge. LoopExperiment shows the failure mode.
 */
public final class OptionNegotiator {

    public enum Q { NO, YES, WANTNO, WANTYES }

    public interface Sender { void send(int verb, int option, String meaning); }

    /** Which options we are willing to enable. */
    public interface Policy {
        boolean acceptLocal(int option);   // peer sent DO: will we enable it on our side?
        boolean acceptRemote(int option);  // peer sent WILL: do we allow it on its side?
    }

    /** Called for every negotiation step, for logs and the dashboard sequence diagram. */
    public interface Observer {
        void onStep(boolean received, int verb, int option, boolean usSide, Q before, Q after, String meaning, String note);
        void onChange(boolean usSide, int option, boolean enabled);
    }

    // textbook meanings (from the point of view of whoever SENDS the message)
    public static final String OFFER_EN = "Offering to enable", ACCEPT_REQ_EN = "Accepting a request to enable";
    public static final String REJECT_REQ_EN = "Rejecting a request to enable", OFFER_DIS = "Offering to disable", ACCEPT_REQ_DIS = "Accepting a request to disable";
    public static final String APPROVE_OFFER_EN = "Approving an offer to enable", REQ_EN = "Requesting to enable";
    public static final String DISAPPROVE_OFFER_EN = "Disapproving an offer to enable", APPROVE_OFFER_DIS = "Approving an offer to disable", REQ_DIS = "Requesting to disable";

    private final Q[] us = new Q[256];
    private final Q[] him = new Q[256];
    private final boolean[] usQueue = new boolean[256];   // true = OPPOSITE
    private final boolean[] himQueue = new boolean[256];
    private final Sender sender;
    private final Policy policy;
    private volatile Observer observer;
    private int messagesSent;

    public OptionNegotiator(Sender sender, Policy policy) {
        this.sender = sender;
        this.policy = policy;
        for (int i = 0; i < 256; i++) { us[i] = Q.NO; him[i] = Q.NO; }
    }

    public void setObserver(Observer o) { this.observer = o; }
    public synchronized Q usState(int opt) { return us[opt]; }
    public synchronized Q himState(int opt) { return him[opt]; }
    public synchronized boolean isLocal(int opt) { return us[opt] == Q.YES; }
    public synchronized boolean isRemote(int opt) { return him[opt] == Q.YES; }
    public synchronized boolean usQueued(int opt) { return usQueue[opt]; }
    public synchronized boolean himQueued(int opt) { return himQueue[opt]; }
    public int messagesSent() { return messagesSent; }

    // ------------------------------------------------------------------ receiving

    public synchronized void receive(int verb, int opt) {
        switch (verb) {
            case Telnet.WILL: recvWill(opt); break;
            case Telnet.WONT: recvWont(opt); break;
            case Telnet.DO: recvDo(opt); break;
            case Telnet.DONT: recvDont(opt); break;
            default: break;
        }
    }

    private void recvWill(int o) {
        Q b = him[o];
        String meaning = b == Q.NO ? OFFER_EN : b == Q.WANTYES ? ACCEPT_REQ_EN : "redundant (already in that mode)";
        String note;
        switch (b) {
            case NO:
                if (policy.acceptRemote(o)) { him[o] = Q.YES; send(Telnet.DO, o, APPROVE_OFFER_EN); note = "we accept: DO"; changed(false, o, true); }
                else { send(Telnet.DONT, o, DISAPPROVE_OFFER_EN); note = "we refuse: DONT"; }
                break;
            case YES: note = "already enabled: no reply (prevents a loop)"; break;
            case WANTNO:
                if (!himQueue[o]) { him[o] = Q.NO; note = "error: DONT answered by WILL"; }
                else { him[o] = Q.YES; himQueue[o] = false; note = "error: DONT answered by WILL"; changed(false, o, true); }
                break;
            case WANTYES:
                if (!himQueue[o]) { him[o] = Q.YES; note = "our DO acknowledged"; changed(false, o, true); }
                else { him[o] = Q.WANTNO; himQueue[o] = false; send(Telnet.DONT, o, REQ_DIS); note = "acknowledged, but we changed our mind meanwhile: DONT"; }
                break;
            default: note = "";
        }
        step(true, Telnet.WILL, o, false, b, him[o], meaning, note);
    }

    private void recvWont(int o) {
        Q b = him[o];
        String meaning = b == Q.YES ? OFFER_DIS : b == Q.WANTNO ? ACCEPT_REQ_DIS : b == Q.WANTYES ? REJECT_REQ_EN : "redundant (already disabled)";
        String note;
        switch (b) {
            case NO: note = "already disabled: no reply"; break;
            case YES: him[o] = Q.NO; send(Telnet.DONT, o, APPROVE_OFFER_DIS); note = "a WONT must always be accepted: DONT"; changed(false, o, false); break;
            case WANTNO:
                if (!himQueue[o]) { him[o] = Q.NO; note = "our DONT acknowledged"; changed(false, o, false); }
                else { him[o] = Q.WANTYES; himQueue[o] = false; send(Telnet.DO, o, REQ_EN); note = "acknowledged; queued request: DO"; }
                break;
            case WANTYES:
                him[o] = Q.NO; himQueue[o] = false; note = "our DO refused"; break;
            default: note = "";
        }
        step(true, Telnet.WONT, o, false, b, him[o], meaning, note);
    }

    private void recvDo(int o) {
        Q b = us[o];
        String meaning = b == Q.NO ? REQ_EN : b == Q.WANTYES ? APPROVE_OFFER_EN : "redundant (already in that mode)";
        String note;
        switch (b) {
            case NO:
                if (policy.acceptLocal(o)) { us[o] = Q.YES; send(Telnet.WILL, o, ACCEPT_REQ_EN); note = "we agree: WILL"; changed(true, o, true); }
                else { send(Telnet.WONT, o, REJECT_REQ_EN); note = "we refuse: WONT"; }
                break;
            case YES: note = "already enabled: no reply (prevents a loop)"; break;
            case WANTNO:
                if (!usQueue[o]) { us[o] = Q.NO; note = "error: WONT answered by DO"; }
                else { us[o] = Q.YES; usQueue[o] = false; note = "error: WONT answered by DO"; changed(true, o, true); }
                break;
            case WANTYES:
                if (!usQueue[o]) { us[o] = Q.YES; note = "our WILL acknowledged"; changed(true, o, true); }
                else { us[o] = Q.WANTNO; usQueue[o] = false; send(Telnet.WONT, o, OFFER_DIS); note = "acknowledged, but we changed our mind: WONT"; }
                break;
            default: note = "";
        }
        step(true, Telnet.DO, o, true, b, us[o], meaning, note);
    }

    private void recvDont(int o) {
        Q b = us[o];
        String meaning = b == Q.YES ? REQ_DIS : b == Q.WANTNO ? APPROVE_OFFER_DIS : b == Q.WANTYES ? DISAPPROVE_OFFER_EN : "redundant (already disabled)";
        String note;
        switch (b) {
            case NO: note = "already disabled: no reply"; break;
            case YES: us[o] = Q.NO; send(Telnet.WONT, o, ACCEPT_REQ_DIS); note = "a DONT must always be accepted: WONT"; changed(true, o, false); break;
            case WANTNO:
                if (!usQueue[o]) { us[o] = Q.NO; note = "our WONT acknowledged"; changed(true, o, false); }
                else { us[o] = Q.WANTYES; usQueue[o] = false; send(Telnet.WILL, o, OFFER_EN); note = "acknowledged; queued request: WILL"; }
                break;
            case WANTYES:
                us[o] = Q.NO; usQueue[o] = false; note = "our WILL refused"; break;
            default: note = "";
        }
        step(true, Telnet.DONT, o, true, b, us[o], meaning, note);
    }

    // ------------------------------------------------------------------ requesting

    /** Ask to enable/disable an option on OUR side (WILL / WONT). Returns a note. */
    public synchronized String requestLocal(int o, boolean enable) {
        Q b = us[o];
        String note;
        if (enable) {
            switch (b) {
                case NO: us[o] = Q.WANTYES; send(Telnet.WILL, o, OFFER_EN); note = "offer: WILL"; break;
                case YES: note = "already enabled"; break;
                case WANTNO: if (!usQueue[o]) { usQueue[o] = true; note = "queued (OPPOSITE)"; } else note = "already queued"; break;
                case WANTYES: if (usQueue[o]) { usQueue[o] = false; note = "queue cleared"; } else note = "already negotiating"; break;
                default: note = "";
            }
        } else {
            switch (b) {
                case NO: note = "already disabled"; break;
                case YES: us[o] = Q.WANTNO; send(Telnet.WONT, o, OFFER_DIS); note = "withdraw: WONT"; changed(true, o, false); break;
                case WANTNO: if (usQueue[o]) { usQueue[o] = false; note = "queue cleared"; } else note = "already negotiating"; break;
                case WANTYES: if (!usQueue[o]) { usQueue[o] = true; note = "queued (OPPOSITE)"; } else note = "already queued"; break;
                default: note = "";
            }
        }
        step(false, enable ? Telnet.WILL : Telnet.WONT, o, true, b, us[o], enable ? OFFER_EN : OFFER_DIS, "request: " + note);
        return note;
    }

    /** Ask the peer to enable/disable an option on ITS side (DO / DONT). */
    public synchronized String requestRemote(int o, boolean enable) {
        Q b = him[o];
        String note;
        if (enable) {
            switch (b) {
                case NO: him[o] = Q.WANTYES; send(Telnet.DO, o, REQ_EN); note = "ask: DO"; break;
                case YES: note = "already enabled"; break;
                case WANTNO: if (!himQueue[o]) { himQueue[o] = true; note = "queued (OPPOSITE)"; } else note = "already queued"; break;
                case WANTYES: if (himQueue[o]) { himQueue[o] = false; note = "queue cleared"; } else note = "already negotiating"; break;
                default: note = "";
            }
        } else {
            switch (b) {
                case NO: note = "already disabled"; break;
                case YES: him[o] = Q.WANTNO; send(Telnet.DONT, o, REQ_DIS); note = "ask to stop: DONT"; changed(false, o, false); break;
                case WANTNO: if (himQueue[o]) { himQueue[o] = false; note = "queue cleared"; } else note = "already negotiating"; break;
                case WANTYES: if (!himQueue[o]) { himQueue[o] = true; note = "queued (OPPOSITE)"; } else note = "already queued"; break;
                default: note = "";
            }
        }
        step(false, enable ? Telnet.DO : Telnet.DONT, o, false, b, him[o], enable ? REQ_EN : REQ_DIS, "request: " + note);
        return note;
    }

    // ------------------------------------------------------------------ helpers

    private void send(int verb, int o, String meaning) {
        messagesSent++;
        sender.send(verb, o, meaning);
    }

    /** Log the step first, then announce option changes, so follow-ups (e.g. SB TTYPE SEND) come after their cause. */
    private void step(boolean received, int verb, int o, boolean usSide, Q before, Q after, String meaning, String note) {
        Observer ob = observer;
        if (ob != null) ob.onStep(received, verb, o, usSide, before, after, meaning, note);
        while (!pending.isEmpty()) {
            int[] c = pending.remove(0);
            if (ob != null) ob.onChange(c[0] == 1, c[1], c[2] == 1);
        }
    }

    private final java.util.List<int[]> pending = new java.util.ArrayList<>();

    private void changed(boolean usSide, int o, boolean enabled) {
        pending.add(new int[]{usSide ? 1 : 0, o, enabled ? 1 : 0});
    }
}

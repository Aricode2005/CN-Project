package telnet.server;

/**
 * A remote authentication server (AAA), consulted at login when the configuration says
 * "aaa authentication login default group radius local".
 */
public interface RemoteAuth {
    /** Result of one authentication: accepted with a privilege level, rejected, or no answer from the server. */
    final class Answer {
        public final boolean accepted, timedOut; public final int privilege; public final String message;
        public Answer(boolean accepted, boolean timedOut, int privilege, String message) {
            this.accepted = accepted; this.timedOut = timedOut; this.privilege = privilege; this.message = message;
        }
    }
    Answer authenticate(String user, String password, TelnetSession s);
    /** One-paragraph status for "show aaa servers". */
    String status();
}

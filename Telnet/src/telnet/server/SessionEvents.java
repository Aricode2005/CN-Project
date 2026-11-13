package telnet.server;

/**
 * Things that happen to a VTY session, for modules that watch sessions without being part of them:
 * the HA cluster (replicates session state so it can be resumed on another node) and RADIUS
 * accounting (Start / Interim-Update / Stop records). All methods run on the session's own thread.
 */
public interface SessionEvents {
    /** Login succeeded (or a detached session was resumed); the session is now in EXEC mode. */
    default void loggedIn(TelnetSession s, boolean resumed) { }
    /** A command line was executed in EXEC or configuration mode. */
    default void command(TelnetSession s, String line) { }
    /** The session ended. {@code why} is "exit", "logout", "quit", "Ctrl-D", "exec-timeout", "node crashed", "disconnected", ... */
    default void closed(TelnetSession s, String why) { }
}

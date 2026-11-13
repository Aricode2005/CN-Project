package telnet.server;

/** Resumes a detached session ("resume" or "resume TOKEN" typed at the Username: prompt). */
public interface Resumer {
    /** @return null when resumed, otherwise the reason it could not be resumed (printed to the user). */
    String resume(TelnetSession s, String token);
}

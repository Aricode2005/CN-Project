package telnet.server;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import telnet.core.Hub;
import telnet.core.Json;

/**
 * Brute-force protection, after Cisco IOS "login block-for S attempts N within W":
 * if N logins fail within W seconds, the device enters "quiet mode" and refuses
 * every login for S seconds.
 */
public final class LoginGuard {

    private final DeviceConfig cfg;
    private final Deque<Long> failures = new ArrayDeque<>();
    private volatile long quietUntil;
    private long totalFailures, totalSuccess, totalBlockedAttempts, quietPeriods;
    private final List<String> history = new ArrayList<>();

    public LoginGuard(DeviceConfig cfg) { this.cfg = cfg; }

    public synchronized long quietSecondsLeft() {
        long ms = quietUntil - System.currentTimeMillis();
        return ms > 0 ? (ms + 999) / 1000 : 0;
    }

    public synchronized boolean blocked() {
        if (quietSecondsLeft() > 0) { totalBlockedAttempts++; return true; }
        return false;
    }

    public synchronized void success(String user, String from) {
        totalSuccess++;
        note("Login Success [user: " + user + "] [Source: " + from + "]");
    }

    /** Returns true if this failure switched the device into quiet mode. */
    public synchronized boolean failure(String user, String from) {
        totalFailures++;
        long now = System.currentTimeMillis();
        failures.addLast(now);
        while (!failures.isEmpty() && now - failures.peekFirst() > cfg.blockWithinSec * 1000L) failures.removeFirst();
        note("Login failed [user: " + user + "] [Source: " + from + "] [Reason: Login Authentication Failed]");
        if (failures.size() >= cfg.blockAttempts) {
            quietUntil = now + cfg.blockForSec * 1000L;
            failures.clear();
            quietPeriods++;
            note("%SEC_LOGIN-1-QUIET_MODE_ON: Still timeleft for watching failures is 0 secs, [user: " + user
                    + "] [Source: " + from + "] [Reason: Login Authentication Failed] blocked for " + cfg.blockForSec + " secs");
            return true;
        }
        return false;
    }

    public synchronized void unblock() {
        quietUntil = 0; failures.clear();
        note("%SEC_LOGIN-5-QUIET_MODE_OFF: Quiet Mode is OFF (cleared by administrator)");
    }

    private void note(String s) {
        history.add(s);
        if (history.size() > 60) history.remove(0);
        Hub.I.log("[SECURITY] " + s);
    }

    public synchronized String showLogin() {
        StringBuilder b = new StringBuilder();
        b.append("     A login delay of 0 seconds is applied.\n");
        b.append("     Router enabled to watch for login Attacks.\n");
        b.append("     If more than ").append(cfg.blockAttempts).append(" login failures occur in ").append(cfg.blockWithinSec)
         .append(" seconds or less,\n     logins will be disabled for ").append(cfg.blockForSec).append(" seconds.\n\n");
        long q = quietSecondsLeft();
        b.append(q > 0 ? "     Router presently in Quiet-Mode. Will remain in Quiet-Mode for " + q + " seconds.\n"
                       : "     Router presently in Normal-Mode.\n");
        b.append("     Current Watch Window: ").append(failures.size()).append(" failure(s) in the last ").append(cfg.blockWithinSec).append(" s.\n");
        b.append("     Totals: ").append(totalSuccess).append(" success, ").append(totalFailures).append(" failed, ")
         .append(totalBlockedAttempts).append(" refused in quiet mode.\n");
        return b.toString();
    }

    public synchronized String json() {
        List<String> h = new ArrayList<>();
        for (String s : history) h.add(Json.str(s));
        return Json.obj("quietLeft", quietSecondsLeft(), "blockFor", cfg.blockForSec, "attempts", cfg.blockAttempts,
                "within", cfg.blockWithinSec, "window", failures.size(), "failures", totalFailures, "success", totalSuccess,
                "refused", totalBlockedAttempts, "quietPeriods", quietPeriods, "history", Json.raw(Json.arr(h)));
    }
}

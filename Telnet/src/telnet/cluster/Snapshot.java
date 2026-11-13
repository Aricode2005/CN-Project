package telnet.cluster;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * The replicated state of one logged-in VTY session: everything needed to continue it on another node.
 * Sent between nodes as one UDP datagram:  SNAP \t token \t node \t state \t updated \t detachedAt \t priv \t config \t b64(user) \t b64(client) \t b64(history) \t b64(screen)
 */
final class Snapshot {
    String token, node, state, user, client, screen;
    int priv; boolean config; long updated, detachedAt;
    List<String> history = new ArrayList<>();

    static final String ATTACHED = "ATTACHED", DETACHED = "DETACHED";

    String encode() {
        return String.join("\t", "SNAP", token, node, state, String.valueOf(updated), String.valueOf(detachedAt), String.valueOf(priv),
                config ? "1" : "0", b64(user), b64(client), b64(String.join("\n", history)), b64(screen));
    }

    static Snapshot decode(String s) {
        String[] f = s.split("\t", -1);
        if (f.length != 12 || !f[0].equals("SNAP")) return null;
        Snapshot x = new Snapshot();
        x.token = f[1]; x.node = f[2]; x.state = f[3]; x.updated = Long.parseLong(f[4]); x.detachedAt = Long.parseLong(f[5]);
        x.priv = Integer.parseInt(f[6]); x.config = f[7].equals("1"); x.user = unb64(f[8]); x.client = unb64(f[9]);
        String h = unb64(f[10]); if (!h.isEmpty()) x.history.addAll(Arrays.asList(h.split("\n")));
        x.screen = unb64(f[11]);
        return x;
    }

    private static String b64(String s) { return Base64.getEncoder().encodeToString((s == null ? "" : s).getBytes(StandardCharsets.UTF_8)); }
    private static String unb64(String s) { return new String(Base64.getDecoder().decode(s), StandardCharsets.UTF_8); }
}

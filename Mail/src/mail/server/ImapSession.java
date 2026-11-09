package mail.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import mail.core.Hub;
import mail.mime.Mime;
import mail.store.MailStore;

/**
 * IMAP4rev1 server session (RFC 3501, plus IDLE 2177, UIDPLUS 4315, MOVE 6851, NAMESPACE, ID,
 * UNSELECT, SPECIAL-USE). Unlike POP3, mail STAYS on the server: the client works on folders,
 * flags (\Seen \Answered \Flagged \Deleted \Draft) and server-side search, and every client
 * connected to the same mailbox sees the others' changes.
 *
 *   * OK greeting → LOGIN → SELECT INBOX → FETCH / STORE / SEARCH / COPY / EXPUNGE / IDLE → LOGOUT
 *
 * Every command carries a tag; untagged "*" lines carry data, the tagged line ends the command.
 */
public final class ImapSession extends Session {

    private enum State { NOT_AUTHENTICATED, AUTHENTICATED, SELECTED }

    private State state = State.NOT_AUTHENTICATED;
    private String user;
    private MailStore.Folder sel;
    private boolean readOnly;
    // this session's view of the selected mailbox (sequence number = index + 1)
    private final List<Long> view = new ArrayList<>();
    private final Map<Long, Set<String>> seenFlags = new HashMap<>();
    private long seenVersion;
    private volatile boolean idling;

    public ImapSession(Context ctx, Socket s, boolean implicitTls) throws IOException { super(ctx, s, "IMAP", implicitTls); }

    // ================================================================== main loop

    @Override
    protected void session() throws IOException {
        untagged("OK [CAPABILITY " + caps() + "] JU-IMAP4rev1 server ready", "greeting (NOT AUTHENTICATED state)");
        while (true) {
            List<Object> cmd = readCommand();
            if (cmd == null) return;
            if (cmd.size() < 2) { send("* BAD missing command", "error"); continue; }
            String tag = str(cmd.get(0));
            String name = str(cmd.get(1)).toUpperCase(Locale.ROOT);
            boolean uid = false;
            if (name.equals("UID") && cmd.size() > 2) { uid = true; name = str(cmd.get(2)).toUpperCase(Locale.ROOT); cmd.remove(1); }
            List<Object> args = new ArrayList<>(cmd.subList(2, cmd.size()));
            try {
                if (!dispatch(tag, name, args, uid)) return;
            } catch (IndexOutOfBoundsException | IllegalArgumentException e) {
                tagged(tag, "BAD " + name + " syntax error" + (e.getMessage() != null ? ": " + e.getMessage() : ""));
            }
        }
    }

    private boolean dispatch(String tag, String c, List<Object> a, boolean uid) throws IOException {
        // commands valid in any state
        switch (c) {
            case "CAPABILITY": untagged("CAPABILITY " + caps(), "what this server supports"); tagged(tag, "OK CAPABILITY completed"); return true;
            case "NOOP": if (state == State.SELECTED) sync(true); tagged(tag, "OK NOOP completed"); return true;
            case "LOGOUT": untagged("BYE JU-IMAP server logging out", "server will close the connection"); tagged(tag, "OK LOGOUT completed"); return false;
            case "ID": untagged("ID (\"name\" \"JU-Mail\" \"version\" \"1.0\" \"vendor\" \"Jadavpur CSE\")", "server identification (RFC 2971)"); tagged(tag, "OK ID completed"); return true;
            default: break;
        }
        if (state == State.NOT_AUTHENTICATED) {
            switch (c) {
                case "STARTTLS":
                    if (secure || ctx.tls == null) { tagged(tag, "BAD TLS already active or not available"); return true; }
                    tagged(tag, "OK Begin TLS negotiation now"); upgradeTls(); return true;
                case "LOGIN": login(tag, str(a.get(0)), str(a.get(1))); return true;
                case "AUTHENTICATE": authenticate(tag, a); return true;
                default: tagged(tag, "BAD " + c + " not allowed before LOGIN"); return true;
            }
        }
        switch (c) {
            case "NAMESPACE": untagged("NAMESPACE ((\"\" \"/\")) NIL NIL", "personal namespace, hierarchy delimiter \"/\""); tagged(tag, "OK NAMESPACE completed"); return true;
            case "SELECT": case "EXAMINE": select(tag, str(a.get(0)), c.equals("EXAMINE")); return true;
            case "CREATE": tagged(tag, ctx.store.createFolder(user, str(a.get(0))) ? "OK CREATE completed" : "NO [ALREADYEXISTS] cannot create"); return true;
            case "DELETE": tagged(tag, ctx.store.deleteFolder(user, str(a.get(0))) ? "OK DELETE completed" : "NO cannot delete"); return true;
            case "RENAME": tagged(tag, ctx.store.renameFolder(user, str(a.get(0)), str(a.get(1))) ? "OK RENAME completed" : "NO cannot rename"); return true;
            case "SUBSCRIBE": case "UNSUBSCRIBE": tagged(tag, "OK " + c + " completed"); return true;
            case "LIST": case "LSUB": list(tag, c, str(a.get(0)), str(a.get(1))); return true;
            case "STATUS": status(tag, str(a.get(0)), (List<?>) a.get(1)); return true;
            case "APPEND": append(tag, a); return true;
            default: break;
        }
        if (state != State.SELECTED) { tagged(tag, "BAD " + c + " needs a selected mailbox (SELECT first)"); return true; }
        switch (c) {
            case "CHECK": sync(true); tagged(tag, "OK CHECK completed"); return true;
            case "CLOSE": if (!readOnly) expunge(false, null); unselect(); tagged(tag, "OK CLOSE completed (deleted messages expunged)"); return true;
            case "UNSELECT": unselect(); tagged(tag, "OK UNSELECT completed"); return true;
            case "EXPUNGE":
                if (readOnly) { tagged(tag, "NO mailbox is read-only"); return true; }
                expunge(true, uid && !a.isEmpty() ? set(str(a.get(0)), true) : null); tagged(tag, "OK EXPUNGE completed"); return true;
            case "SEARCH": search(tag, a, uid); return true;
            case "FETCH": fetch(tag, str(a.get(0)), a.get(1), uid); return true;
            case "STORE": store(tag, str(a.get(0)), str(a.get(1)), a.get(2), uid); return true;
            case "COPY": case "MOVE": copy(tag, str(a.get(0)), str(a.get(1)), uid, c.equals("MOVE")); return true;
            case "IDLE": idle(tag); return true;
            default: tagged(tag, "BAD unknown command " + c); return true;
        }
    }

    private static String caps() {
        return "IMAP4rev1 STARTTLS AUTH=PLAIN IDLE UIDPLUS MOVE NAMESPACE ID UNSELECT SPECIAL-USE LITERAL+";
    }

    // ================================================================== authentication

    private void login(String tag, String u, String p) throws IOException {
        if (u.contains("@")) u = u.substring(0, u.indexOf('@'));
        if (ctx.store.authenticate(u, p)) {
            user = u.toLowerCase(Locale.ROOT); state = State.AUTHENTICATED;
            tagged(tag, "OK [CAPABILITY " + caps() + "] LOGIN completed, now in AUTHENTICATED state");
            Hub.I.event("IMAP", user + " logged in (" + id + ")");
        } else tagged(tag, "NO [AUTHENTICATIONFAILED] Invalid credentials");
    }

    private void authenticate(String tag, List<Object> a) throws IOException {
        if (!str(a.get(0)).equalsIgnoreCase("PLAIN")) { tagged(tag, "NO unsupported mechanism"); return; }
        String resp = a.size() > 1 ? str(a.get(1)) : null;
        if (resp == null) { send("+ ", "send base64 credentials"); resp = readLine(); logClient(resp, "base64(\\0user\\0password)"); }
        String[] p = new String(Base64.getDecoder().decode(resp.trim()), StandardCharsets.UTF_8).split("\u0000", -1);
        if (p.length < 3) { tagged(tag, "BAD bad AUTHENTICATE data"); return; }
        login(tag, p[1], p[2]);
    }

    // ================================================================== mailboxes

    private void select(String tag, String name, boolean examine) throws IOException {
        MailStore.Folder f = ctx.store.folder(user, name);
        if (f == null) { unselect(); tagged(tag, "NO [NONEXISTENT] no such mailbox"); return; }
        sel = f; readOnly = examine; state = State.SELECTED;
        view.clear(); seenFlags.clear();
        int recent = f.recent();
        for (MailStore.Message m : f.list()) { view.add(m.uid); seenFlags.put(m.uid, new TreeSet<>(m.flags)); }
        seenVersion = f.version;
        if (!examine) ctx.store.clearRecent(f);
        untagged("FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)", "flags defined in this mailbox");
        untagged(view.size() + " EXISTS", "number of messages");
        untagged(recent + " RECENT", "messages new since the last session");
        int firstUnseen = 0;
        List<MailStore.Message> ms = f.list();
        for (int i = 0; i < ms.size(); i++) if (!ms.get(i).flags.contains("\\Seen")) { firstUnseen = i + 1; break; }
        if (firstUnseen > 0) untagged("OK [UNSEEN " + firstUnseen + "] first unseen message", "sequence number of the first unread message");
        untagged("OK [UIDVALIDITY " + f.uidValidity + "] UIDs valid", "if this changes, cached UIDs are invalid");
        untagged("OK [UIDNEXT " + f.uidNext() + "] predicted next UID", "");
        untagged("OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] flags saved permanently", "");
        tagged(tag, "OK [" + (examine ? "READ-ONLY" : "READ-WRITE") + "] " + (examine ? "EXAMINE" : "SELECT") + " completed, now in SELECTED state");
    }

    private void unselect() { sel = null; view.clear(); seenFlags.clear(); state = State.AUTHENTICATED; }

    private void list(String tag, String cmd, String ref, String pattern) throws IOException {
        if (pattern.isEmpty()) { untagged(cmd + " (\\Noselect) \"/\" \"\"", "hierarchy delimiter"); tagged(tag, "OK " + cmd + " completed"); return; }
        String regex = (ref + pattern).replace(".", "\\.").replace("*", ".*").replace("%", "[^/]*");
        for (String n : ctx.store.folderNames(user)) {
            if (!n.matches("(?i)" + regex)) continue;
            String attr = "\\HasNoChildren";
            if (n.equalsIgnoreCase("Sent")) attr += " \\Sent";
            if (n.equalsIgnoreCase("Drafts")) attr += " \\Drafts";
            if (n.equalsIgnoreCase("Trash")) attr += " \\Trash";
            untagged(cmd + " (" + attr + ") \"/\" " + quote(n), "");
        }
        tagged(tag, "OK " + cmd + " completed");
    }

    private void status(String tag, String name, List<?> items) throws IOException {
        MailStore.Folder f = ctx.store.folder(user, name);
        if (f == null) { tagged(tag, "NO no such mailbox"); return; }
        StringBuilder b = new StringBuilder();
        for (Object o : items) {
            String it = str(o).toUpperCase(Locale.ROOT);
            long v = it.equals("MESSAGES") ? f.count() : it.equals("RECENT") ? f.recent() : it.equals("UIDNEXT") ? f.uidNext()
                    : it.equals("UIDVALIDITY") ? f.uidValidity : it.equals("UNSEEN") ? f.unseen() : -1;
            if (v >= 0) b.append(b.length() > 0 ? " " : "").append(it).append(' ').append(v);
        }
        untagged("STATUS " + quote(f.name) + " (" + b + ")", "counts without selecting the mailbox");
        tagged(tag, "OK STATUS completed");
    }

    private void append(String tag, List<Object> a) throws IOException {
        String name = str(a.get(0));
        MailStore.Folder f = ctx.store.folder(user, name);
        if (f == null) { tagged(tag, "NO [TRYCREATE] no such mailbox"); return; }
        Set<String> flags = new LinkedHashSet<>();
        byte[] msg = null;
        for (int i = 1; i < a.size(); i++) {
            Object o = a.get(i);
            if (o instanceof List) for (Object fl : (List<?>) o) flags.add(normFlag(str(fl)));
            else if (o instanceof byte[]) msg = (byte[]) o;
        }
        if (msg == null) { tagged(tag, "BAD APPEND needs a message literal"); return; }
        long uid = ctx.store.append(user, f.name, msg, flags);
        Hub.I.event("IMAP", user + " APPENDed a message to " + f.name + " (UID " + uid + ")");
        if (sel == f) sync(true);
        tagged(tag, "OK [APPENDUID " + f.uidValidity + " " + uid + "] APPEND completed");
    }

    // ================================================================== selected state

    /** Report changes made by OTHER sessions (new mail, expunges, flag changes). */
    private synchronized void sync(boolean allowExpunge) throws IOException {
        if (sel == null || sel.version == seenVersion) return;
        List<MailStore.Message> now = sel.list();
        Map<Long, MailStore.Message> byUid = new HashMap<>();
        for (MailStore.Message m : now) byUid.put(m.uid, m);
        if (allowExpunge) {
            for (int i = 0; i < view.size(); ) {
                if (!byUid.containsKey(view.get(i))) {
                    seenFlags.remove(view.get(i));
                    view.remove(i);
                    untagged((i + 1) + " EXPUNGE", "message " + (i + 1) + " was removed by another client; later numbers shift down");
                } else i++;
            }
        }
        for (int i = 0; i < view.size(); i++) {
            MailStore.Message m = byUid.get(view.get(i));
            if (m == null) continue;
            Set<String> fl = new TreeSet<>(m.flags);
            if (!fl.equals(seenFlags.get(m.uid))) {
                seenFlags.put(m.uid, fl);
                untagged((i + 1) + " FETCH (UID " + m.uid + " FLAGS (" + String.join(" ", fl) + "))", "flags changed by another client (e.g. read on another device)");
            }
        }
        int before = view.size();
        for (MailStore.Message m : now) if (!seenFlags.containsKey(m.uid) && !view.contains(m.uid)) { view.add(m.uid); seenFlags.put(m.uid, new TreeSet<>(m.flags)); }
        if (view.size() != before) untagged(view.size() + " EXISTS", (view.size() - before) + " new message(s) arrived");
        seenVersion = sel.version;
    }

    private void expunge(boolean report, List<Integer> onlyIdx) throws IOException {
        List<Long> gone;
        if (onlyIdx != null) {   // UID EXPUNGE: only the given UIDs, and only if they are \Deleted
            Set<Long> chosen = new java.util.HashSet<>();
            Map<Long, MailStore.Message> b = byUid();
            for (int i : onlyIdx) { MailStore.Message m = b.get(view.get(i)); if (m != null && m.flags.contains("\\Deleted")) chosen.add(m.uid); }
            gone = ctx.store.expungeUids(user, sel, chosen);
        } else gone = ctx.store.expunge(user, sel);
        synchronized (this) {
            for (long uid : gone) {
                int i = view.indexOf(uid);
                if (i < 0) continue;
                view.remove(i); seenFlags.remove(uid);
                if (report) untagged((i + 1) + " EXPUNGE", "message removed for good; higher sequence numbers shift down by one");
            }
            seenVersion = sel.version;
        }
        if (!gone.isEmpty()) Hub.I.event("IMAP", user + " expunged " + gone.size() + " message(s) from " + sel.name);
    }

    private void search(String tag, List<Object> keys, boolean uid) throws IOException {
        List<MailStore.Message> ms = messagesInView();
        StringBuilder r = new StringBuilder("SEARCH");
        for (int i = 0; i < ms.size(); i++) {
            int[] pos = {0};
            boolean all = true;
            while (pos[0] < keys.size()) all &= match(ms.get(i), i, keys, pos);
            if (all) r.append(' ').append(uid ? ms.get(i).uid : i + 1);
        }
        untagged(r.toString(), "matching " + (uid ? "UIDs" : "sequence numbers") + " — the search ran on the server");
        tagged(tag, "OK SEARCH completed");
    }

    private boolean match(MailStore.Message m, int idx, List<Object> k, int[] pos) {
        Object o = k.get(pos[0]++);
        if (o instanceof List) { List<Object> sub = cast(o); int[] p = {0}; boolean all = true; while (p[0] < sub.size()) all &= match(m, idx, sub, p); return all; }
        String key = str(o).toUpperCase(Locale.ROOT);
        Set<String> f = m.flags;
        switch (key) {
            case "ALL": return true;
            case "SEEN": return f.contains("\\Seen");
            case "UNSEEN": return !f.contains("\\Seen");
            case "ANSWERED": return f.contains("\\Answered");
            case "UNANSWERED": return !f.contains("\\Answered");
            case "FLAGGED": return f.contains("\\Flagged");
            case "UNFLAGGED": return !f.contains("\\Flagged");
            case "DELETED": return f.contains("\\Deleted");
            case "UNDELETED": return !f.contains("\\Deleted");
            case "DRAFT": return f.contains("\\Draft");
            case "RECENT": return m.recent;
            case "NEW": return m.recent && !f.contains("\\Seen");
            case "OLD": return !m.recent;
            case "NOT": return !match(m, idx, k, pos);
            case "OR": { boolean x = match(m, idx, k, pos); boolean y = match(m, idx, k, pos); return x || y; }
            case "FROM": case "TO": case "CC": case "SUBJECT": {
                String h = m.header(key.charAt(0) + key.substring(1).toLowerCase(Locale.ROOT));
                return h != null && h.toLowerCase(Locale.ROOT).contains(str(k.get(pos[0]++)).toLowerCase(Locale.ROOT));
            }
            case "HEADER": { String h = m.header(str(k.get(pos[0]++))); String v = str(k.get(pos[0]++)); return h != null && h.toLowerCase(Locale.ROOT).contains(v.toLowerCase(Locale.ROOT)); }
            case "BODY": { String v = str(k.get(pos[0]++)).toLowerCase(Locale.ROOT); return bodyText(m).toLowerCase(Locale.ROOT).contains(v); }
            case "TEXT": { String v = str(k.get(pos[0]++)).toLowerCase(Locale.ROOT); return new String(m.raw, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT).contains(v); }
            case "LARGER": return m.size() > Long.parseLong(str(k.get(pos[0]++)));
            case "SMALLER": return m.size() < Long.parseLong(str(k.get(pos[0]++)));
            case "UID": return set(str(k.get(pos[0]++)), true).contains(idx);
            case "SINCE": case "BEFORE": case "ON": pos[0]++; return true;   // date keys accepted, not filtered
            default:
                if (Character.isDigit(key.charAt(0)) || key.equals("*")) return set(key, false).contains(idx);
                throw new IllegalArgumentException("unknown search key " + key);
        }
    }

    private void store(String tag, String setStr, String item, Object value, boolean uid) throws IOException {
        String it = item.toUpperCase(Locale.ROOT);
        boolean silent = it.endsWith(".SILENT");
        if (silent) it = it.substring(0, it.length() - 7);
        Set<String> given = new LinkedHashSet<>();
        if (value instanceof List) for (Object o : (List<?>) value) given.add(normFlag(str(o)));
        else given.add(normFlag(str(value)));
        if (readOnly) { tagged(tag, "NO mailbox is read-only"); return; }
        Map<Long, MailStore.Message> byUid = byUid();
        for (int i : set(setStr, uid)) {
            MailStore.Message m = byUid.get(view.get(i));
            if (m == null) continue;
            Set<String> f = new TreeSet<>(m.flags);
            if (it.equals("+FLAGS")) f.addAll(given); else if (it.equals("-FLAGS")) f.removeAll(given); else { f.clear(); f.addAll(given); }
            ctx.store.setFlags(user, sel, m, f);
            synchronized (this) { seenFlags.put(m.uid, new TreeSet<>(f)); }
            if (!silent) untagged((i + 1) + " FETCH (" + (uid ? "UID " + m.uid + " " : "") + "FLAGS (" + String.join(" ", f) + "))", "new flags of message " + (i + 1));
        }
        synchronized (this) { seenVersion = sel.version; }
        tagged(tag, "OK STORE completed");
    }

    private void copy(String tag, String setStr, String dest, boolean uid, boolean move) throws IOException {
        MailStore.Folder d = ctx.store.folder(user, dest);
        if (d == null) { tagged(tag, "NO [TRYCREATE] no such mailbox"); return; }
        Map<Long, MailStore.Message> byUid = byUid();
        List<String> src = new ArrayList<>(), dst = new ArrayList<>();
        List<Integer> idx = set(setStr, uid);
        for (int i : idx) {
            MailStore.Message m = byUid.get(view.get(i));
            if (m == null) continue;
            Set<String> fl = new TreeSet<>(m.flags);
            fl.remove("\\Deleted");
            long nu = ctx.store.append(user, d.name, m.raw, fl);
            src.add(String.valueOf(m.uid)); dst.add(String.valueOf(nu));
        }
        String code = "COPYUID " + d.uidValidity + " " + String.join(",", src) + " " + String.join(",", dst);
        if (move) {
            untagged("OK [" + code + "] moved", "");
            Set<Long> movedUids = new java.util.HashSet<>();
            for (String s : src) movedUids.add(Long.parseLong(s));
            List<Long> gone = ctx.store.expungeUids(user, sel, movedUids);     // only the moved ones
            synchronized (this) {
                for (long u : gone) { int i = view.indexOf(u); if (i >= 0) { view.remove(i); seenFlags.remove(u); untagged((i + 1) + " EXPUNGE", "moved away"); } }
                seenVersion = sel.version;
            }
            Hub.I.event("IMAP", user + " moved " + src.size() + " message(s) " + sel.name + " → " + d.name);
            tagged(tag, "OK MOVE completed");
        } else {
            Hub.I.event("IMAP", user + " copied " + src.size() + " message(s) " + sel.name + " → " + d.name);
            tagged(tag, "OK [" + code + "] COPY completed");
        }
    }

    /** IDLE (RFC 2177): server pushes EXISTS/EXPUNGE/FETCH as they happen, until the client says DONE. */
    private void idle(String tag) throws IOException {
        send("+ idling", "server will now push changes in real time; client ends with DONE");
        idling = true;
        Thread w = new Thread(() -> {
            while (idling) {
                try { Thread.sleep(250); sync(true); } catch (Exception e) { return; }
            }
        }, id + "-idle");
        w.setDaemon(true);
        w.start();
        Hub.I.event("IDLE", user + " is IDLE on " + sel.name + " (" + id + ")");
        String l;
        while ((l = readLine()) != null) {
            logClient(l, l.equalsIgnoreCase("DONE") ? "stop idling" : "");
            if (l.equalsIgnoreCase("DONE")) break;
        }
        idling = false;
        if (l == null) throw new IOException("closed during IDLE");
        tagged(tag, "OK IDLE terminated");
    }

    // ================================================================== FETCH

    private void fetch(String tag, String setStr, Object itemsObj, boolean uid) throws IOException {
        List<Object> items = new ArrayList<>();
        if (itemsObj instanceof List) items.addAll(cast(itemsObj));
        else {
            String m = str(itemsObj).toUpperCase(Locale.ROOT);
            if (m.equals("ALL")) for (String s : new String[]{"FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE"}) items.add(s);
            else if (m.equals("FAST")) for (String s : new String[]{"FLAGS", "INTERNALDATE", "RFC822.SIZE"}) items.add(s);
            else if (m.equals("FULL")) for (String s : new String[]{"FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", "BODY"}) items.add(s);
            else items.add(itemsObj);
        }
        if (uid && items.stream().noneMatch(o -> str(o).equalsIgnoreCase("UID"))) items.add(0, "UID");
        Map<Long, MailStore.Message> byUid = byUid();
        for (int i : set(setStr, uid)) {
            MailStore.Message m = byUid.get(view.get(i));
            if (m == null) continue;
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            w(o, "* " + (i + 1) + " FETCH (");
            boolean first = true, setSeen = false;
            List<String> summary = new ArrayList<>();
            for (Object itObj : items) {
                String it = str(itObj);
                String up = it.toUpperCase(Locale.ROOT);
                if (!first) w(o, " ");
                first = false;
                if (up.equals("UID")) w(o, "UID " + m.uid);
                else if (up.equals("FLAGS")) { summary.add("FLAGS"); w(o, "FLAGS (" + String.join(" ", flagsAfter(m, setSeen)) + ")"); }
                else if (up.equals("INTERNALDATE")) w(o, "INTERNALDATE \"" + new SimpleDateFormat("dd-MMM-yyyy HH:mm:ss Z", Locale.US).format(new Date(m.internalDate)) + "\"");
                else if (up.equals("RFC822.SIZE")) w(o, "RFC822.SIZE " + m.size());
                else if (up.equals("ENVELOPE")) { summary.add("ENVELOPE"); w(o, "ENVELOPE "); envelope(o, Mime.parse(m.raw)); }
                else if (up.equals("BODYSTRUCTURE") || up.equals("BODY")) { summary.add(up); w(o, up + " "); bodystructure(o, Mime.parse(m.raw)); }
                else if (up.equals("RFC822")) { setSeen = true; summary.add("RFC822"); w(o, "RFC822 "); literal(o, m.raw); }
                else if (up.equals("RFC822.HEADER")) { summary.add("HEADER"); w(o, "RFC822.HEADER "); literal(o, Mime.parse(m.raw).headerText.getBytes(StandardCharsets.ISO_8859_1)); }
                else if (up.equals("RFC822.TEXT")) { setSeen = true; summary.add("TEXT"); w(o, "RFC822.TEXT "); literal(o, Mime.parse(m.raw).body); }
                else if (up.startsWith("BODY[") || up.startsWith("BODY.PEEK[")) {
                    boolean peek = up.startsWith("BODY.PEEK[");
                    if (!peek) setSeen = true;
                    String sec = it.substring(it.indexOf('[') + 1, it.indexOf(']'));
                    String partial = it.substring(it.indexOf(']') + 1);
                    byte[] data = section(m, sec);
                    String label = "BODY[" + sec + "]";
                    if (partial.startsWith("<")) {
                        String[] pr = partial.substring(1, partial.length() - 1).split("\\.");
                        int start = Integer.parseInt(pr[0]);
                        int len = pr.length > 1 ? Integer.parseInt(pr[1]) : data.length;
                        int s = Math.min(start, data.length), e = Math.min(data.length, s + len);
                        data = java.util.Arrays.copyOfRange(data, s, e);
                        label += "<" + start + ">";
                    }
                    summary.add(label + (peek ? " (peek: \\Seen not set)" : ""));
                    w(o, label + " ");
                    literal(o, data);
                } else throw new IllegalArgumentException("unknown FETCH item " + it);
            }
            if (setSeen && !readOnly && !m.flags.contains("\\Seen")) {
                Set<String> f = new TreeSet<>(m.flags); f.add("\\Seen");
                ctx.store.setFlags(user, sel, m, f);
                synchronized (this) { seenFlags.put(m.uid, new TreeSet<>(f)); seenVersion = sel.version; }
                if (items.stream().noneMatch(x -> str(x).equalsIgnoreCase("FLAGS"))) w(o, " FLAGS (" + String.join(" ", f) + ")");
            }
            w(o, ")\r\n");
            sendBytes(o.toByteArray(), "* " + (i + 1) + " FETCH (" + (uid ? "UID " + m.uid + " " : "") + String.join(" ", summary) + " …)");
        }
        tagged(tag, "OK FETCH completed");
    }

    private Set<String> flagsAfter(MailStore.Message m, boolean seen) {
        Set<String> f = new TreeSet<>(m.flags);
        if (seen && !readOnly) f.add("\\Seen");
        return f;
    }

    /** BODY[section]: "", HEADER, TEXT, HEADER.FIELDS (..), HEADER.FIELDS.NOT (..), MIME, 1, 1.2, 2.TEXT … */
    private static byte[] section(MailStore.Message msg, String sec) {
        Mime.Part p = Mime.parse(msg.raw);
        if (sec.isEmpty()) return msg.raw;
        String[] path = sec.split("\\.");
        int i = 0;
        boolean wholeChild = false;
        while (i < path.length && path[i].matches("\\d+")) {
            int n = Integer.parseInt(path[i]);
            if (p.multipart()) { if (n - 1 >= p.children.size()) return new byte[0]; p = p.children.get(n - 1); }
            else if (n != 1) return new byte[0];
            i++; wholeChild = true;
        }
        if (i == path.length) return wholeChild ? p.body : msg.raw;
        String rest = String.join(".", java.util.Arrays.copyOfRange(path, i, path.length)).toUpperCase(Locale.ROOT);
        if (rest.equals("HEADER") || rest.equals("MIME")) return p.headerText.getBytes(StandardCharsets.ISO_8859_1);
        if (rest.equals("TEXT")) return p.body;
        if (rest.startsWith("HEADER.FIELDS")) {
            boolean not = rest.startsWith("HEADER.FIELDS.NOT");
            String list = sec.substring(sec.indexOf('(') + 1, sec.lastIndexOf(')'));
            Set<String> want = new java.util.HashSet<>();
            for (String s : list.trim().split("\\s+")) want.add(s.toLowerCase(Locale.ROOT));
            StringBuilder b = new StringBuilder();
            for (String[] h : p.headers) if (want.contains(h[0].toLowerCase(Locale.ROOT)) != not) b.append(h[0]).append(": ").append(h[1]).append("\r\n");
            return b.append("\r\n").toString().getBytes(StandardCharsets.UTF_8);
        }
        return new byte[0];
    }

    private void envelope(ByteArrayOutputStream o, Mime.Part p) {
        String from = p.header("From");
        w(o, "(" + nstr(p.header("Date")) + " " + nstr(p.header("Subject")) + " ");
        addrList(o, from); w(o, " ");
        addrList(o, p.header("Sender") != null ? p.header("Sender") : from); w(o, " ");
        addrList(o, p.header("Reply-To") != null ? p.header("Reply-To") : from); w(o, " ");
        addrList(o, p.header("To")); w(o, " ");
        addrList(o, p.header("Cc")); w(o, " ");
        addrList(o, p.header("Bcc")); w(o, " ");
        w(o, nstr(p.header("In-Reply-To")) + " " + nstr(p.header("Message-ID")) + ")");
    }

    private void addrList(ByteArrayOutputStream o, String h) {
        if (h == null || h.trim().isEmpty()) { w(o, "NIL"); return; }
        w(o, "(");
        for (String a : splitAddrs(h)) {
            String name = null, addr = a.trim();
            int lt = a.indexOf('<');
            if (lt >= 0) { name = a.substring(0, lt).trim().replace("\"", ""); addr = Mime.addr(a); }
            String mbox = addr.contains("@") ? addr.substring(0, addr.indexOf('@')) : addr;
            String host = addr.contains("@") ? addr.substring(addr.indexOf('@') + 1) : "";
            w(o, "(" + nstr(name == null || name.isEmpty() ? null : name) + " NIL " + nstr(mbox) + " " + nstr(host) + ")");
        }
        w(o, ")");
    }

    private static List<String> splitAddrs(String h) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean q = false; int angle = 0;
        for (char c : h.toCharArray()) {
            if (c == '"') q = !q;
            if (c == '<') angle++;
            if (c == '>') angle--;
            if (c == ',' && !q && angle == 0) { out.add(cur.toString()); cur.setLength(0); } else cur.append(c);
        }
        if (cur.length() > 0) out.add(cur.toString());
        return out;
    }

    private void bodystructure(ByteArrayOutputStream o, Mime.Part p) {
        if (p.multipart()) {
            w(o, "(");
            for (Mime.Part c : p.children) bodystructure(o, c);
            w(o, " " + quote(p.subtype.toUpperCase(Locale.ROOT)) + ")");
            return;
        }
        StringBuilder params = new StringBuilder();
        for (Map.Entry<String, String> e : p.params.entrySet()) params.append(params.length() > 0 ? " " : "").append(quote(e.getKey().toUpperCase(Locale.ROOT))).append(' ').append(quote(e.getValue()));
        w(o, "(" + quote(p.type.toUpperCase(Locale.ROOT)) + " " + quote(p.subtype.toUpperCase(Locale.ROOT)) + " "
                + (params.length() > 0 ? "(" + params + ")" : "NIL") + " NIL NIL " + quote(p.encoding.toUpperCase(Locale.ROOT)) + " " + p.body.length
                + (p.type.equals("text") ? " " + p.lines() : "") + ")");
    }

    // ================================================================== sets and lookups

    private List<MailStore.Message> messagesInView() {
        Map<Long, MailStore.Message> b = byUid();
        List<MailStore.Message> out = new ArrayList<>();
        for (long u : view) { MailStore.Message m = b.get(u); if (m != null) out.add(m); }
        return out;
    }

    private Map<Long, MailStore.Message> byUid() {
        Map<Long, MailStore.Message> b = new HashMap<>();
        for (MailStore.Message m : sel.list()) b.put(m.uid, m);
        return b;
    }

    /** Sequence set ("1:3,5,7:*") → 0-based indices into the view; with uid=true the numbers are UIDs. */
    private List<Integer> set(String s, boolean uid) {
        List<Integer> out = new ArrayList<>();
        if (view.isEmpty()) return out;
        long max = uid ? view.get(view.size() - 1) : view.size();
        for (String part : s.split(",")) {
            String[] r = part.split(":");
            long a = r[0].equals("*") ? max : Long.parseLong(r[0]);
            long b = r.length > 1 ? (r[1].equals("*") ? max : Long.parseLong(r[1])) : a;
            long lo = Math.min(a, b), hi = Math.max(a, b);
            if (uid && r.length > 1 && r[1].equals("*") && lo > max) lo = max;   // "n:*" always includes the last UID
            for (int i = 0; i < view.size(); i++) {
                long key = uid ? view.get(i) : i + 1;
                if (key >= lo && key <= hi && !out.contains(i)) out.add(i);
            }
        }
        java.util.Collections.sort(out);
        return out;
    }

    // ================================================================== command reader / tokenizer

    /** Read one command, handling {n} literals (we answer "+ Ready" and read n raw bytes). */
    private List<Object> readCommand() throws IOException {
        String line = readLine();
        if (line == null) return null;
        List<Object> tokens = new ArrayList<>();
        StringBuilder shown = new StringBuilder();
        while (true) {
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("\\{(\\d+)(\\+?)\\}$").matcher(line);
            if (m.find()) {
                String before = line.substring(0, m.start());
                shown.append(before);
                tokens.addAll(tokenize(before));
                int n = Integer.parseInt(m.group(1));
                if (m.group(2).isEmpty()) {
                    logClient(shown + "{" + n + "}", "a literal of " + n + " bytes follows");
                    send("+ Ready for literal data", "continuation request: send the " + n + " bytes");
                    shown.setLength(0);
                }
                byte[] lit = readBytes(n);
                tokens.add(lit);
                shown.append("{" + n + " bytes}");
                line = readLine();
                if (line == null) return null;
            } else {
                shown.append(line);
                tokens.addAll(tokenize(line));
                break;
            }
        }
        logClient(shown.toString(), cmdNote(tokens));
        return tokens;
    }

    private static List<Object> tokenize(String s) {
        List<Object> root = new ArrayList<>();
        java.util.Deque<List<Object>> stack = new java.util.ArrayDeque<>();
        stack.push(root);
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == ' ') { i++; continue; }
            if (c == '(') { List<Object> l = new ArrayList<>(); stack.peek().add(l); stack.push(l); i++; continue; }
            if (c == ')') { if (stack.size() > 1) stack.pop(); i++; continue; }
            if (c == '"') {
                StringBuilder b = new StringBuilder();
                i++;
                while (i < s.length() && s.charAt(i) != '"') { if (s.charAt(i) == '\\' && i + 1 < s.length()) i++; b.append(s.charAt(i++)); }
                i++;
                stack.peek().add(b.toString());
                continue;
            }
            StringBuilder b = new StringBuilder();
            int depth = 0;
            while (i < s.length()) {
                char d = s.charAt(i);
                if (d == '[') depth++;
                if (d == ']') depth--;
                if (depth == 0 && (d == ' ' || d == ')' || d == '(')) break;
                b.append(d); i++;
            }
            stack.peek().add(b.toString());
        }
        return root;
    }

    // ================================================================== output helpers

    private void untagged(String s, String note) throws IOException { send("* " + s, note); }
    private void tagged(String tag, String s) throws IOException {
        if (state == State.SELECTED && !s.startsWith("BAD") && !idling) sync(true);
        send(tag + " " + s, s.startsWith("OK") ? "command completed (tagged response ends it)" : s.startsWith("NO") ? "command failed" : "protocol error");
    }

    private static void w(ByteArrayOutputStream o, String s) { byte[] b = s.getBytes(StandardCharsets.UTF_8); o.write(b, 0, b.length); }
    private static void literal(ByteArrayOutputStream o, byte[] d) { w(o, "{" + d.length + "}\r\n"); o.write(d, 0, d.length); }

    private static String quote(String s) { return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""; }
    private static String nstr(String s) {
        if (s == null) return "NIL";
        if (s.indexOf('\r') >= 0 || s.indexOf('\n') >= 0) s = s.replace("\r", " ").replace("\n", " ");
        return quote(s);
    }

    private static String str(Object o) { return o instanceof byte[] ? new String((byte[]) o, StandardCharsets.UTF_8) : String.valueOf(o); }
    @SuppressWarnings("unchecked") private static List<Object> cast(Object o) { return (List<Object>) o; }
    private static String normFlag(String f) {
        String l = f.toLowerCase(Locale.ROOT);
        switch (l) {
            case "\\seen": return "\\Seen"; case "\\answered": return "\\Answered"; case "\\flagged": return "\\Flagged";
            case "\\deleted": return "\\Deleted"; case "\\draft": return "\\Draft"; default: return f;
        }
    }

    private String bodyText(MailStore.Message m) {
        Mime.Part p = Mime.parse(m.raw);
        while (p.multipart() && !p.children.isEmpty()) p = p.children.get(0);
        return p.text();
    }

    private static String cmdNote(List<Object> t) {
        if (t.size() < 2) return "";
        String c = str(t.get(1)).toUpperCase(Locale.ROOT);
        if (c.equals("UID") && t.size() > 2) c = "UID " + str(t.get(2)).toUpperCase(Locale.ROOT);
        switch (c) {
            case "LOGIN": return "user + password (plain text unless STARTTLS/TLS)";
            case "CAPABILITY": return "what can you do?";
            case "LIST": return "which folders exist on the server?";
            case "SELECT": return "open a folder read-write";
            case "EXAMINE": return "open a folder read-only";
            case "STATUS": return "counts of a folder without opening it";
            case "FETCH": case "UID FETCH": return "get parts of messages (headers, flags, body…)";
            case "STORE": case "UID STORE": return "change flags (e.g. +FLAGS (\\Seen) = mark as read)";
            case "SEARCH": case "UID SEARCH": return "search done by the SERVER";
            case "COPY": case "UID COPY": return "copy messages to another folder";
            case "MOVE": case "UID MOVE": return "move messages to another folder";
            case "EXPUNGE": return "permanently remove \\Deleted messages";
            case "APPEND": return "upload a message into a folder (e.g. Sent)";
            case "IDLE": return "wait for the server to PUSH changes";
            case "CREATE": return "create a folder on the server";
            case "LOGOUT": return "end the session";
            case "NOOP": return "nothing — but lets the server report changes";
            default: return "";
        }
    }
}

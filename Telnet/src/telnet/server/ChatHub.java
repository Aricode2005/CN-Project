package telnet.server;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import telnet.core.Hub;
import telnet.core.Json;

/**
 * Multi-terminal WhatsApp-style Group Chat & Direct Messaging hub shared across all VTY lines.
 *
 * Features:
 *  - Named chat rooms/groups (default "#general", or switch via "/room <name>")
 *  - Real-time message broadcast with delivery ticks (✓ single / ✓✓ delivered to N peers)
 *  - Quoted replies ("/reply <id> <text>") and reactions ("/react <id> <emoji>")
 *  - Direct messages ("/dm <user|vty> <text>") across VTY lines
 *  - Live character-at-a-time typing indicators (powered by Telnet WILL ECHO + WILL SGA)
 *  - Transport security badge per message (telnets [TLS] vs plaintext [PLAIN])
 */
public final class ChatHub {

    public static final class ChatMessage {
        public final int id;
        public final long time;
        public final String room;
        public final String sender;       // e.g. "admin"
        public final int senderLine;      // e.g. 0 for vty0, -1 for dashboard/system
        public final String transport;    // "telnets", "telnet", "system", "web"
        public final String kind;         // "msg", "dm", "system"
        public final String dmTarget;     // non-null for DMs
        public final int replyToId;       // >0 if quoting an earlier message
        public final String replyPreview; // snippet of the quoted message
        public final String text;
        public volatile int deliveredCount;
        public final Map<String, Set<String>> reactions = new LinkedHashMap<>(); // emoji -> set of users

        ChatMessage(int id, String room, String sender, int senderLine, String transport,
                    String kind, String dmTarget, int replyToId, String replyPreview, String text, int deliveredCount) {
            this.id = id;
            this.time = System.currentTimeMillis();
            this.room = room;
            this.sender = sender;
            this.senderLine = senderLine;
            this.transport = transport;
            this.kind = kind;
            this.dmTarget = dmTarget;
            this.replyToId = replyToId;
            this.replyPreview = replyPreview;
            this.text = text;
            this.deliveredCount = deliveredCount;
        }

        public synchronized void addReaction(String emoji, String user) {
            reactions.computeIfAbsent(emoji, k -> new LinkedHashSet<>()).add(user);
        }

        public synchronized String reactionsSummary() {
            if (reactions.isEmpty()) return "";
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, Set<String>> e : reactions.entrySet()) {
                if (sb.length() > 0) sb.append(' ');
                sb.append('[').append(e.getKey()).append(' ').append(String.join(",", e.getValue())).append(']');
            }
            return sb.toString();
        }

        public synchronized String json() {
            List<String> rList = new ArrayList<>();
            for (Map.Entry<String, Set<String>> e : reactions.entrySet()) {
                List<String> uList = new ArrayList<>();
                for (String u : e.getValue()) uList.add(Json.str(u));
                rList.add(Json.obj("emoji", e.getKey(), "users", Json.raw(Json.arr(uList))));
            }
            return Json.obj(
                    "id", id,
                    "time", time,
                    "room", room,
                    "sender", sender,
                    "line", senderLine,
                    "transport", transport,
                    "kind", kind,
                    "dmTarget", dmTarget == null ? "" : dmTarget,
                    "replyToId", replyToId,
                    "replyPreview", replyPreview == null ? "" : replyPreview,
                    "text", text,
                    "delivered", deliveredCount,
                    "reactions", Json.raw(Json.arr(rList))
            );
        }
    }

    /** One chat for every router: the standalone router (2323) and the HA cluster nodes behind 2330 share it,
     *  so users the load balancer put on different nodes still talk in the same rooms. */
    public static final ChatHub SHARED = new ChatHub();

    private static List<TelnetSession> sessions() { return VtyPool.allSessions(); }

    /** "vty0" on the standalone router, "vty0@R2" on cluster node R2 (line numbers repeat across nodes). */
    public static String where(TelnetSession s) {
        String n = s.pool() == null ? "" : s.pool().node;
        return "vty" + s.line + (n == null || n.isEmpty() ? "" : "@" + n);
    }

    private final AtomicInteger msgIds = new AtomicInteger();
    private final CopyOnWriteArrayList<ChatMessage> messages = new CopyOnWriteArrayList<>();
    private final Set<String> knownRooms = ConcurrentHashMap.newKeySet();
    private final SimpleDateFormat timeFmt = new SimpleDateFormat("HH:mm:ss");

    private ChatHub() {
        knownRooms.add("#general");
        knownRooms.add("#netops");
        knownRooms.add("#security");
    }

    public static String normalizeRoom(String raw) {
        if (raw == null || raw.trim().isEmpty()) return "#general";
        String r = raw.trim().toLowerCase().replaceAll("[^a-z0-9_#-]", "");
        if (r.isEmpty()) return "#general";
        return r.startsWith("#") ? r : "#" + r;
    }

    public Set<String> rooms() {
        Set<String> all = new LinkedHashSet<>(knownRooms);
        for (TelnetSession s : sessions()) {
            if (s.mode == TelnetSession.Mode.CHAT && s.chatRoom != null) all.add(s.chatRoom);
        }
        return all;
    }

    public List<TelnetSession> membersInRoom(String room) {
        String r = normalizeRoom(room);
        List<TelnetSession> list = new ArrayList<>();
        for (TelnetSession s : sessions()) {
            if (s.mode == TelnetSession.Mode.CHAT && r.equals(s.chatRoom)) list.add(s);
        }
        return list;
    }

    public ChatMessage findMessage(int id) {
        for (int i = messages.size() - 1; i >= 0; i--) {
            ChatMessage m = messages.get(i);
            if (m.id == id) return m;
        }
        return null;
    }

    public List<ChatMessage> recentForRoom(String room, int limit) {
        String r = normalizeRoom(room);
        List<ChatMessage> out = new ArrayList<>();
        for (ChatMessage m : messages) {
            if (r.equals(m.room) && !"dm".equals(m.kind)) out.add(m);
        }
        if (out.size() > limit) return new ArrayList<>(out.subList(out.size() - limit, out.size()));
        return out;
    }

    /** Called when a VTY session joins a room. */
    public void onJoin(TelnetSession s, String room) {
        String r = normalizeRoom(room);
        knownRooms.add(r);
        s.chatRoom = r;
        int others = 0;
        for (TelnetSession peer : membersInRoom(r)) {
            if (peer != s) others++;
        }
        ChatMessage sys = record(r, s.user, s.line, s.transport, "system", null, 0, null,
                s.user + " (vty" + s.line + ", " + badge(s.transport) + ") joined " + r, others + 1);
        for (TelnetSession peer : membersInRoom(r)) {
            if (peer != s) peer.deliverChatLine(formatTerminalLine(sys, peer));
        }
        Hub.I.log("[CHAT] " + s.user + " (vty" + s.line + ") joined " + r);
    }

    /** Called when a VTY session leaves a room. */
    public void onLeave(TelnetSession s, String reason) {
        String r = s.chatRoom;
        if (r == null || r.isEmpty()) return;
        List<TelnetSession> peers = membersInRoom(r);
        int others = 0;
        for (TelnetSession peer : peers) if (peer != s) others++;
        ChatMessage sys = record(r, s.user, s.line, s.transport, "system", null, 0, null,
                s.user + " (vty" + s.line + ") left " + r + (reason != null && !reason.isEmpty() ? " (" + reason + ")" : ""), others);
        for (TelnetSession peer : peers) {
            if (peer != s) peer.deliverChatLine(formatTerminalLine(sys, peer));
        }
        Hub.I.log("[CHAT] " + s.user + " (vty" + s.line + ") left " + r);
    }

    /** Post a group message from a VTY session (or reply if replyToId > 0). */
    public ChatMessage postGroupMessage(TelnetSession sender, String text, int replyToId) {
        String r = normalizeRoom(sender.chatRoom);
        knownRooms.add(r);
        String preview = null;
        int validReply = 0;
        if (replyToId > 0) {
            ChatMessage orig = findMessage(replyToId);
            if (orig != null) {
                validReply = orig.id;
                preview = orig.sender + ": " + clip(orig.text, 36);
            }
        }
        List<TelnetSession> recipients = membersInRoom(r);
        int delivered = Math.max(1, recipients.size());
        ChatMessage msg = record(r, sender.user, sender.line, sender.transport, "msg", null, validReply, preview, text, delivered);
        for (TelnetSession peer : recipients) {
            peer.deliverChatLine(formatTerminalLine(msg, peer));
        }
        Hub.I.log("[CHAT] " + r + " #" + msg.id + " " + sender.user + "@vty" + sender.line + " (" + sender.transport + "): " + text);
        return msg;
    }

    /** Post a group message from the Web Dashboard. */
    public ChatMessage postWebMessage(String room, String senderName, String text) {
        String r = normalizeRoom(room);
        knownRooms.add(r);
        String sender = (senderName == null || senderName.trim().isEmpty()) ? "web-admin" : senderName.trim();
        List<TelnetSession> recipients = membersInRoom(r);
        int delivered = recipients.size() + 1;
        ChatMessage msg = record(r, sender, -1, "web", "msg", null, 0, null, text, delivered);
        for (TelnetSession peer : recipients) {
            peer.deliverChatLine(formatTerminalLine(msg, peer));
        }
        Hub.I.log("[CHAT] " + r + " #" + msg.id + " " + sender + "@web: " + text);
        return msg;
    }

    /** Send a Direct Message (/dm) to a username or vty line (e.g., "admin" or "vty1" or "1"). */
    public String sendDirectMessage(TelnetSession sender, String targetSpec, String text) {
        List<TelnetSession> targets = new ArrayList<>();
        String spec = targetSpec.trim();
        int lineNo = -1;
        if (spec.toLowerCase().startsWith("vty")) {
            try { lineNo = Integer.parseInt(spec.substring(3)); } catch (NumberFormatException ignored) { }
        } else if (spec.matches("\\d+")) {
            try { lineNo = Integer.parseInt(spec); } catch (NumberFormatException ignored) { }
        }
        if (lineNo >= 0) {
            TelnetSession t = sender.pool().byLine(lineNo);          // own router first, then any node
            if (t == null || t.user.isEmpty()) for (TelnetSession x : sessions()) if (x.line == lineNo && !x.user.isEmpty()) { t = x; break; }
            if (t != null && !t.user.isEmpty()) targets.add(t);
        } else {
            for (TelnetSession s : sessions()) {
                if (s.user.equalsIgnoreCase(spec)) targets.add(s);
            }
        }
        if (targets.isEmpty()) {
            return "% No online user or VTY line matching '" + targetSpec + "'. Use /members to see active terminals.";
        }
        String label = targets.get(0).user + "@vty" + targets.get(0).line;
        ChatMessage dm = record(sender.chatRoom, sender.user, sender.line, sender.transport, "dm", label, 0, null, text, targets.size());
        sender.deliverChatLine(formatTerminalLine(dm, sender));
        for (TelnetSession t : targets) {
            if (t == sender) continue;
            if (t.mode == TelnetSession.Mode.CHAT) {
                t.deliverChatLine(formatTerminalLine(dm, t));
            } else {
                t.notifyAsync("*** [WhatsApp DM from " + sender.user + "@vty" + sender.line + "]: " + text
                        + " (type 'chat' to open group chat) ***");
            }
        }
        Hub.I.log("[CHAT-DM] " + sender.user + "@vty" + sender.line + " -> " + label + ": " + text);
        return null;
    }

    /** Add a reaction to a message ID and notify everyone in that message's room. */
    public String react(String user, int line, String room, int msgId, String emoji) {
        ChatMessage m = findMessage(msgId);
        if (m == null) return "% Message #" + msgId + " not found.";
        m.addReaction(emoji, user);
        String notice = "  * " + user + (line >= 0 ? "@vty" + line : "@web") + " reacted " + emoji
                + " to #" + m.id + " (\"" + clip(m.text, 28) + "\")  " + m.reactionsSummary();
        for (TelnetSession peer : membersInRoom(m.room)) {
            peer.deliverChatLine(notice);
        }
        Hub.I.log("[CHAT] " + user + " reacted " + emoji + " to #" + m.id);
        return null;
    }

    /** Format a chat message for display on a VTY terminal (ANSI-aware if supported). */
    public String formatTerminalLine(ChatMessage m, TelnetSession viewer) {
        String ts;
        synchronized (timeFmt) { ts = timeFmt.format(new Date(m.time)); }
        boolean ansi = viewer != null && viewer.ansi();
        if ("system".equals(m.kind)) {
            String line = "[" + ts + "] * " + m.text;
            return ansi ? "\u001b[1m" + line + "\u001b[0m" : line;
        }
        boolean isMe = viewer != null && m.senderLine == viewer.line && m.sender.equals(viewer.user);
        String who = isMe ? "You (" + m.sender + "@vty" + m.senderLine + ")"
                : (m.senderLine >= 0 ? m.sender + "@vty" + m.senderLine : m.sender + "@web");
        String secBadge = badge(m.transport);
        // plain ASCII: the NVT is 7-bit, so a Telnet terminal would show "??" for check marks
        String ticks = m.deliveredCount > 1 ? "delivered(" + m.deliveredCount + ")" : "sent";
        StringBuilder sb = new StringBuilder();
        if (m.replyToId > 0 && m.replyPreview != null) {
            sb.append("           > re #").append(m.replyToId).append(' ').append(m.replyPreview).append("\n");
        }
        if ("dm".equals(m.kind)) {
            String dmHdr = "[" + ts + "] [DM #" + m.id + "] " + who + " -> " + m.dmTarget + " [" + secBadge + "]: ";
            sb.append(ansi ? "\u001b[7m" + dmHdr + "\u001b[0m " : dmHdr).append(m.text).append("  ").append(ticks);
        } else {
            String hdr = "[" + ts + "] [#" + m.id + "] " + who + " [" + secBadge + "]: ";
            sb.append(ansi && isMe ? "\u001b[1m" + hdr + "\u001b[0m" : hdr).append(m.text).append("  ").append(ticks);
        }
        String rx = m.reactionsSummary();
        if (!rx.isEmpty()) sb.append(' ').append(rx);
        return sb.toString();
    }

    public static String badge(String transport) {
        if ("telnets".equalsIgnoreCase(transport)) return "TLS";
        if ("web".equalsIgnoreCase(transport)) return "WEB";
        return "PLAIN";
    }

    private ChatMessage record(String room, String sender, int line, String transport,
                               String kind, String dmTarget, int replyToId, String replyPreview, String text, int delivered) {
        ChatMessage m = new ChatMessage(msgIds.incrementAndGet(), room, sender, line, transport, kind, dmTarget, replyToId, replyPreview, text, delivered);
        messages.add(m);
        while (messages.size() > 250) messages.remove(0);
        return m;
    }

    private static String clip(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max - 3) + "...";
    }

    /** Build JSON state for the Web Dashboard (/api/state). */
    public String json() {
        List<String> roomJson = new ArrayList<>();
        for (String r : rooms()) {
            List<String> mems = new ArrayList<>();
            for (TelnetSession s : membersInRoom(r)) {
                boolean typing = s.isTypingInChat();
                mems.add(Json.obj(
                        "line", s.line,
                        "node", s.pool() == null ? "" : s.pool().node,
                        "user", s.user,
                        "transport", s.transport,
                        "status", s.chatStatus,
                        "typing", typing
                ));
            }
            roomJson.add(Json.obj("name", r, "members", Json.raw(Json.arr(mems))));
        }
        List<String> msgJson = new ArrayList<>();
        int start = Math.max(0, messages.size() - 60);
        for (int i = start; i < messages.size(); i++) {
            msgJson.add(messages.get(i).json());
        }
        return Json.obj(
                "rooms", Json.raw(Json.arr(roomJson)),
                "messages", Json.raw(Json.arr(msgJson))
        );
    }
}

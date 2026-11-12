package boot.rarp;

import java.util.ArrayList;
import java.util.List;
import boot.Topology;
import boot.Topology.Station;
import boot.core.Field;
import boot.core.Hub;
import boot.core.Json;

/**
 * A simulated Ethernet: RARP is a layer-2 protocol (EtherType 0x8035, no IP, no UDP), so it cannot be
 * sent through Java sockets. Frames here are real RARP frames, byte for byte; the LAN delivers them:
 * a broadcast reaches every station on the same segment, and the router does NOT forward it.
 */
public final class Lan {

    private final Topology topo;
    public Lan(Topology topo) { this.topo = topo; }

    public static final class Event {
        public final double t; public final String kind, from, segment, note; public final List<String> to; public final byte[] frame;
        Event(double t, String kind, String from, List<String> to, String segment, String note, byte[] frame) { this.t = t; this.kind = kind; this.from = from; this.to = to; this.segment = segment; this.note = note; this.frame = frame; }
        public String json() {
            List<String> tt = new ArrayList<>(); for (String s : to) tt.add(Json.str(s));
            String fr = "null", fields = "[]";
            if (frame != null) {
                List<String> f = new ArrayList<>(); for (Field x : Rarp.decode(frame).fields) f.add(x.json());
                fr = Json.str(Field.hex(frame)); fields = "[" + String.join(",", f) + "]";
            }
            return Json.obj("t", t, "kind", kind, "from", from, "to", Json.raw("[" + String.join(",", tt) + "]"), "segment", segment, "note", note, "hex", Json.raw(fr), "fields", Json.raw(fields));
        }
    }

    /** Power on a diskless workstation: it broadcasts RARP requests until a server answers (3 tries). */
    public synchronized List<Event> boot(String wsName) {
        List<Event> ev = new ArrayList<>();
        Station ws = topo.station(wsName);
        if (ws == null || ws.fixedIp != null) { ev.add(new Event(0, "error", "-", List.of(), "", "not a diskless workstation: " + wsName, null)); return ev; }
        String sid = "rarp:" + ws.name;
        ev.add(new Event(0, "power", ws.name, List.of(), ws.segment, ws.name + " powers on. It has no disk, so it knows only its MAC " + ws.mac + " (burned into the network card). It needs an IP address before it can do anything over IP.", null));
        double t = 2;
        for (int attempt = 1; attempt <= 3; attempt++) {
            byte[] req = Rarp.frame(Rarp.BROADCAST, ws.mac, Rarp.REQUEST, ws.mac, "0.0.0.0", ws.mac, "0.0.0.0");
            List<String> hear = new ArrayList<>();
            for (Station s : topo.stations) if (s.segment.equals(ws.segment) && s != ws) hear.add(s.name);
            ev.add(new Event(t, "broadcast", ws.name, hear, ws.segment, (attempt > 1 ? "Retry " + attempt + ": " : "") + "RARP request to ff:ff:ff:ff:ff:ff (op 3): \"my MAC is " + ws.mac + ", what is my IP?\" Every station on LAN " + ws.segment + " receives the frame.", req));
            Hub.I.line(new Hub.Line(sid, "RARP", true, "RARP request (op 3) broadcast from " + ws.mac + " on LAN " + ws.segment, attempt > 1 ? "retry " + attempt : "who knows my IP?"));
            t += 1;
            ev.add(new Event(t, "blocked", "ROUTER" + (ws.segment.equals("B") ? "-B" : ""), List.of(), ws.segment, "The router receives the broadcast but does not forward it: link-layer broadcasts stop at the router. " +
                    (ws.segment.equals("B") ? "The RARP server is on LAN A, so it never hears this request." : "(Nothing else needs it here.)"), null));
            Station srv = null;
            for (Station s : topo.stations) if (s.segment.equals(ws.segment) && s.role.startsWith("RARP")) srv = s;
            Topology.Entry e = srv == null ? null : topo.table.get(ws.mac);
            if (srv != null) {
                t += 2;
                if (e == null) {
                    ev.add(new Event(t, "lookup", srv.name, List.of(), ws.segment, "The RARP server looks up " + ws.mac + " in /etc/ethers: no entry. It stays silent (RARP has no \"not found\" reply).", null));
                    Hub.I.line(new Hub.Line(sid, "RARP", false, "server: " + ws.mac + " not in /etc/ethers, no reply", "RARP servers only answer known MACs"));
                } else {
                    ev.add(new Event(t, "lookup", srv.name, List.of(), ws.segment, "The RARP server finds " + ws.mac + " → " + e.ip + " in /etc/ethers.", null));
                    t += 1;
                    byte[] rep = Rarp.frame(ws.mac, srv.mac, Rarp.REPLY, srv.mac, srv.fixedIp, ws.mac, e.ip);
                    ev.add(new Event(t, "unicast", srv.name, List.of(ws.name), ws.segment, "RARP reply (op 4) sent unicast to " + ws.mac + ": \"your IP is " + e.ip + "\". The reply carries an IP address only: no subnet mask, no router, no boot file.", rep));
                    Hub.I.line(new Hub.Line(sid, "RARP", false, "RARP reply (op 4) " + srv.mac + " → " + ws.mac + ": TPA = " + e.ip, "IP address only"));
                    t += 1;
                    ev.add(new Event(t, "done", ws.name, List.of(), ws.segment, ws.name + " now knows its IP: " + e.ip + ". Next it would still need a mask, a router and its boot image from elsewhere (TFTP to the server).", null));
                    Hub.I.event("RARP", ws.name + " (" + ws.mac + ") learned " + e.ip);
                    return ev;
                }
            }
            t += 1000.0 * attempt;
            ev.add(new Event(t, "timeout", ws.name, List.of(), ws.segment, "No reply after " + attempt + " s. The workstation waits longer and tries again.", null));
        }
        ev.add(new Event(t + 1, "fail", ws.name, List.of(), ws.segment, ws.name + " gives up: " + (ws.segment.equals("B") ? "the RARP server is on the other side of a router, and RARP cannot cross routers. Every LAN would need its own RARP server." : "nobody has its MAC registered."), null));
        Hub.I.event("RARP", ws.name + " got no answer");
        return ev;
    }
}

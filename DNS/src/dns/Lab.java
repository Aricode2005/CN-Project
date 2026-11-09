package dns;

import java.util.ArrayList;
import java.util.List;
import dns.server.AuthServer;
import dns.zone.Zone;
import static dns.wire.Message.*;

/**
 * A miniature Internet naming tree, every level a real UDP/TCP DNS server on its own loopback address:
 *
 *   a.root-servers.lab   127.0.0.10   "."                 delegates edu. (and the reverse zone)
 *   ns.edu-servers.lab   127.0.0.11   "edu."              delegates myuniv.edu.
 *   ns1.myuniv.edu       127.0.0.12   "myuniv.edu."       delegates cse.myuniv.edu.
 *   dns.cse.myuniv.edu   127.0.0.13   "cse.myuniv.edu."   the Assignment 6 records, authoritative
 */
public final class Lab {

    public static final int PORT = 5300;
    public final List<AuthServer> servers = new ArrayList<>();
    public final Zone root = new Zone(""), edu = new Zone("edu"), uni = new Zone("myuniv.edu"), cse = new Zone("cse.myuniv.edu"), rev = new Zone("151.168.192.in-addr.arpa");
    public AuthServer cseServer;

    public Lab() {
        root.add("@", SOA, 86400, "a.root-servers.lab nstld.root-servers.lab 2026110901 1800 900 604800 86400")
            .add("@", NS, 518400, "a.root-servers.lab")
            .add("a.root-servers.lab", A, 518400, "127.0.0.10")
            .add("edu", NS, 172800, "ns.edu-servers.lab")
            .add("ns.edu-servers.lab", A, 172800, "127.0.0.11")
            .add("151.168.192.in-addr.arpa", NS, 86400, "dns.cse.myuniv.edu")
            .add("dns.cse.myuniv.edu", A, 86400, "127.0.0.13");

        edu.add("@", SOA, 86400, "ns.edu-servers.lab hostmaster.edu-servers.lab 2026110901 1800 900 604800 86400")
           .add("@", NS, 172800, "ns.edu-servers.lab")
           .add("myuniv.edu", NS, 172800, "ns1.myuniv.edu")
           .add("ns1.myuniv.edu", A, 172800, "127.0.0.12");

        uni.add("@", SOA, 3600, "ns1.myuniv.edu hostmaster.myuniv.edu 2026110901 3600 600 604800 300")
           .add("@", NS, 86400, "ns1.myuniv.edu")
           .add("ns1.myuniv.edu", A, 86400, "127.0.0.12")
           .add("www.myuniv.edu", A, 600, "192.168.150.10")
           .add("cse.myuniv.edu", NS, 86400, "dns.cse.myuniv.edu")
           .add("dns.cse.myuniv.edu", A, 86400, "127.0.0.13");

        // Assignment 6, Q7 (192.168.151.0/24) + mail, MX, TXT for the Mail module
        cse.add("@", SOA, 3600, "dns.cse.myuniv.edu admin.cse.myuniv.edu 2026110901 3600 600 604800 60")
           .add("@", NS, 86400, "dns.cse.myuniv.edu")
           .add("dns.cse.myuniv.edu", A, 86400, "127.0.0.13")
           .add("dhcp.cse.myuniv.edu", A, 300, "192.168.151.2")
           .add("www.cse.myuniv.edu", A, 120, "192.168.151.4")
           .add("ftp.cse.myuniv.edu", A, 300, "192.168.151.5")
           .add("web.cse.myuniv.edu", CNAME, 300, "www.cse.myuniv.edu")
           .add("@", MX, 300, "10 mail.cse.myuniv.edu")
           .add("mail.cse.myuniv.edu", A, 300, "127.0.0.1")
           .add("@", TXT, 300, "\"v=spf1 a:mail.cse.myuniv.edu -all\"")
           .add("dns.cse.myuniv.edu", TXT, 300, "\"Packet Tracer address 192.168.151.3; in this lab it listens on 127.0.0.13:5300\"")
           .add("bank.cse.myuniv.edu", A, 300, "192.168.151.20");
        StringBuilder big = new StringBuilder();
        for (int i = 1; i <= 12; i++) big.append(String.format("\"line %02d of a long TXT record: big answers do not fit in 512 bytes of UDP\" ", i));
        cse.add("big.cse.myuniv.edu", TXT, 300, big.toString().trim());

        rev.add("@", SOA, 3600, "dns.cse.myuniv.edu admin.cse.myuniv.edu 2026110901 3600 600 604800 60")
           .add("@", NS, 86400, "dns.cse.myuniv.edu")
           .add("2.151.168.192.in-addr.arpa", PTR, 300, "dhcp.cse.myuniv.edu")
           .add("3.151.168.192.in-addr.arpa", PTR, 300, "dns.cse.myuniv.edu")
           .add("4.151.168.192.in-addr.arpa", PTR, 300, "www.cse.myuniv.edu")
           .add("5.151.168.192.in-addr.arpa", PTR, 300, "ftp.cse.myuniv.edu")
           .add("20.151.168.192.in-addr.arpa", PTR, 300, "bank.cse.myuniv.edu");
    }

    public Lab start() throws Exception {
        servers.add(new AuthServer("root", "a.root-servers.lab", "127.0.0.10", PORT, List.of(root)).start());
        servers.add(new AuthServer("edu", "ns.edu-servers.lab", "127.0.0.11", PORT, List.of(edu)).start());
        servers.add(new AuthServer("myuniv", "ns1.myuniv.edu", "127.0.0.12", PORT, List.of(uni)).start());
        cseServer = new AuthServer("cse", "dns.cse.myuniv.edu", "127.0.0.13", PORT, List.of(cse, rev)).start();
        servers.add(cseServer);
        return this;
    }

    public void stop() { for (AuthServer s : servers) s.stop(); }
}

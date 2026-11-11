"""
Interoperability test: a BOOTP client written independently in Python (struct, RFC 951 layout)
talks to OUR Java BOOTP server and relay agent.
Start the lab first (run.bat), then:   python interop_test.py
"""
import random, socket, struct, sys

ok = fail = 0
def check(name, cond, detail=""):
    global ok, fail
    ok, fail = (ok + 1, fail) if cond else (ok, fail + 1)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name:<60} {detail}")

def ip(b): return ".".join(str(x) for x in b)

def bootp(mac, port):
    xid = random.randint(0, 0xFFFFFFFF)
    chaddr = bytes(int(x, 16) for x in mac.split(":")) + bytes(10)
    pkt = struct.pack(">BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, xid, 0, 0, bytes(4), bytes(4), bytes(4), bytes(4), chaddr, bytes(64), bytes(128))
    pkt += bytes([99, 130, 83, 99, 255]) + bytes(59)                       # vendor area: magic cookie + END
    assert len(pkt) == 300
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 1068)); s.settimeout(3)
    s.sendto(pkt, ("127.0.0.1", port))
    try:
        while True:
            d, _ = s.recvfrom(1500)
            if struct.unpack(">I", d[4:8])[0] == xid: return xid, d
    finally:
        s.close()

print("\n--- Python BOOTP client -> our server (LAN A) ----------------------------------")
xid, d = bootp("08:00:20:0a:01:02", 1067)
check("BOOTREPLY (op 2), 300 bytes, same xid", d[0] == 2 and len(d) == 300, f"xid=0x{xid:08x}")
check("yiaddr = 10.0.1.22", ip(d[16:20]) == "10.0.1.22", ip(d[16:20]))
check("siaddr = boot server 10.0.1.5", ip(d[20:24]) == "10.0.1.5")
check("file = /tftpboot/sunos-ws2.img", d[108:236].rstrip(b"\0").decode() == "/tftpboot/sunos-ws2.img")
check("vendor area: magic cookie, then option 1 (mask 255.255.255.0)", d[236:240] == bytes([99, 130, 83, 99]) and d[240] == 1 and ip(d[242:246]) == "255.255.255.0")

print("\n--- Python BOOTP client -> relay agent (LAN B) -> our server ---------------------")
xid, d = bootp("08:00:20:0a:02:04", 2067)
check("reply came back through the relay: yiaddr = 10.0.2.24", ip(d[16:20]) == "10.0.2.24")
check("giaddr = 10.0.2.1 and hops = 1 (set by the relay agent)", ip(d[24:28]) == "10.0.2.1" and d[3] == 1, f"giaddr={ip(d[24:28])} hops={d[3]}")

print(f"\n  {ok} passed, {fail} failed")
sys.exit(1 if fail else 0)

"""
Interoperability test: tools we did NOT write talk to OUR DNS servers.
  1. Windows' own nslookup  (a real-world DNS client)
  2. a DNS packet built by hand in Python with struct (an independent implementation of RFC 1035)
Start the lab first (run.bat), then:   python interop_test.py
"""
import random, socket, struct, subprocess, sys

ok = fail = 0
def check(name, cond, detail=""):
    global ok, fail
    ok, fail = (ok + 1, fail) if cond else (ok, fail + 1)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name:<62} {detail}")

def nslookup(*args):
    p = subprocess.run(["nslookup", *args], capture_output=True, text=True, timeout=20)
    return p.stdout + p.stderr

def raw_query(server, port, name, qtype=1, rd=1):
    tid = random.randint(0, 0xFFFF)
    q = struct.pack(">HHHHHH", tid, 0x0100 if rd else 0, 1, 0, 0, 0)
    q += b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0" + struct.pack(">HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
    s.sendto(q, (server, port)); d, _ = s.recvfrom(4096)
    rid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", d[:12])
    return tid, rid, flags, an, ns, ar, d

def has(out, *words): return all(w in out for w in words)

print("\n--- Windows nslookup -> our recursive resolver ----------------------------------")
out = nslookup("www.cse.myuniv.edu", "127.0.0.1")
port53 = "192.168.151.4" in out
if not port53:
    out = nslookup("-port=5300", "www.cse.myuniv.edu", "127.0.0.1")
P = [] if port53 else ["-port=5300"]
check("nslookup www.cse.myuniv.edu -> 192.168.151.4", "192.168.151.4" in out, "port 53" if port53 else "port 5300")
out = nslookup(*P, "web.cse.myuniv.edu", "127.0.0.1")
check("nslookup web (CNAME alias of www)", has(out, "www.cse.myuniv.edu", "192.168.151.4"))
out = nslookup(*P, "-type=MX", "cse.myuniv.edu", "127.0.0.1")
check("nslookup -type=MX cse.myuniv.edu", "mail.cse.myuniv.edu" in out)
out = nslookup(*P, "192.168.151.5", "127.0.0.1")
check("reverse: nslookup 192.168.151.5 -> ftp.cse.myuniv.edu", "ftp.cse.myuniv.edu" in out)
out = nslookup(*P, "nosuch.cse.myuniv.edu", "127.0.0.1")
check("nslookup of a missing name reports non-existent domain", "Non-existent" in out or "NXDOMAIN" in out)
out = nslookup("-norecurse", "www.cse.myuniv.edu", "127.0.0.10")
check("nslookup -norecurse to the lab root: no address (only a referral)", "192.168.151.4" not in out and "127.0.0.10" in out and "No response" not in out)
out = nslookup("www.cse.myuniv.edu", "127.0.0.10")
check("nslookup (RD=1) to the lab root: it recurses down the chain", "192.168.151.4" in out)
out = nslookup("www.cse.myuniv.edu", "127.0.0.13")
check("nslookup straight to the authoritative cse server", "192.168.151.4" in out)

print("\n--- hand-built packets (Python struct) -----------------------------------------")
tid, rid, flags, an, ns, ar, d = raw_query("127.0.0.1", 5300, "dhcp.cse.myuniv.edu")
check("resolver: ID echoed, QR=1, RA=1, one answer", tid == rid and flags & 0x8000 and flags & 0x80 and an == 1, f"flags=0x{flags:04x}")
check("answer RDATA = 192.168.151.2", d[-4:] == bytes([192, 168, 151, 2]))
tid, rid, flags, an, ns, ar, d = raw_query("127.0.0.13", 5300, "www.cse.myuniv.edu", rd=0)
check("authoritative server: AA=1, RA=0", flags & 0x0400 and not flags & 0x80, f"flags=0x{flags:04x}")
tid, rid, flags, an, ns, ar, d = raw_query("127.0.0.11", 5300, "www.cse.myuniv.edu", rd=0)
check(".edu server: referral (an=0, ns=1, glue ar=1)", an == 0 and ns == 1 and ar == 1, f"an={an} ns={ns} ar={ar}")
tid, rid, flags, an, ns, ar, d = raw_query("127.0.0.13", 5300, "big.cse.myuniv.edu", qtype=16, rd=0)
check("big TXT over UDP: TC bit set, reply kept within 512 bytes", flags & 0x0200 and len(d) <= 512, f"{len(d)} bytes")

print(f"\n  {ok} passed, {fail} failed")
sys.exit(1 if fail else 0)

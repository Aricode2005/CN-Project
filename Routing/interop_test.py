"""
Interoperability test: an independent decoder (written separately in Python, straight from the RFCs)
checks the bytes our Java routers actually put on the wire.
  1. RIPv2 (RFC 2453): header, 20-byte entries, AFI, masks, metrics 0..16
  2. OSPFv2 (RFC 2328): packet checksum (one's complement) + every LSA's Fletcher checksum, sequence numbers
  3. BGP-4 (RFC 4271): marker, length, UPDATE attributes, AS_PATH, and that every rejected path really contains the receiver's AS
Start the lab first (run.bat), then:   python interop_test.py
"""
import json, struct, sys, urllib.parse, urllib.request

try: sys.stdout.reconfigure(encoding="utf-8")
except Exception: pass
URL = "http://localhost:8088/api/run"
ok = fail = 0
def check(name, cond, detail=""):
    global ok, fail
    ok, fail = (ok + 1, fail) if cond else (ok, fail + 1)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name:<66} {detail}")

def run(**q):
    data = urllib.parse.urlencode(q).encode()
    return json.load(urllib.request.urlopen(urllib.request.Request(URL, data=data), timeout=30))

def msgs(trace): return [m for r in trace["rounds"] for m in r["msgs"]]

# ---------------------------------------------------------------- RIP
print("\n--- RIPv2 (RFC 2453) --------------------------------------------------------------")
t = run(scn="count3", split=1, poison=1)
rips = [bytes.fromhex(m["hex"]) for m in msgs(t)]
def rip(b):
    cmd, ver, zero = struct.unpack("!BBH", b[:4])
    entries = [struct.unpack("!HHIIII", b[4 + 20 * i: 24 + 20 * i]) for i in range((len(b) - 4) // 20)]
    return cmd, ver, zero, entries
parsed = [rip(b) for b in rips]
check("every packet: command 2 (response), version 2, zero field 0", all(p[0] == 2 and p[1] == 2 and p[2] == 0 for p in parsed), f"{len(rips)} packets")
check("length = 4 + 20 × entries for every packet", all((len(b) - 4) % 20 == 0 for b in rips))
check("every entry: AFI 2, mask 255.255.255.0, next hop 0.0.0.0", all(e[0] == 2 and e[3] == 0xFFFFFF00 and e[4] == 0 for p in parsed for e in p[3]))
check("metrics stay within RIP's 0..16 (16 = infinity)", all(0 <= e[5] <= 16 for p in parsed for e in p[3]))
d_metrics = [e[5] for p in parsed for e in p[3] if e[2] == (10 << 24 | 4 << 8)]   # 10.0.4.0 = router D's network
check("count to infinity is visible in the bytes: D's metric climbs to 16", max(d_metrics) == 16 and len(set(d_metrics)) > 8, f"{sorted(set(d_metrics))}")

# ---------------------------------------------------------------- OSPF
print("\n--- OSPFv2 (RFC 2328) -------------------------------------------------------------")
t = run(scn="ospf")
osp = [bytes.fromhex(m["hex"]) for m in msgs(t)]
def inet_sum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return s
def fletcher_ok(lsa):
    c0 = c1 = 0
    for x in lsa[2:]: c0 = (c0 + x) % 255; c1 = (c1 + c0) % 255
    return c0 == 0 and c1 == 0
check("version 2, type 4 (LS Update), length field = packet length", all(b[0] == 2 and b[1] == 4 and struct.unpack("!H", b[2:4])[0] == len(b) for b in osp), f"{len(osp)} packets")
check("OSPF packet checksum verifies (one's-complement sum = 0xFFFF)", all(inet_sum(b) == 0xFFFF for b in osp))
lsas = []
for b in osp:
    n = struct.unpack("!I", b[24:28])[0]; o = 28
    for _ in range(n):
        ln = struct.unpack("!H", b[o + 18:o + 20])[0]; lsas.append(b[o:o + ln]); o += ln
check("every Router-LSA's Fletcher checksum verifies (age excluded)", all(fletcher_ok(l) for l in lsas), f"{len(lsas)} LSAs")
check("the flooded LSAs are the new ones: sequence 0x80000002", all(struct.unpack("!I", l[12:16])[0] == 0x80000002 for l in lsas))
c_lsa = [l for l in lsas if l[11] == 3]                                              # advertising router 10.255.0.3 = C
check("C's new LSA no longer lists the C–D link (2 links: A and B)", c_lsa and struct.unpack("!H", c_lsa[0][22:24])[0] == 2)

# ---------------------------------------------------------------- BGP
print("\n--- BGP-4 (RFC 4271) --------------------------------------------------------------")
t = run(scn="bgp")
ms = msgs(t)
raw = [(m, bytes.fromhex(m["hex"])) for m in ms]
check("every message: 16 × 0xFF marker and length field = message length", all(b[:16] == b"\xff" * 16 and struct.unpack("!H", b[16:18])[0] == len(b) for _, b in raw), f"{len(raw)} messages")
opens = [b for m, b in raw if b[18] == 1]
check("OPEN: version 4, hold time 180, AS numbers 100..400", opens and all(b[19] == 4 and struct.unpack("!H", b[22:24])[0] == 180 and struct.unpack("!H", b[20:22])[0] in (100, 200, 300, 400) for b in opens), f"{len(opens)} OPENs")
def as_path(b):
    wl = struct.unpack("!H", b[19:21])[0]; al = struct.unpack("!H", b[21 + wl:23 + wl])[0]; o = 23 + wl; end = o + al
    while o < end:
        flags, typ = b[o], b[o + 1]; ln = b[o + 2]; v = b[o + 3:o + 3 + ln]
        if typ == 2: return [struct.unpack("!H", v[2 + 2 * i:4 + 2 * i])[0] for i in range(v[1])]
        o += 3 + ln
    return None
ups = [(m, b) for m, b in raw if b[18] == 2]
check("UPDATE AS_PATHs decode to what the dashboard showed", all((as_path(b) or None) == m.get("path") for m, b in ups if m["type"] == "UPDATE"), f"{len(ups)} UPDATEs")
names_as = {i: 100 * (i + 1) for i in range(4)}
loops = [(m, b) for m, b in ups if m.get("loop")]
check("every path marked 'loop' really contains the receiver's own AS", loops and all(names_as[m["to"]] in as_path(b) for m, b in loops), f"{len(loops)} rejected")
wd = [b for m, b in ups if m["type"] == "WITHDRAW"]
check("withdrawals: withdrawn-routes field = 10.4.0.0/16, no attributes", wd and all(b[19:26] == bytes([0, 3, 16, 10, 4, 0, 0]) for b in wd), f"{len(wd)} withdrawals")

print(f"\n  {ok} passed, {fail} failed")
sys.exit(1 if fail else 0)

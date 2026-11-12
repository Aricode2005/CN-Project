"""
Interoperability test: HTTP clients we did NOT write talk to OUR server and OUR proxy.
  1. Python's http.client (keep-alive, HEAD, conditional GET, Range, chunked decoding, cookies, Basic auth)
  2. Python's urllib through our caching proxy (MISS then HIT)
  3. curl (Windows ships curl.exe): verbose request, gzip, 100-continue upload, proxy
Start the lab first (run.bat), then:   python interop_test.py
"""
import base64, gzip, http.client, shutil, subprocess, sys, urllib.request

try: sys.stdout.reconfigure(encoding="utf-8")
except Exception: pass
HOST, PORT, PROXY = "127.0.0.1", 8800, 3128
WWW = "www.cse.myuniv.edu"
ok = fail = 0
def check(name, cond, detail=""):
    global ok, fail
    ok, fail = (ok + 1, fail) if cond else (ok, fail + 1)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name:<64} {detail}")

print("\n--- Python http.client -----------------------------------------------------------")
c = http.client.HTTPConnection(HOST, PORT, timeout=10)
c.request("GET", "/gallery.html", headers={"Host": WWW})
r = c.getresponse(); page = r.read()
check("GET /gallery.html → 200, Content-Length honoured", r.status == 200 and len(page) == int(r.getheader("Content-Length")), f"{len(page)} bytes")
sock1 = c.sock
c.request("HEAD", "/img/1.svg", headers={"Host": WWW}); h = c.getresponse(); h.read()
check("HEAD on the same (kept-alive) connection: headers, no body", h.status == 200 and c.sock is sock1 and int(h.getheader("Content-Length")) > 0)
etag = r.getheader("ETag")
c.request("GET", "/gallery.html", headers={"Host": WWW, "If-None-Match": etag}); n = c.getresponse(); n.read()
check("conditional GET (If-None-Match) → 304 Not Modified", n.status == 304, etag)
c.request("GET", "/big.bin", headers={"Host": WWW, "Range": "bytes=10-19"}); g = c.getresponse(); part = g.read()
check("Range bytes=10-19 → 206, 10 bytes, Content-Range", g.status == 206 and len(part) == 10 and g.getheader("Content-Range") == "bytes 10-19/65536", g.getheader("Content-Range"))
c.request("GET", "/clock", headers={"Host": WWW}); k = c.getresponse(); ticks = k.read().decode()
check("chunked /clock decoded by http.client (5 ticks)", k.getheader("Transfer-Encoding") == "chunked" and ticks.count("tick") == 5)
c.close()

c = http.client.HTTPConnection(HOST, PORT, timeout=10)
c.request("POST", "/login", body="user=bob&pass=bob123", headers={"Host": WWW, "Content-Type": "application/x-www-form-urlencoded"})
l = c.getresponse(); l.read(); cookie = (l.getheader("Set-Cookie") or "").split(";")[0]
c.request("GET", "/cart", headers={"Host": WWW, "Cookie": cookie}); cart = c.getresponse().read().decode()
check("login → Set-Cookie; sending it back → the server knows bob", l.status == 303 and cookie.startswith("sid=") and "bob" in cart, cookie[:16] + "…")
auth = base64.b64encode(b"subham:ju2026").decode()
c.request("GET", "/private/", headers={"Host": WWW, "Authorization": "Basic " + auth}); a = c.getresponse(); a.read()
check("Basic authentication → 200", a.status == 200)
c.close()

print("\n--- Python urllib through our caching proxy ---------------------------------------")
opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://{HOST}:{PROXY}"}))
url = f"http://{WWW}/img/7.svg"
x1 = opener.open(url, timeout=10); b1 = x1.read(); x2 = opener.open(url, timeout=10); b2 = x2.read()
check("urllib via proxy: 2nd fetch is a HIT with the same bytes", x2.headers.get("X-Cache") == "HIT" and b1 == b2, f"{x1.headers.get('X-Cache')} → {x2.headers.get('X-Cache')}")

print("\n--- curl --------------------------------------------------------------------------")
curl = shutil.which("curl.exe") or shutil.which("curl")
if curl:
    p = subprocess.run([curl, "-sv", "--compressed", "-H", f"Host: {WWW}", f"http://{HOST}:{PORT}/news.html"], capture_output=True, text=True, timeout=20)
    check("curl --compressed → Content-Encoding: gzip, decoded page", "content-encoding: gzip" in p.stderr.lower() and "Department news" in p.stdout)
    p = subprocess.run([curl, "-sv", "-X", "PUT", "--data-binary", "z" * 2000, "-H", "Expect: 100-continue", "-H", f"Host: {WWW}", f"http://{HOST}:{PORT}/files/curl.txt"], capture_output=True, text=True, timeout=20)
    check("curl PUT with Expect: 100-continue → 100 then 201/204", "100 Continue" in p.stderr and ("201" in p.stderr or "204" in p.stderr))
    p = subprocess.run([curl, "-s", "-D", "-", "-x", f"{HOST}:{PROXY}", f"http://{WWW}/img/9.svg", "-o", "NUL" if sys.platform == "win32" else "/dev/null"], capture_output=True, text=True, timeout=20)
    p = subprocess.run([curl, "-s", "-D", "-", "-x", f"{HOST}:{PROXY}", f"http://{WWW}/img/9.svg", "-o", "NUL" if sys.platform == "win32" else "/dev/null"], capture_output=True, text=True, timeout=20)
    check("curl -x (proxy): X-Cache: HIT and Via: 1.1 ju-proxy", "X-Cache: HIT" in p.stdout and "Via: 1.1 ju-proxy" in p.stdout)
else:
    print("  (skipped: curl not found)")

print(f"\n  {ok} passed, {fail} failed")
sys.exit(1 if fail else 0)

"""
Interoperability test: FTP clients we did NOT write talk to OUR FTP server.
  1. Python's ftplib: passive, active, and FTPS (FTP_TLS)
  2. Windows' own ftp.exe (it only speaks ACTIVE mode: the server connects back to it)
Start the lab first (run.bat), then:   python interop_test.py
"""
import ftplib, hashlib, io, os, ssl, subprocess, sys, tempfile

HOST, PORT = "127.0.0.1", 2121
ok = fail = 0
def check(name, cond, detail=""):
    global ok, fail
    ok, fail = (ok + 1, fail) if cond else (ok, fail + 1)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name:<62} {detail}")

print("\n--- Python ftplib ---------------------------------------------------------------")
f = ftplib.FTP(); f.connect(HOST, PORT, timeout=10)
check("welcome is 220", f.getwelcome().startswith("220"), f.getwelcome()[:40])
f.login("alice", "alice123")
check("login + PWD", f.pwd() == "/home/alice")
f.set_pasv(True)
names = f.nlst("/pub")
check("passive NLST /pub", any(n.endswith("logo.png") for n in names), f"{len(names)} names")
buf = io.BytesIO(); f.retrbinary("RETR /pub/logo.png", buf.write)
logo = buf.getvalue()
check("passive RETR binary (PNG signature intact)", logo[:8] == b"\x89PNG\r\n\x1a\n", f"{len(logo)} bytes")
f.set_pasv(False)
lines = []; f.retrlines("LIST /pub", lines.append)
check("ACTIVE LIST /pub (server connects back to ftplib)", any("readme.txt" in l for l in lines), f"{len(lines)} lines")
f.set_pasv(True)
f.storbinary("STOR py-upload.png", io.BytesIO(logo))
check("STOR then SIZE matches", f.size("py-upload.png") == len(logo))
f.delete("py-upload.png")
f.quit()

ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE   # lab certificate is self-signed
t = ftplib.FTP_TLS(context=ctx); t.connect(HOST, PORT, timeout=10)
t.login("alice", "alice123"); t.prot_p()
buf = io.BytesIO(); t.retrbinary("RETR /pub/logo.png", buf.write)
check("FTPS: FTP_TLS AUTH TLS + PROT P + RETR", buf.getvalue() == logo)
t.quit()

print("\n--- Windows ftp.exe (active mode only) -------------------------------------------")
if os.name == "nt":
    with tempfile.TemporaryDirectory() as d:
        script = os.path.join(d, "s.txt")
        with open(script, "w") as s:
            s.write(f"open {HOST} {PORT}\nalice\nalice123\npwd\nbinary\nlcd {d}\nget /pub/rfc959-notes.txt notes.txt\nls /pub\nquit\n")
        p = subprocess.run(["ftp", "-s:" + script], capture_output=True, text=True, timeout=60, cwd=d)
        out = p.stdout + p.stderr
        got = os.path.exists(os.path.join(d, "notes.txt"))
        check("ftp.exe logs in (230) and sees PWD", "230" in out and "257" in out)
        check("ftp.exe GET in binary mode (PORT → server connects back)", got and "226" in out)
        check("ftp.exe ls /pub", "readme.txt" in out)
else:
    print("  (skipped: not Windows)")

print(f"\n  {ok} passed, {fail} failed")
sys.exit(1 if fail else 0)

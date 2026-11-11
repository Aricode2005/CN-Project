"""
Interoperability test: Python's standard-library mail clients (smtplib, poplib, imaplib) —
independent, real-world implementations — talk to OUR Java servers.
Start the lab first (run.bat), then:   python interop_test.py
"""
import imaplib, poplib, smtplib, ssl, sys, time
from email.message import EmailMessage

HOST, DOMAIN = "localhost", "cse.myuniv.edu"
ok = fail = 0

def check(name, cond, detail=""):
    global ok, fail
    ok, fail = (ok + 1, fail) if cond else (ok, fail + 1)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name:<62} {detail}")

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE           # our certificate is self-signed (lab)

print("\n--- smtplib (SMTP + STARTTLS + AUTH) -----------------------------------------")
msg = EmailMessage()
msg["From"], msg["To"], msg["Subject"] = f"alice@{DOMAIN}", f"bob@{DOMAIN}", "Hello from Python smtplib"
msg.set_content("Sent by Python's smtplib to the JU Mail Lab server.\n.a line starting with a dot")
msg.add_attachment(b"\x00\x01binary\xff", maintype="application", subtype="octet-stream", filename="data.bin")
with smtplib.SMTP(HOST, 2525, timeout=10) as s:
    code, _ = s.ehlo("python")
    check("EHLO", code == 250, str(code))
    s.starttls(context=ctx); s.ehlo("python")
    check("STARTTLS", s.sock.version() is not None, s.sock.version())
    s.login("alice", "alice123")
    check("AUTH", True)
    refused = s.send_message(msg)
    check("send_message accepted for bob", refused == {})
with smtplib.SMTP_SSL(HOST, 2465, context=ctx, timeout=10) as s:
    s.login("alice", "alice123")
    check("SMTP_SSL (implicit TLS) + login", True)

time.sleep(0.3)
print("\n--- poplib (POP3) ---------------------------------------------------------------")
p = poplib.POP3(HOST, 1110, timeout=10)
p.stls(context=ctx)
p.user("bob"); p.pass_("bob123")
count, size = p.stat()
check("STLS + USER/PASS + STAT", count > 0, f"{count} messages, {size} octets")
resp, lines, _ = p.retr(count)
text = b"\r\n".join(lines).decode()
check("RETR newest message is ours", "Hello from Python smtplib" in text)
check("dot-stuffed line restored by the client", "\n.a line starting with a dot" in text.replace("\r\n", "\n"))
resp, uidl, _ = p.uidl()
check("UIDL", len(uidl) == count)
p.quit()

print("\n--- imaplib (IMAP4rev1) -------------------------------------------------------")
m = imaplib.IMAP4(HOST, 1143)
m.starttls(ssl_context=ctx)
typ, _ = m.login("bob", "bob123")
check("STARTTLS + LOGIN", typ == "OK")
typ, data = m.list()
check("LIST", typ == "OK" and any(b"Sent" in d for d in data), str(len(data)) + " folders")
typ, data = m.select("INBOX")
check("SELECT", typ == "OK", data[0].decode() + " messages")
typ, data = m.search(None, 'SUBJECT', '"Python smtplib"')
ids = data[0].split()
check("SEARCH SUBJECT", len(ids) >= 1, data[0].decode())
typ, data = m.fetch(ids[-1], "(BODY.PEEK[HEADER.FIELDS (SUBJECT)] FLAGS)")
check("FETCH BODY.PEEK[HEADER.FIELDS]", b"Python smtplib" in data[0][1])
typ, data = m.fetch(ids[-1], "(BODYSTRUCTURE)")
check("FETCH BODYSTRUCTURE (multipart)", b"MIXED" in data[0], data[0][:90].decode() + "…")
typ, data = m.fetch(ids[-1], "(BODY[2])")
check("FETCH BODY[2] = the attachment part (base64)", typ == "OK" and b"AAFiaW5hcnn/" in data[0][1])
m.store(ids[-1], "+FLAGS", "\\Flagged")
typ, data = m.fetch(ids[-1], "(FLAGS)")
check("STORE +FLAGS \\Flagged", b"\\Flagged" in data[0] and b"\\Seen" in data[0], data[0].decode())
typ, data = m.append("Sent", "(\\Seen)", None, b"Subject: appended by imaplib\r\n\r\nhello\r\n")
check("APPEND (literal)", typ == "OK", data[0].decode())
check("CREATE / DELETE folder", m.create("PyTest")[0] == "OK" and m.delete("PyTest")[0] == "OK")
m.logout()
m = imaplib.IMAP4_SSL(HOST, 2993, ssl_context=ctx)
check("IMAP4_SSL (implicit TLS) LOGIN", m.login("alice", "alice123")[0] == "OK")
m.logout()

print(f"\n  {ok} passed, {fail} failed")
sys.exit(1 if fail else 0)

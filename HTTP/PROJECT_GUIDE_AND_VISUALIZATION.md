# HTTP/1.1: Requests, Persistence, Caching and State
## Complete Protocol Reference, Architecture & Live Demonstration Guide

---

## Table of Contents
1. [Project Overview & What We Built](#1-project-overview--what-we-built)
2. [Message Formats](#2-message-formats)
3. [System Architecture](#3-system-architecture)
4. [Detailed Protocol Workflows & Sequence Diagrams](#4-detailed-protocol-workflows--sequence-diagrams)
   - [4.1 Non-Persistent (HTTP/1.0) vs Persistent (HTTP/1.1)](#41-non-persistent-http10-vs-persistent-http11)
   - [4.2 Pipelining and Head-of-Line Blocking](#42-pipelining-and-head-of-line-blocking)
   - [4.3 Conditional GET → 304](#43-conditional-get--304)
   - [4.4 The Caching Proxy: MISS, HIT, REVALIDATED](#44-the-caching-proxy-miss-hit-revalidated)
   - [4.5 Cookies: State on a Stateless Protocol](#45-cookies-state-on-a-stateless-protocol)
   - [4.6 Basic Authentication](#46-basic-authentication)
   - [4.7 Chunked Transfer and 100-continue](#47-chunked-transfer-and-100-continue)
5. [How to Run & Visualize Everything](#5-how-to-run--visualize-everything)
6. [Step-by-Step Live Demonstration Script (For Presentation / Viva)](#6-step-by-step-live-demonstration-script-for-presentation--viva)
7. [Viva & Technical Examination Questions](#7-viva--technical-examination-questions)

---

## 1. Project Overview & What We Built

**HTTP** (HyperText Transfer Protocol) is the web's application protocol:
- A client sends a **request** and a server returns a **response**.
- It is plain text, on TCP port 80.
- It is **stateless**: the server forgets each request once it is answered.

HTTP/1.0 (RFC 1945, 1996) opened a new TCP connection for every object. HTTP/1.1 (RFC 2068 → 2616 → today's RFC 9110/9111/9112) added persistent connections, pipelining, the mandatory `Host` header, chunked transfer, byte ranges and much better caching.

This module implements all of that in pure Java (JDK 11+, zero dependencies):

1. **Origin server** (`127.0.0.1:8800`, and `:80` when free):
   - one thread per connection, with requests answered strictly in order;
   - keep-alive with a 15 s timeout;
   - HTTP/1.0 rules, `Connection: close`;
   - two **virtual hosts** (`www.cse.myuniv.edu`, `intranet.cse.myuniv.edu`);
   - methods: GET, HEAD, POST, PUT, DELETE, OPTIONS;
   - conditional GET (ETag / Last-Modified), byte ranges, chunked responses and requests;
   - `Expect: 100-continue`, gzip;
   - cookies (login + cart), Basic authentication;
   - redirects 301/302/303;
   - the error codes 400, 401, 403, 404, 405, 411, 413, 416, 500, 501, 505.
2. **Client** (`WebClient`): one-at-a-time or **pipelined** requests, a cookie jar, and timestamps for every step.
3. **WAN emulator** (`127.0.0.1:8801`):
   - holds the client's first bytes for 1 RTT (the TCP handshake);
   - delays every chunk by RTT/2 each way;
   - serialises at the link rate.

   Without it, loopback's 0 ms delay would make every strategy look the same.
4. **Caching proxy** (`127.0.0.1:3128`):
   - freshness from `max-age`, `Expires` or the 10% heuristic;
   - validation with `If-None-Match` / `If-Modified-Since`;
   - `no-store` and `private` respected;
   - `Via` / `Age` / `X-Cache` headers;
   - HTTPS through `CONNECT` tunnels.
5. **Dashboard** (`http://localhost:8087`), designed as a library reading room: request slips, catalogue cards with status stamps, a waterfall of the four connection strategies, and a reserve shelf (the cache).
6. **Verification**: 52 automated checks, plus 11 interop checks (Python `http.client`, `urllib` through our proxy, and `curl`).

---

## 2. Message Formats

### 2.1 Request

```
GET /news.html HTTP/1.1\r\n                ← request line: method SP target SP version
Host: www.cse.myuniv.edu\r\n                ← mandatory in 1.1 (virtual hosting)
User-Agent: JU-WebClient/1.0\r\n
If-None-Match: "news-1"\r\n                 ← conditional: "only if changed"
\r\n                                         ← blank line ends the head
(body, only for POST/PUT; its length from Content-Length or chunked coding)
```

### 2.2 Response

```
HTTP/1.1 200 OK\r\n                         ← status line: version SP code SP reason
Date: Wed, 11 Nov 2026 18:16:48 GMT\r\n
Server: JU-HTTP/1.1 (pure Java)\r\n
Content-Type: text/html; charset=utf-8\r\n
Cache-Control: max-age=5\r\n                 ← how long caches may reuse it
Last-Modified: Wed, 11 Nov 2026 18:11:22 GMT\r\n
ETag: "news-1"\r\n                           ← validator for conditional GET
Content-Length: 780\r\n                      ← body framing (or Transfer-Encoding: chunked)
Keep-Alive: timeout=15, max=99\r\n
\r\n
<!doctype html>…
```

### 2.3 Chunked body

```
13\r\n                ← chunk size in HEX (0x13 = 19 bytes)
tick 1 at 00:15:02\n\r\n
13\r\n
tick 2 at 00:15:02\n\r\n
0\r\n                 ← zero-size chunk: end of the body
\r\n
```

### 2.4 Status code classes

| Class | Meaning | Ours |
|:--|:--|:--|
| 1xx | informational: more is coming | 100 Continue |
| 2xx | success | 200, 201 Created, 204 No Content, 206 Partial Content |
| 3xx | redirection | 301, 302, 303 See Other, 304 Not Modified |
| 4xx | client error | 400, 401, 403, 404, 405, 411, 413, 416 |
| 5xx | server error | 500, 501, 505 |

---

## 3. System Architecture

```mermaid
flowchart LR
    subgraph Client side
        B["Your browser / curl / Python"]
        W["Our WebClient<br/>(pipelining, cookie jar, timings)"]
    end
    P["Caching proxy :3128<br/>reserve shelf: fresh? stale? → revalidate"]
    L["WAN emulator :8801<br/>+1 RTT handshake · RTT/2 each way · link rate"]
    subgraph Origin ["Origin server :8800 (+ :80)"]
        O["Origin: one thread per TCP connection<br/>requests answered in order"]
        S["Site: virtual hosts www / intranet<br/>conditional GET · Range · cookies · auth · PUT/DELETE · chunked · gzip"]
    end
    D["Dashboard :8087"]
    B -- "direct" --> O
    W -- "page-load experiments" --> L --> O
    B -- "proxy-form: GET http://host/path" --> P -- "only on MISS / revalidate" --> L
    O --> S
    O -. "every request line + status line" .-> D
    P -. "HIT / MISS / REVALIDATED / TUNNEL" .-> D
```

---

## 4. Detailed Protocol Workflows & Sequence Diagrams

### 4.1 Non-Persistent (HTTP/1.0) vs Persistent (HTTP/1.1)

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server
    Note over C,S: HTTP/1.0: one TCP connection per object
    C->>S: SYN
    S-->>C: SYN-ACK  (1 RTT)
    C->>S: ACK + GET /gallery.html
    S-->>C: 200 OK + page, then close  (1 RTT)
    C->>S: SYN (new connection for 1.svg)
    S-->>C: SYN-ACK
    C->>S: GET /img/1.svg
    S-->>C: 200 OK, close
    Note over C,S: … 11 objects × 2 RTT ≈ 22 RTT (we measured 2491 ms at RTT 100 ms)
    Note over C,S: HTTP/1.1 keep-alive: one handshake, then 1 RTT per object ≈ 2 + 10 = 12 RTT (1466 ms)
```

| Strategy | Formula (N = 10 objects after the page) | At RTT 100 ms | Measured |
|:--|:--|:--|:--|
| Non-persistent, serial | (N+1) × 2 RTT | 2200 ms | ~2300–2500 ms |
| Non-persistent, k = 5 parallel | 2 RTT + ⌈N/k⌉ × 2 RTT | 600 ms | ~690–740 ms |
| Persistent, no pipelining | 2 RTT + N × RTT | 1200 ms | ~1250–1470 ms |
| Persistent + pipelining | 2 RTT + 1 RTT | 300 ms | ~315–435 ms |

The small extra time is the transmission time of the bytes at the link rate, plus Java thread scheduling.

### 4.2 Pipelining and Head-of-Line Blocking

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server
    C->>S: GET /img/1.svg · GET /img/2.svg · GET /img/3.svg  (one write, no waiting)
    S-->>C: 200 (1.svg)
    S-->>C: 200 (2.svg)
    S-->>C: 200 (3.svg)
    Note over S: responses MUST come back in request order.<br/>If 1.svg were slow (/slow), 2 and 3 would wait behind it:<br/>head-of-line blocking. HTTP/2 fixes this with multiplexed streams.
```

### 4.3 Conditional GET → 304

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (with a cached copy)
    participant S as Server
    C->>S: GET /news.html
    S-->>C: 200 OK · ETag "news-1" · Last-Modified · body (780 B)
    C->>S: GET /news.html · If-None-Match: "news-1"
    S-->>C: 304 Not Modified (no body): reuse your copy
    Note over S: someone edits the page → ETag "news-2"
    C->>S: GET /news.html · If-None-Match: "news-1"
    S-->>C: 200 OK · ETag "news-2" · new body
```

### 4.4 The Caching Proxy: MISS, HIT, REVALIDATED

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (LAN)
    participant P as Proxy :3128
    participant O as Origin (across the WAN)
    C->>P: GET http://www.cse.myuniv.edu/img/5.svg
    P->>O: GET /img/5.svg  (Via: 1.1 ju-proxy)
    O-->>P: 200 · Cache-Control: max-age=300
    P-->>C: 200 · X-Cache: MISS  (~2 RTT across the WAN)
    C->>P: GET … same URL
    P-->>C: 200 · X-Cache: HIT · Age: 3  (served from the shelf, ~0.5 ms)
    Note over P: max-age runs out → copy is stale
    C->>P: GET … same URL
    P->>O: GET · If-None-Match: "img-5"
    O-->>P: 304 Not Modified
    P-->>C: 200 · X-Cache: REVALIDATED (cached body, no body crossed the WAN)
```

### 4.5 Cookies: State on a Stateless Protocol

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (cookie jar)
    participant S as Server (session table)
    C->>S: GET /cart
    S-->>C: 200: "Who are you?" (no Cookie header)
    C->>S: POST /login  user=alice&pass=alice123
    S->>S: create session sid=GN41… → {user: alice, cart: []}
    S-->>C: 303 See Other · Location: /cart · Set-Cookie: sid=GN41…; HttpOnly; SameSite=Lax
    C->>S: GET /cart · Cookie: sid=GN41…
    S-->>C: 200: "Hello alice", cart (0)
    C->>S: POST /cart/add item=Forouzan · Cookie: sid=GN41…
    S-->>C: 303 → /cart: now 1 item
```

### 4.6 Basic Authentication

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server
    C->>S: GET /private/
    S-->>C: 401 Unauthorized · WWW-Authenticate: Basic realm="CSE staff"
    C->>S: GET /private/ · Authorization: Basic YWxpY2U6YWxpY2UxMjM=
    Note over C,S: that is just base64("alice:alice123"): anyone on the path can decode it
    S-->>C: 200 OK
```

### 4.7 Chunked Transfer and 100-continue

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server
    C->>S: GET /clock
    S-->>C: 200 OK · Transfer-Encoding: chunked (length unknown in advance)
    S-->>C: 13␍␊ tick 1 …␍␊
    S-->>C: 13␍␊ tick 2 …␍␊  (… 5 ticks, 300 ms apart)
    S-->>C: 0␍␊␍␊  (end)
    C->>S: PUT /files/big-upload.txt · Content-Length: 4001 · Expect: 100-continue  (headers only)
    S-->>C: HTTP/1.1 100 Continue
    C->>S: (the 4001-byte body)
    S-->>C: 201 Created · Location: /files/big-upload.txt
```

---

## 5. How to Run & Visualize Everything

```powershell
cd HTTP
.\run.bat                 # origin :8800 (+80), WAN link :8801, proxy :3128, dashboard http://localhost:8087
.\run.bat --verify        # 52 automated checks (stop the running lab first)
python interop_test.py    # http.client, urllib via proxy, curl (11 checks)
curl -v -H "Host: www.cse.myuniv.edu" http://127.0.0.1:8800/news.html
curl -x 127.0.0.1:3128 -D - -o NUL http://www.cse.myuniv.edu/img/1.svg   # run twice: MISS then HIT
```

| Section | What it shows |
|:--|:--|
| 001 Ask at the desk | build any request (method, target, Host, version, route: direct / WAN / proxy); raw request and response with CRLFs; stamped status |
| 002 Four ways to fetch | RTT / k / link-rate controls; waterfall per strategy (handshake hatched, waiting, receiving); ledger of formula vs measured |
| 003 Has it changed? | 200 → 304 → (edit) → 200, step by step |
| 004 The reserve shelf | gallery through the proxy: MISS/HIT tiles, freshness bars, "go stale", "edit news.html" |
| 005 Reader's ticket | cookie and Basic-auth walkthroughs |
| 006 Other services | methods, virtual hosts, ranges, chunked, 100-continue, gzip, redirects |
| 007 By hand | raw text on a fresh TCP connection (pipelining by hand) |
| 008 Status stamps | every code; click to produce it |
| 009 Desk log | every request and status line the server handled, with explanations |

---

## 6. Step-by-Step Live Demonstration Script (For Presentation / Viva)

1. **Start**: run `run.bat`, open `http://localhost:8087`, and also open `http://localhost:8800/` in a browser tab. That page came from our server.
2. **One exchange (001)**: press *POST login*. Point out the request line, Host, the blank line and the body, then the 303, `Location` and `Set-Cookie`.
3. **The headline experiment (002)**: RTT 100 ms, then *Measure all four*. Press **Forward ▶** four times.
   - HTTP/1.0 uses 11 connections, each with a hatched handshake: ≈ 22 RTT.
   - Keep-alive is a staircase of one RTT per object.
   - Pipelining sends everything at once: ≈ 3 RTT.

   The ledger shows the formula and the measurement side by side.
4. **304 (003)**: three Forwards: 200 with an ETag, then 304 with no body, then (after an edit) 200 with a new ETag.
5. **Proxy (004)**: *Borrow the gallery* twice. The first time is 11 MISS (slow); the second is 11 HIT (~0.5 ms each). Then *let every copy go stale* and borrow again: REVALIDATED.
6. **Cookies (005)**: "Who are you?", then login and Set-Cookie, then the Cookie comes back and the server knows alice.
7. **By hand (007)**: send the pipelined example. Three responses come back, in order, on one connection.
8. **Real browser**: set the browser's proxy to `127.0.0.1:3128` and load `http://www.cse.myuniv.edu/gallery.html` twice. The desk log shows MISS, then HIT.

---

## 7. Viva & Technical Examination Questions

**Q1: Why is HTTP called stateless, and how do websites remember you?**
*Answer:* Each request is handled on its own: the server keeps nothing about earlier requests. **Cookies** add state on top. The server sends `Set-Cookie: sid=…`, the browser returns `Cookie: sid=…` on every later request, and the server looks the id up in its session table. The state lives on the server; the cookie is only the key.

**Q2: Persistent vs non-persistent connections?**
*Answer:*
- **Non-persistent** (HTTP/1.0 default): one TCP connection per object, so every object pays a handshake RTT plus a request RTT, ≈ 2 RTT each.
- **Persistent** (HTTP/1.1 default): one connection is reused, so after the first handshake each object costs ≈ 1 RTT.

The server closes an idle persistent connection after a timeout (15 s here), or when the client sends `Connection: close`.

**Q3: What is pipelining, and why didn't browsers use it?**
*Answer:* The client sends several requests without waiting for each response; responses must come back **in order**. Total time ≈ 3 RTT for our gallery. Browsers left it off because of **head-of-line blocking** (one slow response delays all the rest) and buggy proxies. HTTP/2 replaced it with multiplexed streams over one connection.

**Q4: Calculate the time for a page with 10 images, RTT = 100 ms.**
*Answer:*
- Non-persistent: (10+1) × 2 RTT = 2.2 s.
- Persistent without pipelining: 2 RTT + 10 RTT = 1.2 s.
- Persistent with pipelining: 2 RTT + 1 RTT = 0.3 s.
- 5 parallel non-persistent connections: 2 RTT + ⌈10/5⌉ × 2 RTT = 0.6 s.

All ignore transmission time. Our measurements match within 10–20%.

**Q5: Why is the `Host` header mandatory in HTTP/1.1?**
*Answer:* For **virtual hosting**: many sites share one IP address and port, and the server picks the site from `Host`. Our server serves different pages for `www` and `intranet` on the same socket, and a 1.1 request without Host gets **400**.

**Q6: GET vs POST vs PUT? What does idempotent mean?**
*Answer:*
- **GET** reads (safe; no body).
- **POST** submits data for processing: not idempotent, so doing it twice may create two orders.
- **PUT** stores the body at exactly that URL: idempotent, so doing it twice equals doing it once (201 the first time, 204 after).
- **DELETE** is idempotent too.
- **HEAD** is GET without the body.
- **OPTIONS** lists the allowed methods (the `Allow` header).

**Q7: How does a conditional GET save bandwidth?**
*Answer:* The first response carries validators (`ETag`, `Last-Modified`). Later the client sends `If-None-Match` / `If-Modified-Since`. If unchanged, the server answers **304 Not Modified** with headers only and no body, and the client reuses its copy.

**Q8: What is a web cache (proxy), and why do organisations use one?**
*Answer:* A server near the users that keeps copies of responses.
- It cuts **response time**: a HIT is served at LAN speed, with no WAN round trips.
- It cuts **access-link traffic**, so the institution's Internet link is less loaded.

Freshness comes from `Cache-Control: max-age` (or `Expires`). Stale copies are revalidated with a conditional GET. `no-store` or `private` responses are not stored. `Via` shows that a proxy was involved and `Age` says how old the copy is.

**Q9: Why can't the proxy cache HTTPS?**
*Answer:* For HTTPS the browser sends `CONNECT host:443`. The proxy then just relays bytes (a tunnel), and everything inside is TLS-encrypted, so it can neither read nor cache it.

**Q10: How does the receiver know where an HTTP body ends?**
*Answer:* There are three ways:
1. **Content-Length** gives the byte count.
2. **Transfer-Encoding: chunked** sends chunks prefixed with a hex size, ending with a 0-size chunk. It is used when the length isn't known in advance (our `/clock`).
3. Old HTTP/1.0 responses only: the server **closes** the connection.

Without one of these, a persistent connection couldn't carry a second response.

**Q11: What are 301, 302, 303 and 304?**
*Answer:*
- **301**: moved permanently (update bookmarks).
- **302**: found elsewhere, temporarily.
- **303**: see other; do a GET on Location, used after a POST.
- **304**: not modified (conditional GET).

All redirects use the `Location` header.

**Q12: What is `Expect: 100-continue`?**
*Answer:* The client sends only the headers of a large upload and waits. The server replies `100 Continue` (an interim 1xx response) if it will accept the body, or a final error (e.g. 401 or 413) if not. This avoids sending a big body for nothing. `curl` does this automatically for large PUT/POST requests, and our interop test checks it.

**Q13: Is Basic authentication secure?**
*Answer:* No. `Authorization: Basic YWxpY2U6YWxpY2UxMjM=` is just base64 of `alice:alice123`: encoded, not encrypted. It is only safe over HTTPS. (Same lesson as Telnet and FTP.)

**Q14: Byte ranges?**
*Answer:* `Range: bytes=1000-1999` → **206 Partial Content** with `Content-Range: bytes 1000-1999/65536`. Used to resume downloads (like FTP's REST) and for video seeking. A range past the end gives **416**.

**Q15: HTTP/1.1 vs HTTP/2 vs HTTP/3?**
*Answer:*
- **HTTP/1.1**: text, one request at a time per connection (or pipelined, in order).
- **HTTP/2**: binary frames, many **streams multiplexed** on one TCP connection, header compression (HPACK). It removes HTTP-level head-of-line blocking, but TCP's remains.
- **HTTP/3**: HTTP over **QUIC (UDP 443)**: no TCP head-of-line blocking, 0/1-RTT setup, TLS 1.3 built in. (We saw QUIC in Assignment 5.)

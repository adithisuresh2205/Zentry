# SentinelGate (Zentry) — System Architecture Baseline
## Phase 1: Repository & Application Architecture Inspection

**Course**: 20CYS401 – Secure Software Engineering  
**System Name**: SentinelGate (Zentry) Zero-Trust Web Application Security Gateway  
**Document Classification**: Architectural Baseline & Inspection Record (Phase 1)  
**Date**: September 2026  
**Status**: APPROVED & SYNCHRONIZED

---

## 1. System Overview & Architectural Topology

SentinelGate operates as a **Zero-Trust Web Application Security Gateway and Web Application Firewall (WAF)** acting as an intelligent reverse proxy positioned between untrusted client traffic and internal application services.

```mermaid
graph TD
    Client["Client / Untrusted WAN<br/>(Browsers, CLI, Mobile, Attackers)"] -->|HTTPS (Port 443) / HTTP (Port 80)| Nginx["Edge Reverse Proxy (Nginx 1.27 Alpine)<br/>TLS Termination, Header Sanitization, Ingress Controls"]
    
    subgraph DMZ_Perimeter ["Perimeter Inspection Layer"]
        Nginx -->|HTTP Forward (Port 8000)| Gateway["SentinelGate Core Engine (FastAPI / Python 3.12)<br/>ASGI Middleware Pipeline"]
    end

    subgraph ZeroTrust_Pipeline ["7-Stage Zero-Trust Request Pipeline"]
        Gateway --> S1["Stage 1: Envelope Extraction & Anti-Spoofing"]
        S1 --> S2["Stage 2: IP Reputation & CIDR Blocklist Gate"]
        S2 --> S3["Stage 3: Identity & Token Attestation (JWT + jti)"]
        S3 --> S4["Stage 4: Device Posture & Entropy Evaluation"]
        S4 --> S5["Stage 5: Deep WAF Threat Engine (OWASP Top 10)"]
        S5 --> S6["Stage 6: Multi-Signal Risk Scoring & Policy Decision"]
        S6 --> S7["Stage 7: HMAC-SHA256 Audit Sealing & Broadcast"]
    end

    subgraph State_Storage ["State & Persistence Tier"]
        Gateway <-->|Sliding Window, jti Blocklist (<1ms)| Redis[("Redis 7 Alpine Cache<br/>Port 6379 (Password Protected)")]
        Gateway <-->|ACID Persistence, HMAC Chains| Postgres[("PostgreSQL 16 Alpine Database<br/>Port 5432 (Internal Network Only)")]
    end

    subgraph Upstream_Application ["Protected Internal Applications"]
        S6 -->|ALLOW (Policy HTTP 200)| DemoApp["Protected Demo REST API<br/>(/api/users, /api/products, /api/search)"]
    end

    subgraph Tactical_SOC ["Presentation & Telemetry Tier"]
        S7 -.->|WebSocket Live Stream /ws/security-events| Frontend["Next.js 14 Tactical SOC Dashboard<br/>Port 3000 (React 18 / Tailwind CSS)"]
        Frontend <-->|REST Admin APIs /security/*| Gateway
    end
```

---

## 2. Technical Stack Specifications

| Layer / Component | Technology / Framework | Version | Purpose in Secure Architecture |
| :--- | :--- | :--- | :--- |
| **Ingress Proxy** | Nginx Alpine | 1.27.0 | TLS termination (TLS 1.2/1.3), SSL offloading, client IP preservation (`X-Forwarded-For`), HTTP header hardening. |
| **Security Gateway** | Python / FastAPI / Starlette | 3.12 / 0.115+ | High-performance async ASGI core executing the 7-stage Zero-Trust inspection pipeline before request reaching application code. |
| **Runtime Server** | Uvicorn (standard) | 0.30+ | Multi-worker ASGI web server with strict proxy-header parsing and access logging. |
| **Data Serialization** | Pydantic v2 / Orjson | 2.7+ / 3.10+ | Fast, strictly validated schema definitions preventing mass assignment, prototype pollution, and malformed JSON injection. |
| **Cryptographic Auth** | PyJWT / Passlib (Bcrypt) / hashlib | 2.8+ / 1.7.4 | Cryptographic token minting/verification, bcrypt password hashing (12 work factor rounds), HMAC-SHA256 log integrity sealing. |
| **Persistence (RDBMS)** | PostgreSQL Alpine / SQLAlchemy Async | 16.0 / 2.0+ | ACID storage of user credentials, persistent IP blocklists, WAF rules, and HMAC-chained security audit events. |
| **Migrations** | Alembic | 1.13+ | Version-controlled, deterministic relational database schema migrations. |
| **Cache & State Store** | Redis Alpine / redis-py async | 7.0 / 5.0+ | Microsecond-latency in-memory sliding window rate-limiting counters, active IP bans, and revoked JWT `jti` blocklists. |
| **Frontend Dashboard** | Next.js / React / TypeScript / Tailwind | 14.2 / 18.3 / 5.0 | High-density Tactical SOC dashboard with real-time WebSocket telemetry, glassmorphism UI, zero mock synthetic data. |
| **Container Engine** | Docker & Docker Compose | 29.8 / Compose v2 | Multi-stage, non-root user execution (`UID 1001`), resource constraints, internal isolated network topology. |

---

## 3. The 7-Stage Zero-Trust Request Pipeline

Every inbound HTTP request arriving at SentinelGate is intercepted by `GatewayMiddleware` (`backend/gateway.py`) and processed sequentially:

1. **Stage 1: Envelope Extraction & Anti-Spoofing (`backend/network.py`)**
   - Resolves true client IP by walking the `X-Forwarded-For` chain against configured trusted proxy CIDRs (`TRUSTED_PROXIES`), preventing IP spoofing.
   - Groups IPv6 addresses into `/48` ISP subnet prefixes to eliminate botnet IP-hopping evasion.
   - Assigns a cryptographically unique `X-Request-ID` (UUIDv4) to trace the transaction across all subsystems.

2. **Stage 2: IP Reputation & Blocklist Gate (`backend/gateway.py`)**
   - Queries Redis memory and PostgreSQL `ip_blocklist` for manual, automated, or CIDR-based IP bans.
   - If blocked: short-circuits immediately with HTTP 403 Forbidden without invoking downstream application logic.

3. **Stage 3: Identity & Token Attestation (`backend/auth/`)**
   - Extracts `Authorization: Bearer <JWT>` header or session cookies.
   - Validates HMAC/RSA signature, expiration (`exp`), and audience (`aud`).
   - Checks Redis `jti` blacklist for instant token revocation upon logout or administrative revocation.

4. **Stage 4: Device Posture & Entropy Evaluation (`backend/gateway.py`)**
   - Evaluates User-Agent entropy, client headers, and anomaly indicators (e.g., automated scanners, headless browsers, cURL / Python clients).
   - Generates baseline risk points for suspicious user agents.

5. **Stage 5: Deep WAF Threat Detection Engine (`backend/threat_detection/`)**
   - Normalizes payload through a multi-pass evasion-prevention pipeline (URL unquoting, HTML entity decoding, Unicode canonicalization, null-byte stripping).
   - Runs parallel pattern matchers against query parameters, headers, and request body for:
     - SQL Injection (`SQLI_001` - `SQLI_006`)
     - Cross-Site Scripting (`XSS_001` - `XSS_005`)
     - Path Traversal & LFI (`TRAV_001` - `TRAV_004`)
     - Command Injection (`CMD_001` - `CMD_004`)
     - Server-Side Request Forgery (`SSRF_001` - `SSRF_003`)
     - Credential Brute-Force Abuse (`BRUTE_001` - `BRUTE_003`)

6. **Stage 6: Multi-Signal Risk Scoring & Policy Decision (`backend/risk_engine/`, `backend/policy/`)**
   - Aggregates multi-dimensional risk signals into a cumulative integer score $R \in [0, 100]$:
     $$R = \min\left(100, \sum w_i \cdot \text{signal}_i\right)$$
   - Evaluates against Zero-Trust Policy Matrix:
     - $R < 30$: `ALLOW` (Forward request to upstream application with telemetry headers)
     - $30 \le R < 60$: `CHALLENGE` / `WARN` (Allow with strict rate-limiting / stepped-up scrutiny)
     - $R \ge 60$: `BLOCK` (Immediate HTTP 403 Forbidden with security event dispatch)

7. **Stage 7: HMAC-SHA256 Audit Sealing & Stream Broadcast (`backend/audit/`, `backend/routes/ws.py`)**
   - Constructs a structured audit event.
   - Cryptographically binds the event into an immutable HMAC-SHA256 blockchain-style hash chain:
     $$\text{HMAC}_n = \text{HMAC-SHA256}(K, \text{Payload}_n \mathbin{\Vert} \text{HMAC}_{n-1})$$
   - Dispatches live telemetry to active SOC analysts via WebSocket channel `/ws/security-events`.

---

## 4. Database Schema Baseline

The persistent PostgreSQL database comprises four core tables managed by Alembic:

1. **`users`**:
   - `id` (UUID PK), `username` (VARCHAR 100 UNIQUE), `password_hash` (VARCHAR 255), `role` (ADMIN, ANALYST, USER), `is_active` (BOOL), `created_at` (TIMESTAMPTZ), `last_login` (TIMESTAMPTZ).
2. **`ip_blocklist`**:
   - `id` (UUID PK), `ip` (VARCHAR 64 UNIQUE), `reason` (VARCHAR 255), `blocked_at` (TIMESTAMPTZ), `expires_at` (TIMESTAMPTZ NULL), `created_by` (UUID FK -> users.id).
3. **`security_events`**:
   - `id` (UUID PK), `request_id` (VARCHAR 36 INDEX), `timestamp` (TIMESTAMPTZ INDEX), `source_ip` (VARCHAR 64 INDEX), `client_ipv6` (BOOL), `method` (VARCHAR 10), `path` (VARCHAR 1024), `query_string` (TEXT NULL), `user_agent` (TEXT NULL), `user_id` (UUID FK -> users.id NULL), `threats` (JSON), `risk_score` (INT), `risk_level` (VARCHAR 20 INDEX), `action` (VARCHAR 30 INDEX), `response_code` (INT NULL), `duration_ms` (INT NULL), `hmac_chain` (VARCHAR 128), `created_at` (TIMESTAMPTZ).
4. **`waf_rules`**:
   - `id` (UUID PK), `rule_id` (VARCHAR 50 UNIQUE), `name` (VARCHAR 255), `category` (VARCHAR 100), `severity` (VARCHAR 20), `enabled` (BOOL), `risk_weight` (INT), `updated_at` (TIMESTAMPTZ), `updated_by` (UUID FK -> users.id NULL).

---

## 5. Live Environment Verification Record

During Phase 1 inspection, the production container stack was audited directly on the host system:

- **Docker Version**: 29.8.0, build 88096ef
- **Active Container Services**:
  - `sentinelgate-nginx-1`: Port 80, 443 (Healthy, Up 10+ hours)
  - `sentinelgate-frontend-1`: Port 3000 (Healthy, Up 10+ hours)
  - `sentinelgate-gateway-1`: Port 8000 (Healthy, Up 10+ hours)
  - `sentinelgate-db-1`: PostgreSQL 16 (Healthy, Up 10+ hours)
  - `sentinelgate-redis-1`: Redis 7 (Healthy, Up 10+ hours)
- **Database Status**:
  - Registered Users: 4 (`admin`, `analyst`, `user`, `sim_analyst`)
  - Logged Security Events: 396 HMAC-sealed events
  - WAF Rules Engine: Fully initialized and responsive
- **API Health Check**: HTTP 200 OK (`GET /health`) returned in < 2ms.
- **Frontend Dashboard**: HTTP 200 OK (`GET http://localhost:3000`) serving Next.js 14 Tactical UI.

---

## 6. Phase 1 Conclusion & Hand-off

The existing application architecture has been fully verified and mapped. All underlying subsystems adhere to secure coding principles. The project is ready for **Phase 2: Requirements Engineering & Software Requirements Specification (SRS)** under Course Outcome CO1.

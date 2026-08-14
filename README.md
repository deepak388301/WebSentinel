# 🛡 WebSentinel

**Intelligent Web Attack Investigation Platform**

WebSentinel is a lightweight security monitoring platform that sits in front of a web application as a reverse proxy and WAF-style inspection layer. It watches incoming requests, detects common web attacks, scores their severity, and presents the findings through a live dashboard.

Unlike active scanners such as Burp Suite or OWASP ZAP, WebSentinel passively inspects live traffic and answers practical questions such as:

- Is someone attacking the site right now?
- What type of attack is it?
- Which endpoint is being targeted?
- How serious is the activity?
- What remediation should be applied?

The current implementation focuses on request inspection, logging, incident creation, and automatic blocking of high-severity attacks.

---

## ✨ Features

| Feature | Description |
|---|---|
| 📊 Live Request Monitoring | Every incoming HTTP request is logged in real time |
| 🚨 Attack Detection | SQL Injection, XSS, Path Traversal, Brute Force, Directory Enumeration, Command Injection, NoSQL Injection, SSRF, XXE |
| 📝 Automatic Incident Creation | Suspicious requests become structured, trackable incidents |
| 📈 Risk Scoring | Each finding receives a 0–100 score and a severity classification |
| 🎯 MITRE ATT&CK Mapping | Incidents include a relevant MITRE technique ID |
| 💡 Explainability | Findings include evidence and remediation guidance |
| 📊 Analytics Dashboard | The UI displays attack trends and summary statistics |
| 🛡️ Automatic Blocking | Critical and High severity findings are blocked before reaching the backend |
| 🔐 Dashboard Authentication | Single-admin login with rate-limiting, CSRF protection, and secure session cookies |
| 🛡️ CSP Nonces | Per-request Content Security Policy nonces on all inline scripts and styles |
| 📧 Email Alerting | Optional SMTP alerting for Critical/High incidents with per-IP cooldown |

---

## 🏗 How it works

The request lifecycle is straightforward:

1. A client sends a request to the WebSentinel proxy.
2. The app collects request metadata such as IP address, method, URL, headers, payload, and user agent.
3. The detection engine runs the payload through multiple detector modules.
4. If a detector matches, the risk engine scores the finding and creates an incident.
5. If the finding is Critical or High severity, the request is blocked (403 Forbidden). Otherwise, it is forwarded to the backend.
6. The dashboard reads the stored data to show recent activity and analytics.

```text
Client → WebSentinel Proxy → Inspect request → Run detectors → Score risk → Save incident → Forward/Block → Dashboard
```

---

## 🧰 Tech Stack

| Technology | Category | Purpose |
|---|---|---|
| Python | Language | Backend logic and detection rules |
| Flask | Web Framework | Routes, request handling, and templates |
| Flask-SQLAlchemy | ORM | Database models and persistence |
| Flask-Migrate / Alembic | Migrations | Schema versioning and migration management |
| PostgreSQL | Database | Stores requests and incidents (via Docker Compose) |
| HTML / Bootstrap | Frontend | Dashboard UI |
| JavaScript | Frontend | Basic dashboard interactivity |
| Chart.js | Charting | Analytics visuals |
| pytest | Testing | Regression tests for core logic |

---

## 📂 Project Structure

```text
WebSentinel/
├── proxy_app.py                # Main Flask app and proxy logic
├── start_websentinel.sh        # Starts the app (migrations + Gunicorn)
├── Dockerfile                  # Container image (runs as non-root)
├── docker-compose.yml          # App + PostgreSQL stack
├── requirements.txt            # Python dependencies
├── detectors/                  # Attack detection modules
│   ├── __init__.py
│   ├── sql.py
│   ├── xss.py
│   ├── traversal.py
│   ├── brute_force.py
│   └── enumeration.py
├── database/
│   ├── models.py               # Request and Incident SQLAlchemy models
│   └── init_db.py              # Database initialization/reset/seeding
├── utils/
│   ├── risk_engine.py          # Risk scoring and severity mapping
│   ├── alerting.py             # Email alerts (auto-detects SMTP provider)
│   ├── ip_blocklist.py         # Blocked-IP management + auto-blocking
│   ├── rate_limit.py           # In-memory per-IP rate limiting
│   └── reference_helpers.py    # MITRE / OWASP reference lookups
├── templates/                  # Dashboard HTML templates
│   ├── base.html
│   ├── login.html
│   ├── home.html
│   ├── live_monitor.html
│   ├── incidents.html
│   ├── analytics.html
│   ├── blocklist.html
│   └── settings.html
├── static/                     # Bootstrap/Chart.js vendor assets
├── migrations/                 # Alembic migrations (flask db upgrade)
├── tests/                      # Regression tests
│   ├── conftest.py
│   └── test_*.py
└── docs/
    └── architecture-diagram.png
```

---

## 🌐 Deployment Model

The current implementation is a Flask-based reverse proxy that inspects all traffic and automatically blocks Critical and High severity attacks. Medium and Low severity findings are logged and forwarded.

### Important note

This project currently focuses on local development and lightweight deployment. It does not implement TLS termination inside the Flask app by itself. In production, you should place it behind a reverse proxy or run it behind a TLS-terminating layer such as Nginx, Traefik, or Gunicorn with certificates.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- pip
- Docker and Docker Compose

### Installation

```bash
git clone https://github.com/deepak388301/WebSentinel.git
cd WebSentinel
pip install -r requirements.txt
```

### Start the full stack (Docker Compose)

```bash
docker compose up -d
```

This starts both PostgreSQL and the WebSentinel app in containers. The app
runs database migrations automatically on startup. The dashboard is
available at `http://127.0.0.1:8080/websentinel/`.

> **Targeting a service on your host machine?** Inside a container,
> `127.0.0.1` refers to the container itself, not the host. Use
> `host.docker.internal` (Mac/Windows) or `--network=host` (Linux) as
> `WEBSENTINEL_TARGET`. Docker Compose already maps `host.docker.internal`
> for you via `extra_hosts` in the compose file.

### Initialize the database

Local runs default to a SQLite file (`instance/websentinel.db`) with no
setup required. If you want to manage the schema manually, or use
PostgreSQL outside Docker:

```bash
python database/init_db.py            # run all migrations
python database/init_db.py --reset    # downgrade to base, then re-apply
python database/init_db.py --seed     # insert sample data for the dashboard
```

### Run tests

```bash
pytest -q
```

### Run the app locally

1. Copy the example environment file and adjust it for your setup:

```bash
cp .env.example .env
```

2. Make sure the target site is already running. WebSentinel must forward requests to a real upstream application. For a quick local test, start any simple site first:

```bash
mkdir -p /tmp/websentinel-target && cd /tmp/websentinel-target && python -m http.server 9000
```

3. Start WebSentinel:

```bash
./start_websentinel.sh
```

The script applies database migrations automatically and serves the proxy
and dashboard on a single port (`http://localhost:8080`). You can also run
it directly with the Flask dev server:

```bash
python proxy_app.py
```

Required environment variables:

```bash
WEBSENTINEL_ADMIN_PASS=<strong-password>       # REQUIRED — the app refuses to start without it
WEBSENTINEL_TARGET=http://127.0.0.1:9000
```

Optional environment variables (with defaults):

```bash
WEBSENTINEL_PORT=8080                  # proxy + dashboard port
WEBSENTINEL_DB_URI=                    # default: SQLite (instance/websentinel.db); docker-compose sets PostgreSQL
WEBSENTINEL_SECRET_KEY=                # default: random per start
```

> The app loads these from `.env` automatically (python-dotenv) whenever the
> file is present, so `cp .env.example .env` + editing it is enough.

Email alerting via the Gmail API (optional — one email per attacker IP per cooldown):

```bash
WEBSENTINEL_ALERT_ENABLED=false                # set true to enable
WEBSENTINEL_ALERT_EMAIL=you@gmail.com          # the Gmail account that receives alerts
WEBSENTINEL_ALERT_COOLDOWN_MINUTES=60          # suppress repeat alerts for this long
```

**No SMTP, no app passwords.** Alerts are sent through the Gmail API using
OAuth. Two files are needed:

1. **`credentials.json`** — an OAuth client of type *Desktop app* from
   [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
   (see "One-time setup" below). Drop it in the WebSentinel directory.
2. **`token.json`** — created by the one-time login (see below). It's a
   secret — `.gitignore`d — so back it up if you move machines.

### One-time setup (Gmail API)

1. Go to [Google Cloud Console](https://console.cloud.google.com/) → create
   a project (or pick one).
2. **APIs & Services → Library** → search for *Gmail API* → **Enable**.
3. **APIs & Services → OAuth consent screen** → External → add your email as
   a test user (the app only needs `gmail.send`, so no verification is
   required for personal use).
4. **APIs & Services → Credentials → Create Credentials → OAuth client ID →
   Desktop app** → download the JSON and save it as `credentials.json` in the
   WebSentinel directory.
5. Enable alerting (`WEBSENTINEL_ALERT_ENABLED=true`) and run the one-time
   login — this opens the browser, signs you into the Gmail account that
   receives alerts, and writes `token.json`:

   ```bash
   python -m utils.alerting authorize
   ```

6. (Optional) Confirm delivery without waiting for an attack:

   ```bash
   python -m utils.alerting send-test --email you@gmail.com
   ```

> **First-run behavior:** if `token.json` is missing, an alert tries to run
> the browser login itself, which only works on a machine with a browser and
> blocks the request until the login completes. Prefer step 5's command.
> If `credentials.json` is missing, the failure is reported clearly in the
> server log **and** shown as a warning on the dashboard Settings page —
> it is never silently dropped.

The token's refresh token expires if unused for ~7 days; just delete
`token.json` and run `python -m utils.alerting authorize` again.

### Running in Docker

The OAuth login must run **locally first** (it needs a browser). Complete
the one-time setup above on your host, then reuse the resulting
`credentials.json` + `token.json` in the container by mounting them:

```yaml
# docker-compose.yml — add to the `app` service:
volumes:
  - ./credentials.json:/app/credentials.json:ro
  - ./token.json:/app/token.json:ro
```

(Optional: the paths are configurable via `WEBSENTINEL_GOOGLE_CREDENTIALS`
and `WEBSENTINEL_GOOGLE_TOKEN` if you mount them elsewhere.)

Then open:

- http://localhost:8080/websentinel/

### Target Management

The backend target that WebSentinel forwards traffic to can be managed from
the dashboard (**Targets** page under `/websentinel/targets`) instead of
editing source code or environment configuration.

Flow:

```text
Client → WebSentinel → active protected target → response → WebSentinel → Client
```

Key points:

- **Only one target is ever active at a time.** The Targets page lets you
  add, edit, enable/disable, delete, and *Test* many configured targets, and
  **Set Active** promotes one enabled target to the active slot — clearing
  `active` on every other row in a single database update. The proxy forwards
  every request to that single active target. There is **no** simultaneous
  multi-target routing (no host- or path-based routing).
- **On first startup**, if the `targets` table is empty, WebSentinel
  auto-creates one row from `WEBSENTINEL_TARGET` (falling back to
  `DEFAULT_TARGET_URL`), marked both enabled and active. After that one-time
  bootstrap the database is the sole source of truth for the active target;
  the environment variable only seeds the initial row and is not re-read on
  every request. If the table is empty for any other reason (e.g. the only
  target was deleted), the proxy falls back to
  `WEBSENTINEL_TARGET`/`DEFAULT_TARGET_URL` directly and logs a clear warning.
- **Security model — informational notice, not a hard block.** Target URLs
  are validated server-side (absolute `http`/`https` only, hostname required,
  no embedded credentials, trailing slashes stripped, no exact duplicates).
  A target that points at a loopback/private/link-local address (for example
  `http://127.0.0.1:9000` or `http://localhost:5173`) is **accepted** — such
  internal backends are a legitimate, common deployment — and the UI shows a
  "Private/internal" badge asking you to confirm the choice. The same
  IP-classification logic as the SSRF detector (`detectors/ssrf.py`) is used,
  so the notice never disagrees with the detector. The optional **Test**
  action uses the already-validated stored URL with a short timeout and
  `allow_redirects=False` (a redirect to an internal address would be a
  classic SSRF bypass), and never affects proxy behavior.
- Every management action requires the dashboard admin login and is a
  CSRF-protected POST; deletion requires explicit confirmation.

Rate limiting (proxy traffic, not the dashboard):

```bash
WEBSENTINEL_RATE_LIMIT=100                 # requests per window per client IP (0 disables)
WEBSENTINEL_RATE_LIMIT_WINDOW=60           # window in seconds
```

Exceeding the limit returns **429 Too Many Requests** with a `Retry-After`
header; the IP is allowed again once the window slides past the oldest
request. Rate limiting is a *temporary throttle* — it never writes to the
blocklist (403 auto-blocks come only from the attack detectors), and the
login endpoint has its own separate throttle. The limiter is in-memory, so
keep a single Gunicorn worker per instance (the default).

Client IP detection: WebSentinel uses the raw socket peer and ignores
client-supplied `X-Forwarded-For` (it rewrites it on the way out), so IPs
can't be spoofed. If you run behind a **single trusted reverse proxy**
(Nginx, Traefik, Cloudflare, ...), set `WEBSENTINEL_TRUST_PROXY=true` — the
real client IP is then read from the right-most `X-Forwarded-For` entry
(the one your trusted proxy appends), so each real client gets its own
rate-limit bucket.

### Test the setup

You can generate a sample suspicious request with:

```bash
curl "http://127.0.0.1:8080/search?q=<script>alert(1)</script>"
```

Then visit the dashboard to review the stored request and incident.

---

## 🔍 Detected Attack Types

| Attack Type | Detection Method | MITRE Technique |
|---|---|---|
| SQL Injection | Keyword and regex matching for UNION SELECT, tautologies, comments, and other common patterns | T1190 |
| Cross-Site Scripting (XSS) | Script tag and JavaScript event-handler pattern matching | T1059.007 |
| Path Traversal | `../` sequences and sensitive path patterns | T1083 |
| Brute Force | Repeated failed authentication activity tracking | T1110 |
| Directory Enumeration | Scanner-style path probing such as `.env`, `.git`, and admin paths | T1595.003 |
| Command Injection | Shell metacharacter and command separator pattern matching | T1059 |
| NoSQL Injection | MongoDB-specific operator injection patterns (`$where`, `$ne`, `$gt`) | T1190 |
| SSRF | Internal IP, cloud metadata URI, and dangerous scheme detection | T1190 |
| XXE | XML external entity patterns in XML-typed request bodies | T611 |

---

## ⚠️ Current Limitations

- Detection is rule-based rather than machine-learning-based
- False positives can still occur for some edge-case legitimate input

---

## 🔮 Future Enhancements

- [ ] AI-assisted anomaly detection
- [ ] Honeypot-style decoy endpoints
- [ ] Better correlation across IPs, endpoints, and time windows
- [ ] Redis-backed rate limiting
- [ ] More advanced WAF rule generation
- [ ] Cloud deployment (AWS)
- [ ] Raspberry Pi network sensor mode (IDS appliance)

---


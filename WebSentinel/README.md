# 🛡 WebSentinel

**Intelligent Web Attack Investigation Platform**

WebSentinel is a lightweight security monitoring platform that sits in front of a web application as a reverse proxy and WAF-style inspection layer. It watches incoming requests, detects common web attacks, scores their severity, and presents the findings through a live dashboard.

Unlike active scanners such as Burp Suite or OWASP ZAP, WebSentinel passively inspects live traffic and answers practical questions such as:

- Is someone attacking the site right now?
- What type of attack is it?
- Which endpoint is being targeted?
- How serious is the activity?
- What remediation should be applied?

The current implementation focuses on request inspection, logging, incident creation, and basic blocking in protect mode.

---

## ✨ Features

| Feature | Description |
|---|---|
| 📊 Live Request Monitoring | Every incoming HTTP request is logged in real time |
| 🚨 Attack Detection | SQL Injection, XSS, Path Traversal, Brute Force, and Directory Enumeration |
| 📝 Automatic Incident Creation | Suspicious requests become structured, trackable incidents |
| 📈 Risk Scoring | Each finding receives a 0–100 score and a severity classification |
| 🎯 MITRE ATT&CK Mapping | Incidents include a relevant MITRE technique ID |
| 💡 Explainability | Findings include evidence and remediation guidance |
| 📊 Analytics Dashboard | The UI displays attack trends and summary statistics |
| 🛡️ Protect Mode | Critical and High severity findings can be blocked before reaching the backend |

---

## 🏗 How it works

The request lifecycle is straightforward:

1. A client sends a request to the WebSentinel proxy.
2. The app collects request metadata such as IP address, method, URL, headers, payload, and user agent.
3. The detection engine runs the payload through multiple detector modules.
4. If a detector matches, the risk engine scores the finding and creates an incident.
5. The request is either forwarded or blocked depending on the configured mode.
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
| SQLite | Database | Stores requests and incidents |
| HTML / Bootstrap | Frontend | Dashboard UI |
| JavaScript | Frontend | Basic dashboard interactivity |
| Chart.js | Charting | Analytics visuals |
| pytest | Testing | Regression tests for core logic |

---

## 📂 Project Structure

```text
WebSentinel/
├── proxy_app.py                # Main Flask app and proxy logic
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
│   └── risk_engine.py          # Risk scoring and severity mapping
├── templates/                  # Dashboard HTML templates
│   ├── base.html
│   ├── home.html
│   ├── live_monitor.html
│   ├── incidents.html
│   └── analytics.html
├── tests/                      # Regression tests
│   ├── conftest.py
│   └── test_risk_engine.py
└── docs/
    └── architecture-diagram.png
```

---

## 🌐 Deployment Model

The current implementation is a Flask-based reverse proxy that can operate in two modes:

| Mode | Behavior |
|---|---|
| `detect` | Logs and scores suspicious traffic, but forwards everything to the backend |
| `protect` | Blocks requests classified as Critical or High severity before they reach the backend |

### Important note

This project currently focuses on local development and lightweight deployment. It does not implement TLS termination inside the Flask app by itself. In production, you should place it behind a reverse proxy or run it behind a TLS-terminating layer such as Nginx, Traefik, or Gunicorn with certificates.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.9+
- pip

### Installation

```bash
git clone https://github.com/deepak388301/WebSentinel.git
cd WebSentinel
pip install -r requirements.txt
```

### Initialize the database

```bash
python database/init_db.py            # create tables if they don't exist
python database/init_db.py --reset     # drop tables and recreate them
python database/init_db.py --seed      # insert sample data for the dashboard
```

### Run tests

```bash
pytest -q
```

### Run the app locally

For the simplest user experience, WebSentinel now includes a helper script that starts the app with Gunicorn and HTTPS termination using certificate files.

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

The script will generate a self-signed certificate automatically if `cert.pem` and `key.pem` are missing.

Required environment variables:

```bash
WEBSENTINEL_TARGET=http://127.0.0.1:9000
WEBSENTINEL_MODE=detect
WEBSENTINEL_DB_URI=sqlite:///websentinel.db
WEBSENTINEL_PORT=8443
SSL_CERT_PATH=cert.pem
SSL_KEY_PATH=key.pem
```

Then open:

- https://127.0.0.1:8443/websentinel/
- or https://localhost:8443/websentinel/

### Test the setup

You can generate a sample suspicious request with:

```bash
curl -k "https://127.0.0.1:8443/search?q=<script>alert(1)</script>"
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

---

## ⚠️ Current Limitations

- Detection is rule-based rather than machine-learning-based
- Brute-force tracking is currently lightweight and resets on restart
- The app uses SQLite by default and is best suited for local or small deployments
- False positives can still occur for some edge-case legitimate input

---

## 🔮 Future Enhancements

- [ ] AI-assisted anomaly detection
- [ ] Honeypot-style decoy endpoints
- [ ] Better correlation across IPs, endpoints, and time windows
- [ ] Alerting via email or messaging services
- [ ] Redis-backed rate limiting and brute-force tracking
- [ ] PostgreSQL support for larger deployments
- [ ] Docker containerization
- [ ] More advanced WAF rule generation
- [ ] Cloud deployment (AWS)
- [ ] Raspberry Pi network sensor mode (IDS appliance)

---

## 👤 Author

**Deepak**
Aspiring VAPT Analyst | Electronics & Communication Engineering, Karpagam Institute of Technology

---

## 📄 License

This project is built for educational and portfolio purposes as part of a VAPT skills-development roadmap.

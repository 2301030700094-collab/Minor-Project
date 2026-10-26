# Security Log Analyzer

A Flask web app that uploads security log files, parses them, detects
suspicious activity, shows a dashboard with charts, and generates a
downloadable PDF report.

Supports **three log types in a single file** — lines are auto-detected,
so you can mix them freely:
- **Auth logs** (login attempts)
- **Application logs** (INFO/WARNING/ERROR/CRITICAL)
- **Network/Firewall logs** (allow/block traffic)

## Setup

```bash
cd SecurityLogAnalyzer
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

Two sample files are included:
- `logs/sample.log` — auth-only, for a quick original-format demo
- `logs/sample_mixed.log` — all three log types mixed together, upload
  this one to see every detection rule fire at once

## Detection Rules

**Auth logs**

| Rule | Trigger |
|---|---|
| Brute Force | Same IP has more than 5 failed logins |
| Odd Hour Login | Login attempt between 2 AM and 4 AM |
| Credential Stuffing | Same IP tries 4+ distinct usernames |
| Malformed Log | IP address is not valid IPv4 |
| High Risk Account | A single username has more than 10 failed logins |

**Application logs**

| Rule | Trigger |
|---|---|
| Frequent Errors | More than 5 ERROR/CRITICAL entries in the file |
| Critical Event | Any single CRITICAL entry is flagged immediately |

**Network/Firewall logs**

| Rule | Trigger |
|---|---|
| Port Scan | Same source IP contacts 5+ distinct destination ports |
| Blocked Traffic Spike | Same source IP has more than 5 BLOCK/DENY entries |

## Project Structure

```
SecurityLogAnalyzer/
├── app.py                 Main Flask app (routes, DB)
├── requirements.txt
├── analyzer/
│   ├── parser.py           Log line parsing (regex)
│   ├── detector.py         Suspicious activity rules
│   └── report.py           PDF report generation
├── templates/
│   ├── index.html          Upload page + history
│   └── dashboard.html      Stats, charts, search/filter
├── static/
│   ├── css/style.css
│   ├── js/dashboard.js     Search/filter via /api/logs
│   └── charts/             Generated chart PNGs
├── uploads/                Uploaded log files
├── reports/                Generated PDF reports
├── logs/sample.log         Demo log file
└── database.db             SQLite DB (created on first run)
```

## Expected Log Line Formats

```
# Auth
2026-07-20 10:21:14 LOGIN SUCCESS user=admin ip=192.168.1.5
2026-07-20 10:22:20 LOGIN FAILED user=root ip=10.10.10.2

# Application
2026-07-20 14:32:10 [INFO] Server started on port 5000
2026-07-20 14:35:02 [ERROR] Database connection timeout after 30s

# Network / Firewall
2026-07-20 15:02:11 NETWORK ALLOW src=192.168.1.10 dst=8.8.8.8 port=443 proto=TCP
2026-07-20 15:02:45 NETWORK BLOCK src=45.33.10.7 dst=192.168.1.5 port=22 proto=TCP
```

All three formats can appear in the same uploaded file — each line is
auto-detected and routed to the matching parser.

## Notes / Next Steps

This covers Steps 1–13 of the original project plan (upload, parsing,
analysis, detection rules, dashboard, charts, search, filter,
suspicious IP table, PDF download, DB storage, history). Optional
extras you could add for extra marks: dark mode, login page, CSV
export, email report, auto-refresh dashboard.

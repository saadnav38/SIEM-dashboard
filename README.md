# SIEM Dashboard

A Security Information and Event Management (SIEM) dashboard built from scratch to aggregate, correlate, and visualize security events from multiple log sources in real time.

## Overview

This project replicates core functionality found in enterprise SIEM platforms like Splunk and IBM QRadar. It ingests logs from multiple sources, normalizes them into a consistent schema, runs correlation rules to detect attack patterns, and visualizes everything through an interactive web dashboard.

Built as a portfolio project to demonstrate practical knowledge of security operations, log analysis, and threat detection.

## Features

- **Multi-source log ingestion** supporting Suricata IDS alerts, Linux auth logs, firewall logs, and Suricata eve.json (flow, DNS, DHCP events)
- **Log normalization** converting different log formats into a consistent event schema with standard fields
- **Correlation rule engine** detecting brute force attacks, account compromise, and port scans across multiple events
- **Real time dashboard** showing event timelines, severity distribution, event type breakdown, and top source IPs
- **Forensic pivot** clicking any source IP filters the entire dashboard to show only that IP's activity
- **Severity based alerting** with configurable thresholds and Slack webhook notifications for critical events
- **Time range filtering** across last 1 hour, 24 hours, and 7 days windows
- **Export capabilities** downloading filtered events as CSV or JSON for external analysis
- **Session based authentication** with hashed passwords protecting all routes and API endpoints
- **Real Suricata data** ingested from a live Kali Linux home lab running Suricata 8.0.3 with Emerging Threats rules

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| Database | SQLite |
| Frontend | HTML, CSS, Vanilla JavaScript |
| Charts | Chart.js |
| Log Source | Suricata IDS (eve.json), Linux auth.log, firewall logs |
| Auth | Werkzeug password hashing, Flask sessions |

## Project Structure
SIEM-dashboard/
├── app.py            # Flask backend and REST API endpoints
├── database.py       # SQLite schema and connection management
├── ingestor.py       # Log parsers and normalization engine
├── correlator.py     # Correlation rule engine and alert generation
├── rules.json        # Configurable detection rules
├── templates/
│   ├── index.html    # Main dashboard
│   └── login.html    # Authentication page
└── static/
├── css/style.css
└── js/dashboard.js

## Detection Rules

The correlation engine detects the following patterns:

| Rule | Threshold | Severity |
|---|---|---|
| Brute Force Attack | 5+ failed logins in 10 minutes from same IP | High |
| Account Compromise | Failed logins followed by successful login | Critical |
| Port Scan | 3+ IDS alerts in 5 minutes from same IP | High |

Rules are configurable via `rules.json` without modifying code.

## Setup and Installation

**Prerequisites:** Python 3.8+, pip

```bash
# Clone the repository
git clone https://github.com/saadnvv/SIEM-dashboard.git
cd SIEM-dashboard

# Install dependencies
pip install flask werkzeug python-dotenv

# Initialize the database
python database.py

# Ingest sample logs or point to your own eve.json
python ingestor.py

# Run correlation rules
python correlator.py

# Start the dashboard
python app.py
```

Open your browser to `http://127.0.0.1:5000`

**Default credentials:**
**Credentials are set via environment variables. Copy `.env.example` to `.env` and set your own passwords before running.**

## Slack Alerting

To enable Slack notifications for critical and high severity alerts:

1. Create a Slack incoming webhook at https://api.slack.com/messaging/webhooks
2. Copy `config.example.json` to `config.json`
3. Add your webhook URL to `config.json`

Critical and high severity alerts will automatically post to your Slack channel.

## Log Sources

**Suricata eve.json** Place your Suricata eve.json in the `logs/` directory. The ingestor handles alert, flow, DNS, and DHCP event types automatically.

**Auth logs** Place Linux auth.log in the `logs/` directory for SSH login event parsing.

**Firewall logs** Place firewall logs in the `logs/` directory for connection allow/deny event parsing.

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/events` | GET | Paginated events with filters |
| `/api/alerts` | GET | Triggered correlation alerts |
| `/api/stats` | GET | Severity counts, type counts, top IPs |
| `/api/timeline` | GET | Event volume per hour |
| `/api/export` | GET | Export events as CSV or JSON |
| `/api/events/<id>` | GET | Single event detail |
| `/api/ingest` | POST | Trigger log ingestion and correlation |

## SIEM Concepts Demonstrated

**Log Normalization** Raw logs from different sources look completely different. The ingestor converts every log format into a consistent schema so events from Suricata, auth.log, and firewall logs are all stored and queried the same way.

**Event Correlation** Individual events rarely tell the full story. The correlation engine looks across multiple events to detect patterns. A single failed login is noise. Fifty failed logins from the same IP followed by a successful login is a compromised account.

**Alert Fatigue Prevention** Real SIEMs generate thousands of alerts. This dashboard groups related alerts by source IP and rule name to prevent analysts from being overwhelmed by duplicate notifications.

**Forensic Pivoting** When an analyst sees a suspicious IP they can click Investigate to instantly filter the entire dashboard to that IP's activity, replicating the pivot workflow used in commercial SIEM platforms.

## Comparison to Commercial SIEMs

| Feature | This Project | Splunk | IBM QRadar |
|---|---|---|---|
| Log ingestion | File based | Agent based | Agent based |
| Correlation rules | Config file | SPL queries | AQL queries |
| Storage | SQLite | Proprietary | PostgreSQL |
| Visualization | Chart.js | Built in | Built in |
| Scale | Single host | Enterprise | Enterprise |

## Limitations

- Single host deployment, not designed for distributed log collection at scale
- SQLite is suitable for development and small deployments, production would use PostgreSQL
- Correlation rules are evaluated on demand rather than in real time streaming
- No machine learning based anomaly detection

## Author

Saad Nav | [LinkedIn](https://linkedin.com/in/saadnav) | [GitHub](https://github.com/saadnav38)

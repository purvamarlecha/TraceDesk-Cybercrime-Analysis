# TraceDesk — Cybercrime Analysis Workspace

A student-friendly Flask + SQLite web application that combines official Indian cybercrime statistics with account-based incident tracking and explainable URL triage.

## Features
- **Login / signup / logout:** account validation, unique email addresses and Werkzeug password hashing.
- **Account-scoped cases:** users can only see, update and export their own incident records.
- **Activity audit trail:** records key actions such as incident creation, status updates, URL checks and CSV exports.
- **Evidence note integrity demo:** stores a SHA-256 digest of an optional evidence note. A hash can help detect changes to the same text, but does not prove authenticity or chain of custody.
- **Explainable URL triage:** transparent rule-based checks for visible URL patterns. It does not open URLs or query threat intelligence.
- **Public data provenance:** official national yearly totals and limitations.
- **CSV export, search and status workflow.**
- **Privacy-aware design:** simulated examples are clearly labelled; the app does not file police reports.

## Real data included
`data/ncrb_national_cases.csv` contains official national registered-case totals:
- 2019: 44,735
- 2020: 50,035
- 2021: 52,974
- 2022: 65,893
- 2023: 86,420

Source: Ministry of Home Affairs / Press Information Bureau, *Cyber Crime Cases*, 17 March 2026:
https://www.pib.gov.in/PressReleaseIframePage.aspx?PRID=2244504&lang=1&reg=3

Official NCRB catalogue:
https://www.data.gov.in/catalog/crime-india-2023

These are registered cases, not every incident that occurred. Do not infer individual risk or guilt from national totals. Three starter incident records are explicitly simulated teaching examples.

## Run locally
1. Install Python 3.10 or later.
2. Open this folder in VS Code and open a terminal.
3. Optional virtual environment:
   - Windows: `python -m venv .venv` then `.venv\\Scripts\\activate`
   - macOS/Linux: `python3 -m venv .venv` then `source .venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Start: `python app.py`
6. Open `http://127.0.0.1:5000`, then choose **Create account**.

The SQLite database `cybercrime.db` is created automatically. If you already ran an earlier version, the app adds the `user_id` column when possible. The starter example cases are assigned to the first account created so the initial workspace has example data.

## Project structure
```
cybercrime_analysis/
├── app.py
├── requirements.txt
├── README.md
├── data/ncrb_national_cases.csv
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── signup.html
│   ├── index.html
│   ├── cases.html
│   ├── report.html
│   ├── analyzer.html
│   ├── audit.html
│   └── data.html
└── static/style.css
```

## Viva explanation
**Problem:** Public cybercrime statistics are hard to explore, and incident notes need consistent documentation.

**Solution:** TraceDesk combines a public-data dashboard, authenticated incident workspace, URL triage, audit trail and evidence-note hashing.

**Data science angle:** yearly trend analysis, year-on-year percentage change, structured data, search and CSV export. The trend is descriptive, not predictive.

**Cybersecurity angle:** password hashing, session-based access, account-scoped records, URL warning signals, SHA-256 and auditability.

**Limitations:** this is a classroom prototype. The URL score is heuristic, examples are simulated, and national case counts do not represent all cybercrime. The audit log is not tamper-proof. For real deployment, use a strong environment secret, HTTPS, CSRF protection, rate limiting, secure cookie settings, backups, and proper administrative controls.

## Safety
Do not enter real passwords you use elsewhere, full financial identifiers or unredacted victim details. For actual cybercrime in India, use https://cybercrime.gov.in/ or call 1930 for financial cyber fraud assistance.

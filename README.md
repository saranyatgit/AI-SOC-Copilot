# 🛡️ AI-Powered SOC Copilot

An AI-assisted Security Operations Center (SOC) platform that detects anomalous
network traffic using machine learning, maps detected attacks to the **MITRE
ATT&CK** framework, generates AI-written incident explanations with **Google
Gemini**, and gives analysts a persistent, filterable incident workflow — all
through an interactive dashboard plus a companion REST API.

Built on the **CICIDS2017** intrusion detection dataset.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Dataset](#dataset)
- [REST API](#rest-api)
- [Known Limitations](#known-limitations)
- [Roadmap / Future Improvements](#roadmap--future-improvements)
- [Acknowledgments](#acknowledgments)

---

## Overview

Security analysts are flooded with network traffic logs and alerts, most of
which are noise. This project explores how machine learning and generative AI
can help triage that noise: an **Isolation Forest** model flags anomalous
network flows, each flagged flow is mapped to a MITRE ATT&CK tactic and
technique, and **Gemini** turns the raw statistics into a plain-English
incident summary an analyst can act on immediately — complete with indicators
of compromise, SOC recommendations, and business impact.

Incidents are persisted in SQLite, so they survive restarts and can be
tracked through an investigation workflow (Open → Investigating → Resolved),
and the whole thing sits behind a login screen instead of being open to
anyone who finds the URL.

## Key Features

- **🚨 ML-Based Anomaly Detection** — Isolation Forest trained on CICIDS2017
  network flow features (packet timing, flag counts, byte rates, and more)
- **🎯 MITRE ATT&CK Mapping** — detected anomalies are mapped to real tactics,
  techniques, technique IDs, descriptions, and mitigations
- **🤖 AI-Generated Incident Explanations** — Google Gemini turns raw
  detection output into a threat summary, IoCs, SOC recommendations, and
  business impact assessment
- **📄 PDF Incident Reports** — one-click, professional incident reports via
  ReportLab
- **📑 Persistent Incident Management** — incidents are stored in SQLite (not
  lost on restart), with filtering by status/risk and a full
  Open → Investigating → Resolved workflow
- **📂 CSV Upload & Analysis** — upload your own CICIDS2017-format flow
  export and run it through the same detection pipeline, with automatic
  handling of missing values and column validation against the trained model
- **🔐 Authentication** — salted, hashed (PBKDF2-HMAC-SHA256) credential
  storage; no open self-registration after the first admin account is created
- **🌐 REST API** — a FastAPI backend exposing incidents (list, filter, get,
  update status, delete) and summary stats programmatically, with
  auto-generated OpenAPI docs
- **📊 Analytics Dashboard** — attack distribution, flow duration
  distributions, and destination port analysis via Plotly/Matplotlib

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend / Dashboard | Streamlit |
| Backend API | FastAPI, Uvicorn |
| Machine Learning | Scikit-learn (Isolation Forest) |
| Generative AI | Google Gemini API |
| Threat Intelligence | MITRE ATT&CK Framework |
| Database | SQLite |
| Data Processing | Pandas, NumPy |
| Visualization | Matplotlib, Plotly |
| Reporting | ReportLab |
| Auth | Python `hashlib` (PBKDF2-HMAC-SHA256), no external auth dependency |

## Project Structure

```
AI-SOC-Copilot/
├── ai/
│   └── gemini_explainer.py       # Gemini prompt construction & API calls
├── dashboard/
│   ├── home.py
│   ├── log_viewer.py             # Raw security log viewer
│   ├── anomaly_dashboard.py       # Threat detection on the built-in dataset
│   ├── csv_upload.py             # Threat detection on user-uploaded CSVs
│   ├── analytics.py               # Charts: attack distribution, flow stats
│   ├── incidents.py               # Persistent incident management UI
│   └── reports.py
├── data/
│   └── raw/
│       └── combined_logs.csv     # CICIDS2017 data (not committed — see below)
├── ml/
│   └── anomaly_detector.py       # Feature prep, model training/loading, prediction
├── models/
│   └── isolation_forest.pkl      # Trained model (generated locally, not committed)
├── reports/
│   ├── generated/                # Output PDF incident reports
│   └── pdf_report.py
├── threat_intelligence/
│   └── mitre_mapper.py           # MITRE ATT&CK tactic/technique lookups
├── utils/
│   ├── incident_db.py            # SQLite incident storage & queries
│   ├── auth_db.py                # SQLite user accounts & password hashing
│   ├── risk_score.py             # Risk level assignment
│   └── combine_dataset.py        # CICIDS2017 CSV consolidation
├── api.py                        # FastAPI backend (separate process from Streamlit)
├── app.py                        # Streamlit entry point
├── requirements.txt
└── README.md
```

## Getting Started

### Prerequisites

- Python 3.10+
- A [Google Gemini API key](https://ai.google.dev/)
- The [CICIDS2017 dataset](https://www.unb.ca/cic/datasets/ids-2017.html)
  (not included in this repo due to size)

### Installation

```bash
git clone https://github.com/<your-username>/AI-SOC-Copilot.git
cd AI-SOC-Copilot

python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

pip install -r requirements.txt
```

### Configuration

```bash
cp .env.example .env
```

Then edit `.env` and add your key:

```
GEMINI_API_KEY=your_gemini_api_key_here
```

### Prepare the Data & Model

1. Download CICIDS2017 and consolidate it into `data/raw/combined_logs.csv`
   (see `utils/combine_dataset.py`).
2. Train and save the model:

```bash
python ml/anomaly_detector.py
```

This trains the Isolation Forest on the numeric features of your combined
dataset and saves it to `models/isolation_forest.pkl`.

### Run the App

```bash
streamlit run app.py
```

On first launch, you'll be prompted to create the admin account (no open
signup after that). Log in, and you'll land on the dashboard.

### Run the API (optional, separate process)

```bash
uvicorn api:app --reload --port 8000
```

Interactive API docs are available at `http://127.0.0.1:8000/docs`.

## Dataset

This project uses **CICIDS2017**, a labeled network intrusion detection
dataset from the Canadian Institute for Cybersecurity. Note that this
dataset does **not** include source/destination IP addresses — detection and
enrichment logic here is built entirely around flow-level statistics (flow
duration, packet rates, byte rates, flag counts, and similar), not
IP-reputation lookups.

## REST API

The FastAPI backend (`api.py`) exposes the incident database independently
of the Streamlit UI:

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Liveness check |
| GET | `/incidents` | List incidents (filter by `status`, `risk`) |
| GET | `/incidents/stats` | Summary counts (total, by status, high risk) |
| GET | `/incidents/{id}` | Fetch a single incident |
| PATCH | `/incidents/{id}/status` | Update workflow status |
| DELETE | `/incidents/{id}` | Delete an incident |

The API and the Streamlit app share the same SQLite database file, so
incidents created in one are visible in the other.

> **Note:** the API currently has no authentication of its own — it's
> intended for local/demo use alongside the Streamlit app, not public
> exposure as-is.

## Known Limitations

Being upfront about what's simplified rather than hiding it:

- **Attack type classification is a placeholder.** Every flow the model
  flags as suspicious is currently labeled `"Port Scan"` for MITRE mapping
  purposes, regardless of what the traffic actually looks like. Real
  multi-class attack classification is a natural next step.
- **Risk scoring is binary (High/Low)**, not the finer-grained
  Critical/High/Medium/Low tiering that would better reflect real SOC
  triage.
- **Session-based auth only.** Login state lives in Streamlit's
  `session_state`, not a persistent cookie or token — refreshing the browser
  logs you out. Fine for a demo; a real deployment would want proper session
  tokens.
- **No rate limiting or role-based access control** on either the dashboard
  or the API — every authenticated user has full access.

## Roadmap / Future Improvements

- [ ] Real multi-class attack-type classification (replacing the current
      placeholder mapping)
- [ ] Tiered risk scoring (Critical/High/Medium/Low)
- [ ] Persistent, token-based authentication sessions
- [ ] API authentication (key or token-based)


## Acknowledgments

- [CICIDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html) —
  Canadian Institute for Cybersecurity, University of New Brunswick
- [MITRE ATT&CK](https://attack.mitre.org/) framework
- [Google Gemini](https://ai.google.dev/) for AI-generated threat explanations

---


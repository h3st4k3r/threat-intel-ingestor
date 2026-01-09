# CTI Intel Ingest

A lightweight, open-source Cyber Threat Intelligence (CTI) ingestion and staging pipeline that collects **vulnerabilities**, **malware IOCs**, and **cybersecurity news** from open sources, normalizes artifacts, deduplicates entries, and stores everything locally in **SQLite** for downstream consumption (OpenCTI / Elastic / AI workflows).

## What this project does

- Pulls CTI data from multiple open sources (API + RSS)
- Normalizes records into a consistent internal schema (vuln / ioc / news)
- Deduplicates reliably using stable fingerprints
- Persists artifacts in a local SQLite database (`intel.db`)
- Prints a compact preview of the latest stored items after each run

This repo is intentionally the **ingestion layer** only: it focuses on getting clean, consistent, reusable data into a local store. Export to OpenCTI / Elastic and advanced enrichment are planned as next steps.

## Data sources (current)

### Vulnerabilities
- CISA Known Exploited Vulnerabilities (KEV)
- NVD (NIST) CVEs (API 2.0, time window mode)

### Malware IOCs
- MalwareBazaar (recent samples)

### Cybersecurity news / context
- RSS/Atom feeds (configurable list in `main.py`)

## Project structure

```
app/
  collectors/
    base.py
    cisa_kev.py
    malwarebazaar.py
    news_rss.py
    nvd_cves.py
  http_client.py
  runner.py
  storage.py
  models.py
  conf.example.py
  main.py
```

## Requirements

- Look the requirements.txt

## Quick start

### 1) Create and activate venv
```bash
python -m venv .venv
source .venv/bin/activate
```

### 2) Install dependencies
```bash
pip install -U pip
pip install requests feedparser
```

### 3) Configure secrets

Copy the template and fill in your API keys:

```bash
cp app/conf.example.py app/conf.py
```

Edit `app/conf.py`:

```python

NVD_API_KEY = "YOUR_NVD_API_KEY"
MLW_API_KEY = "YOUR_MALWAREBAZAAR_API_KEY"

```

### 4) Run
```bash
python app/main.py
```

You should see per-collector stats and a preview of the last 10 stored items.

## Output

- SQLite DB: `intel.db`
- Table: `items` (deduplicated by `fingerprint`)
- Console preview shows:
  - `kind` (vuln / ioc / news)
  - `source`
  - `source_id` (shortened)
  - `title` (shortened)

## Notes / operational considerations

- Some RSS sources may enforce anti-bot measures; the HTTP client uses a browser-like User-Agent for better compatibility.
- NVD calls should be rate-limited. The collector sleeps between pages to avoid hammering the API.
- This repository intentionally does **not** include any OpenCTI/Elastic exporters yet; it is a staging layer.

## Roadmap

Planned next steps:
- OpenCTI export (STIX mapping + dedup + watermark)
- Elastic ingestion strategy (OpenCTI connector or STIX feed -> Elastic TI)
- IOC expansion: ThreatFox, URLhaus, Feodo Tracker, Spamhaus DROP/EDROP, etc.
- Enrichment: confidence scoring, tagging, expiration/TTL, and cross-source correlation

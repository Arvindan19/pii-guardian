# PII Guardian

PII Guardian is a data privacy tool that uses AI-powered PII detection to automatically anonymise sensitive institutional data. Built with Python, Streamlit, and Microsoft Presidio, it replaces real personal information with realistic fake data while preserving the structure and analytical value of your datasets. Designed specifically for Australian university workflows, it handles student records, grades, and financial identifiers out of the box.

## Live Demo

🔗 [https://pii-guardian-caimjbmk9hbtixme63lkta.streamlit.app/](https://pii-guardian-caimjbmk9hbtixme63lkta.streamlit.app/)

## What It Does

- **AI Scan tab** — Presidio's NLP engine automatically detects and redacts names, email addresses, and phone numbers across all columns without any configuration required.
- **Column Mode tab** — Manually map any column to one of 42 university-specific fake data types, including Student ID, WAM, unit codes, TFN, BSB, and other Australian academic and financial identifiers.
- **Re-link tab** — Restores original data after analysis is complete using an encrypted lookup table, so anonymised datasets can always be traced back to the source records when authorised.

## Why It Matters

- **Australian Privacy Act compliance** — Helps institutions meet their obligations under the Privacy Act 1988 before sharing data with third parties, researchers, or external systems.
- **Data never leaves the device in local mode** — All processing runs on-device with no external API calls, so sensitive student information is never transmitted over a network.
- **Consistent substitution preserves analytical integrity** — The same real value always maps to the same fake value, keeping anonymised data groupable and aggregatable for downstream analysis.

## Tech Stack

Python · Streamlit · Microsoft Presidio · spaCy · Faker · Pandas · GitHub · Streamlit Cloud

## How To Run Locally

**Option 1 — Python (recommended):**
```bash
py -3.11 -m streamlit run app.py
```

**Option 2 — Windows executable (no installation needed):**
```
Double-click PII-Guardian.exe
```

## What I Would Add Next

- **Multi-sheet Excel support** — Allow per-sheet anonymisation configuration so workbooks with different data types on each tab can be processed in a single pass.
- **Audit log** — Record who anonymised which file, when, and with which column mappings, to satisfy institutional data governance requirements.
- **Student management system integration** — Direct connectors to common university platforms (e.g. Callista, PeopleSoft) to pull and push data without manual CSV exports.

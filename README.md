# Aegis Guard

**Live demo:** https://aegis-guard-vanguard.streamlit.app/

## Problem
Phishing attacks and online scams pose serious threats to digital security. Users often struggle to identify malicious URLs, fraudulent messages, and deceptive websites before interacting with them. Existing security awareness gaps leave users vulnerable to financial fraud, data theft, and identity compromise.

## Solution
Aegis is a Python-based, AI-assisted phishing detection system designed to identify potential cyber threats before users click. By analysing URLs and suspicious messages using machine learning and rule-based detection, Aegis provides risk assessments, explainable threat indicators, and actionable safety recommendations, empowering users to make safer digital decisions.

## Features
- Feature 1 (working)
- Feature 2 (working)

## Tech stack
- Python 3.14, Streamlit
- (APIs, datasets, libraries)

## Setup
```powershell
git clone https://github.com/kevalya-rathore/url-check.git
cd url-check
py -V:3.14 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

## Environment variables
Copy `.streamlit/secrets.toml.example` to `.streamlit/secrets.toml` and fill in:

| Name | What it is |
|---|---|
| `API_KEY` | placeholder: your own key from ... |

## Known limitations
- ...

## Future scope
- ...

## Third-party tools and AI disclosure
- Starter template: this repo began from our own pre-event template (empty Streamlit skeleton, README, `.gitignore`), declared as boilerplate.
- Libraries / APIs / datasets: ...
- AI tools: (none / which tool, and what it was used for)

## Team contributions
| Member | Role | Built |
|---|---|---|
| Kevalya Rathore | App lead | |
| Abhay Katta | Logic/data | |
| Mohammad Zaid Qureshi | UX + testing | |
| Prakarsh Jain | Docs + pitch | |

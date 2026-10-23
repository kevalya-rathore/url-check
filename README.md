# Aegis Guard

**Live demo:** https://aegis-guard-vanguard.streamlit.app/

## Problem
Phishing attacks and online scams pose serious threats to digital security. Users often struggle to identify malicious URLs, fraudulent messages, and deceptive websites before interacting with them. Existing security awareness gaps leave users vulnerable to financial fraud, data theft, and identity compromise.

## Solution
Aegis Guard checks a link, an SMS/WhatsApp message, or a QR code for phishing warning signs **before** you open it. It never visits the link: every check works offline on the text of the link or message. The verdict is one of three levels (Low, Caution, High), and every warning sign behind it is labelled **FACT** (anyone can verify it from the link) or **HEURISTIC** (an educated guess from common scam patterns), with safe next steps and where to report fraud in India.

## Features
- **Link check (working).** 14 offline checks: official brand domains (132 brands in `data/brands.json`, plus every RBI-only `.bank.in` bank), brand impersonation and one-letter typos (lookalike typos like `paytn` count more), lookalike letters and punycode, IP-address hosts, the `@` trick, plain `http://`, risky endings, link shorteners, free-hosting abuse, links hidden inside links, and offline snapshots of the OpenPhish phishing feed (23 Oct 2026) and the URLhaus malware-download feed from abuse.ch (24 Oct 2026).
- **Hidden redirect destinations (working).** Redirect links from Google (`/url`, `/goto`), Facebook (`/l.php`) and YouTube (`/redirect`) are judged by the destination written inside them. That destination is read from the link text and never opened. A redirect link with no readable destination is flagged.
- **Message check (working).** Urgency and threat words, requests for an OTP/PIN/password, "pay first to receive" tricks, Indian threat scams (digital arrest, customs, challan, electricity cut-off), and a brand named in the message whose link goes to a site that brand doesn't own. Every link in the message is also run through the link check, and a message is never rated safer than its riskiest link.
- **QR code check (working).** Upload a picture of a QR code. It is decoded from the pixels only (zxing-cpp), then checked as a link, a UPI payment or a message.
- **UPI payment check (working).** For `upi://` links, typed in or from a QR code, the app checks for a malformed payee ID, autopay mandates, a pre-filled amount, "refund/prize/cashback" bait, and a payee using a bank or brand name. It always reminds you that a UPI QR code can only take money from you.
- **Browser extension (working, load unpacked).** Right-click a link or selected text in Chrome and choose "Check with Aegis Guard". The extension opens the app with the link already checked. Right-click the page itself to check every link on it: with `api.py` running, risky links get a warning badge right on the page, including links whose text names a different site from where they really go.
- **Examples and Evaluation pages (working).** 71 labelled, synthetic, defanged examples (links, messages and UPI payment links). The Evaluation page runs all of them and lists every false alarm and miss.
- **Defanged input (working).** `hxxps://` and `[.]` are turned back into a real link before checking.

## Tech stack
- Python 3.14, Streamlit 1.66.1 (multipage app with `st.navigation`)
- `tldextract` (built-in suffix snapshot, no download), Pillow + `zxing-cpp` (QR decoding)
- Data: `data/brands.json` (brand → official domains), `data/openphish_feed.txt` (offline OpenPhish snapshot, non-commercial use), `data/urlhaus_feed.txt` (offline URLhaus snapshot), `data/examples.csv` (labelled examples)
- Browser extension: Chrome Manifest V3 (`extension/`)
- No API keys, no LLM, no network calls during a check

## Project layout
| Path | What it is |
|---|---|
| `app.py` | Entry point: page config, logo, theme fixes, top navigation bar |
| `pages/home.py` | Check a link, message or QR code; shows the verdict, signals and next steps |
| `pages/examples.py` | The labelled examples, each with an "Analyze" button |
| `pages/evaluation.py` | Accuracy, false alarms and misses on the examples |
| `pages/how_it_works.py` | Plain-language explanation of every check, the verdict rules and the limitations |
| `logic.py` | All detection logic, no Streamlit: `analyze_url`, `analyze_text`, `analyze_upi`, `decode_qr`, `analyze_qr_text`, `evaluate_examples` |
| `extension/` | The Chrome right-click extension |
| `api.py` | Local-only server the extension uses to mark risky links on the page itself |
| `assets/qr-test-images/` | Four sample QR codes for the demo (official SBI link, lookalike phishing link, fake UPI refund, normal shop UPI) |

## Setup
```powershell
git clone https://github.com/kevalya-rathore/url-check.git
cd url-check
py -V:3.14 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

### Browser extension
1. Open `chrome://extensions` and turn on **Developer mode**.
2. Click **Load unpacked** and choose the `extension` folder.
3. Right-click any link (or select a message) and choose **Check with Aegis Guard**.

The extension sends to the live demo by default. To use a local copy, change `APP` in `extension/background.js` to `http://localhost:8501/` and reload the extension. It passes the link as `?url=...` (or a selected message as `?text=...`), and the home page checks it once on arrival.

**Check a whole page.** Right-click empty space on a page and choose **Check all links on this page with Aegis Guard**. If `python api.py` is running (a local-only server on `127.0.0.1:8600`), risky links get a red or amber badge right on the page: hover over a badge for the reasons, or click it for the full explanation. Without `api.py`, up to 40 of the page's links open in the app as a list instead (`?links=...`).

## Environment variables
None. The app runs fully offline and reads no secrets. `.streamlit/secrets.toml.example` is left over from the starter template.

## Known limitations
- Because we never open the link, a scam page on a clean-looking domain with no suspicious words or endings is rated **Low**.
- A hacked official website still matches our official-domain list.
- Brand checks cover the 132 brands in `brands.json`. Impersonation of other organisations relies on the general checks.
- One-letter typos of short brand names (e.g. `sbl` for SBI) aren't flagged, to avoid false alarms.
- The OpenPhish and URLhaus snapshots age within hours, so a link that isn't on either list is not automatically safe.
- Redirect unwrapping only knows Google, Facebook and YouTube redirect links.
- A UPI ID can't be verified offline: we can't tell whether `shop@okaxis` really belongs to that shop.
- Only the first QR code in a picture is checked.
- Message checks are English only.
- Lookalike typos count more, so a real company one doubled letter from a brand (phillips.com vs Philips) is rated Caution.
- A UPI payee's name can't be verified, so a real shop's billing QR that uses a brand name and fills in the amount is rated Caution.
- The checks make no network calls, but the live demo runs on Streamlit Community Cloud, so what you paste is sent there to be checked (the app doesn't save it). The extension puts the link or selected text in the page address, so it also appears in browser history. Remove OTPs, PINs and account numbers before checking a message, or run the app locally.
- Current results on our own test set (24 Oct 2026): 67 of 71 correct, 2 false alarms, 2 misses. The Evaluation page always shows the live numbers.

## Future scope
- Optional domain-age lookup via RDAP (off by default, `timeout=5`, visible "couldn't check" fallback)
- Hindi and other Indian-language message checks
- More redirect wrappers, and a larger, regularly refreshed phishing list
- Publishing the browser extension to the Chrome Web Store, plus a mobile share-sheet target

## Third-party tools and AI disclosure
- Starter template: this repo began from our own pre-event template (empty Streamlit skeleton, README, `.gitignore`), declared as boilerplate.
- Libraries: Streamlit, tldextract, Pillow, zxing-cpp.
- Datasets: OpenPhish community feed (snapshot of 23 Oct 2026, non-commercial use); URLhaus by abuse.ch (snapshot of 24 Oct 2026).
- AI tools: Claude Code and Google Antigravity were used to review code against the brief and explain fixes. Claude Code also applied some changes the team lead asked for and reviewed (the brand-vs-link and lookalike-typo checks, the UPI examples, and wording fixes); the Evaluation page shows their effect.

## Team contributions
| Member | Role |
|---|---|
| Kevalya Rathore | App lead |
| Abhay Katta | Logic/data |
| Mohammad Zaid Qureshi | UX + testing |
| Prakarsh Jain | Docs + pitch |

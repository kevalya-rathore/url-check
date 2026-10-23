# Team conventions

Rules for every teammate **and every AI tool** (Claude Code, Antigravity, ...) working in this repo. If a rule here and an AI suggestion disagree, this file wins.

## Files and owners

One owner per file. Only the owner edits it. Fill in the names at the venue.

| File | What goes in it | Owner |
|---|---|---|
| `app.py` | Entry point: page config, logo, theme CSS fixes, the `st.navigation` bar listing every page | App lead: |
| `pages/home.py`, `examples.py`, `evaluation.py`, `how_it_works.py` | One page per feature. A new page must also be added to the `pages` list in `app.py` | one person per page |
| `logic.py` | Core processing. Plain Python, **no `import streamlit`**, no network calls | Logic/data: |
| `data/brands.json`, `data/examples.csv`, `data/openphish_feed.txt` | Brand → official domains, labelled examples, offline phishing list | Logic/data: |
| `extension/` | Chrome right-click extension (`manifest.json`, `background.js`) | App lead: |
| `assets/` | Logo and the sample QR codes in `qr-test-images/` | App lead: |
| `README.md`, `PITCH.md` | Submission docs, pitch | Docs + pitch: |
| `requirements.txt`, `CONVENTIONS.md`, `.streamlit/secrets.toml.example` | Shared: **add lines only**, never rewrite | everyone |

Planned but not created (no need yet): `api.py` for the optional RDAP domain-age lookup, `test_logic.py` for plain `assert` tests (run: `py test_logic.py`).

Create a file only when it's needed. A new file gets a row here first.

Need a change in someone else's file? Ask the owner. They make it, or you make it together while they watch.

## Interfaces (decide in the first hour)

Write the function signatures before building, so pages can call them on day one. Until the real code exists, the function returns hard-coded fake data.

| Function | Input | Returns | File |
|---|---|---|---|
| `analyze_url(url)` | `str` (a link, or a `upi://` link, which it passes to `analyze_upi`) | result dict | `logic.py` |
| `analyze_text(text)` | `str` (SMS / WhatsApp message) | result dict | `logic.py` |
| `analyze_upi(upi)` | `str` (`upi://pay?...` or `upi://mandate?...`) | result dict | `logic.py` |
| `decode_qr(image_file)` | uploaded picture | `list[str]`, the text of each QR code; raises `ValueError` if none | `logic.py` |
| `analyze_qr_text(text)` | `str` from `decode_qr` | result dict (one word → `analyze_url`, longer → `analyze_text`) | `logic.py` |
| `refang_url(text)` | `str` | `str` (`hxxps://` → `https://`, `[.]` → `.`) | `logic.py` |
| `load_examples()` | none | `list[dict]`, rows of `examples.csv` | `logic.py` |
| `evaluate_examples()` | none | `dict` with `total`, `correct`, `accuracy`, `false_alarms`, `misses` (and `error` if the CSV is missing) | `logic.py` |

The result dict is `{"input", "score" (0-100), "level" ("Low" / "Caution" / "High"), "signals": [{"kind", "check", "title", "evidence", "points", "advice"}], "next_steps": [str]}`, as described at the top of `logic.py`.

The home page also accepts `?url=...` or `?text=...` in its address (sent by the browser extension) and checks it once on arrival.

## Code rules

- Every page follows the `pages/home.py` shape: setup -> input -> PART 1 (actions, only on submit) -> PART 2 (display, every rerun).
- `session_state` keys: brackets only (`st.session_state["items"]`), and only the keys listed below. New key = new row here first.
- Secrets: `st.secrets["NAME"]` only. Never in a `.py` file, never committed. Add a placeholder to `secrets.toml.example`.
- Every new `import` of a package -> add it to `requirements.txt` in the same commit.
- Every network call has `timeout=5` and a fallback, so the demo never breaks.

| `session_state` key | Type | Set by |
|---|---|---|
| `result` | result dict, or `None` before the first check | `pages/home.py` (also `pages/examples.py` before switching to the home page) |

## Git rules

1. `git pull` when you start working and right before every push.
2. Commit small, every 30–60 minutes, with a message that says what changed.
3. Before you push: `streamlit run app.py` and click through your part. `main` is the live demo.
4. Run `git status` and `git diff` before every commit. Commit only your own files.
5. Shared files (`requirements.txt` etc.): pull, add your line, commit and push straight away.
6. Merge conflict: keep both sides unless they truly clash, run the app, then commit. Ask for help if unsure.
7. Feature freeze at **hour 16 (06:00 Saturday)**. After it, bug fixes only.

## AI tools

- AI may only edit files you own. Check every diff before committing.
- AI never commits or pushes. A human does, after reading the change.
- **Nobody commits code they can't explain line by line.** The judges will ask.
- Note which tool you used for what, for the README disclosure.

# Team conventions

Rules for every teammate **and every AI tool** (Claude Code, Antigravity, ...) working in this repo. If a rule here and an AI suggestion disagree, this file wins.

## Files and owners

One owner per file. Only the owner edits it. Fill in the names at the venue.

| File | What goes in it | Owner |
|---|---|---|
| `app.py` | Home page: page config, title, shared `session_state` setup | App lead: |
| `pages/N_Name.py` | One page per feature (Streamlit adds it to the sidebar) | one person per page |
| `logic.py` | Core processing. Plain Python, **no `import streamlit`** | Logic/data: |
| `api.py` | `requests` / LLM calls, each with a fallback to `sample_data.json` | Logic/data: |
| `storage.py` | Reading and writing JSON/CSV/SQLite | (assign) |
| `test_logic.py` | Plain `assert` tests for `logic.py`. Run: `py test_logic.py` | UX + testing: |
| `README.md`, `PITCH.md` | Submission docs, pitch | Docs + pitch: |
| `requirements.txt`, `CONVENTIONS.md`, `.streamlit/secrets.toml.example` | Shared: **add lines only**, never rewrite | everyone |

Create a file only when it's needed. A new file gets a row here first.

Need a change in someone else's file? Ask the owner. They make it, or you make it together while they watch.

## Interfaces (decide in the first hour)

Write the function signatures before building, so pages can call them on day one. Until the real code exists, the function returns hard-coded fake data.

| Function | Input | Returns | File |
|---|---|---|---|
| `process(text)` | `str` | `dict` | `logic.py` |

## Code rules

- Every page follows the `app.py` shape: setup -> input -> PART 1 (actions, only on submit) -> PART 2 (display, every rerun).
- `session_state` keys: brackets only (`st.session_state["items"]`), and only the keys listed below. New key = new row here first.
- Secrets: `st.secrets["NAME"]` only. Never in a `.py` file, never committed. Add a placeholder to `secrets.toml.example`.
- Every new `import` of a package -> add it to `requirements.txt` in the same commit.
- Every network call has `timeout=5` and a fallback, so the demo never breaks.

| `session_state` key | Type | Set by |
|---|---|---|
| `items` | list of dicts | `app.py` |

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

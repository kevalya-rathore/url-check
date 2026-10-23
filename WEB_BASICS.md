# Web basics: one page to read at the venue

Not part of the app. Delete this file from the event repo, or keep it out of the commit.

## Client and server

- The **client** (the browser, or your Python code using `requests`) sends a **request** to a **URL**.
- The **server** sends back a **response**, which has a **status code** and a **body**. The body is often JSON.
- Your Streamlit app is itself a server. The browser on your phone is a client of it.

## HTTP methods

| Method | Meaning | Example |
|---|---|---|
| `GET` | Read something. Changes nothing. | Get the weather for Jaipur |
| `POST` | Send data to create something or start an action | Submit a form, ask an LLM a question |
| `PUT` / `PATCH` | Update something | Edit a profile |
| `DELETE` | Remove something | Delete an expense |

## Status codes

| Code | Meaning | What to do |
|---|---|---|
| 200 | OK | Use the body |
| 201 | Created | Your `POST` worked |
| 400 | Bad request | Your parameters are wrong. Read the API docs |
| 401 / 403 | Not logged in / not allowed | The API key is missing or wrong |
| 404 | Not found | The URL is wrong |
| 429 | Too many requests | You hit the rate limit. Slow down, or use cached data |
| 500 / 503 | The server broke | Not your fault. Fall back to sample data |

The rule: 2xx = success, 4xx = **your** mistake, 5xx = **their** problem.

## API key

- An API key is a password for your **code**. It goes in `.streamlit/secrets.toml` (locally) and in the app's **Secrets** settings (in the cloud).
- Read it with `st.secrets["API_KEY"]`. Never write it in a `.py` file, and never commit it.

## CORS, in one paragraph

Browsers stop JavaScript on site A from reading responses from site B, unless site B allows it. That's CORS. **It doesn't affect your Streamlit app**, because your Python code calls APIs from the server, not from the browser. If a judge asks, the answer is: "Our API calls happen server-side in Python, so CORS doesn't apply."

## `requests` with a fallback (demo mode)

```python
import json
import requests

def get_data(city):
    try:
        response = requests.get(
            "https://api.example.com/weather",
            params={"city": city},
            timeout=5,
        )
        response.raise_for_status()      # turns 4xx/5xx into an exception
        return response.json()           # JSON body -> dicts and lists
    except requests.RequestException:
        with open("sample_data.json") as f:
            return json.load(f)          # saved response: the demo never breaks
```

- `timeout=5`: without it, a dead network can freeze the app forever.
- `try`/`except`: in C you'd check a return code after every call. In Python, the error jumps straight to `except`.
- Save one real response to `sample_data.json` as soon as the API works.

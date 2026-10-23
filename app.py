# Starter template (declared boilerplate, written before the event).
# Shape: setup -> input -> PART 1 (actions, only on submit) -> PART 2 (display, every rerun)
import streamlit as st

from logic import full_url_scan, verdict

st.set_page_config(page_title="Aegis Guard", page_icon="🛡️")
st.title("Aegis Guard")
st.caption("Enter a URL to see phishing warning signs before you click.")

if "result" not in st.session_state:
    st.session_state["result"] = None

with st.form("input", clear_on_submit=False):
    text = st.text_input("Link to check", placeholder="www.getmalware.com").strip()
    submitted = st.form_submit_button("Check link")

# PART 1: actions, only on the run where the button was clicked
if submitted:
    if not text:
        st.error("Input can't be empty.")
    elif len(text) > 2000:
        st.error("Input can't be more than 2000 characters.")
    else:
        score, reasons = full_url_scan(text, online=False)
        label, colour, advice = verdict(score)
        st.session_state["result"] = {
            "input": text,
            "score": score,
            "label": label,
            "colour": colour,
            "advice": advice,
            "reasons": reasons,
        }

# PART 2: display, on every rerun, read from session_state
result = st.session_state["result"]
if result is None:
    st.info("Paste a link above and press Check link.")
else:
    st.code(result["input"], language=None)
    if result["colour"] == "error":
        st.error(result["label"])
    elif result["colour"] == "warning":
        st.warning(result["label"])
    else:
        st.success(result["label"])
    st.metric("Risk score", f"{result['score']} / 100")
    st.subheader("Why")
    if not result["reasons"]:
        st.text("No warning signs found.")
    for reason in result["reasons"]:
        st.text("• " + reason)
    st.subheader("What to do")
    st.write(result["advice"])
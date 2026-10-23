# Starter template (declared boilerplate, written before the event).
# Shape: setup -> input -> PART 1 (actions, only on submit) -> PART 2 (display, every rerun)
import streamlit as st

from logic import analyze_text, analyze_url

st.set_page_config(page_title="Aegis Guard", page_icon="🛡️")
st.title("Aegis Guard")
st.caption("Paste a link or a message from SMS, WhatsApp or email to see phishing warning signs before you click.")

if "result" not in st.session_state:
    st.session_state["result"] = None

mode = st.radio("What do you want to check?", ["Link", "Message"], horizontal=True)

with st.form("input", clear_on_submit=False):
    if mode == "Link":
        text = st.text_input("Link to check", placeholder="e.g. sbi.co.in").strip()
    else:
        text = st.text_area("Message to check", placeholder="Paste the SMS or WhatsApp message here").strip()
    submitted = st.form_submit_button("Check")

# PART 1: actions, only on the run where the button was clicked
if submitted:
    if not text:
        st.error("Input can't be empty.")
    elif len(text) > 2000:
        st.error("Input can't be more than 2000 characters.")
    else:
        if mode == "Link":
            st.session_state["result"] = analyze_url(text, online=False)
        else:
            st.session_state["result"] = analyze_text(text, online=False)

# PART 2: display, on every rerun, read from session_state
result = st.session_state["result"]
if result is None:
    st.info("Paste a link above and press Check link.")
else:
    st.code(result["input"], language=None)
    if result["level"] == "High":
        st.error("HIGH RISK: don't click, reply or pay.")
    elif result["level"] == "Caution":
        st.warning("CAUTION: some warning signs found. Check before you act.")
    else:
        st.success("LOW RISK: no strong warning signs found.")
    st.metric("Risk score", f"{result['score']} / 100")
    st.subheader("Why")
    if not result["signals"]:
        st.text("No warning signs found.")
    for signal in result["signals"]:
        with st.container(border=True):
            st.markdown(f"**{signal['kind']}** · {signal['points']:+d} points")
            st.text(signal["title"])
            st.code(signal["evidence"], language=None)
    st.subheader("What to do")
    for step in result["next_steps"]:
        st.markdown(f"- {step}")

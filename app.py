# Starter template (declared boilerplate, written before the event).
# Shape: setup -> input -> PART 1 (actions, only on submit) -> PART 2 (display, every rerun)
import streamlit as st

from logic import process

st.set_page_config(page_title="Aegis Guard", page_icon="🚀")
st.title("Aegis Guard")
st.caption("Enter a URL to check safety rating")

if "result" not in st.session_state:
    st.session_state["result"] = []

with st.form("input", clear_on_submit=False):
    text = st.text_input("URL").strip()
    submitted = st.form_submit_button("Submit")

# PART 1: actions, only on the run where the button was clicked
if submitted:
    if not text:
        st.error("Input can't be empty.")
    elif len(text) > 2000:
        st.error("Input can't be more than 2000 characters")
    else:
        st.session_state["result"]

# PART 2: display, on every rerun, read from session_state
if not st.session_state["items"]:
    st.info("Nothing yet.")
else:
    st.dataframe(st.session_state["result"])

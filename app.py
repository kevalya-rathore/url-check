# Starter template (declared boilerplate, written before the event).
# Shape: setup -> input -> PART 1 (actions, only on submit) -> PART 2 (display, every rerun)
import streamlit as st

from logic import process

st.set_page_config(page_title="APP NAME", page_icon="🚀")
st.title("APP NAME")
st.caption("One sentence: who this is for and what it does.")

if "items" not in st.session_state:
    st.session_state["items"] = []

with st.form("input", clear_on_submit=True):
    text = st.text_input("Input").strip()
    submitted = st.form_submit_button("Submit")

# PART 1: actions, only on the run where the button was clicked
if submitted:
    if not text:
        st.error("Input can't be empty.")
    else:
        st.session_state["items"].append(process(text))
        st.success("Added.")

# PART 2: display, on every rerun, read from session_state
if not st.session_state["items"]:
    st.info("Nothing yet.")
else:
    st.dataframe(st.session_state["items"])

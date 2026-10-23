# Examples page: our labelled test links and messages. "Analyze" opens one on the home page.
# Shape: setup -> load the examples -> display (each "Analyze" button acts on the run it was clicked)
import streamlit as st

from logic import analyze_text, analyze_url, load_examples, refang_url


def analyze_and_open(row):
    """Check one example and show its result on the home page."""
    clean_input = refang_url(row["input"])    # turn "hxxps://sbi[.]xyz" back into a real link, only for checking
    if row["channel"] == "url":
        st.session_state["result"] = analyze_url(clean_input)
    else:
        st.session_state["result"] = analyze_text(clean_input)
    st.switch_page("app.py")    # the home page shows whatever is in st.session_state["result"]


def show_examples(rows, tab_name):
    """One bordered box per example, with an "Analyze" button."""
    for number, row in enumerate(rows):
        with st.container(border=True):
            st.code(row["input"], language=None)    # shown exactly as stored (defanged), never as a link
            channel = "Link" if row["channel"] == "url" else "Message"
            st.caption(f"{channel} · {row['why']}")
            # Every button needs its own key, otherwise Streamlit stops with a "DuplicateWidgetID" error
            if st.button("Analyze", key=f"{tab_name}-{number}"):
                analyze_and_open(row)


st.set_page_config(page_title="Examples - Aegis Guard", page_icon="🛡️")
st.title("Examples")
st.caption(
    "All examples are synthetic and written for testing. Suspicious links are shown defanged "
    "(hxxp and [.]), so none of them is clickable."
)

examples = load_examples()
if not examples:
    st.info("No examples yet: data/examples.csv is missing or empty.")
    st.stop()

suspicious = [row for row in examples if row["label"] == "suspicious"]
benign = [row for row in examples if row["label"] == "benign"]
st.write(f"{len(examples)} examples: {len(suspicious)} suspicious and {len(benign)} benign.")

suspicious_tab, benign_tab = st.tabs([f"Suspicious ({len(suspicious)})", f"Benign ({len(benign)})"])
with suspicious_tab:
    show_examples(suspicious, "suspicious")
with benign_tab:
    show_examples(benign, "benign")

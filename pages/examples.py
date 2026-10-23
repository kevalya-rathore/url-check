# Examples page: our labelled test links and messages. "Analyze" opens one on the home page.
# Shape: header -> load the examples -> display (each "Analyze" button acts on the run it was clicked)
import streamlit as st

from logic import analyze_text, analyze_url, load_examples, refang_url


def analyze_and_open(row):
    """Check one example and show its result on the home page."""
    clean_input = refang_url(row["input"])    # turn "hxxps://sbi[.]xyz" back into a real link, only for checking
    if row["channel"] == "url":
        st.session_state["result"] = analyze_url(clean_input)
    else:
        st.session_state["result"] = analyze_text(clean_input)
    st.switch_page("pages/home.py")    # the home page shows whatever is in st.session_state["result"]


def show_examples(rows, tab_name):
    """Example cards in two columns, each with its label, channel, reason and an "Analyze" button."""
    left, right = st.columns(2)
    for number, row in enumerate(rows):
        column = left if number % 2 == 0 else right    # alternate between the two columns
        with column.container(border=True):
            with st.container(horizontal=True):
                if row["label"] == "suspicious":
                    st.badge("Suspicious", icon=":material/warning:", color="red")
                else:
                    st.badge("Benign", icon=":material/check_circle:", color="green")
                if row["channel"] == "url":
                    st.badge("Link", icon=":material/link:", color="gray")
                else:
                    st.badge("Message", icon=":material/sms:", color="gray")
            st.code(row["input"], language=None, wrap_lines=True)    # shown exactly as stored (defanged), never as a link
            st.caption(row["why"])
            # Every button needs its own key, otherwise Streamlit stops with a "DuplicateWidgetID" error
            if st.button("Analyze", key=f"{tab_name}-{number}", icon=":material/arrow_forward:", width="stretch"):
                analyze_and_open(row)


st.title("Examples", anchor=False, text_alignment="center")
st.markdown("#### Our labelled test links and messages", text_alignment="center")

examples = load_examples()
if not examples:
    st.info("No examples yet: data/examples.csv is missing or empty.")
    st.stop()

suspicious = [row for row in examples if row["label"] == "suspicious"]
benign = [row for row in examples if row["label"] == "benign"]
with st.container(horizontal=True, horizontal_alignment="center"):
    st.badge(f"{len(examples)} examples", icon=":material/dataset:", color="gray")
    st.badge("All synthetic", icon=":material/science:", color="gray")
    st.badge("Links shown defanged", icon=":material/link_off:", color="gray")
st.caption(
    "Suspicious links are written as hxxp and [.] so none of them can be clicked. "
    "Press Analyze to see the full verdict on the home page.",
    text_alignment="center",
)

suspicious_tab, benign_tab = st.tabs([f":material/warning: Suspicious ({len(suspicious)})",
                                      f":material/check_circle: Benign ({len(benign)})"])
with suspicious_tab:
    show_examples(suspicious, "suspicious")
with benign_tab:
    show_examples(benign, "benign")

st.page_link("pages/evaluation.py", label="See how Aegis Guard scores on all of them", icon=":material/insights:")

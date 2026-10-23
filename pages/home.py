# Home page: paste a link or a message and see its warning signs.
# Shape: header -> input -> PART 1 (actions, only on submit) -> PART 2 (display, every rerun)
import streamlit as st

from logic import analyze_text, analyze_url, refang_url


def severity(points):
    """Turn a signal's points into a severity label and badge colour, so no raw numbers appear on screen."""
    if points <= 0:
        return "Reassuring", "green"
    if points >= 30:
        return "Severe", "red"
    if points >= 15:
        return "Moderate", "orange"
    return "Minor", "gray"


def show_signal(signal):
    """One card per warning sign: severity and kind badges, the explanation, and the exact evidence."""
    label, color = severity(signal["points"])
    with st.container(border=True):
        with st.container(horizontal=True):    # puts the two badges side by side
            st.badge(label, color=color)
            if signal["kind"] == "FACT":
                st.badge("FACT", icon=":material/verified:", color="blue",
                         help="Something anyone can check from the link or message itself")
            else:
                st.badge("HEURISTIC", icon=":material/lightbulb:", color="violet",
                         help="An educated guess based on common scam patterns; it can be wrong")
        st.text(signal["title"])    # plain text, because titles can contain the suspicious link
        st.code(signal["evidence"], language=None)


st.title("Aegis :violet[Guard]", anchor=False, text_alignment="center")    # "violet" is Athena Gold in our theme
st.markdown("#### Stop the scam before the click", text_alignment="center")
with st.container(horizontal=True, horizontal_alignment="center"):    # a centred row of trust badges
    st.badge("Works offline", icon=":material/wifi_off:", color="gray")
    st.badge("Never opens your link", icon=":material/visibility_off:", color="gray")
    st.badge("Explains every warning", icon=":material/info:", color="gray")

if "result" not in st.session_state:
    st.session_state["result"] = None

mode = st.segmented_control("What do you want to check?", ["Link", "Message"], default="Link", required=True)

with st.form("input", clear_on_submit=False):
    if mode == "Link":
        text = st.text_input("Link to check", placeholder="e.g. sbi.co.in").strip()
    else:
        text = st.text_area("Message to check", placeholder="Paste the SMS or WhatsApp message here").strip()
    submitted = st.form_submit_button("Check for warning signs", type="primary", icon=":material/search:", width="stretch")

# PART 1: actions, only on the run where the button was clicked
if submitted:
    if not text:
        st.error("Input can't be empty.")
    elif len(text) > 2000:
        st.error("Input can't be more than 2000 characters.")
    else:
        clean_text = refang_url(text)    # undo "hxxp" and "[.]" so links copied from safe write-ups are checked properly
        try:
            if mode == "Link":
                st.session_state["result"] = analyze_url(clean_text)
            else:
                st.session_state["result"] = analyze_text(clean_text)
        except ValueError:
            st.session_state["result"] = None
            st.error("That doesn't look like a valid link. Check for stray brackets and try again.")

# PART 2: display, on every rerun, read from session_state
result = st.session_state["result"]
if result is None:
    # Before the first check: three steps that explain what the app does
    st.divider()
    paste_col, check_col, verdict_col = st.columns(3)
    with paste_col.container(border=True):
        st.markdown(":material/content_paste: **1. Paste**")
        st.caption("A link or message you received by SMS, WhatsApp or email.")
    with check_col.container(border=True):
        st.markdown(":material/manage_search: **2. We check**")
        st.caption("13 link checks and 4 message checks, run offline in under a second.")
    with verdict_col.container(border=True):
        st.markdown(":material/task_alt: **3. Get a clear verdict**")
        st.caption("How risky it is, the reasons behind it, and safe next steps.")
    st.page_link("pages/examples.py", label="Browse some examples of malicious links", icon=":material/list_alt:")
else:
    st.divider()
    # The verdict in words and colour, never colour alone
    if result["level"] == "High":
        st.error("**High risk.** Don't click, reply or pay.", icon="🚨")
    elif result["level"] == "Caution":
        st.warning("**Be careful.** Some warning signs found. Check before you act.", icon="⚠️")
    else:
        st.success("**Low risk.** No strong warning signs found.", icon="✅")

    # A summary row: the level, how many warning signs, and how many of them are facts
    warnings = [signal for signal in result["signals"] if signal["points"] > 0]
    facts = [signal for signal in warnings if signal["kind"] == "FACT"]
    level_col, warning_col, fact_col = st.columns(3)
    level_col.metric("Threat level", result["level"], border=True)
    warning_col.metric("Warning signs", len(warnings), border=True)
    fact_col.metric("Of which facts", len(facts), border=True)
    st.progress(result["score"], text="Threat meter")

    st.caption("What we checked")
    st.code(result["input"], language=None)

    st.subheader("Why", anchor=False)
    signals = sorted(result["signals"], key=lambda s: s["points"], reverse=True)    # most severe first
    if not signals:
        st.text("No warning signs found.")
    for signal in signals:
        show_signal(signal)

    st.subheader("What to do now", anchor=False)
    with st.container(border=True):
        for number, step in enumerate(result["next_steps"], start=1):
            st.markdown(f"{number}. {step}")

st.divider()
st.caption(
    "Aegis Guard shows warning signs, not a guarantee. If in doubt, contact the organisation through its "
    "official app or website. Report fraud at cybercrime.gov.in or call 1930.",
    text_alignment="center",
)

# Home page: paste a link or a message and see its warning signs.
# Shape: header -> input -> PART 1 (actions, only on submit) -> PART 2 (display, every rerun)
import streamlit as st

from logic import analyze_qr_text, analyze_text, analyze_url, decode_qr, refang_url


def severity(points):
    """Turn a signal's points into a severity label and badge colour, so no raw numbers appear on screen."""
    if points <= 0:
        return "Reassuring", "green"
    if points >= 30:
        return "Severe", "red"
    if points >= 15:
        return "Moderate", "orange"
    return "Minor", "gray"


def threat_disc(score, level):
    """
    A ring (an SVG drawing) that fills up as the threat grows, coloured and labelled by the level.
    Only our own values (a number and a level name) go into it, never the user's input.
    """
    color = {"High": "#FB7185", "Caution": "#FBBF24", "Low": "#34D399"}[level]    # Coral, Amber, Emerald
    circumference = 2 * 3.1416 * 80    # the ring's radius is 80
    filled = circumference * score / 100
    # The coloured part of the ring, starting at the top; left out when there's no threat at all
    arc = "" if score == 0 else (
        f'<circle cx="100" cy="100" r="80" fill="none" stroke="{color}" stroke-width="16" stroke-linecap="round" '
        f'stroke-dasharray="{filled:.1f} {circumference:.1f}" transform="rotate(-90 100 100)"/>'
    )
    font = 'font-family="Inter, Segoe UI, Arial, sans-serif"'
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200" viewBox="0 0 200 200">
  <circle cx="100" cy="100" r="80" fill="none" stroke="#24344D" stroke-width="16"/>
  {arc}
  <text x="100" y="102" text-anchor="middle" {font} font-size="28" font-weight="700" fill="{color}">{level}</text>
  <text x="100" y="128" text-anchor="middle" {font} font-size="13" fill="#94A3B8">threat level</text>
</svg>"""


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

mode = st.segmented_control("What do you want to check?", ["Link", "Message", "QR code"], default="Link", required=True)

with st.form("input", clear_on_submit=False):
    image = None
    if mode == "Link":
        text = st.text_input("Link to check", placeholder="e.g. sbi.co.in or upi://pay?pa=...").strip()
    elif mode == "Message":
        text = st.text_area("Message to check", placeholder="Paste the SMS or WhatsApp message here").strip()
    else:
        text = ""
        image = st.file_uploader("Picture of the QR code", type=["png", "jpg", "jpeg", "webp"])
    submitted = st.form_submit_button("Check for warning signs", type="primary", icon=":material/search:", width="stretch")

# PART 1: actions, only on the run where the button was clicked
if submitted and mode == "QR code":
    if image is None:
        st.error("Choose a picture of a QR code first.")
    else:
        try:
            codes = decode_qr(image)    # only reads the picture; nothing the code points to is opened
        except ValueError:
            st.session_state["result"] = None
            st.error("No QR code found in that picture. Try a sharper photo with the whole code in view.")
        else:
            if len(codes) > 1:
                st.info(f"This picture has {len(codes)} QR codes. Checking the first one.")
            st.session_state["result"] = analyze_qr_text(codes[0])
elif submitted:
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

    # The threat disc on the left; a summary card of what was found on the right
    severities = [severity(signal["points"])[0] for signal in result["signals"]]    # e.g. ["Severe", "Minor"]
    warnings = [signal for signal in result["signals"] if signal["points"] > 0]
    facts = [signal for signal in warnings if signal["kind"] == "FACT"]
    disc_col, summary_col = st.columns([3, 2], vertical_alignment="center")
    with disc_col.container(horizontal_alignment="center"):    # st.html would strip the drawing, st.image shows it
        st.image(threat_disc(result["score"], result["level"]), width=200)
    with summary_col.container(border=True):
        if not warnings:
            st.markdown("##### No warning signs")
        elif len(warnings) == 1:
            st.markdown("##### 1 warning sign")
        else:
            st.markdown(f"##### {len(warnings)} warning signs")
        with st.container(horizontal=True):    # one badge per severity that was found
            for label, color in [("Severe", "red"), ("Moderate", "orange"), ("Minor", "gray"), ("Reassuring", "green")]:
                if label in severities:
                    st.badge(f"{severities.count(label)} {label}", color=color)
        if warnings:
            with st.container(horizontal=True):    # how many of the warnings are facts, and how many are educated guesses
                st.badge(f"{len(facts)} FACT", icon=":material/verified:", color="blue")
                st.badge(f"{len(warnings) - len(facts)} HEURISTIC", icon=":material/lightbulb:", color="violet")

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

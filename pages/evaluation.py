# Evaluation page: runs every labelled example through the analyzer and shows what we got wrong.
# Every number here comes from evaluate_examples(), so the page always matches our tests.
import streamlit as st

from logic import evaluate_examples

LEVEL_COLORS = {"High": "red", "Caution": "orange", "Low": "green"}


def show_wrong_answers(records, expected):
    """One card per wrong answer: our verdict, the expected one, the input, the reason, and the signals that fired."""
    for record in records:
        with st.container(border=True):
            with st.container(horizontal=True):
                st.badge(f"Rated {record['predicted_level']}", color=LEVEL_COLORS[record["predicted_level"]])
                st.badge(f"Expected {expected}", icon=":material/flag:", color="gray")
            st.code(record["input"], language=None, wrap_lines=True)    # defanged, never a clickable link
            st.caption(f"Why it's labelled {record['label']}: {record['why']}")
            if not record["signals"]:
                st.text("• No warning signs were found")
            for title in record["signals"]:
                st.text("• " + title)    # titles can contain the suspicious domain, so plain text only


st.title("Evaluation", anchor=False, text_alignment="center")
st.markdown("#### How well does Aegis Guard do on our test set?", text_alignment="center")

results = evaluate_examples()
if "error" in results:
    st.error(results["error"])
    st.stop()
if results["total"] == 0:
    st.info("There are no examples to evaluate yet.")
    st.stop()

st.caption(
    f"We ran all {results['total']} labelled, synthetic examples through the same offline checks used on the "
    "home page. A benign example counts as correct only if it comes out Low; a suspicious one counts as "
    "correct if it comes out Caution or High.",
    text_alignment="center",
)

total_col, correct_col, false_alarm_col, miss_col = st.columns(4)
total_col.metric("Examples", results["total"], border=True)
correct_col.metric("Correct", f"{results['accuracy']:.0%}", border=True)
false_alarm_col.metric("False alarms", len(results["false_alarms"]), border=True)
miss_col.metric("Misses", len(results["misses"]), border=True)
st.progress(results["accuracy"], text=f"{results['correct']} of {results['total']} examples correct")

false_alarm_tab, miss_tab = st.tabs([f":material/notifications_off: False alarms ({len(results['false_alarms'])})",
                                     f":material/visibility_off: Misses ({len(results['misses'])})"])
with false_alarm_tab:
    st.caption("Benign examples we wrongly rated Caution or High.")
    if results["false_alarms"]:
        show_wrong_answers(results["false_alarms"], "Low")
    else:
        st.success("No false alarms on this test set.")
with miss_tab:
    st.caption("Suspicious examples we rated Low.")
    if results["misses"]:
        show_wrong_answers(results["misses"], "Caution or High")
    else:
        st.success("No misses on this test set.")

# Written by hand from the results above: update it whenever the checks or examples change
st.subheader("What we learned", anchor=False)
with st.container(border=True):
    st.markdown(
        """
- **A curated brand list can't cover every country site.** Amazon's real German site (amazon.de) isn't in
  our list, so it looks like "Amazon on the wrong domain".
- **Not all typos are equal.** Treating every one-letter typo as serious would catch paytn.com, but would also flag
  real names like kodak.com (one letter from Kotak). So only lookalike typos count more: n for m, a doubled letter,
  two letters swapped. That catches paytn and leaves kodak alone, but it does flag phillips.com, a real company one
  doubled letter from Philips.
- **A brand name on a UPI QR code proves nothing either way.** Anyone can type "Reliance Digital" as the payee name,
  so a real shop's billing QR with the amount filled in comes out Caution.
- **Some scams have no tell-tale words.** "Hi Mom, this is my new number, please send money" uses ordinary
  language, so keyword checks can't catch it. That needs a different kind of check.
- **Testing on new examples matters.** Our first prize-scam rule also flagged a real "Pay Rs 1 to get
  Spotify Premium" offer. We only noticed because we tested on examples written before the fix.
"""
    )

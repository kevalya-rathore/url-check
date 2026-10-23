# Evaluation page: runs every labelled example through the analyzer and shows what we got wrong.
# Every number here comes from evaluate_examples(), so the page always matches our tests.
import streamlit as st

from logic import evaluate_examples


def show_wrong_answers(records, expected):
    """One bordered box per wrong answer: the input, our verdict, the reason for its label, and the signals that fired."""
    for record in records:
        with st.container(border=True):
            st.code(record["input"], language=None)    # defanged, never a clickable link
            st.text(f"Rated {record['predicted_level']} (score {record['score']}), expected {expected}")
            st.caption(f"Why it's labelled {record['label']}: {record['why']}")
            if not record["signals"]:
                st.text("• No warning signs were found")
            for title in record["signals"]:
                st.text("• " + title)    # titles can contain the suspicious domain, so plain text only


st.set_page_config(page_title="Evaluation - Aegis Guard", page_icon="🛡️")
st.title("Evaluation")

results = evaluate_examples()
if "error" in results:
    st.error(results["error"])
    st.stop()
if results["total"] == 0:
    st.info("There are no examples to evaluate yet.")
    st.stop()

st.markdown(
    f"We ran all {results['total']} labelled, synthetic examples through the same offline checks used on "
    "the home page. A **benign** example counts as correct only if it comes out **Low**; a **suspicious** "
    "one counts as correct if it comes out **Caution** or **High**."
)

total_col, correct_col, false_alarm_col, miss_col = st.columns(4)
total_col.metric("Examples", results["total"])
correct_col.metric("Correct", f"{results['correct']} ({results['accuracy']:.0%})")
false_alarm_col.metric("False alarms", len(results["false_alarms"]))
miss_col.metric("Misses", len(results["misses"]))

st.header("False alarms")
st.caption("Benign examples we wrongly rated Caution or High.")
if results["false_alarms"]:
    show_wrong_answers(results["false_alarms"], "Low")
else:
    st.success("No false alarms on this test set.")

st.header("Misses")
st.caption("Suspicious examples we rated Low.")
if results["misses"]:
    show_wrong_answers(results["misses"], "Caution or High")
else:
    st.success("No misses on this test set.")

# Written by hand from the results above: update it whenever the checks or examples change
st.header("What we learned")
st.markdown(
    """
- **A curated brand list can't cover every country site.** Amazon's real German site (amazon.de) isn't in
  our list, so it looks like "Amazon on the wrong domain".
- **Typo detection is a trade-off.** Scoring one-letter typos higher would catch paytn.com, but would also
  flag real names like kodak.com (one letter from Kotak). We chose fewer false alarms.
- **Some scams have no tell-tale words.** "Hi Mom, this is my new number, please send money" uses ordinary
  language, so keyword checks can't catch it. That needs a different kind of check.
- **Testing on new examples matters.** Our first prize-scam rule also flagged a real "Pay Rs 1 to get
  Spotify Premium" offer. We only noticed because we tested on examples written before the fix.
"""
)

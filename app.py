# Aegis Guard entry point: the shared page settings, the logo, and the navigation bar.
# Run with "streamlit run app.py". Each page lives in its own file in the pages/ folder.
import streamlit as st

st.set_page_config(page_title="Aegis Guard", page_icon="🛡️")
st.logo("assets/logo.svg", size="large")

# The theme file can't set button text colour, so these two rules follow the AEGIS palette:
# navy text on Cyber Cyan buttons, and a gold outline when a button is reached with the keyboard.
st.html("""
<style>
button[data-testid^="stBaseButton-primary"],
button[data-testid^="stBaseButton-primary"]:hover,
button[data-testid^="stBaseButton-primary"] * { color: #0B1120 !important; }
button:focus-visible { outline: 2px solid #D8AD60 !important; outline-offset: 3px; }
</style>
""")

pages = [
    st.Page("pages/home.py", title="Check a link", icon=":material/shield:", default=True),
    st.Page("pages/examples.py", title="Examples", icon=":material/list_alt:"),
    st.Page("pages/evaluation.py", title="Evaluation", icon=":material/insights:"),
    st.Page("pages/how_it_works.py", title="How it works", icon=":material/menu_book:"),
]
st.navigation(pages, position="top").run()    # shows the pages as a bar across the top

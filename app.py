# Aegis Guard entry point: the shared page settings, the logo, and the navigation bar.
# Run with "streamlit run app.py". Each page lives in its own file in the pages/ folder.
import streamlit as st

st.set_page_config(page_title="Aegis Guard", page_icon="🛡️")
st.logo("assets/logo.svg", size="large", icon_image="assets/shield.svg")

pages = [
    st.Page("pages/home.py", title="Check a link", icon=":material/shield:", default=True),
    st.Page("pages/examples.py", title="Examples", icon=":material/list_alt:"),
    st.Page("pages/evaluation.py", title="Evaluation", icon=":material/insights:"),
    st.Page("pages/how_it_works.py", title="How it works", icon=":material/menu_book:"),
]
st.navigation(pages, position="top").run()    # shows the pages as a bar across the top

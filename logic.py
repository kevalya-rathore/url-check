# Core logic: plain Python, no Streamlit, so it can be tested on its own.


def process(text):
    return {"input": text, "length": len(text)}

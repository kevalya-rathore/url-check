# How it works page: a plain-language explanation of the checks, how verdicts are reached, and the limits.
import streamlit as st

st.title("How it works", anchor=False, text_alignment="center")
st.markdown("#### What Aegis Guard checks, how it decides, and what it can't do", text_alignment="center")
with st.container(horizontal=True, horizontal_alignment="center"):
    st.badge("FACT = verifiable", icon=":material/verified:", color="blue")
    st.badge("HEURISTIC = educated guess", icon=":material/lightbulb:", color="violet")
    st.badge("No AI black box", icon=":material/rule:", color="gray")

st.divider()

# -----------------------------------------------------------------------------
# 1. WHAT AEGIS GUARD DOES
# -----------------------------------------------------------------------------
st.header("1. What Aegis Guard does", anchor=False)
st.markdown(
    """
    Aegis Guard is built for anyone in India who receives a suspicious or unexpected link by SMS, 
    WhatsApp, or email. Before you click, it analyzes the link or message text for deceptive warning signs, 
    explains what looks suspicious, and tells you safe actions to take instead.
    """
)

# -----------------------------------------------------------------------------
# 2. WE NEVER OPEN THE LINK
# -----------------------------------------------------------------------------
st.header("2. Why we never open the link", anchor=False)
st.markdown(
    """
    Our analysis inspects **only the text** of the link or message. We never connect to the destination server, 
    download web pages, execute scripts, or follow redirects.
    
    **Why this rule is critical:**
    - **Harmful content protection:** Visiting an unknown scam website can trigger malicious script downloads, 
      exploit kit execution, or deceptive login prompts directly on your device.
    - **Scammer tracking defense:** Many phishing links include a unique tracking code created specifically for you. 
      Simply opening the page confirms to the attacker that your phone number or email is active and monitored, 
      marking you for further aggressive scams.
    
    *What about domain registration checks?* A domain-age lookup asks the official public registry how recently 
    a domain was registered, without contacting the website itself. **In this demo, domain-age lookups are not enabled;** 
    all checks run 100% offline for maximum speed and privacy.
    """
)

# -----------------------------------------------------------------------------
# 3. FACTS VS HEURISTICS
# -----------------------------------------------------------------------------
st.header("3. Facts vs Heuristics", anchor=False)
st.markdown(
    """
    Every warning signal produced by Aegis Guard is explicitly labeled as either a **FACT** or a **HEURISTIC**:
    """
)

col_fact, col_heur = st.columns(2)
with col_fact.container(border=True):
    st.badge("FACT", icon=":material/verified:", color="blue")
    st.markdown(
        """
        Something objective that anyone can verify directly from the link or message text with complete certainty.
        
        *Examples:*
        - The link uses a raw IP address instead of a domain name.
        - The link explicitly uses unencrypted `http://`.
        - The domain contains non-Latin lookalike letters or punycode.
        - The domain matches an officially verified organization site (e.g. `sbi.co.in`).
        """
    )

with col_heur.container(border=True):
    st.badge("HEURISTIC", icon=":material/lightbulb:", color="violet")
    st.markdown(
        """
        An educated guess based on patterns frequently seen in scam campaigns. While indicative, a heuristic can occasionally be wrong.
        
        *Examples:*
        - The address looks like a spelling variation or typo of `paytm`.
        - The link ending (`.xyz`, `.top`) is commonly used in low-cost scam setups.
        - The message text uses artificial urgency phrases like *"digital arrest"* or *"account blocked"*.
        """
    )

st.info(
    "**Why this distinction matters:** We clearly distinguish facts from heuristics so you know "
    "which findings are verified structural evidence and which are pattern-based inferences."
)

# -----------------------------------------------------------------------------
# 4. THE CHECKS
# -----------------------------------------------------------------------------
st.header("4. The checks", anchor=False)
st.markdown(
    "Below are the security checks evaluated by our offline detection engine, "
    "whether each one is a fact or a heuristic, and how serious a warning it is:"
)

checks_data = [
    {
        "Check": "Known phishing site",
        "What it looks for": "The link or website appears in our offline snapshot of the OpenPhish feed",
        "Kind": "FACT",
        "Severity": "Severe"
    },
    {
        "Check": "Official domain",
        "What it looks for": "Domain is on our list of a brand's official sites, or is a .bank.in bank (no credit when that site only hosts someone else's page or redirect)",
        "Kind": "FACT",
        "Severity": "Reassuring"
    },
    {
        "Check": "Brand on wrong domain",
        "What it looks for": "Brand name, or a longer form from its own domains like hdfcbank, used on a domain that isn't one of its official sites (e.g. sbi on .xyz)",
        "Kind": "HEURISTIC",
        "Severity": "Severe"
    },
    {
        "Check": "Asks for a secret",
        "What it looks for": "Message text prompts recipient to share an OTP, PIN, CVV, or password",
        "Kind": "HEURISTIC",
        "Severity": "Severe"
    },
    {
        "Check": "IP address host",
        "What it looks for": "A raw numeric IP address (e.g. 192.168.1.1) instead of a website name",
        "Kind": "FACT",
        "Severity": "Severe"
    },
    {
        "Check": "Lookalike letters",
        "What it looks for": "Non-Latin characters or punycode (xn--) impersonating legitimate Latin letters",
        "Kind": "FACT",
        "Severity": "Severe"
    },
    {
        "Check": "@ trick",
        "What it looks for": "Contains '@' where text before it disguises the real destination host",
        "Kind": "FACT",
        "Severity": "Moderate"
    },
    {
        "Check": "No HTTPS",
        "What it looks for": "Link explicitly uses unencrypted http:// instead of secure https://",
        "Kind": "FACT",
        "Severity": "Minor"
    },
    {
        "Check": "Phishing form on free host",
        "What it looks for": "Brand names or login words hosted on free platforms (Google Sites, Forms, etc.)",
        "Kind": "HEURISTIC",
        "Severity": "Severe"
    },
    {
        "Check": "Brand in subdomain",
        "What it looks for": "Brand name (or a longer form like icicibank) appears as a word in the address while the actual domain is owned by someone else",
        "Kind": "HEURISTIC",
        "Severity": "Severe"
    },
    {
        "Check": "Typo of a brand",
        "What it looks for": "Domain is one letter away from a well-known brand name (e.g. paytn for paytm)",
        "Kind": "HEURISTIC",
        "Severity": "Moderate"
    },
    {
        "Check": "Coercion theme",
        "What it looks for": "Threat themes in messages (digital arrest, customs seizure, traffic challan, electricity disconnection)",
        "Kind": "HEURISTIC",
        "Severity": "Severe"
    },
    {
        "Check": "Urgency words",
        "What it looks for": "Pressure words in a message ('urgent', 'suspended', 'expired', 'act now'…)",
        "Kind": "HEURISTIC",
        "Severity": "Minor to Severe, depending on how many"
    },
    {
        "Check": "Redirect inside link",
        "What it looks for": "A full link to a different, non-official website hidden inside the link",
        "Kind": "HEURISTIC",
        "Severity": "Severe"
    },
    {
        "Check": "Pay to receive",
        "What it looks for": "Advance-fee pattern in message ('pay ... to receive / claim / refund')",
        "Kind": "HEURISTIC",
        "Severity": "Moderate, or Severe if a prize is mentioned"
    },
    {
        "Check": "Risky ending",
        "What it looks for": "Domain ending frequently abused in cheap scams (.xyz, .top, .click, .buzz, etc.)",
        "Kind": "HEURISTIC",
        "Severity": "Moderate"
    },
    {
        "Check": "Link shortener",
        "What it looks for": "URL shortening services (bit.ly, tinyurl.com, etc.) hiding the real destination",
        "Kind": "HEURISTIC",
        "Severity": "Moderate"
    },
    {
        "Check": "Phishing words",
        "What it looks for": "Several credential keywords in the address (login, verify, kyc, banking…)",
        "Kind": "HEURISTIC",
        "Severity": "Moderate"
    },
    {
        "Check": "Many subdomains",
        "What it looks for": "A long chain of subdomains in front of the real domain name",
        "Kind": "HEURISTIC",
        "Severity": "Moderate"
    },
    {
        "Check": "Long link",
        "What it looks for": "Unusually long link, used to push the real destination off-screen",
        "Kind": "HEURISTIC",
        "Severity": "Minor"
    },
    {
        "Check": "Hyphens or digits",
        "What it looks for": "Lots of hyphens or digits in the domain name",
        "Kind": "HEURISTIC",
        "Severity": "Minor"
    },
]

st.table(checks_data, hide_index=True)

with st.expander("Examples of common scam patterns (defanged)"):
    st.markdown("Here is how deceptive links structure these patterns:")
    st.markdown("**1. Brand placed in subdomain to mislead:**")
    st.code("hxxp://sbi.co.in.verify-kyc-account[.]top/update", language=None)
    st.markdown("**2. Typosquatting / brand spelling similarity:**")
    st.code("hxxps://paytn[.]com/cashback-offer", language=None)
    st.markdown("**3. Raw IP address hosting a login page:**")
    st.code("hxxp://192.168.1.1/banking/login", language=None)
    st.caption("Note: All examples above are defanged and harmless.")

# -----------------------------------------------------------------------------
# 5. HOW WE REACH A VERDICT
# -----------------------------------------------------------------------------
st.header("5. How we reach a verdict", anchor=False)
st.markdown(
    """
    1. **Weighing the evidence:** Every warning sign adds to the overall threat, and serious signs count more
       than minor ones. Reassuring signs, like a brand's verified official domain, lower it.
    2. **Three levels:**
       - **Low risk:** No strong warning signs found.
       - **Caution:** Some warning signs present. Check before you act.
       - **High risk:** Strong evidence of a scam. Don't click.
    3. **The rule against false alarms:**
       A single educated guess can never make a link **High risk** on its own. High risk needs either
       **a strong verifiable fact** or warnings from **at least two different checks**; otherwise the
       verdict stays at **Caution**.
    4. **Message risk rule:** 
       When analyzing a message containing links, the overall message is always rated at least as risky as its riskiest embedded link.
    """
)

# -----------------------------------------------------------------------------
# 6. KNOWN LIMITATIONS
# -----------------------------------------------------------------------------
st.header("6. Known limitations", anchor=False)
with st.expander("Read our known limitations and design boundaries", expanded=False):
    st.markdown(
        """
        We believe in being specific and transparent about what our offline analysis cannot do:
        
        - **No page content inspection:** Because we never open the link, a scam page hosted on an otherwise 
          clean, normal domain without suspicious keywords or unusual endings will be classified as **Low**.
        - **Compromised authentic sites:** If an official, legitimate website is hacked or compromised, 
          it will still match our verified whitelist or look clean to structural checks.
        - **Curated brand list:** About 130 Indian and international brands (banks, UPI apps, shopping, delivery,
          government services, telecom, utilities), plus every bank on the RBI-only .bank.in domain.
          Impersonation of organizations outside this list relies on the general checks.
        - **Typo detection trade-offs:** Spelling-similarity checks can occasionally flag ordinary words 
          that happen to look similar to a brand name.
        - **Short brand names:** One-letter typos of very short brand names (for example sbl for SBI) are not
          flagged, because at that length too many ordinary words differ by just one letter.
        - **The phishing list ages quickly:** Phishing sites often live only hours, so an offline snapshot misses
          newer ones. That's why the structural checks stay the main defence.
        - **Language support:** Message analysis currently checks English keywords and patterns only.
        - **Probabilistic nature of heuristics:** Heuristics can produce both false alarms and misses. 
          Our measured benchmark accuracy, false alarms, and misses are published on the **Evaluation** page.
        """
    )

# -----------------------------------------------------------------------------
# 7. WHAT'S BUILT, AND WHAT ISN'T
# -----------------------------------------------------------------------------
st.header("7. What's built, and what isn't", anchor=False)
col_built, col_not_built = st.columns(2)

with col_built.container(border=True):
    st.badge("Built & running in this demo", icon=":material/check_circle:", color="green")
    st.markdown(
        """
        - **Offline link analysis:** Fast structural checks for brand spoofing, lookalikes, risky endings, and hidden destinations.
        - **SMS & WhatsApp message analysis:** Detection of urgency language, requests for secret credentials, and advance-fee schemes.
        - **Explainable verdicts:** Every warning is labelled Fact or Heuristic, with safe next steps.
        - **Labelled test cases:** Synthetic examples of safe and phishing links and messages on the **Examples** page.
        - **Evaluation benchmark:** Automated accuracy and false-alarm testing on the **Evaluation** page.
        - **Offline analysis:** No network calls during a scan; nothing you paste is sent anywhere.
        - **Known phishing list:** Offline snapshot of the OpenPhish community feed (23 Oct 2026), used non-commercially. A link that isn't on the list is not automatically safe.
        """
    )

with col_not_built.container(border=True):
    st.badge("Not built / not enabled", icon=":material/schedule:", color="orange")
    st.markdown(
        """
        - **Domain-age registry lookup:** Not enabled in this demo (offline-only operation).
        - **Email header analysis:** SPF, DKIM, and DMARC inspection is not included.
        - **Page opening or screenshots:** Deliberately omitted to prevent exposing users to malicious payloads.
        - **AI / LLM generated text:** Scans use deterministic, auditable rules rather than opaque language models.
        """
    )

# -----------------------------------------------------------------------------
# 8. WHERE TO REPORT A SCAM
# -----------------------------------------------------------------------------
st.header("8. Where to report a scam", anchor=False)
st.markdown(
    """
    If you encounter a phishing link or suspected financial fraud in India, report it through official government channels:
    
    - **National Cyber Crime Reporting Portal:** Visit [cybercrime.gov.in](https://cybercrime.gov.in) or call helpline **1930** immediately for financial fraud.
    - **Chakshu Facility (Sanchar Saathi):** Report suspected fraudulent calls, SMS, or WhatsApp messages at [sancharsaathi.gov.in](https://sancharsaathi.gov.in).
    - **Golden Safety Rule:** If in doubt, never click a link sent to you. Open the official mobile application directly or type the organization's verified website address yourself.
    """
)

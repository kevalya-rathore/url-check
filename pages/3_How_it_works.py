import streamlit as st

st.set_page_config(
    page_title="How It Works - Aegis Guard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ How Aegis Guard Works")
st.markdown(
    "A transparent, plain-language guide to how Aegis Guard detects phishing threats, "
    "how it scores risk, and what safeguards it applies."
)

st.divider()

# -----------------------------------------------------------------------------
# 1. WHAT AEGIS GUARD DOES
# -----------------------------------------------------------------------------
st.header("1. What Aegis Guard does")
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
st.header("2. Why we never open the link")
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
st.header("3. Facts vs Heuristics")
st.markdown(
    """
    Every warning signal produced by Aegis Guard is explicitly labeled as either a **FACT** or a **HEURISTIC**:
    """
)

col_fact, col_heur = st.columns(2)
with col_fact:
    st.markdown(
        """
        ### 🔍 FACT
        Something objective that anyone can verify directly from the link or message text with complete certainty.
        
        *Examples:*
        - The link uses a raw IP address instead of a domain name.
        - The link explicitly uses unencrypted `http://`.
        - The domain contains non-Latin lookalike letters or punycode.
        - The domain matches an officially verified organization site (e.g. `sbi.co.in`).
        """
    )

with col_heur:
    st.markdown(
        """
        ### 💡 HEURISTIC
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
st.header("4. The checks and scoring signals")
st.markdown(
    "Below are the security checks evaluated by our offline detection engine, "
    "along with their classification and risk point values:"
)

checks_data = [
    {
        "Check": "Known phishing site",
        "What it looks for": "The link or website appears in our offline snapshot of the OpenPhish feed",
        "Kind": "FACT",
        "Points": "+60"
    },
    {
        "Check": "Official domain",
        "What it looks for": "Domain is on our list of a brand's official sites, or is a .bank.in bank (no credit when that site only hosts someone else's page or redirect)",
        "Kind": "FACT",
        "Points": "−35"
    },
    {
        "Check": "Brand on wrong domain",
        "What it looks for": "Brand name, or a longer form from its own domains like hdfcbank, used on a domain that isn't one of its official sites (e.g. sbi on .xyz)",
        "Kind": "HEURISTIC",
        "Points": "+40"
    },
    {
        "Check": "Asks for a secret",
        "What it looks for": "Message text prompts recipient to share an OTP, PIN, CVV, or password",
        "Kind": "HEURISTIC",
        "Points": "+35"
    },
    {
        "Check": "IP address host",
        "What it looks for": "A raw numeric IP address (e.g. 192.168.1.1) instead of a website name",
        "Kind": "FACT",
        "Points": "+30"
    },
    {
        "Check": "Lookalike letters",
        "What it looks for": "Non-Latin characters or punycode (xn--) impersonating legitimate Latin letters",
        "Kind": "FACT",
        "Points": "+30"
    },
    {
        "Check": "@ trick",
        "What it looks for": "Contains '@' where text before it disguises the real destination host",
        "Kind": "FACT",
        "Points": "+25"
    },
    {
        "Check": "No HTTPS",
        "What it looks for": "Link explicitly uses unencrypted http:// instead of secure https://",
        "Kind": "FACT",
        "Points": "+10"
    },
    {
        "Check": "Phishing form on free host",
        "What it looks for": "Brand names or login words hosted on free platforms (Google Sites, Forms, etc.)",
        "Kind": "HEURISTIC",
        "Points": "+35"
    },
    {
        "Check": "Brand in subdomain",
        "What it looks for": "Brand name (or a longer form like icicibank) appears as a word in the address while the actual domain is owned by someone else",
        "Kind": "HEURISTIC",
        "Points": "+30"
    },
    {
        "Check": "Typo of a brand",
        "What it looks for": "Domain differs by one letter from a brand name of 5+ letters (e.g. paytn for paytm)",
        "Kind": "HEURISTIC",
        "Points": "+30"
    },
    {
        "Check": "Coercion theme",
        "What it looks for": "Threat themes in messages (digital arrest, customs seizure, traffic challan, electricity disconnection)",
        "Kind": "HEURISTIC",
        "Points": "+30"
    },
    {
        "Check": "Urgency words",
        "What it looks for": "Pressure words in message ('urgent', 'suspended', 'expired', 'act now'…)",
        "Kind": "HEURISTIC",
        "Points": "up to +30 (+10/word)"
    },
    {
        "Check": "Redirect inside link",
        "What it looks for": "A full link to a different, non-official website hidden inside the link",
        "Kind": "HEURISTIC",
        "Points": "+35"
    },
    {
        "Check": "Pay to receive",
        "What it looks for": "Advance-fee pattern in message ('pay ... to receive / claim / refund')",
        "Kind": "HEURISTIC",
        "Points": "+25 (+30 if a prize or win is mentioned)"
    },
    {
        "Check": "Risky ending",
        "What it looks for": "Domain ending frequently abused in cheap scams (.xyz, .top, .click, .buzz, etc.)",
        "Kind": "HEURISTIC",
        "Points": "+20"
    },
    {
        "Check": "Link shortener",
        "What it looks for": "URL shortening services (bit.ly, tinyurl.com, etc.) hiding the real destination",
        "Kind": "HEURISTIC",
        "Points": "+15"
    },
    {
        "Check": "Phishing words",
        "What it looks for": "Two or more credential keywords in path/subdomain (login, verify, kyc, banking…)",
        "Kind": "HEURISTIC",
        "Points": "+15"
    },
    {
        "Check": "Many subdomains",
        "What it looks for": "Three or more subdomain labels before the main domain name",
        "Kind": "HEURISTIC",
        "Points": "+15"
    },
    {
        "Check": "Long link",
        "What it looks for": "Unusually long link (over 75 characters) used to push destination off-screen",
        "Kind": "HEURISTIC",
        "Points": "+10"
    },
    {
        "Check": "Hyphens or digits",
        "What it looks for": "Two or more hyphens or three or more digits in domain name",
        "Kind": "HEURISTIC",
        "Points": "+10"
    },
]

st.table(checks_data)

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
# 5. HOW THE SCORE BECOMES A LEVEL
# -----------------------------------------------------------------------------
st.header("5. How the score becomes a level")
st.markdown(
    """
    1. **Summing points:** Points from every triggered signal are summed together and bounded between **0 and 100**.
    2. **Score brackets:**
       - **Low Risk (0 to 29):** Minimal or no warning signs found.
       - **Caution (30 to 59):** Moderate warning signs present. Proceed with care.
       - **High Risk (60 to 100):** Multiple critical warning signs detected. Do not click.
    3. **The rule against false alarms:** 
       To be rated **High Risk**, a score of 60 or above is not enough on its own. The scan strictly requires 
       either **at least one strong FACT** (20+ points) or warnings from **at least two different checks**. 
       This prevents an isolated heuristic guess from unfairly sounding a major alarm. If this condition is not met, 
       the level is safely capped at **Caution**.
    4. **Message risk rule:** 
       When analyzing a message containing links, the overall message is always rated at least as risky as its riskiest embedded link.
    """
)

# -----------------------------------------------------------------------------
# 6. KNOWN LIMITATIONS
# -----------------------------------------------------------------------------
st.header("6. Known limitations")
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
        - **Short brand names:** One-letter typos of 3–4 letter brands (for example sbl for SBI) are not
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
st.header("7. What's built, and what isn't")
col_built, col_not_built = st.columns(2)

with col_built:
    st.success("### ✅ Built & running in this demo")
    st.markdown(
        """
        - **Offline link analysis:** Fast structural checks for brand spoofing, lookalikes, risky endings, and hidden destinations.
        - **SMS & WhatsApp message analysis:** Detection of urgency language, requests for secret credentials, and advance-fee schemes.
        - **Explainable scoring engine:** Clear Fact vs Heuristic breakdown with safe recommendations.
        - **Labelled test cases:** Synthetic examples of safe and phishing links and messages on the **Examples** page.
        - **Evaluation benchmark:** Automated accuracy and false-alarm testing on the **Evaluation** page.
        - **Offline analysis:** No network calls during a scan; nothing you paste is sent anywhere.
        - **Known phishing list:** Offline snapshot of the OpenPhish community feed (23 Oct 2026), used non-commercially. A link that isn't on the list is not automatically safe.
        """
    )

with col_not_built:
    st.warning("### ⏳ Not built / not enabled")
    st.markdown(
        """
        - **Domain-age registry lookup:** Not enabled in this demo (offline-only operation).
        - **QR-code scanner:** Parsing links embedded in images is not implemented.
        - **Email header analysis:** SPF, DKIM, and DMARC inspection is not included.
        - **Page opening or screenshots:** Deliberately omitted to prevent exposing users to malicious payloads.
        - **AI / LLM generated text:** Scans use deterministic, auditable rules rather than opaque language models.
        """
    )

# -----------------------------------------------------------------------------
# 8. WHERE TO REPORT A SCAM
# -----------------------------------------------------------------------------
st.header("8. Where to report a scam")
st.markdown(
    """
    If you encounter a phishing link or suspected financial fraud in India, report it through official government channels:
    
    - 🏛️ **National Cyber Crime Reporting Portal:** Visit [cybercrime.gov.in](https://cybercrime.gov.in) or call helpline **1930** immediately for financial fraud.
    - 📱 **Chakshu Facility (Sanchar Saathi):** Report suspected fraudulent calls, SMS, or WhatsApp messages at [sancharsaathi.gov.in](https://sancharsaathi.gov.in).
    - 🛡️ **Golden Safety Rule:** If in doubt, never click a link sent to you. Open the official mobile application directly or type the organization's verified website address yourself.
    """
)

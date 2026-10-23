"""logic.py - detection logic for ScamShield (CY-01)

Every checker function returns TWO things:
    score   -> a number (more points = more dangerous)
    reasons -> a list of sentences explaining why points were added
"""

from datetime import datetime
from difflib import SequenceMatcher   # compares how similar two words are
from urllib.parse import urlparse     # splits a URL into parts

import tldextract                     # splits a domain into subdomain/domain/suffix


# =====================================================
# 1. SETTINGS (lists we compare against)
# =====================================================
BRANDS = ["sbi", "hdfc", "icici", "paytm", "phonepe", "amazon", "google", "flipkart"]

# Real websites of those brands (we trust these)
OFFICIAL_SITES = ["sbi.co.in", "hdfcbank.com", "icicibank.com", "paytm.com",
                  "phonepe.com", "amazon.in", "amazon.com", "google.com", "flipkart.com"]

BAD_ENDINGS = ["xyz", "top", "click", "buzz", "tk", "ml", "ga", "cf", "live", "icu"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "is.gd", "rb.gy"]

PHISH_WORDS = ["login", "verify", "secure", "update", "kyc", "account",
               "confirm", "banking", "wallet", "reward", "free", "bonus"]

URGENT_WORDS = ["urgent", "blocked", "suspended", "kyc", "expire", "last chance",
                "claim", "reward", "prize", "verify now", "act now", "lottery"]

SECRET_WORDS = ["otp", "pin", "cvv", "password", "card number", "upi pin"]

LINK_ENDINGS = [".com", ".in", ".xyz", ".top", ".click", ".co", ".ly", ".net", ".org"]


# =====================================================
# 2. SMALL HELPER FUNCTIONS
# =====================================================
def normalize(url):
    """Make sure the URL starts with http:// or https://"""
    url = url.strip()                       # remove spaces at both ends
    if url.startswith("http://") or url.startswith("https://"):
        return url
    return "http://" + url


def is_ip_address(host):
    """Return True if host looks like 192.168.1.1"""
    host = host.split(":")[0]               # remove port number like :8080
    parts = host.split(".")                 # "1.2.3.4" -> ["1","2","3","4"]
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():              # every part must be only digits
            return False
    return True


def count_digits(text):
    """Count how many digits (0-9) are in the text"""
    count = 0
    for letter in text:
        if letter.isdigit():
            count = count + 1
    return count


# =====================================================
# 3. LAYER 1: URL CHECK (works offline, very fast)
# =====================================================
def check_url(url):
    score = 0
    reasons = []

    url = normalize(url)
    url_lower = url.lower()
    parsed = urlparse(url)
    ext = tldextract.extract(url)

    # Example: http://login.sbi-kyc.xyz/page
    #   ext.subdomain = "login"
    #   ext.domain    = "sbi-kyc"
    #   ext.suffix    = "xyz"
    host = parsed.netloc.lower()                    # "login.sbi-kyc.xyz"
    real_domain = ext.domain + "." + ext.suffix     # "sbi-kyc.xyz" (the true owner)

    # If it is an official site, stop here and say it is safe
    if real_domain in OFFICIAL_SITES:
        return 0, ["Official website: " + real_domain]

    # Check 1: IP address instead of a name
    if is_ip_address(host):
        score = score + 30
        reasons.append("Uses an IP address instead of a website name")

    # Check 2: '@' symbol (browser ignores everything before it)
    if "@" in url:
        score = score + 20
        reasons.append("Contains '@' symbol to hide the real website")

    # Check 3: very long URL
    if len(url) > 75:
        score = score + 10
        reasons.append("URL is very long")

    # Check 4: too many subdomains (dots in the subdomain part)
    if ext.subdomain.count(".") >= 2:
        score = score + 15
        reasons.append("Too many subdomains")

    # Check 5: no HTTPS
    if parsed.scheme != "https":
        score = score + 10
        reasons.append("Does not use HTTPS")

    # Check 6: risky ending like .xyz
    last_part = ext.suffix.split(".")[-1]           # "co.in" -> "in"
    if last_part in BAD_ENDINGS:
        score = score + 20
        reasons.append("Risky domain ending: ." + ext.suffix)

    # Check 7: link shortener
    if real_domain in SHORTENERS:
        score = score + 15
        reasons.append("Shortened link hides the real destination")

    # Check 8: many hyphens or digits in the domain name
    if host.count("-") >= 2 or count_digits(ext.domain) >= 3:
        score = score + 10
        reasons.append("Many hyphens or digits in the domain")

    # Check 9: '//' appearing twice means a hidden redirect
    if url.count("//") > 1:
        score = score + 10
        reasons.append("Possible hidden redirect")

    # Check 10: look-alike (punycode) characters
    if "xn--" in host:
        score = score + 20
        reasons.append("Uses look-alike characters in the domain")

    # Check 11: scammy words inside the URL
    found_words = []
    for word in PHISH_WORDS:
        if word in url_lower:
            found_words.append(word)
    if len(found_words) >= 2:                       # need 2+, one word is common
        score = score + 15
        reasons.append("Scam words in URL: " + ", ".join(found_words))

    # Check 12: pretending to be a known brand
    for brand in BRANDS:
        name_part = ext.subdomain + "." + ext.domain
        if brand in name_part.lower() and ext.domain != brand:
            score = score + 30
            reasons.append("Pretends to be '" + brand + "' but real domain is '" + real_domain + "'")
            break                                   # stop after first match

        similarity = SequenceMatcher(None, ext.domain, brand).ratio()   # 0 to 1
        if ext.domain != brand and similarity > 0.8:
            score = score + 30
            reasons.append("Looks like a fake spelling of '" + brand + "'")
            break

    if score > 100:
        score = 100
    return score, reasons


# =====================================================
# 4. LAYER 2: ONLINE CHECKS (need internet)
# =====================================================
def check_domain_age(url):
    """New websites (made recently) are often scams."""
    try:
        import whois
        ext = tldextract.extract(url)
        info = whois.whois(ext.domain + "." + ext.suffix)
        created = info.creation_date

        if type(created) == list:                   # sometimes WHOIS gives a list
            created = created[0]
        if created is None:
            return 0, []

        created = created.replace(tzinfo=None)      # avoid timezone errors
        age_days = (datetime.now() - created).days

        if age_days < 30:
            return 30, ["Website is only " + str(age_days) + " days old"]
        if age_days < 180:
            return 10, ["Website is fairly new (" + str(age_days) + " days)"]
        return 0, []
    except Exception:
        return 0, []                                # on any error, add no points


def unshorten(url):
    """Follow redirects. Returns (final_url, number_of_redirects)."""
    try:
        import requests
        response = requests.get(normalize(url), timeout=5,
                                headers={"User-Agent": "Mozilla/5.0"})
        return response.url, len(response.history)
    except Exception:
        return normalize(url), 0


def check_page(url):
    """Look inside the web page for password boxes and suspicious forms."""
    score = 0
    reasons = []
    try:
        import requests
        from bs4 import BeautifulSoup

        response = requests.get(normalize(url), timeout=5,
                                headers={"User-Agent": "Mozilla/5.0"})
        html = response.text
        soup = BeautifulSoup(html, "html.parser")
        my_domain = tldextract.extract(url).registered_domain

        # Password box on the page
        if soup.find("input", {"type": "password"}) is not None:
            score = score + 20
            reasons.append("Page asks for a password")

        # Form that sends data to another website
        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action.startswith("http"):
                form_domain = tldextract.extract(action).registered_domain
                if form_domain != my_domain:
                    score = score + 30
                    reasons.append("Form sends your data to a different website")
                    break

        # Hidden iframe
        for frame in soup.find_all("iframe"):
            style = frame.get("style", "").replace(" ", "")
            if "display:none" in style:
                score = score + 15
                reasons.append("Hidden iframe found")
                break

        # Right-click blocked
        if "oncontextmenu" in html.lower():
            score = score + 5
            reasons.append("Right-click is disabled on the page")
    except Exception:
        pass                                        # ignore errors, return what we have
    return score, reasons


# =====================================================
# 5. FULL URL SCAN (runs everything together)
# =====================================================
def full_url_scan(url, online=True):
    score, reasons = check_url(url)

    # Only do the slow internet checks if asked, and if not already 100
    if online and score < 100:
        final_url, hops = unshorten(url)

        if hops >= 3:
            score = score + 15
            reasons.append(str(hops) + " redirects before reaching the website")

        # If the link led somewhere else, check that final website too
        if final_url != normalize(url):
            final_score, final_reasons = check_url(final_url)
            score = score + int(final_score / 2)    # count half the points
            for r in final_reasons:
                reasons.append("(Final site) " + r)

        age_score, age_reasons = check_domain_age(final_url)
        score = score + age_score
        reasons = reasons + age_reasons

        page_score, page_reasons = check_page(final_url)
        score = score + page_score
        reasons = reasons + page_reasons

    if score > 100:
        score = 100
    return score, reasons


# =====================================================
# 6. MESSAGE CHECK (SMS / WhatsApp text)
# =====================================================
def find_links(text):
    """Pick out the words that look like links."""
    links = []
    for word in text.split():                       # split message into words
        word = word.strip(".,!?()\"'")              # remove punctuation at the ends
        lower = word.lower()
        if lower.startswith("http") or lower.startswith("www."):
            links.append(word)
        else:
            for ending in LINK_ENDINGS:
                if ending in lower:
                    links.append(word)
                    break
    return links


def check_message(text, online=False):
    score = 0
    reasons = []
    low = text.lower()

    # Urgency / reward words
    found_urgent = []
    for word in URGENT_WORDS:
        if word in low:
            found_urgent.append(word)
    if len(found_urgent) > 0:
        points = 10 * len(found_urgent)
        if points > 30:
            points = 30                             # keywords alone can't give more than 30
        score = score + points
        reasons.append("Urgency/reward words: " + ", ".join(found_urgent))

    # Asking for secret information
    found_secret = []
    for word in SECRET_WORDS:
        if word in low:
            found_secret.append(word)
    if len(found_secret) > 0:
        score = score + 30
        reasons.append("Asks for private info: " + ", ".join(found_secret))

    # "Pay Rs 1 to receive money" trick
    if ("pay" in low or "send" in low) and ("receive" in low or "refund" in low):
        score = score + 20
        reasons.append("'Pay first to receive money' trick")

    # Check every link inside the message
    for link in find_links(text):
        link_score, link_reasons = full_url_scan(link, online)
        score = score + int(link_score / 2)         # count half the points
        for r in link_reasons:
            reasons.append("[" + link + "] " + r)

    if score > 100:
        score = 100
    return score, reasons


# =====================================================
# 7. FINAL VERDICT
# =====================================================
def verdict(score):
    """Turn a score into (label, colour, advice)."""
    if score >= 60:
        return "🔴 SCAM", "error", "Do NOT click. Never share OTP/PIN. Report at cybercrime.gov.in or call 1930."
    elif score >= 30:
        return "🟡 SUSPICIOUS", "warning", "Be careful. Open the official website yourself instead."
    else:
        return "🟢 LIKELY SAFE", "success", "No major red flags, but stay alert."

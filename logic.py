"""logic.py - Detection logic for Aegis Guard (CY-01).

Implements multi-layered, offline-first analysis for URLs and text messages.
Distinguishes verifiable structural facts (FACT) from pattern-based inferences (HEURISTIC).
Nothing here touches the network: every check works on the text of the link or message.

Result shape:
    {
        "input": str,
        "score": int (0-100),
        "level": "Low" | "Caution" | "High",
        "signals": [
            {
                "kind": "FACT" | "HEURISTIC",
                "check": str,
                "title": str,
                "evidence": str,
                "points": int,
                "advice": str
            }, ...
        ],
        "next_steps": [str, ...]
    }

How this file is organised:
    1. Settings      word lists, the brand list (data/brands.json), lookalike letters
    2. Helpers       small functions the checks use; 2b loads the phishing list; 2c turns points into a level
    3. analyze_url   runs 13 checks on one link
    4. analyze_text  checks a message, then runs analyze_url on every link inside it
    5. Evaluation    runs data/examples.csv through the analyzer for the Evaluation page

Every check that finds something adds a "signal" (one warning sign) worth some points.
The points are added up into a score, and the score becomes a level: Low, Caution or High.
"""

import csv
import json
from pathlib import Path
import re
from urllib.parse import parse_qs, unquote, urlparse

import tldextract
import zxingcpp
from PIL import Image, UnidentifiedImageError

# tldextract splits a website name into parts. suffix_list_urls=() makes it use its built-in
# list of endings and never download one; extra_suffixes teaches it the new ".bank.in" ending.
_EXTRACTOR = tldextract.TLDExtract(cache_dir=False, suffix_list_urls=(), extra_suffixes=["bank.in"])

# Folder that holds brands.json, the phishing feed and examples.csv
DATA_DIR = Path(__file__).resolve().parent / "data"

# =====================================================
# 1. SETTINGS & BRAND DATA
# =====================================================

def load_brands() -> tuple[dict, dict, dict]:
    """
    Load brand -> official domains from data/brands.json.
    Returns (brand_to_domains, official_domain_to_brand, name_to_brand).
    """
    brands_path = DATA_DIR / "brands.json"
    with open(brands_path, "r", encoding="utf-8-sig") as f:
        brand_map = json.load(f)

    # Reverse lookup for registered official domains
    official_domains = {}
    # Every name that points to a brand: the brand itself ("hdfc"), plus longer
    # forms of it used in its own domains ("hdfcbank" from "hdfcbank.com")
    brand_names = {}
    for brand, domains in brand_map.items():
        brand_names[brand] = brand
        for domain in domains:
            official_domains[domain.lower()] = brand
            name = domain.lower().split(".")[0]    # "hdfcbank.com" -> "hdfcbank"
            if brand in name:                      # skip unrelated names like "office" (Microsoft)
                brand_names[name] = brand

    return brand_map, official_domains, brand_names


BRANDS, OFFICIAL_DOMAINS, BRAND_NAMES = load_brands()

# Score cut-offs: below 30 is Low, 30 to 59 is Caution, 60 and above can be High
CAUTION_SCORE = 30
HIGH_SCORE = 60

# Links longer than this many characters count as "unusually long"
LONG_LINK_LENGTH = 75

BAD_ENDINGS = {
    "xyz", "top", "click", "buzz", "tk", "ml", "ga", "cf",
    "live", "icu", "work", "loan", "fit", "rest", "surf", "monster"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly",
    "is.gd", "rb.gy", "shorturl.at", "tiny.cc", "ow.ly"
}

FREE_HOSTS = {
    "sites.google.com", "docs.google.com", "forms.google.com",
    "drive.google.com", "firebaseapp.com", "web.app", "github.io",
    "pages.dev", "weebly.com", "wixsite.com", "blogspot.com",
    "amazonaws.com", "googleapis.com"
}

PHISH_WORDS = [
    "login", "verify", "secure", "update", "kyc", "account",
    "confirm", "banking", "wallet", "reward", "bonus", "claim",
    "credential", "password", "authenticate", "pan"
]

URGENT_WORDS = [
    "urgent", "suspended", "expire", "expired", "blocked",
    "last chance", "act now", "action required", "immediately", "immediate",
    "penalty", "challan", "disconnect", "electricity cutoff", "power cutoff",
    "digital arrest", "customs", "arrest warrant", "deactivation",
    # other forms of the words above, because whole-word matching won't find "urgently" inside "urgent"
    "urgently", "disconnected", "suspension", "deactivated"
]

SECRET_WORDS = [
    "otp", "pin", "cvv", "password", "card number", "upi pin", "passcode"
]

# Words in a UPI payee name or note that promise you money; a QR code can only take money from you
UPI_BAIT_WORDS = [
    "refund", "cashback", "prize", "reward", "lottery", "winner", "won", "receive",
    "bonus", "claim", "gift", "lucky draw", "kyc", "verify"
]

# Lookalike characters mapped to the Latin letter they imitate,
# e.g. Cyrillic "\u0430" looks exactly like Latin "a", and "0" is often used for "o"
HOMOGLYPH_MAP = {
    "\u0430": "a", "\u0441": "c", "\u0435": "e", "\u043e": "o",
    "\u0440": "p", "\u0455": "s", "\u0456": "i", "\u0458": "j",
    "\u0443": "y", "\u0445": "x", "\u045d": "i", "\u0406": "i",
    "\u0501": "d", "\u051b": "q", "\u0578": "n", "\u03b1": "a",
    "\u03bf": "o", "\u03c5": "u", "\u03bd": "v",
    "0": "o", "1": "l", "3": "e", "5": "s"
}


# =====================================================
# 2. STRING & DOMAIN UTILITIES
# =====================================================

def normalize_url(url: str) -> tuple[str, bool]:
    """Add "http://" if the link has none, so Python can split it into parts. Returns (link, did_the_user_type_it)."""
    url = url.strip()
    has_scheme = url.startswith("http://") or url.startswith("https://")
    if has_scheme:
        return url, True
    return "http://" + url, False


def is_ip_address(host: str) -> bool:
    """True if the host is a number address like 192.168.1.1 instead of a name."""
    clean_host = host.split(":")[0].strip("[]")
    parts = clean_host.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
    return True


def count_digits(text: str) -> int:
    """How many digits (0-9) are in the text."""
    count = 0
    for char in text:
        if char.isdigit():
            count += 1
    return count


def one_edit_apart(a: str, b: str) -> bool:
    """True if a and b differ by exactly one changed, added or removed letter (e.g. "paytn" and "paytm")."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    for i in range(min(len(a), len(b))):
        if a[i] != b[i]:
            # At the first difference: the rest must match after a changed, added or removed letter
            return a[i + 1:] == b[i + 1:] or a[i + 1:] == b[i:] or a[i:] == b[i + 1:]
    return True    # no difference found, so one word is the other plus one letter at the end


def normalize_visual_lookalikes(text: str) -> str:
    """Replace lookalike letters with the Latin letter they imitate, e.g. "g00gle" -> "google", "rn" -> "m"."""
    lower_text = text.lower()
    lower_text = lower_text.replace("rn", "m").replace("vv", "w")
    result = []
    for char in lower_text:
        result.append(HOMOGLYPH_MAP.get(char, char))    # keep the letter if it isn't in the map
    return "".join(result)


def extract_domain_parts(url: str):
    """Split a link's host into .subdomain, .domain and .suffix, e.g. "login.sbi.co.in" -> "login", "sbi", "co.in"."""
    return _EXTRACTOR(url)


def detect_punycode_or_unicode(host: str) -> tuple[bool, str]:
    """Does the host use non-Latin letters or punycode ("xn--")? Returns (yes/no, the host in punycode form)."""
    has_non_ascii = any(ord(char) > 127 for char in host)    # characters above 127 aren't plain English letters
    has_punycode = "xn--" in host.lower()

    puny_host = host
    if has_non_ascii:
        try:
            puny_host = host.encode("idna").decode("ascii")
        except Exception:
            puny_host = host

    return (has_non_ascii or has_punycode), puny_host


# =====================================================
# 2b. KNOWN PHISHING LIST (offline OpenPhish snapshot)
# =====================================================

FEED_DATE = "23 Oct 2026"

# Redirect pages that trusted sites put in front of outgoing links: (domain, path) -> query fields holding the real link
REDIRECT_WRAPPERS = {
    ("google.com", "/url"): ("q", "url"),
    ("google.co.in", "/url"): ("q", "url"),
    ("google.com", "/goto"): ("url",),
    ("google.co.in", "/goto"): ("url",),
    ("facebook.com", "/l.php"): ("u",),
    ("youtube.com", "/redirect"): ("q",),
}

# Services where one host serves many different people's files
SHARED_STORAGE = {"backblazeb2.com", "contabostorage.com", "googleapis.com", "dropbox.com"}


def url_key(url: str) -> str:
    """Host + path in lowercase, without scheme, query or trailing slash, so two links can be compared."""
    parsed = urlparse(url)
    return ((parsed.hostname or "") + parsed.path).lower().rstrip("/")


def load_phishing_feed() -> tuple[set, set]:
    """Read data/openphish_feed.txt into (exact links, whole hosts). Never opens any of the links."""
    feed_path = DATA_DIR / "openphish_feed.txt"
    links = set()
    hosts = set()
    with open(feed_path, "r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            links.add(url_key(line))
            host = (urlparse(line).hostname or "").lower()
            domain_parts = extract_domain_parts(line)
            registered = f"{domain_parts.domain}.{domain_parts.suffix}".lower()
            # On shared services one bad page doesn't make every page on that host bad
            if host in FREE_HOSTS or registered in SHORTENERS or registered in SHARED_STORAGE or registered in OFFICIAL_DOMAINS:
                continue
            hosts.add(host)
    return links, hosts


PHISHING_LINKS, PHISHING_HOSTS = load_phishing_feed()


# =====================================================
# 2c. SHARED SCORING HELPERS (used by links and messages)
# =====================================================

REPORT_STEPS = [
    "Report suspicious links and fraud at cybercrime.gov.in or call 1930.",
    "For fraudulent SMS or calls, report via Chakshu on sancharsaathi.gov.in.",
]


def decide_level(score: int, signals: list) -> str:
    """
    Turn a 0-100 score into "Low", "Caution" or "High".
    High also needs real evidence: one strong FACT (20+ points) or warnings
    from at least two different checks, so a single guess can't make it High.
    """
    if score < CAUTION_SCORE:
        return "Low"
    if score < HIGH_SCORE:
        return "Caution"
    strong_facts = [signal for signal in signals if signal["kind"] == "FACT" and signal["points"] >= 20]
    checks_that_fired = set(signal["check"] for signal in signals if signal["points"] > 0)
    if len(strong_facts) >= 1 or len(checks_that_fired) >= 2:
        return "High"
    return "Caution"


def build_next_steps(signals: list, level: str, nothing_found_message: str) -> list:
    """Each signal's advice once, plus where to report it if High, or a default message if nothing was found."""
    next_steps = []
    for signal in signals:
        if signal["advice"] not in next_steps:
            next_steps.append(signal["advice"])
    if level == "High":
        for step in REPORT_STEPS:
            if step not in next_steps:
                next_steps.append(step)
    if not next_steps:
        next_steps.append(nothing_found_message)
    return next_steps


# =====================================================
# 3. URL ANALYSIS
# =====================================================

def analyze_url(raw_url: str) -> dict:
    """
    Check one link for phishing warning signs, without ever opening it.
    Returns the result dictionary described at the top of this file.
    """
    original_input = raw_url.strip()
    if not original_input:
        return {
            "input": original_input,
            "score": 0,
            "level": "Low",
            "signals": [],
            "next_steps": ["Enter a valid URL to analyze."]
        }

    # A UPI payment link isn't a website, so it gets its own checks
    if original_input.lower().startswith("upi://"):
        return analyze_upi(original_input)

    url, had_explicit_scheme = normalize_url(original_input)
    parsed = urlparse(url)
    domain_parts = extract_domain_parts(url)

    host = (parsed.hostname or "").lower()
    # The part someone actually registers, e.g. "sbi.co.in" for "login.sbi.co.in"
    registered_domain = f"{domain_parts.domain}.{domain_parts.suffix}".lower() if domain_parts.suffix else domain_parts.domain.lower()

    signals = []

    # Check 0: a trusted site's redirect page (e.g. Google's /url and /goto) is judged by where it leads
    wrapper_fields = REDIRECT_WRAPPERS.get((registered_domain, parsed.path))
    if wrapper_fields:
        fields = {key.lower(): values[0].strip() for key, values in parse_qs(parsed.query).items()}
        for field in wrapper_fields:
            if fields.get(field, "").lower().startswith(("http://", "https://")):
                return analyze_url(fields[field])    # "What we checked" then shows the real destination
        signals.append({
            "kind": "FACT",
            "check": "hidden_destination",
            "title": f"The real destination is hidden inside {registered_domain}'s redirect link",
            "evidence": parsed.path,
            "points": 30,
            "advice": "Select the web address shown under the search result and check that instead, or type the site's address yourself."
        })

    # Check 1: the domain is one of a brand's official sites (lowers the score)
    is_official = False
    official_brand_match = OFFICIAL_DOMAINS.get(registered_domain)
    if official_brand_match is None and domain_parts.suffix == "bank.in":
        official_brand_match = domain_parts.domain    # only RBI-verified banks can register .bank.in
    if official_brand_match:
        is_official = True
        signals.append({
            "kind": "FACT",
            "check": "official_domain",
            "title": f"Verified official domain for {official_brand_match.upper()}",
            "evidence": registered_domain,
            "points": -35,
            "advice": f"This domain matches the registered official site for {official_brand_match.upper()}."
        })

    # Check 2: brand or login words on a free hosting service (e.g. a fake SBI form on Google Sites)
    full_path_and_query = (parsed.path + " " + parsed.query).lower()
    # True if the host is a free host or a site under one, e.g. "mysite.pages.dev"
    is_free_host = any(host == free_host or host.endswith("." + free_host) for free_host in FREE_HOSTS)
    if is_free_host:
        suspicious_path_tokens = []
        for brand in BRANDS:
            if re.search(rf"\b{re.escape(brand)}\b", full_path_and_query):
                suspicious_path_tokens.append(brand)
        for phish in PHISH_WORDS:
            if re.search(rf"\b{re.escape(phish)}\b", full_path_and_query):
                suspicious_path_tokens.append(phish)

        if suspicious_path_tokens:
            signals.append({
                "kind": "HEURISTIC",
                "check": "hosting_abuse",
                "title": "Suspicious brand or phishing keywords hosted on a free platform",
                "evidence": f"Path contains: {', '.join(set(suspicious_path_tokens))}",
                "points": 35,
                "advice": "Attackers frequently host credential-harvesting forms on free services like Google Sites or Forms."
            })

    # Check 3: another website's link hidden in the query string (after the "?")
    redirect_targets = []
    for link in re.findall(r"https?://[^\s&]+", unquote(parsed.query), re.IGNORECASE):
        target = extract_domain_parts(link)
        target_domain = f"{target.domain}.{target.suffix}".lower()
        if target_domain != registered_domain and target_domain not in OFFICIAL_DOMAINS:
            redirect_targets.append(target_domain)
    if redirect_targets:
        signals.append({
            "kind": "HEURISTIC",
            "check": "open_redirect",
            "title": "Forwards to a different website hidden inside the link",
            "evidence": ", ".join(redirect_targets),
            "points": 35,
            "advice": "The real destination is the second website, not the trusted one at the start. Don't open it."
        })

    # Check 4: listed in the offline OpenPhish snapshot (a FACT about the list, not about the site today)
    if url_key(url) in PHISHING_LINKS or host in PHISHING_HOSTS:
        signals.append({
            "kind": "FACT",
            "check": "known_phishing",
            "title": f"Listed as a phishing site in the OpenPhish feed (snapshot of {FEED_DATE})",
            "evidence": host,
            "points": 60,
            "advice": "Don't open it. Report it at cybercrime.gov.in or call 1930."
        })

    # Check 5: a numeric IP address instead of a name
    if is_ip_address(host):
        signals.append({
            "kind": "FACT",
            "check": "ip_host",
            "title": "Uses a numeric IP address instead of a domain name",
            "evidence": host,
            "points": 30,
            "advice": "Legitimate banking and enterprise portals use verified domain names, not raw IP addresses."
        })

    # Check 6: an "@" in the website part, which hides the real destination
    if "@" in parsed.netloc:
        signals.append({
            "kind": "FACT",
            "check": "at_symbol",
            "title": "Contains '@' symbol to disguise actual host destination",
            "evidence": "@",
            "points": 25,
            "advice": "Browsers treat text before '@' as user credentials and navigate to what follows."
        })

    # Check 7: plain http:// (only if the user actually typed it)
    if had_explicit_scheme and parsed.scheme == "http":
        signals.append({
            "kind": "FACT",
            "check": "no_https",
            "title": "Does not use secure HTTPS encryption",
            "evidence": "http://",
            "points": 10,
            "advice": "Never enter passwords or confidential details on unencrypted HTTP pages."
        })

    # Check 8: non-Latin lookalike letters or punycode ("xn--") in the website name
    has_lookalike, punycode_host = detect_punycode_or_unicode(host)
    if has_lookalike:
        signals.append({
            "kind": "FACT",
            "check": "punycode_lookalike",
            "title": "Uses internationalized (Punycode) or lookalike characters",
            "evidence": punycode_host,
            "points": 30,
            "advice": "This domain uses lookalike characters (homoglyphs) to impersonate a legitimate service."
        })

    # Check 9: an ending often used in scams (.xyz, .top, ...)
    last_suffix = domain_parts.suffix.split(".")[-1].lower()    # e.g. "co.in" -> "in"
    if last_suffix in BAD_ENDINGS:
        signals.append({
            "kind": "HEURISTIC",
            "check": "risky_tld",
            "title": f"Risky top-level domain ending: .{domain_parts.suffix}",
            "evidence": "." + domain_parts.suffix,
            "points": 20,
            "advice": f"Be cautious of links ending in .{domain_parts.suffix}, frequently used in low-cost scam campaigns."
        })

    # Check 10: a link shortener that hides the destination
    if registered_domain in SHORTENERS:
        signals.append({
            "kind": "HEURISTIC",
            "check": "shortener",
            "title": "Shortened link obscures the real destination",
            "evidence": registered_domain,
            "points": 15,
            "advice": "Don't open it. Ask the sender where it leads, or verify on the official app."
        })

    # Check 11: the shape of the link (very long, many subdomains, many hyphens or digits)
    if len(url) > LONG_LINK_LENGTH:
        signals.append({
            "kind": "HEURISTIC",
            "check": "url_length",
            "title": "URL length is unusually long",
            "evidence": f"{len(url)} characters",
            "points": 10,
            "advice": "Inspect the address carefully for hidden parameters or obscured destinations."
        })

    if domain_parts.subdomain and domain_parts.subdomain.count(".") >= 2:
        signals.append({
            "kind": "HEURISTIC",
            "check": "excessive_subdomains",
            "title": "Excessive subdomains used to mimic authentic services",
            "evidence": domain_parts.subdomain,
            "points": 15,
            "advice": "Check the rightmost registered domain name to identify who actually owns the site."
        })

    if host.count("-") >= 2 or count_digits(domain_parts.domain) >= 3:
        signals.append({
            "kind": "HEURISTIC",
            "check": "hyphens_digits",
            "title": "Excessive hyphens or digits in domain name",
            "evidence": domain_parts.domain,
            "points": 10,
            "advice": "Scammers frequently insert hyphens and numbers to create copycat domain names."
        })

    # Check 12: two or more phishing words in the path or subdomain
    # Split into words at / . - _ ? & =  e.g. "/kyc-update" -> "kyc", "update"
    url_tokens = set(re.split(r"[/.\-_?&=]", parsed.path.lower() + " " + domain_parts.subdomain.lower()))
    found_phish_words = [word for word in PHISH_WORDS if word in url_tokens]
    if len(found_phish_words) >= 2:
        signals.append({
            "kind": "HEURISTIC",
            "check": "phish_words",
            "title": f"Multiple phishing keywords in URL: {', '.join(found_phish_words)}",
            "evidence": ", ".join(found_phish_words),
            "points": 15,
            "advice": "Avoid entering credentials on URLs containing multiple account-verification words."
        })

    # Check 13: pretending to be a brand (13a exact name, 13b name inside the host, 13c one-letter typo)
    # First undo punycode and lookalike letters, so "xn--pytm-53d" and "g00gle" compare like "paytm" and "google"
    readable_domain = domain_parts.domain
    if readable_domain.startswith("xn--"):
        try:
            readable_domain = readable_domain.encode("ascii").decode("idna")
        except UnicodeError:
            pass
    normalized_ext_domain = normalize_visual_lookalikes(readable_domain)
    normalized_host = normalize_visual_lookalikes(host)
    host_labels = set(re.split(r"[.\-_]", normalized_host))

    brand_flagged = False

    # 13a. The domain IS a brand name (or a longer form like "hdfcbank"), but not on one of its official sites
    if normalized_ext_domain in BRAND_NAMES and not is_official:
        matched_brand = BRAND_NAMES[normalized_ext_domain]
        official_domains = BRANDS.get(matched_brand, [])
        if registered_domain not in official_domains:
            brand_flagged = True
            primary_official = official_domains[0] if official_domains else f"{matched_brand}.com"
            signals.append({
                "kind": "HEURISTIC",
                "check": "unauthorized_brand_domain",
                "title": f"Uses the name '{matched_brand.upper()}', but '{registered_domain}' is not one of its official sites",
                "evidence": registered_domain,
                "points": 40,
                "advice": f"Type {primary_official} yourself in the browser instead of using this link."
            })

    # 13b. A brand name appears as a word in the host, e.g. "sbi.co.in.verify-kyc.top" or "icicibank-rewards.xyz"
    if not brand_flagged and not is_official:
        for name, brand in BRAND_NAMES.items():
            if name in host_labels and domain_parts.domain != name:
                official_domains = BRANDS.get(brand, [])
                if registered_domain not in official_domains:
                    brand_flagged = True
                    primary_official = official_domains[0] if official_domains else f"{brand}.com"
                    signals.append({
                        "kind": "HEURISTIC",
                        "check": "brand_token_spoof",
                        "title": f"Pretends to be '{brand.upper()}' but real domain is '{registered_domain}'",
                        "evidence": f"Token '{name}' in host '{host}'",
                        "points": 30,
                        "advice": f"Type {primary_official} yourself in the browser instead of using this link."
                    })
                    break

    # 13c. One letter away from a brand of 5+ letters, e.g. "paytn" for "paytm"
    if not brand_flagged and not is_official:
        for brand, official_domains in BRANDS.items():
            if len(brand) >= 5 and one_edit_apart(normalized_ext_domain, brand):
                primary_official = official_domains[0] if official_domains else f"{brand}.com"
                signals.append({
                    "kind": "HEURISTIC",
                    "check": "typosquatting",
                    "title": f"Looks like a deceptive spelling or typo of '{brand.upper()}'",
                    "evidence": domain_parts.domain,
                    "points": 25,
                    "advice": f"Type the official site {primary_official} directly into your address bar."
                })
                break

    # No trusted-site credit when the trusted site is only carrying someone else's content
    if any(signal["check"] in ("hosting_abuse", "open_redirect", "known_phishing", "hidden_destination") for signal in signals):
        signals = [signal for signal in signals if signal["check"] != "official_domain"]

    # Add up the points and keep the score between 0 and 100
    score = max(0, min(100, sum(signal["points"] for signal in signals)))
    level = decide_level(score, signals)
    next_steps = build_next_steps(
        signals, level,
        "No immediate red flags detected, but always confirm website identity before entering credentials."
    )

    return {
        "input": original_input,
        "score": score,
        "level": level,
        "signals": signals,
        "next_steps": next_steps
    }


# =====================================================
# 3b. UPI PAYMENT ANALYSIS (upi://pay links, usually from QR codes)
# =====================================================

def analyze_upi(raw_upi: str) -> dict:
    """
    Check a UPI payment link such as "upi://pay?pa=shop@okaxis&pn=Shop&am=100".
    pa = who gets paid (the UPI ID), pn = the name shown to you, am = the amount, tn = a note.
    Returns the result dictionary described at the top of this file.
    """
    original_input = raw_upi.strip()
    parsed = urlparse(original_input)
    action = parsed.netloc.lower()    # "pay" for a payment, "mandate" for repeating payments (autopay)
    # parse_qs gives lists, e.g. {"pa": ["shop@okaxis"]}; keys are lowercased because some apps write "PA="
    fields = {key.lower(): values[0].strip() for key, values in parse_qs(parsed.query).items()}
    payee_id = fields.get("pa", "")
    payee_name = fields.get("pn", "")
    note = fields.get("tn", "")

    signals = []

    # Check 1: the UPI ID is missing or isn't "name@bank"
    if not re.fullmatch(r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}", payee_id):
        signals.append({
            "kind": "FACT",
            "check": "upi_bad_id",
            "title": "The payee's UPI ID is missing or not in the normal name@bank form",
            "evidence": payee_id or "(no pa= field)",
            "points": 30,
            "advice": "Don't pay with this QR code. Ask the person for their UPI ID and type it in your UPI app yourself."
        })

    # Check 2: sets up automatic repeating payments instead of one payment
    if action == "mandate":
        signals.append({
            "kind": "FACT",
            "check": "upi_mandate",
            "title": "Sets up automatic repeating payments (a UPI autopay mandate), not a single payment",
            "evidence": "upi://mandate",
            "points": 30,
            "advice": "Only approve autopay for a subscription you started yourself, inside that company's own app."
        })

    # Check 3: the amount is already filled in
    amount = fields.get("am", "")
    if amount:
        signals.append({
            "kind": "FACT",
            "check": "upi_fixed_amount",
            "title": f"The amount is already filled in: Rs {amount}",
            "evidence": f"am={amount}",
            "points": 10,
            "advice": "Make sure you actually owe this exact amount before you enter your UPI PIN."
        })

    # Check 4: the name or note promises you money (refund, prize, cashback...)
    name_and_note = (payee_name + " " + note).lower()
    found_bait = [word for word in UPI_BAIT_WORDS if re.search(rf"\b{re.escape(word)}\b", name_and_note)]
    if found_bait:
        signals.append({
            "kind": "HEURISTIC",
            "check": "upi_receive_bait",
            "title": f"Promises you money, but this QR code can only take money from you: {', '.join(found_bait)}",
            "evidence": f"pn={payee_name}  tn={note}".strip(),
            "points": 35,
            "advice": "You never need to scan a QR code or enter your UPI PIN to receive money. Don't pay."
        })

    # Check 5: the payee name or UPI ID uses a bank or company name from brands.json
    name_words = set(re.split(r"[^a-z0-9]+", (payee_name + " " + payee_id.split("@")[0]).lower()))
    for name, brand in BRAND_NAMES.items():
        if name in name_words:
            primary_official = BRANDS[brand][0] if BRANDS.get(brand) else f"{brand}.com"
            signals.append({
                "kind": "HEURISTIC",
                "check": "upi_brand_name",
                "title": f"The payee calls itself '{brand.upper()}', but anyone can choose that name",
                "evidence": f"pn={payee_name}  pa={payee_id}",
                "points": 20,
                "advice": f"To pay {brand.upper()}, use its official app or {primary_official}, not a QR code someone sent you."
            })
            break

    score = max(0, min(100, sum(signal["points"] for signal in signals)))
    level = decide_level(score, signals)
    next_steps = build_next_steps(
        signals, level,
        "Check that the payee name in your UPI app is who you meant to pay before you enter your PIN."
    )
    # The one fact every UPI QR code shares, shown first
    who = f"{payee_name} ({payee_id})" if payee_name else payee_id or "an unknown payee"
    next_steps.insert(0, f"This QR code sends money from your account to {who}. It can never put money into your account.")

    return {
        "input": original_input,
        "score": score,
        "level": level,
        "signals": signals,
        "next_steps": next_steps
    }


# =====================================================
# 3c. QR CODES (read the picture, then pick the right checker)
# =====================================================

def decode_qr(image_file) -> list:
    """
    Read every QR code in a picture and return the text inside each one.
    Only reads the pixels: whatever the code points to is never opened.
    Raises ValueError if the file isn't a picture or has no readable QR code.
    """
    try:
        image = Image.open(image_file)
        image.load()
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError) as error:
        raise ValueError("Not a readable picture") from error
    codes = zxingcpp.read_barcodes(image.convert("L"), formats=zxingcpp.BarcodeFormat.QRCode)    # "L" = greyscale
    texts = [code.text for code in codes if code.text]
    if not texts:
        raise ValueError("No QR code found")
    return texts


def analyze_qr_text(text: str) -> dict:
    """A QR code holds a link, a UPI payment or plain text: one word goes to analyze_url, anything longer to analyze_text."""
    text = text.strip()
    if " " in text or "\n" in text:
        return analyze_text(text)
    return analyze_url(text)    # analyze_url passes upi:// on to analyze_upi


# =====================================================
# 4. MESSAGE ANALYSIS (SMS / WhatsApp)
# =====================================================

def find_links(text: str) -> list:
    """Find everything in a message that looks like a link."""
    links = []
    # Either a link starting with http(s):// or www., or a bare name like "sbi-kyc.xyz" with an optional /path
    pattern = r"(?:https?://|www\.)[^\s<>'\"]+|[a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|org|in|net|xyz|top|click|co|ly|edu|gov|live|icu|io)(?:/[^\s<>'\"]*)?"

    for match in re.finditer(pattern, text, re.IGNORECASE):
        candidate = match.group(0).strip(".,!?()\"';:<>")
        if "." in candidate and not candidate.endswith("."):
            links.append(candidate)

    return links


def analyze_text(text: str) -> dict:
    """
    Check a message for pressure tactics, requests for secrets, and dangerous links.
    Every link inside is checked with analyze_url; a message is never rated safer than its riskiest link.
    """
    original_input = text.strip()
    if not original_input:
        return {
            "input": original_input,
            "score": 0,
            "level": "Low",
            "signals": [],
            "next_steps": ["Enter a message to analyze."]
        }

    signals = []
    text_lower = original_input.lower()

    # Check 1: urgency or threat words (whole words only, so "blocked" doesn't match inside other words)
    found_urgent = []
    for word in URGENT_WORDS:
        pattern = rf"\b{re.escape(word)}\b"
        if re.search(pattern, text_lower):
            found_urgent.append(word)

    if found_urgent:
        points = min(30, 10 * len(found_urgent))
        signals.append({
            "kind": "HEURISTIC",
            "check": "urgency_language",
            "title": f"High-urgency or coercive threat wording detected: {', '.join(found_urgent)}",
            "evidence": ", ".join(found_urgent),
            "points": points,
            "advice": "Scammers manufacture artificial urgency to force hasty decisions. Pause and verify independently."
        })

    # Check 2: asks for a secret, unless the sentence says NOT to share it
    # A request word, then up to 30 characters, then a secret word: e.g. "share the OTP", "enter your PIN"
    secret_words = "|".join(re.escape(word) for word in SECRET_WORDS)
    request_pattern = r"\b(?:share|send|enter|tell|give|provide|reply with)\b[^.\n]{0,30}?\b(?:" + secret_words + r")\b"
    asked_secrets = []
    for match in re.finditer(request_pattern, text_lower):
        # The 10 characters just before the request, to skip "do not share..." and "never share..."
        before = text_lower[max(0, match.start() - 10):match.start()]
        if not re.search(r"\b(?:not|never|don't|dont)\s*$", before):
            asked_secrets.append(match.group(0))

    if asked_secrets:
        signals.append({
            "kind": "HEURISTIC",
            "check": "asks_secret_info",
            "title": "Asks you to share a secret code or password",
            "evidence": "; ".join(asked_secrets),
            "points": 35,
            "advice": "No legitimate bank or organization will ever ask for your OTP, PIN, or password. Never share them."
        })

    # Check 3: "pay first to receive money" tricks, or threat themes common in Indian scams
    pay_receive_pattern = r"\b(?:pay|send)\b[^\.\n;]{1,40}\b(?:to\s+)?(?:receive|claim|get|refund)\b"
    threat_theme_patterns = [
        r"\bdigital\s+arrest\b",
        r"\bcustoms\s+seiz(?:ed|ure)\b",
        r"\btraffic\s+challan\s+pending\b",
        r"\belectricity\b[^.\n]{0,30}\bdisconnect",    # e.g. "electricity connection will be disconnected"
    ]

    if re.search(pay_receive_pattern, text_lower):
        # Paying first to collect a prize or lottery win is the classic advance-fee scam, so it counts more
        mentions_prize = re.search(r"\b(?:won|winner|prize|lottery|lucky\s+draw)\b", text_lower)
        signals.append({
            "kind": "HEURISTIC",
            "check": "pay_to_receive_trick",
            "title": "'Pay first to receive money or reward' deception detected",
            "evidence": "Pay ... to receive/refund pattern",
            "points": 30 if mentions_prize else 25,
            "advice": "Never pay an advance fee or processing charge to receive lottery winnings, prizes, or refunds."
        })
    elif any(re.search(pattern, text_lower) for pattern in threat_theme_patterns):
        signals.append({
            "kind": "HEURISTIC",
            "check": "coercion_extortion_theme",
            "title": "Known threat scam detected (digital arrest, customs, challan or electricity cut-off)",
            "evidence": "Threat theme pattern",
            "points": 30,
            "advice": "Police, customs and power companies never threaten arrest or disconnection by SMS or video call. Contact them through their official website or app."
        })

    # Check 4: every link in the message, checked like a pasted link
    extracted_links = find_links(original_input)
    max_link_score = 0
    max_link_level = "Low"

    for link in extracted_links:
        link_result = analyze_url(link)
        max_link_score = max(max_link_score, link_result["score"])

        link_level = link_result["level"]
        if link_level == "High":
            max_link_level = "High"
        elif link_level == "Caution" and max_link_level != "High":
            max_link_level = "Caution"

        # Copy the link's signals into the message result, labelled with the link they came from
        for signal in link_result["signals"]:
            copied = dict(signal)
            copied["title"] = f"[{link}] {copied['title']}"
            signals.append(copied)

    # Score = the riskiest link's score + the message's own points (copied link signals start with "[")
    text_only_points = sum(signal["points"] for signal in signals if not signal["title"].startswith("["))
    combined_score = max(0, min(100, max_link_score + max(0, text_only_points)))
    level = decide_level(combined_score, signals)

    # A message is never rated safer than its riskiest link
    if max_link_level == "High":
        level = "High"
    elif max_link_level == "Caution" and level == "Low":
        level = "Caution"

    next_steps = build_next_steps(
        signals, level,
        "No immediate red flags detected, but always verify unfamiliar requests through official channels."
    )

    return {
        "input": original_input,
        "score": combined_score,
        "level": level,
        "signals": signals,
        "next_steps": next_steps
    }


# =====================================================
# 5. EXAMPLES AND EVALUATION
# =====================================================

def refang_url(text: str) -> str:
    """Turn a safely written link back into a real one: "hxxps://sbi[.]xyz" -> "https://sbi.xyz"."""
    text = text.replace("hxxps://", "https://").replace("hxxp://", "http://")
    text = text.replace("[.]", ".").replace("[:]", ":")
    return text


def load_examples() -> list:
    """Read data/examples.csv as a list of rows (used by the Examples page)."""
    csv_path = DATA_DIR / "examples.csv"
    if not csv_path.exists():
        return []
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def evaluate_examples() -> dict:
    """
    Run every example in data/examples.csv through the analyzer and count the results.
    Benign examples must come out Low; suspicious ones must come out Caution or High.
    Returns the totals plus the lists of false alarms and misses.
    """
    csv_path = DATA_DIR / "examples.csv"
    if not csv_path.exists():
        return {
            "total": 0,
            "correct": 0,
            "accuracy": 0.0,
            "false_alarms": [],
            "misses": [],
            "error": f"Evaluation dataset not found at {csv_path}"
        }

    total = 0
    correct = 0
    false_alarms = []
    misses = []

    for row in load_examples():
        total += 1
        label = row.get("label", "").strip().lower()
        channel = row.get("channel", "").strip().lower()
        raw_input = row.get("input", "").strip()

        clean_input = refang_url(raw_input)
        if channel == "url":
            result = analyze_url(clean_input)
        else:
            result = analyze_text(clean_input)

        # Everything the Evaluation page shows about a wrong answer
        record = {
            "input": raw_input,
            "label": label,
            "predicted_level": result["level"],
            "score": result["score"],
            "why": row.get("why", "").strip(),
            "signals": [signal["title"] for signal in result["signals"]]
        }

        if label == "benign":
            if result["level"] == "Low":
                correct += 1
            else:
                false_alarms.append(record)
        elif label == "suspicious":
            if result["level"] in ("Caution", "High"):
                correct += 1
            else:
                misses.append(record)

    accuracy = round(correct / total, 4) if total > 0 else 0.0

    return {
        "total": total,
        "correct": correct,
        "accuracy": accuracy,
        "false_alarms": false_alarms,
        "misses": misses
    }
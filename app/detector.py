# app/detector.py

SUSPICIOUS_KEYWORDS = [
    "verify your account", "login now", "urgent", "update your info", 
    "click below", "suspended", "security alert", "unauthorized access"
]

BAD_DOMAINS = [
    ".biz", ".ru", ".cn", ".tk", ".xyz", ".top", "xn--", "bit.ly", "tinyurl.com"
]

CAUTION_DOMAINS = [
    "gmail.com", "hotmail.com", "yahoo.com", "outlook.com", "aol.com", "mail.com", "protonmail.com"
]

SPAMMY_OFFER_KEYWORDS = [
    "build the app", "mobile app", "budget and timeline", "we offer", 
    "develop your app", "software development", "android or ios", 
    "dating app", "ecommerce", "taxi app", "doctor app"
]

KNOWN_BRANDS = [
    "paypal", "microsoft", "amazon", "netflix", "apple", "bank", "irs", "support"
]

def analyze_email(parsed_email):
    risk_score = 0
    flags = []

    body = parsed_email['body'].lower()
    links = parsed_email['links']
    sender = parsed_email['from'] or ""
    subject = parsed_email['subject'] or ""

    # Rule 1: Suspicious phishing keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in body:
            risk_score += 20
            flags.append(f"Keyword found: '{keyword}'")

    # Rule 2: Suspicious link domains
    for link in links:
        for bad in BAD_DOMAINS:
            if bad in link:
                risk_score += 25
                flags.append(f"Suspicious link domain: {bad}")

    # Rule 3: From/Reply-To mismatch
    reply_to = parsed_email.get("reply_to", "")
    if reply_to and reply_to != sender:
        risk_score += 20  # raised from 15
        flags.append(f"Reply-To address mismatch: {reply_to}")

    # Rule 4: SPF/DKIM check (mocked)
    spf_passed = parsed_email.get("spf_passed", True)
    dkim_passed = parsed_email.get("dkim_passed", True)

    if not spf_passed:
        risk_score += 10
        flags.append("SPF check failed")

    if not dkim_passed:
        risk_score += 10
        flags.append("DKIM check failed")

    # Rule 5: Public/free domain caution
    if sender:
        if "<" in sender and ">" in sender:
            email_address = sender.split("<")[1].replace(">", "").strip()
        else:
            email_address = sender.strip()

        domain_part = email_address.split("@")[-1].lower()
        if domain_part in CAUTION_DOMAINS:
            risk_score += 5  # reduced from 10
            flags.append(f"Sender domain is a public provider: {domain_part}")

    # Rule 6: Spammy offer language
    for keyword in SPAMMY_OFFER_KEYWORDS:
        if keyword in body:
            risk_score += 15
            flags.append(f"Possible marketing spam: '{keyword}'")

    # Rule 7: Display name and domain mismatch (spoof detection)
    if sender:
        display_name = sender.split("<")[0].strip().lower()
        if any(brand in display_name for brand in KNOWN_BRANDS):
            if "<" in sender and ">" in sender:
                email_address = sender.split("<")[1].replace(">", "").strip().lower()
                domain = email_address.split("@")[-1]
                if not any(brand in domain for brand in KNOWN_BRANDS):
                    risk_score += 20
                    flags.append(f"Possible spoofing: Display name '{display_name}' doesn't match domain '{domain}'")

    # Rule 8: Return-Path mismatch
    return_path = parsed_email.get("return_path", "").lower()
    if return_path and sender:
        if "@" in sender and "@" in return_path:
            sender_domain = sender.split("@")[-1].replace(">", "").strip()
            return_domain = return_path.split("@")[-1].replace(">", "").strip()
            if sender_domain != return_domain:
                risk_score += 15  # raised from 10
                flags.append(f"Return-Path domain mismatch: {sender_domain} vs {return_domain}")

    # Normalize score
    risk_score = min(risk_score, 100)

    # Final label
    if risk_score >= 70:
        label = "phishing"
    elif risk_score >= 30:
        label = "suspicious"
    else:
        label = "safe"

    return {
        "score": risk_score,
        "label": label,
        "flags": flags
    }

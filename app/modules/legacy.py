# app/modules/legacy.py

from modules.base import DetectionModule

class LegacyDetection(DetectionModule):
    def run(self):
        risk_score = 0
        flags = []
        email = self.parsed_email

        body = email.get('body', '').lower()
        links = email.get('links', [])
        sender = email.get('from', '') or ""
        subject = email.get('subject', '') or ""

        SUSPICIOUS_KEYWORDS = [
            "verify your account", "login now", "urgent", "update your info",
            "click below", "suspended", "security alert", "unauthorized access"
        ]
        BAD_DOMAINS = [".biz", ".ru", ".cn", ".tk", ".xyz", ".top", "xn--", "bit.ly", "tinyurl.com"]
        CAUTION_DOMAINS = ["gmail.com", "hotmail.com", "yahoo.com", "outlook.com", "aol.com", "mail.com", "protonmail.com"]
        SPAMMY_OFFER_KEYWORDS = [
            "build the app", "mobile app", "budget and timeline", "we offer",
            "develop your app", "software development", "android or ios",
            "dating app", "ecommerce", "taxi app", "doctor app"
        ]
        KNOWN_BRANDS = ["paypal", "microsoft", "amazon", "netflix", "apple", "bank", "irs", "support"]

        def extract_email_address(full_string):
            if "<" in full_string and ">" in full_string:
                return full_string.split("<")[1].replace(">", "").strip().lower()
            return full_string.strip().lower()

        # Keyword match in body
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in body:
                risk_score += 20
                flags.append(f"Keyword found: '{keyword}'")

        # Bad domain detection in links
        for link in links:
            for bad in BAD_DOMAINS:
                if bad in link:
                    risk_score += 25
                    flags.append(f"Suspicious link domain: {bad}")

        # Reply-to mismatch
        reply_to = email.get("reply_to", "").lower()
        if reply_to and reply_to != sender.lower():
            risk_score += 20
            flags.append(f"Reply-To address mismatch: {reply_to}")

        # SPF / DKIM checks
        if not email.get("spf_passed", True):
            risk_score += 10
            flags.append("SPF check failed")
        if not email.get("dkim_passed", True):
            risk_score += 10
            flags.append("DKIM check failed")

        # From domain analysis
        if sender:
            email_address = extract_email_address(sender)
            domain_part = email_address.split("@")[-1]
            if domain_part in CAUTION_DOMAINS:
                risk_score += 5
                flags.append(f"Sender domain is a public provider: {domain_part}")

        # Marketing spam check
        for keyword in SPAMMY_OFFER_KEYWORDS:
            if keyword in body:
                risk_score += 15
                flags.append(f"Possible marketing spam: '{keyword}'")

        # Display name mismatch
        if sender:
            display_name = sender.split("<")[0].strip().lower()
            email_address = extract_email_address(sender)
            domain = email_address.split("@")[-1]
            if any(brand in display_name for brand in KNOWN_BRANDS) and not any(brand in domain for brand in KNOWN_BRANDS):
                risk_score += 20
                flags.append(f"Possible spoofing: Display name '{display_name}' doesn't match domain '{domain}'")

        # Return-Path mismatch
        return_path = email.get("return_path", "").lower()
        if return_path and sender:
            sender_domain = sender.split("@")[-1].replace(">", "").strip().lower()
            return_domain = return_path.split("@")[-1].replace(">", "").strip().lower()
            if sender_domain != return_domain:
                risk_score += 15
                flags.append(f"Return-Path domain mismatch: {sender_domain} vs {return_domain}")

        return {
            "score": min(risk_score, 100),
            "flags": flags
        }

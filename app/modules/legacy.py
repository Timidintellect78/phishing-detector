# app/modules/legacy.py

from app.modules.base import DetectionModule

class LegacyDetection(DetectionModule):
    def analyze(self, email_data):
        score = 0
        flags = []

        body = email_data.get('body', '').lower()
        links = email_data.get('links', [])
        sender = email_data.get('from', '')
        subject = email_data.get('subject', '')

        def extract_email_address(full_string):
            if "<" in full_string and ">" in full_string:
                return full_string.split("<")[1].replace(">", "").strip().lower()
            return full_string.strip().lower()

        SUSPICIOUS_KEYWORDS = ["verify your account", "login now", "urgent", "update your info"]
        BAD_DOMAINS = [".ru", ".tk", "bit.ly", "tinyurl.com"]
        CAUTION_DOMAINS = ["gmail.com", "yahoo.com", "hotmail.com"]
        KNOWN_BRANDS = ["paypal", "microsoft", "amazon", "bank"]

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in body:
                score += 15
                flags.append(f"Suspicious keyword detected: {keyword}")

        for link in links:
            for bad in BAD_DOMAINS:
                if bad in link:
                    score += 20
                    flags.append(f"Suspicious domain in link: {bad}")

        reply_to = email_data.get("reply_to", "").lower()
        if reply_to and reply_to != sender.lower():
            score += 15
            flags.append("Reply-To mismatch")

        if not email_data.get("spf_passed", True):
            score += 10
            flags.append("SPF failed")
        if not email_data.get("dkim_passed", True):
            score += 10
            flags.append("DKIM failed")

        if sender:
            email_address = extract_email_address(sender)
            domain = email_address.split("@")[-1]
            if domain in CAUTION_DOMAINS:
                score += 5
                flags.append(f"Free email domain used: {domain}")

        return_path = email_data.get("return_path", "").lower()
        if return_path and "@" in return_path and "@" in sender:
            sender_domain = sender.split("@")[-1]
            return_domain = return_path.split("@")[-1]
            if sender_domain != return_domain:
                score += 10
                flags.append(f"Return-Path mismatch: {sender_domain} vs {return_domain}")

        return {
            "score": min(score, 100),
            "flags": flags
        }

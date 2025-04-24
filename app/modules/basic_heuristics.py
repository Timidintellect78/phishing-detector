# app/modules/basic_heuristics.py

from modules.base import DetectionModule

class BasicHeuristicsModule(DetectionModule):
    def analyze(self, email_data):
        score = 0
        flags = []

        # Simple keyword heuristics
        phishing_keywords = ["verify your account", "click here", "urgent action", "login"]
        body = email_data.get("body", "").lower()
        for kw in phishing_keywords:
            if kw in body:
                score += 10
                flags.append(f"Body contains suspicious phrase: '{kw}'")

        # Suspicious reply-to
        if email_data.get("reply_to") and email_data["reply_to"] != email_data.get("from"):
            score += 20
            flags.append("Reply-To address differs from From address")

        # SPF / DKIM failures
        if not email_data.get("spf_passed", True):
            score += 20
            flags.append("SPF check failed")
        if not email_data.get("dkim_passed", True):
            score += 20
            flags.append("DKIM check failed")

        # Suspicious links
        if email_data.get("links"):
            for link in email_data["links"]:
                if any(domain in link for domain in ["bit.ly", "tinyurl", "rebrand.ly"]):
                    score += 10
                    flags.append(f"Suspicious shortlink found: {link}")

        return {
            "score": min(score, 100),
            "flags": flags
        }

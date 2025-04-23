from base import DetectionModule

class BasicHeuristicsModule(DetectionModule):
    def analyze(self, email_data):
        score = 0
        flags = []

        # Flag suspicious reply-to
        if email_data.get("reply_to") and email_data["reply_to"] != email_data.get("from"):
            score += 20
            flags.append("Reply-To address differs from From address")

        # Check SPF & DKIM
        if not email_data.get("spf_passed"):
            score += 20
            flags.append("SPF check failed")
        if not email_data.get("dkim_passed"):
            score += 20
            flags.append("DKIM check failed")

        # Check for phishing keywords
        body = email_data.get("body", "").lower()
        phishing_keywords = ["verify your account", "click here", "urgent action", "login"]
        for kw in phishing_keywords:
            if kw in body:
                score += 10
                flags.append(f"Body contains suspicious phrase: '{kw}'")

        # Basic link check
        if email_data.get("links"):
            for link in email_data["links"]:
                if any(domain in link for domain in ["bit.ly", "tinyurl", "rebrand.ly"]):
                    score += 10
                    flags.append(f"Suspicious shortlink found: {link}")

        label = "safe"
        if score >= 70:
            label = "phishing"
        elif score >= 30:
            label = "suspicious"

        return {
            "score": min(score, 100),
            "label": label,
            "flags": flags
        }

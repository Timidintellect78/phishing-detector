# app/modules/basic_heuristics.py

from app.modules.base import DetectionModule

class BasicHeuristicsModule(DetectionModule):
    def analyze(self, email_data):
        score = 0
        flags = []

        # Check subject and body for suspicious keywords
        keywords = ['verify your account', 'login here', 'update password', 'urgent', 'click below']
        text = (email_data.get('subject', '') + " " + email_data.get('body', '')).lower()

        for keyword in keywords:
            if keyword in text:
                score += 15
                flags.append(f"Keyword detected: '{keyword}'")

        # Header checks
        if not email_data.get("dkim_passed", True):
            score += 20
            flags.append("DKIM check failed")

        if not email_data.get("spf_passed", True):
            score += 20
            flags.append("SPF check failed")

        if "reply_to" in email_data and email_data.get("reply_to") != email_data.get("from"):
            score += 10
            flags.append("Reply-to address does not match sender")

        # Cap score and assign label
        score = min(score, 100)

        if score < 30:
            label = "safe"
        elif score < 70:
            label = "suspicious"
        else:
            label = "phishing"

        return {
            "score": score,
            "label": label,
            "flags": flags
        }

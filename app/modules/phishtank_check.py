# app/modules/phishtank_check.py

import requests
from app.modules.base import DetectionModule

PHISHTANK_API_URL = "http://data.phishtank.com/data/online-valid.json"

class PhishTankModule(DetectionModule):
    def run(self):
        flags = []
        score = 0
        links = self.parsed_email.get("links", [])

        try:
            resp = requests.get(PHISHTANK_API_URL, timeout=10)
            if resp.status_code != 200:
                flags.append("PhishTank: Failed to fetch phishing database")
                return {"score": score, "flags": flags}

            phishing_data = resp.json()
            phish_urls = {entry['url'].lower() for entry in phishing_data if entry.get('online') == 'yes'}

            for link in links:
                normalized_link = link.strip().lower()
                if normalized_link in phish_urls:
                    score += 30
                    flags.append(f"PhishTank: Known phishing link detected - {link}")

        except Exception as e:
            flags.append(f"PhishTank error: {str(e)}")

        return {"score": score, "flags": flags}

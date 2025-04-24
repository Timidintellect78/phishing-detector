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
            # Fetch the latest PhishTank data
            response = requests.get(PHISHTANK_API_URL, timeout=10)
            if response.status_code != 200:
                flags.append("PhishTank: Failed to fetch phishing database")
                return {"score": 0, "flags": flags}

            phishtank_data = response.json()
            phish_urls = {entry['url'] for entry in phishtank_data}

            for link in links:
                if any(phish_url in link for phish_url in phish_urls):
                    score += 40
                    flags.append(f"PhishTank: Link matches known phishing URL - {link}")

        except Exception as e:
            flags.append(f"PhishTank error: {str(e)}")

        return {"score": score, "flags": flags}

# app/modules/phishtank_check.py

import requests
from urllib.parse import urlparse
from app.modules.base import DetectionModule

PHISHTANK_API_URL = "http://data.phishtank.com/data/online-valid.json"

class PhishTankModule(DetectionModule):
    def run(self):
        flags = []
        score = 0
        links = self.parsed_email.get("links", [])

        try:
            response = requests.get(PHISHTANK_API_URL, timeout=10)
            if response.status_code != 200:
                raise Exception("Failed to fetch phishing database")

            phishtank_data = response.json()

            phish_domains = {
                urlparse(entry["url"]).netloc.lower().strip()
                for entry in phishtank_data if "url" in entry
            }

            for link in links:
                domain = urlparse(link).netloc.lower().strip()
                if domain in phish_domains:
                    score += 40
                    flags.append(f"PhishTank match: {domain}")

        except Exception as e:
            flags.append(f"PhishTank: {str(e)}")

        return {"score": score, "flags": flags}

# app/modules/phishtank_check.py
import csv
import requests
from app.modules.base import DetectionModule

PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.csv"

class PhishTankModule(DetectionModule):
    def run(self):
        flags = []
        score = 0
        email_links = self.parsed_email.get("links", [])

        try:
            response = requests.get(PHISHTANK_URL, timeout=10)
            response.raise_for_status()

            csv_lines = response.text.splitlines()
            reader = csv.DictReader(csv_lines)

            phish_urls = set(row["url"].strip().lower() for row in reader if "url" in row)

            for link in email_links:
                if link.lower() in phish_urls:
                    score += 50
                    flags.append(f"PhishTank match found: {link}")

        except Exception as e:
            flags.append(f"PhishTank: Error fetching phishing database – {str(e)}")

        return {
            "score": min(score, 100),
            "flags": flags
        }

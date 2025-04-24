# app/modules/phishtank_check.py
from modules.base import DetectionModule
import requests

class PhishTankModule(DetectionModule):
    def run(self):
        flags = []
        score = 0
        phishing_found = 0

        for url in self.parsed_email.get("links", []):
            if self.check_phishtank(url):
                score += 25
                phishing_found += 1
                flags.append(f"PhishTank flagged phishing URL: {url}")

        return {
            "score": min(score, 100),
            "flags": flags
        }

    def check_phishtank(self, url):
        try:
            resp = requests.get(
                "https://checkurl.phishtank.com/checkurl/",
                params={"url": url, "format": "json"},
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("results", {}).get("valid", False)
        except Exception as e:
            pass
        return False

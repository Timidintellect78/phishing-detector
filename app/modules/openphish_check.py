# app/modules/openphish_check.py

import requests
from urllib.parse import urlparse
from app.modules.base import DetectionModule

class OpenPhishModule(DetectionModule):
    FEED_URL = "https://openphish.com/feed.txt"

    def __init__(self, email_data):
        super().__init__(email_data)
        self._phish_domains = set()

    def _fetch_feed(self):
        try:
            response = requests.get(self.FEED_URL, timeout=10)
            if response.status_code == 200:
                lines = response.text.strip().splitlines()
                self._phish_domains = {
                    urlparse(url).netloc.lower()
                    for url in lines if urlparse(url).netloc
                }
        except Exception:
            pass  # Silently fail to avoid crashing the app

    def run(self):
        self._fetch_feed()

        flags = []
        score = 0

        if not self._phish_domains:
            return None

        for link in self.parsed_email.get("links", []):
            domain = urlparse(link).netloc.lower()
            if domain in self._phish_domains:
                score += 50
                flags.append(f"⚠️ Link domain `{domain}` matches OpenPhish database")

        return {
            "score": min(score, 100),
            "flags": flags
        }

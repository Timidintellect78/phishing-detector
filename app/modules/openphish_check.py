# app/modules/openphish_check.py

import requests
from app.modules.base import DetectionModule

class OpenPhishModule(DetectionModule):
    FEED_URL = "https://openphish.com/feed.txt"

    def __init__(self, email_data):
        super().__init__(email_data)
        self._phish_urls = set()

    def _fetch_feed(self):
        try:
            response = requests.get(self.FEED_URL, timeout=10)
            if response.status_code == 200:
                self._phish_urls = set(line.strip().lower() for line in response.text.splitlines())
        except Exception as e:
            # No print here to avoid crashing app
            pass

    def run(self):
        self._fetch_feed()
        flags = []
        score = 0

        if not self._phish_urls:
            return None

        for link in self.parsed_email.get("links", []):
            normalized_link = link.strip().lower()
            if normalized_link in self._phish_urls:
                score += 50
                flags.append(f"⚠️ Link matches OpenPhish database: {link}")

        return {
            "score": min(score, 100),
            "flags": flags
        }

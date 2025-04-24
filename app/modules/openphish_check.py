# app/modules/openphish_check.py

import requests
from app.modules.base import DetectionModule

class OpenPhishModule(DetectionModule):
    FEED_URL = "https://openphish.com/feed.txt"

    def __init__(self, email_data):
        super().__init__(email_data)
        self._phish_urls = []

    def _fetch_feed(self):
        try:
            response = requests.get(self.FEED_URL, timeout=10)
            if response.status_code == 200:
                self._phish_urls = response.text.strip().splitlines()
        except Exception as e:
            # For debugging: write to a flag instead of printing
            self._phish_urls = []
            self._fetch_error = str(e)

    def run(self):
        self._fetch_feed()

        flags = []
        score = 0

        if not self._phish_urls:
            flags.append("⚠️ OpenPhish feed could not be fetched or was empty.")
            return {
                "score": 0,
                "flags": flags
            }

        for link in self.parsed_email.get("links", []):
            if any(phish_url in link for phish_url in self._phish_urls):
                flags.append(f"⚠️ Link matches OpenPhish database: {link}")
                score += 50
                break

        return {
            "score": min(score, 100),
            "flags": flags
        }



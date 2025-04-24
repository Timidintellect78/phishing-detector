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
        except Exception:
            # Silently fail if feed cannot be fetched (fail-safe)
            self._phish_urls = []

    def run(self):
        self._fetch_feed()

        flags = []
        score = 0

        if not self._phish_urls:
            return None

        for link in self.parsed_email.get("links", []):
            for phish_url in self._phish_urls:
                # Use startswith to account for query strings or trailing slashes
                if link.startswith(phish_url):
                    score += 50
                    flags.append(f"⚠️ Link matches OpenPhish database: {phish_url}")
                    break  # Stop checking once matched

        return {
            "score": min(score, 100),
            "flags": flags
        }

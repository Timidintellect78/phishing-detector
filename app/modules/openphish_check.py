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
                self._phish_urls = [line.strip().lower().rstrip('/') for line in response.text.splitlines()]
        except Exception:
            pass  # Fail silently for production use

    def run(self):
        self._fetch_feed()
        if not self._phish_urls:
            return None

        flags = []
        score = 0
        email_links = [link.lower().rstrip('/') for link in self.parsed_email.get("links", [])]

        for link in email_links:
            for phish_url in self._phish_urls:
                if phish_url in link:
                    flags.append(f"⚠️ Link matches OpenPhish database: {link}")
                    score += 50
                    break

        return {
            "score": min(score, 100),
            "flags": flags
        }

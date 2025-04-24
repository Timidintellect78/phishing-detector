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
            else:
                print(f"[OpenPhish] Failed to fetch feed. Status: {response.status_code}")
        except Exception as e:
            print(f"[OpenPhish] Exception during fetch: {e}")

    def run(self):
        self._fetch_feed()

        flags = []
        score = 0

        if not self._phish_urls:
            print("[OpenPhish] Feed is empty. Skipping check.")
            return None

        for link in self.parsed_email.get("links", []):
            for phish_url in self._phish_urls:
                if phish_url.strip() in link:
                    score += 50
                    flags.append(f"⚠️ Link matches OpenPhish database: {phish_url}")
                    print(f"[OpenPhish] Match found: {phish_url} in {link}")
                    break  # One match per link is enough

        return {
            "score": min(score, 100),
            "flags": flags
        }

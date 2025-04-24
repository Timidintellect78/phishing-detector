# app/modules/openphish_check.py

import requests
from app.modules.base import DetectionModule

class OpenPhishModule(DetectionModule):
    FEED_URL = "https://openphish.com/feed.txt"

    def __init__(self, email_data):
        super().__init__(email_data)
        self._phish_urls = []

    def _fetch_feed(self):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
        }
        try:
            response = requests.get(self.FEED_URL, timeout=10, headers=headers)
            if response.status_code == 200:
                self._phish_urls = response.text.strip().splitlines()
            else:
                print(f"[OpenPhish] Failed with status {response.status_code}")
        except Exception as e:
            print(f"[OpenPhish] Exception: {e}")

    def run(self):
        self._fetch_feed()

        flags = []
        score = 0

        if not self._phish_urls:
            return None

        for link in self.parsed_email.get("links", []):
            for phish_url in self._phish_urls:
                if phish_url in link:
                    score += 50
                    flags.append(f"⚠️ Link matches OpenPhish database: {phish_url}")
                    break

        return {
            "score": min(score, 100),
            "flags": flags
        }

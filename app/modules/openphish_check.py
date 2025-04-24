# app/modules/openphish_check.py

import requests
import streamlit as st
from app.modules.base import DetectionModule

class OpenPhishModule(DetectionModule):
    FEED_URL = "https://openphish.com/feed.txt"

    def __init__(self, email_data):
        super().__init__(email_data)
        self._phish_urls = []

    def _fetch_feed(self):
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (compatible; PhishingDetector/1.0)"
            }
            response = requests.get(self.FEED_URL, headers=headers, timeout=15)
            if response.status_code == 200:
                self._phish_urls = response.text.strip().splitlines()
            else:
                st.warning("⚠ OpenPhish feed request failed with status code: {}".format(response.status_code))
        except Exception as e:
            st.warning(f"⚠ Failed to fetch OpenPhish feed: {e}")

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

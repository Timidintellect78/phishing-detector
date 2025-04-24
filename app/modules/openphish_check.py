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
                lines = response.text.strip().splitlines()
                if lines:
                    self._phish_urls = [url.strip().lower() for url in lines]
        except Exception as e:
            # Log an error message directly into Streamlit instead of crashing
            import streamlit as st
            st.warning(f"⚠ OpenPhish feed could not be fetched: {e}")

    def run(self):
        self._fetch_feed()
        flags = []
        score = 0

        if not self._phish_urls:
            import streamlit as st
            st.warning("⚠ OpenPhish feed could not be fetched or was empty.")
            return None

        for link in self.parsed_email.get("links", []):
            link_lower = link.strip().lower()
            for phish_url in self._phish_urls:
                if phish_url in link_lower:
                    score += 50
                    flags.append(f"⚠️ Link matches OpenPhish database: {link}")
                    break  # Stop checking once matched

        return {
            "score": min(score, 100),
            "flags": flags
        }


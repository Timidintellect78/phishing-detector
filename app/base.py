# app/base.py

class DetectionModule:
    def analyze(self, email_data):
        """
        Analyze the parsed email data and return a result dictionary with:
            - score: an integer from 0 to 100
            - label: one of 'safe', 'suspicious', 'phishing'
            - flags: a list of strings describing indicators
        """
        raise NotImplementedError("Subclasses must implement this method.")

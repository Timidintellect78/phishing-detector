# app/modules/base.py
class DetectionModule:
    def __init__(self, email_data):
        self.parsed_email = email_data

    def analyze(self, email_data):
        raise NotImplementedError("Subclasses must implement the analyze method.")

    def run(self):
        raise NotImplementedError("Subclasses must implement the run method.")

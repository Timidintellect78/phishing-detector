# app/modules/base.py

class DetectionModule:
    """
    Base class for detection modules. Subclasses must implement analyze().
    """
    def __init__(self, email_data):
        self.email_data = email_data

    def run(self):
        return self.analyze(self.email_data)

    def analyze(self, email_data):
        raise NotImplementedError("analyze() must be implemented by subclasses.")

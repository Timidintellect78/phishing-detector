# app/modules/base.py

class DetectionModule:
    """
    Base class for detection modules. Must implement analyze().
    """
    def analyze(self, email_data):
        raise NotImplementedError("analyze() must be implemented by subclasses.")

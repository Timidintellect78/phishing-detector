# app/detector.py

import os
import importlib
from modules.base import DetectionModule

def analyze_email(parsed_email):
    score = 0
    label = "safe"
    flags = []

    module_dir = os.path.join(os.path.dirname(__file__), "modules")
    for filename in os.listdir(module_dir):
        if filename.endswith(".py") and filename != "base.py":
            module_name = f"app.modules.{filename[:-3]}"
            module = importlib.import_module(module_name)
            for attr in dir(module):
                obj = getattr(module, attr)
                if isinstance(obj, type) and issubclass(obj, DetectionModule) and obj is not DetectionModule:
                    instance = obj(parsed_email)
                    result = instance.run()
                    if result:
                        score += result.get("score", 0)
                        flags.extend(result.get("flags", []))

    if score >= 70:
        label = "phishing"
    elif score >= 30:
        label = "suspicious"

    return {
        "score": min(score, 100),
        "label": label,
        "flags": flags
    }

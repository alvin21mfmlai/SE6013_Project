import os
from defence_mechanisms import safe_from_pretrained, UnsafeModelLoad
from transformers import AutoModelForSequenceClassification

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL = os.path.join(HERE, "payload", "model")

# Route the SAME tampered model through the defence wrapper instead of a raw
# from_pretrained/from_config. The four checks run before any model is built;
# if any fails, UnsafeModelLoad is raised and nothing is constructed -> no payload.
try:
    safe_from_pretrained(
        MODEL,
        loader=AutoModelForSequenceClassification.from_pretrained,
        allow_vulnerable_env=True,   # lab mode: don't refuse just for being on an old version
    )
    print("[!] Model loaded — defence did NOT block (unexpected).")
except UnsafeModelLoad as e:
    print(f"[+] DEFENCE BLOCKED THE LOAD: {e}")

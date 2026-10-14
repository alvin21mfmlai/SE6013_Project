⚠️ Important Before You Start
- This environment is for **academic replication only** within an isolated setup
- **Do not use your real Hugging Face account** — use throwaway accounts only
- Do **not** share or publish any tokens, credentials, or test repo links outside the team
- Keep all project files inside your home directory (`~/`)

## Step 1 - Install Ubuntu

## Step 2 — Update Ubuntu and Install Base Tooling

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-venv python3-pip git strace auditd
```

> `strace` and `auditd` are needed later for monitoring system calls during the exploit demo (B2 section).

---

## Step 3 — Create an Isolated Python Virtual Environment

```bash
python3 -m venv ~/cve-env
source ~/cve-env/bin/activate
```

You should see `(cve-env)` appear in your prompt. **Always activate this environment before working on the project.**

To reactivate in future sessions:

```bash
source ~/cve-env/bin/activate
```

---

## Step 4 — Install Dependencies

With the venv active, install PyTorch's **CPU-only** build first (avoids pulling several GBs of unnecessary CUDA packages):

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
```

Then install the remaining packages, pinning Transformers to the **vulnerable version**:

```bash
pip install "transformers<5.3.0" kernels huggingface_hub
```

Confirm the resolved version:

```bash
pip show transformers
```

Expected output:
```
Name: transformers
Version: 5.2.0   ← must be < 5.3.0
```

Then verify the environment works — open a Python shell:

```bash
python3
```

Run these two lines **separately**:

```python
from transformers import AutoConfig
config = AutoConfig.from_pretrained('gpt2')
```

If it downloads the config and returns without error, your setup is working. Exit with `exit()`.

---

## Step 5 — Set Up Hugging Face Test Accounts

You need **two separate throwaway accounts** — do not use your real HF account for either role.

| Role | Description |
|---|---|
| **Attacker account** | Hosts the private test repo containing the malicious `config.json` |
| **Victim account** | Logged into your Ubuntu environment; runs `from_pretrained()` and triggers the exploit |

1. Create both accounts at [huggingface.com](https://huggingface.com) using spare or temp emails
2. On the **attacker account**, create a new **private** model repository
3. Add the **victim account** as a collaborator on that repo
4. Inside your Ubuntu environment, log in as the **victim account** only:

```bash
huggingface-cli login
```

Paste the victim account's access token when prompted. **Keep the attacker account's token off this machine entirely.**

---

## Step 6 — Set Up the Patched Environment (for Defence Demo)

Create a separate venv with the patched Transformers version for the B3 defence comparison:

```bash
python3 -m venv ~/cve-env-patched
source ~/cve-env-patched/bin/activate
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install "transformers>=5.3.0" huggingface_hub
deactivate
```

Switch between environments as needed:
- **Vulnerable:** `source ~/cve-env/bin/activate`
- **Patched:** `source ~/cve-env-patched/bin/activate`

---

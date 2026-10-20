## Defence Mechanism

### The problem it solves

When a user loads a model from Hugging Face, the library reads a settings file called `config.json`. In vulnerable versions of `transformers`, an attacker can put a special value in this file, for example `"attn_implementation": "attacker-org/evil-kernel"`. The library then downloads code from the attacker's repository and runs it on the user's machine.

The built-in safety switch, `trust_remote_code=False`, does not stop this. That switch only guards one way of running outside code, and this attack uses a different way. Our defence therefore does not rely on a single switch. It checks every input that can affect loading *before* the model is loaded.

### How it works

The defence is a function called `safe_from_pretrained()`. Users call it in place of the normal `from_pretrained()`. It runs four checks in order. If any check fails, the model is not loaded and the user gets an error that explains why.

**Check 1: Is the library patched?**
The function first checks that `transformers` is version 5.3.0 or newer, the version that fixes the bug. It checks this in two ways: the version recorded at install time, and the version of the code that actually runs. The two can differ when a computer has several copies of the library installed. If either one is old, loading is refused.
This check is the real fix. The next checks are backups for systems that cannot upgrade yet. On an old version, they only run if the user deliberately turns on a lab-only option (`allow_vulnerable_env=True`).

**Check 2: Is the risky add-on installed?**
The attack needs an add-on package called `kernels`, which is what downloads and runs code from the Hub. On an old version, if `kernels` is installed, loading is refused. Without this package, the attack cannot work, whatever the config file says.

**Check 3: Is the config file safe?**
The function reads the model's config files and looks for dangerous settings. It never runs anything during this step:

- It only downloads the small settings files, never the model weights or any code files.
- It looks up the exact version (commit) of the model repository once, then checks *and* loads that same version. Without this, an attacker could swap in a malicious file between the check and the load.
- It flags any attention setting that is not one of the known safe values (`eager`, `sdpa`, `flash_attention_2`, `flash_attention_3`, `flex_attention`). A value like `attacker-org/evil-kernel` is blocked, even when it is hidden inside a nested section of the file.
- It also flags other settings known to point at custom code, such as `auto_map`.
- It rejects settings passed in directly by the caller (`config=`), because those would skip the check.

If a person has reviewed the warnings and trusts the model, they can override this check with `accept_findings=True`.

**Check 4: Remote code is always switched off.**
The function always sets `trust_remote_code=False`, even if the caller asked for `True`. This is good practice, but it does **not** protect against this vulnerability, because the attack gets around this switch.

### Summary of protection

| Situation | What stops the attack |
|---|---|
| Library is updated (5.3.0 or newer) | Check 1, the real fix |
| Old library, `kernels` add-on installed | Check 2 |
| Old library, dangerous value in config | Check 3 |
| Model files swapped after checking | Check 3 (same version is checked and loaded) |

### Testing

We tested the defence with harmless fake config files that contain attack-shaped values but cannot do anything. Before the improvements, values such as `attacker-org/evil-kernel` passed the scan. After them, every such case was blocked. 52 automated tests cover all four checks, including the fixed-version download behaviour.

### Limitations

Check 3 works from a list of known dangerous patterns. It cannot catch a new attack it does not know about. The checks lower the risk on an old version but cannot remove it. **Upgrading to `transformers` 5.3.0 or newer is the only complete fix.**

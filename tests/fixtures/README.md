# Test fixtures

Static JSON used to verify the **detection** layer. These files exist only so the
scanner has something to find; they are **inert**:

- They contain no executable code.
- They are **never loaded** by `transformers` and are never passed to
  `from_pretrained`. The test suite parses them only with the config scanner,
  which reads JSON and inspects keys/values — it imports nothing and runs nothing.
- The string values in `flagged/config.json` (e.g.
  `INERT_TEST_PLACEHOLDER.not_a_real_module:does_not_exist`) point at modules that
  do not exist. They are shaped to match the scanner's value patterns so the
  detector can be tested; they are not functional references and cannot execute.

| Fixture | Purpose | Expected scan result |
|---|---|---|
| `benign/config.json` | A normal GPT-2-style config (plain hyperparameters only) | No findings |
| `flagged/config.json` | Carries the field *names* implicated in CVE-2026-4372 plus the documented custom-code field, with inert placeholder values | At least one high-severity finding, including the `_attn_implementation_internal` key |

This mirrors the EICAR convention for antivirus tests: an inert sample that a
detector must flag, carrying none of the capability of the real thing.

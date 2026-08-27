# SD-JWT ZK protocol contract

This repository is a protocol contract and deterministic test-vector foundation
for a future ZK verifier. It intentionally contains no production prover or
Swiss-conformance claim. The initial relation is a flat, restricted MVP; full
Swiss disclosure processing and private status verification are planned later.

Run all offline checks with:

```sh
python3 -m unittest discover -s tests -v
```

Regenerate/validate the deterministic fixture material with:

```sh
python3 scripts/generate_fixtures.py --check
python3 scripts/verify_es256_fixtures.py
python3 scripts/check_references.py
python3 scripts/validate_mermaid.py
```

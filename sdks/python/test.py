from pii_shield import PiiShield, PiiShieldConfig
import json
import os
import sys

def run_parity():
    """Cross-entrypoint parity: assert the Python SDK reproduces the shared
    golden generated from the Go scanner. See sdks/parity/cases.json and
    sdks/parity/parity_test.go (issue #48). The PiiShieldConfig dataclass fields
    are snake_case and match the golden's config keys directly."""
    cases_path = os.path.join(os.path.dirname(__file__), "..", "parity", "cases.json")
    with open(cases_path, "r", encoding="utf-8") as fh:
        cases = json.load(fh)

    ok = True
    for tc in cases:
        cfg = PiiShieldConfig(**tc["config"])
        shield = PiiShield(config=cfg, wasm_path="../../pii-shield-wasi.wasm")
        got = shield.redact(tc["input"])
        if got != tc["expected"]:
            print(f"PARITY FAIL [{tc['name']}]\n  input:    {tc['input']!r}\n  expected: {tc['expected']!r}\n  got:      {got!r}")
            ok = False
        else:
            print(f"parity ok: {tc['name']}")
    return ok

def run_no_salt_check():
    """Without a salt each instance draws its own random one, so the same value
    gets a different tag in each, and never the tag of the old fixed default."""
    text = "password=SuperSecretValue123"
    a = PiiShield(config=PiiShieldConfig(), wasm_path="../../pii-shield-wasi.wasm").redact(text)
    b = PiiShield(config=PiiShieldConfig(), wasm_path="../../pii-shield-wasi.wasm").redact(text)
    old_tag = "password=[HIDDEN:8836e2]"
    ok = a.startswith("password=[HIDDEN:") and a != b and old_tag not in (a, b)
    if ok:
        print("no-salt ok: random per instance")
    else:
        print(f"NO-SALT FAIL: expected two different random tags, got {a!r} and {b!r}")
    return ok

def main():
    try:
        print("Loading WASM module in Python...")
        cfg = PiiShieldConfig(confidence_score=1.5, fail_policy="open")
        shield = PiiShield(config=cfg, wasm_path="../../pii-shield-wasi.wasm")

        test_strings = [
            'User registered with token: 123e4567-e89b-12d3-a456-426614174000',
            'Just a random UUID: 123e4567-e89b-12d3-a456-426614174000',
            'Password is mySuperSecretPassword123!',
            'Invalid payload JSON {}'
        ]

        passed = True
        for txt in test_strings:
            print(f"Original: {txt}")
            redacted = shield.redact(txt)
            print(f"Redacted: {redacted}\n---")
            if "FATAL_ERROR" in redacted:
                passed = False

        if not run_parity():
            passed = False
        if not run_no_salt_check():
            passed = False

        if passed:
            print("SUCCESS")
        else:
            print("FAILED")
            sys.exit(1)
            
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from hashlib import sha256
from pathlib import Path

path = Path(".cursor/rules/ponytail.mdc")
expected = "e5b63124834c65e73208e8349e6cfd90b56757646c576a393932a01adc63940f"

if not path.is_file():
    raise SystemExit("Required Ponytail Cursor rule is missing: .cursor/rules/ponytail.mdc")

data = path.read_bytes().replace(b"\r\n", b"\n")
actual = sha256(data).hexdigest()
if actual != expected:
    raise SystemExit(
        "Required Ponytail Cursor rule changed unexpectedly. "
        "Review the upstream/license/security implications and update the pinned hash intentionally."
    )

print("Ponytail Cursor rule present and pinned.")

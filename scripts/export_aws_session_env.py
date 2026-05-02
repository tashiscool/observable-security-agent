#!/usr/bin/env python3
"""Emit bash `export AWS_*=...` lines from a session creds JSON (STS get-session-token / assume-role output)."""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: export_aws_session_env.py <creds.json>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    if not path.is_file():
        print(f"not found: {path}", file=sys.stderr)
        return 2
    data = json.loads(path.read_text(encoding="utf-8"))
    creds = data.get("Credentials") or data
    ak = creds.get("AccessKeyId") or ""
    sk = creds.get("SecretAccessKey") or ""
    st = creds.get("SessionToken") or ""
    if not ak or not sk:
        print("missing AccessKeyId / SecretAccessKey in JSON", file=sys.stderr)
        return 2
    for name, val in (
        ("AWS_ACCESS_KEY_ID", ak),
        ("AWS_SECRET_ACCESS_KEY", sk),
        ("AWS_SESSION_TOKEN", st),
    ):
        if val:
            print(f"export {name}={shlex.quote(val)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

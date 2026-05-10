"""Dump failed Playwright tests from a JUnit XML report to Markdown.

Used by the CI ``Post failing test list as PR comment`` step. Annotations
on private-repo check runs are auth-gated, so a plain PR comment is the
simplest universal channel.

Usage: ``python3 dump_failed_tests.py <path/to/junit.xml>``
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: dump_failed_tests.py <junit.xml>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    if not path.exists():
        print(f"(no such file: {path})", file=sys.stderr)
        return 0
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        print(f"(failed to parse {path}: {exc})", file=sys.stderr)
        return 0

    rows: list[str] = []
    for tc in tree.iter("testcase"):
        fail = tc.find("failure")
        err = tc.find("error")
        if fail is None and err is None:
            continue
        cls = tc.get("classname", "?")
        name = tc.get("name", "?")
        node = fail if fail is not None else err
        msg = ""
        if node is not None and node.get("message"):
            msg = node.get("message", "").splitlines()[0][:200]
        rows.append(f"- `{cls}` :: `{name}`\n  {msg}")

    if not rows:
        # Empty stdout signals "nothing to post"; the caller's `-s` check
        # short-circuits in that case.
        return 0

    print(f"### Failed E2E tests ({len(rows)})\n")
    print("\n".join(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

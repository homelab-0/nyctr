"""Fail when a test skipped for want of a PostgreSQL server, and say how many PostgreSQL cases ran.

Read the JUnit file of an API run made with NYCTR_TEST_POSTGRES set. A case that skips because
SQLite has one writer, or for any other reason, is left alone; only a skip whose message names
NYCTR_TEST_POSTGRES counts as a PostgreSQL case that did not run.
"""

from __future__ import annotations

import os
import sys
import xml.etree.ElementTree as ET

VARIABLE = "NYCTR_TEST_POSTGRES"


def check(path: str) -> tuple[list[str], int]:
    """Return the cases that skipped for want of PostgreSQL, and how many with postgresql in their name passed."""
    skipped, ran = [], 0
    for case in ET.parse(path).getroot().iter("testcase"):
        name = f"{case.get('classname')}::{case.get('name')}"
        skip = case.find("skipped")
        if skip is not None:
            if VARIABLE in (skip.get("message") or ""):
                skipped.append(name)
        elif case.find("failure") is None and case.find("error") is None and "postgresql" in name:
            ran += 1
    return skipped, ran


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: postgres_cases.py <junit.xml>", file=sys.stderr)
        return 2
    skipped, ran = check(argv[1])
    lines = [f"Cases named for PostgreSQL that passed: {ran}", f"Skipped for want of PostgreSQL: {len(skipped)}"]
    lines += [f"- {name}" for name in skipped]
    print("\n".join(lines))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as out:
            out.write("### PostgreSQL 17 cases\n\n" + "\n".join(lines) + "\n")
    if not ran:
        print("No case named for PostgreSQL ran: the server did not reach the tests.", file=sys.stderr)
        return 1
    if skipped:
        print(f"{VARIABLE} is set in this job, so no case may skip for want of it.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

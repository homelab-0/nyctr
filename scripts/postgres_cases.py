"""Check the cases marked `postgres` in an API run made with NYCTR_TEST_POSTGRES set.

Every test that needs a PostgreSQL server carries the `postgres` marker, and the test configuration
writes it into the JUnit file. This fails when any marked case did not pass (skipped for any reason,
failed or errored), or when fewer than the expected minimum of them ran at all, and it puts the
exact count of marked cases that passed in the job summary.
"""

from __future__ import annotations

import argparse
import os
import sys
import xml.etree.ElementTree as ET


def check(path: str) -> tuple[list[str], int]:
    """Return the marked cases that did not pass, and how many marked cases passed."""
    not_passed, passed = [], 0
    for case in ET.parse(path).getroot().iter("testcase"):
        if not any(p.get("name") == "postgres" for p in case.iter("property")):
            continue
        name = f"{case.get('classname')}::{case.get('name')}"
        if case.find("skipped") is not None:
            not_passed.append(f"{name} (skipped)")
        elif case.find("failure") is not None or case.find("error") is not None:
            not_passed.append(f"{name} (did not pass)")
        else:
            passed += 1
    return not_passed, passed


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("junit")
    parser.add_argument("--minimum", type=int, required=True, help="fewest marked cases that must have passed")
    arguments = parser.parse_args(argv[1:])
    not_passed, passed = check(arguments.junit)
    lines = [f"Cases marked postgres that passed: {passed} (at least {arguments.minimum} expected)",
             f"Marked cases that did not pass: {len(not_passed)}"]
    lines += [f"- {name}" for name in not_passed]
    print("\n".join(lines))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as out:
            out.write("### PostgreSQL 17 cases\n\n" + "\n".join(lines) + "\n")
    if not_passed:
        print("A case marked postgres may not skip: the server is part of this job.", file=sys.stderr)
        return 1
    if passed < arguments.minimum:
        print("Fewer marked cases ran than expected: a test lost its marker or the server did not reach it. "
              "Raise the minimum only when cases were added.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

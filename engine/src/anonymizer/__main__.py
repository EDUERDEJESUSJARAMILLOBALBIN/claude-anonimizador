"""Engine CLI, to use it outside Claude.

    python -m anonymizer profile <file> [--strict]
    python -m anonymizer apply <file> [--plan plan.json] [--output path]

It only prints validated profiles and summaries. Errors come out generic, because openpyxl, csv
and yaml messages often include the value that failed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import engine
from .adapters import UnsupportedFormat
from .profile import InvalidProfile
from .structured import InvalidFile


def main() -> None:
    parser = argparse.ArgumentParser(prog="anonymizer")
    commands = parser.add_subparsers(dest="command", required=True)
    profile = commands.add_parser("profile", help="a value-free profile of the columns")
    profile.add_argument("file", type=Path)
    profile.add_argument("--strict", action="store_true", help="also hide sheet and column names")
    apply = commands.add_parser("apply", help="write the anonymized copy and verify it")
    apply.add_argument("file", type=Path)
    apply.add_argument("--plan", type=Path, help='JSON {"t1": {"c2": "pseudonymize"}}; without a plan the suggestions apply')
    apply.add_argument("--output", type=Path)
    apply.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    try:
        if args.command == "profile":
            print(engine.profile(args.file, args.strict))
        else:
            plan = json.loads(args.plan.read_text()) if args.plan else {}
            print(json.dumps(engine.apply(args.file, plan, args.output, args.strict), ensure_ascii=False))
    except UnsupportedFormat as error:
        sys.exit(f"format not supported yet: {error}")
    except (engine.InvalidPlan, InvalidFile) as error:
        sys.exit(str(error))
    except InvalidProfile as error:
        sys.exit(f"the profile broke the contract ({str(error).split(':')[0]}); use --strict")
    except Exception as error:  # noqa: BLE001 — the original message may carry values
        sys.exit(f"the file could not be processed ({type(error).__name__})")


if __name__ == "__main__":
    main()

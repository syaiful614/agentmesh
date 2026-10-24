"""Command line: redteam, show, verify."""

from __future__ import annotations

import argparse
import json
import sys

from .journal import Journal
from .redteam import run_all


def _redteam(args: argparse.Namespace) -> int:
    results = run_all(journal_dir=args.journal_dir)
    for r in results:
        print(f"[{'PASS' if r.passed else 'FAIL'}] {r.name:<40} -> {r.status:<9} {r.detail}")
    ok = sum(r.passed for r in results)
    print(f"\n{ok}/{len(results)} attack scenarios contained")
    return 0 if ok == len(results) else 1


def _show(args: argparse.Namespace) -> int:
    for e in Journal(args.path).events():
        text = json.dumps(e["data"], sort_keys=True)
        print(f"{e['seq']:>4} {e['kind']:<18} {text[: args.width]}")
    return 0


def _verify(args: argparse.Namespace) -> int:
    ok, bad = Journal(args.path).verify()
    print("journal intact" if ok else f"journal TAMPERED at event {bad}")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentmesh", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("redteam", help="run the offline attack suite")
    p.add_argument("--journal-dir", help="keep one journal file per scenario here")
    p.set_defaults(fn=_redteam)
    p = sub.add_parser("show", help="print a journal")
    p.add_argument("path")
    p.add_argument("--width", type=int, default=110)
    p.set_defaults(fn=_show)
    p = sub.add_parser("verify", help="check a journal's hash chain")
    p.add_argument("path")
    p.set_defaults(fn=_verify)
    args = parser.parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    sys.exit(main())

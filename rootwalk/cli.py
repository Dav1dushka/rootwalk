"""Command line interface.

    rootwalk example.com            A record, with the path from the root
    rootwalk github.com MX
    rootwalk 8.8.8.8                reverse lookup (PTR)
    rootwalk example.com --json     machine-readable output
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys

from . import __version__
from .message import TYPES, type_name
from .resolver import ResolveError, Resolver, Result, reverse_name


class Style:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def render(result: Result, style: Style) -> str:
    lines = [style(f";; rootwalk {result.name} {type_name(result.qtype)}", "2")]
    if result.from_cache:
        lines.append(style(";; served from cache", "2"))
    rows = [(f"{s.server} ({s.address})", "  " * s.depth + s.question, s) for s in result.trace]
    w_server = max((len(r[0]) for r in rows), default=0)
    w_question = max((len(r[1]) for r in rows), default=0)
    w_outcome = max((len(s.outcome) for s in result.trace), default=0)
    for i, (server, question, s) in enumerate(rows, 1):
        color = "32" if s.outcome.startswith("answer") else "31" if s.outcome in ("NXDOMAIN", "SERVFAIL") else "36"
        outcome = style(f"{s.outcome:<{w_outcome}}", color)
        lines.append(f"{i:>2}  {question:<{w_question}}  {style(server.ljust(w_server), '2')}  {outcome}  "
                     f"{s.ms:>4.0f} ms")
    lines.append("")
    if result.rcode != "NOERROR":
        lines.append(style(f"{result.name} does not exist ({result.rcode})", "31"))
    elif not result.records:
        lines.append(style(f"{result.name} has no {type_name(result.qtype)} records", "33"))
    for r in result.records:
        lines.append(f"{r.name:<32} {r.ttl:>6}  {type_name(r.rtype):<5}  {style(r.text(), '1')}")
    return "\n".join(lines)


def as_json(result: Result) -> str:
    return json.dumps({
        "name": result.name, "type": type_name(result.qtype), "rcode": result.rcode, "cached": result.from_cache,
        "records": [{"name": r.name, "type": type_name(r.rtype), "ttl": r.ttl, "value": r.text()}
                    for r in result.records],
        "trace": [{"depth": s.depth, "server": s.server, "address": s.address, "question": s.question,
                   "outcome": s.outcome, "ms": round(s.ms, 1)} for s in result.trace],
    }, indent=2)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="rootwalk", description="Resolve a name from the DNS root, showing every hop.")
    p.add_argument("name", help="domain name, or an IP address for a reverse lookup")
    p.add_argument("type", nargs="?", default=None, type=str.upper, choices=sorted(TYPES),
                   help="record type (default A)")
    p.add_argument("--json", action="store_true", help="print JSON instead of text")
    p.add_argument("--timeout", type=float, default=2.0, help="seconds to wait for each server (default 2)")
    p.add_argument("--root", action="append", metavar="IP", help="start at this server instead of the root hints")
    p.add_argument("--port", type=int, default=53, help="DNS port (default 53)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"rootwalk {__version__}")
    args = p.parse_args(argv)

    name, qtype = args.name, args.type or "A"
    if _is_ip(name):
        name, qtype = reverse_name(name), args.type or "PTR"

    try:
        roots = [(f"root-{i}", ip) for i, ip in enumerate(args.root, 1)] if args.root else None
        result = Resolver(roots=roots, port=args.port, timeout=args.timeout).resolve(name, qtype)
    except ResolveError as exc:
        print(f"rootwalk: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:  # bad name, e.g. a label longer than 63 bytes
        print(f"rootwalk: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(as_json(result))
    else:
        color = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
        print(render(result, Style(color)))
    return 0 if result.rcode == "NOERROR" else 1


if __name__ == "__main__":
    sys.exit(main())

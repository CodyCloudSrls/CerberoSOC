#!/usr/bin/env python3
"""Validate Mikrotik blocklist.rsc file structure and data quality."""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BLOCKLIST = ROOT / "blocklist.rsc"

HEADER_RE = re.compile(r"^# Generated on ")
ENTRY_RE = re.compile(
    r"^:do \{add address=(?P<ip>[^ ]+) list=(?P<list>[^ ]+) comment=(?P<comment>[^}]+)\} on-error=\{\}$"
)


def main() -> int:
    lines = BLOCKLIST.read_text(encoding="utf-8").splitlines()
    errors: list[str] = []

    if not lines:
        errors.append("blocklist.rsc is empty")
    else:
        if not HEADER_RE.match(lines[0]):
            errors.append("first line should be a generated timestamp comment")
        if len(lines) < 2 or lines[1] != ":do {/ip firewall address-list":
            errors.append("missing Mikrotik address-list preamble on line 2")

    entries = []
    for idx, line in enumerate(lines[2:], start=3):
        if line == "}":
            if idx != len(lines):
                errors.append(f"line {idx}: unexpected closing brace")
            continue
        m = ENTRY_RE.match(line)
        if not m:
            errors.append(f"line {idx}: invalid entry format")
            continue
        ip_raw = m.group("ip")
        try:
            ipaddress.ip_address(ip_raw)
        except ValueError:
            errors.append(f"line {idx}: invalid IP address '{ip_raw}'")
        entries.append((ip_raw, m.group("comment")))

    ip_counts = Counter(ip for ip, _ in entries)
    dupes = {ip: count for ip, count in ip_counts.items() if count > 1}

    if errors:
        print("Validation failed:")
        for e in errors:
            print(f"- {e}")
        return 1

    comments = Counter(comment for _, comment in entries)
    print(f"OK: {len(entries)} entries validated")
    print(f"Unique IPs: {len(ip_counts)}")
    if dupes:
        print(f"Duplicate IPs: {len(dupes)}")
        top = sorted(dupes.items(), key=lambda item: item[1], reverse=True)[:10]
        for ip, count in top:
            print(f"- {ip}: {count} occurrences")
    else:
        print("Duplicate IPs: none")

    print("Comment distribution:")
    for comment, count in comments.most_common():
        print(f"- {comment}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

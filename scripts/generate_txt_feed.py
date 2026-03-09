#!/usr/bin/env python3
"""Generate a vendor-neutral plaintext IP feed from blocklist.rsc."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RSC_PATH = ROOT / "blocklist.rsc"
TXT_PATH = ROOT / "blocklist.txt"

ENTRY_RE = re.compile(r"^:do \{add address=(?P<ip>[^ ]+) list=[^ ]+ comment=[^}]+\} on-error=\{\}$")


def main() -> int:
    ips: list[str] = []

    for line in RSC_PATH.read_text(encoding="utf-8").splitlines():
        m = ENTRY_RE.match(line)
        if m:
            ips.append(m.group("ip"))

    unique_ips = sorted(set(ips), key=lambda ip: tuple(int(o) for o in ip.split(".")))

    header = [
        "# CodyCloud free threat-intel blocklist feed",
        "# One IPv4 address per line",
        "# Source: blocklist.rsc",
        "",
    ]
    TXT_PATH.write_text("\n".join(header + unique_ips) + "\n", encoding="utf-8")

    print(f"Generated {TXT_PATH.name}: {len(unique_ips)} unique IPs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

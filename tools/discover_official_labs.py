#!/usr/bin/env python3
"""Query official vendor advisories and rank real-product lab candidates."""

from __future__ import annotations

import argparse
from pathlib import Path

from cve_hunter.tools.vendor_advisories import (
    discover_official_lab_candidates,
    read_cve_file,
    write_official_lab_report,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--vendors",
        default="oracle,jenkins,tomcat,microsoft",
        help="Comma-separated vendors: oracle, jenkins, tomcat, microsoft",
    )
    parser.add_argument(
        "--max-advisories",
        type=int,
        default=1,
        help="Latest advisories/releases to inspect per source category (default: 1)",
    )
    parser.add_argument("--msrc-month", help="MSRC document alias, for example 2026-Jul")
    parser.add_argument(
        "--historical",
        action="store_true",
        help="Resolve target CVEs through historical vendor indexes",
    )
    parser.add_argument(
        "--cve-file",
        type=Path,
        help="UTF-8 text file containing target CVE IDs",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output/vendor_labs"),
        help="Report directory (default: output/vendor_labs)",
    )
    parser.add_argument("--timeout", type=int, default=30, help="Per-request timeout in seconds")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.max_advisories < 1:
        raise SystemExit("--max-advisories must be at least 1")
    if args.historical and not args.cve_file:
        raise SystemExit("--historical requires --cve-file")
    cve_ids = read_cve_file(args.cve_file) if args.cve_file else set()
    if args.cve_file and not cve_ids:
        raise SystemExit(f"No CVE IDs found in {args.cve_file}")
    vendors = [item.strip() for item in args.vendors.split(",") if item.strip()]
    report = discover_official_lab_candidates(
        vendors=vendors,
        max_advisories=args.max_advisories,
        msrc_month=args.msrc_month,
        historical=args.historical,
        cve_ids=cve_ids,
        timeout=args.timeout,
    )
    json_path, markdown_path = write_official_lab_report(report, args.output_dir)
    readiness: dict[str, int] = {}
    for item in report["candidates"]:
        key = item["lab_readiness"]
        readiness[key] = readiness.get(key, 0) + 1
    print(f"candidates={report['candidate_count']} sources={report['source_count']} errors={len(report['errors'])}")
    print("readiness=" + ", ".join(f"{key}:{value}" for key, value in sorted(readiness.items())))
    if cve_ids:
        print(f"matched_cves={report['matched_cve_count']}/{report['requested_cve_count']}")
    print(json_path)
    print(markdown_path)
    return 0 if report["candidate_count"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

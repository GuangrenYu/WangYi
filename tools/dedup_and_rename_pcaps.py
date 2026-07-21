"""One-time dedup and rename of pcap files in dated directories.

For each CVE in data/cve/pcaps/{2026-07-19,2026-07-20,2026-07-21}/:
- Keep the largest pcap (most data captured)
- Rename to CVE-XXXX-XXXXX.pcap
- Delete duplicates/smaller versions
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PCAP_ROOT = ROOT / "data" / "cve" / "pcaps"
DATED_DIRS = ["2026-07-19", "2026-07-20", "2026-07-21"]


def main() -> None:
    changes: list[str] = []
    deleted: list[str] = []

    for dated in DATED_DIRS:
        dir_path = PCAP_ROOT / dated
        if not dir_path.is_dir():
            print(f"SKIP {dated}: directory not found")
            continue

        # Group pcap files by CVE ID
        cve_files: dict[str, list[Path]] = defaultdict(list)
        for pcap in dir_path.glob("*.pcap"):
            match = re.search(r"CVE-\d{4}-\d{4,}", pcap.stem, re.I)
            if not match:
                print(f"SKIP {pcap.name}: no CVE ID found")
                continue
            cve_id = match.group(0).upper()
            cve_files[cve_id].append(pcap)

        # For each CVE, keep the largest, rename to CVE.pcap, delete the rest
        for cve_id, files in sorted(cve_files.items()):
            if not files:
                continue

            # Sort by size descending
            files_sorted = sorted(files, key=lambda p: p.stat().st_size, reverse=True)
            largest = files_sorted[0]
            target_name = f"{cve_id}.pcap"
            target_path = dir_path / target_name

            # If largest already has the target name, we're done for this CVE
            if largest.name == target_name:
                if len(files) > 1:
                    # Delete the smaller duplicates
                    for dup in files_sorted[1:]:
                        print(f"DELETE {dated}/{dup.name} ({dup.stat().st_size} B, kept {largest.stat().st_size} B)")
                        dup.unlink()
                        deleted.append(f"{dated}/{dup.name}")
                continue

            # Rename largest to target
            if target_path.exists():
                # Target exists (but isn't the largest); compare sizes
                existing_size = target_path.stat().st_size
                incoming_size = largest.stat().st_size
                if incoming_size > existing_size:
                    print(f"REPLACE {dated}/{target_name}: {existing_size} B → {incoming_size} B (from {largest.name})")
                    target_path.unlink()
                    largest.rename(target_path)
                    changes.append(f"{dated}/{largest.name} → {target_name} (replaced smaller)")
                else:
                    print(f"KEEP existing {dated}/{target_name} ({existing_size} B > {incoming_size} B from {largest.name})")
                    largest.unlink()
                    deleted.append(f"{dated}/{largest.name}")
            else:
                print(f"RENAME {dated}/{largest.name} → {target_name} ({largest.stat().st_size} B)")
                largest.rename(target_path)
                changes.append(f"{dated}/{largest.name} → {target_name}")

            # Delete remaining smaller files
            for dup in files_sorted[1:]:
                if dup.exists():
                    print(f"DELETE {dated}/{dup.name} ({dup.stat().st_size} B)")
                    dup.unlink()
                    deleted.append(f"{dated}/{dup.name}")

    print("\n=== SUMMARY ===")
    print(f"Renamed/replaced: {len(changes)}")
    print(f"Deleted: {len(deleted)}")
    if changes:
        print("\nChanges:")
        for ch in changes:
            print(f"  {ch}")
    if deleted:
        print(f"\nDeleted ({len(deleted)} files):")
        for d in deleted[:10]:
            print(f"  {d}")
        if len(deleted) > 10:
            print(f"  ... and {len(deleted) - 10} more")


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    main()

#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Set

DIFF_DIR = Path(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "data",
    "diff-20260320_184000-watchlist_batch_20260317_040811-watchlist_batch_20260318_202935"
))
OUTPUT_PATH = Path(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "baselines", "baseline_plugins.json"))
BACKUP_PATH = Path(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "baselines", "baseline_plugins.json.bak"))
PROGRESS_EVERY = 5_000

SAMPLE_CAPS = {
    "EDITED": 120_000,
    "NEWLY ADDED": 30_000,
}

SITE_PATTERN = re.compile(r"^watchlist_batch_[^/]+/chunk-[^/]+/([^/]+)/")

def log(msg):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()

def extract_sites(original_paths):
    sites = set()
    for path in original_paths:
        match = SITE_PATTERN.match(path)
        if match:
            sites.add(match.group(1))
    return sites

def main():
    if not DIFF_DIR.exists():
        log(f"error: diff directory not found: {DIFF_DIR}")
        return 1

    if OUTPUT_PATH.exists() and not BACKUP_PATH.exists():
        shutil.copy2(OUTPUT_PATH, BACKUP_PATH)
        log(f"[backup] {OUTPUT_PATH} -> {BACKUP_PATH}")

    all_sites = set()
    plugin_sites: defaultdict = defaultdict(set)

    n_sigs = 0
    n_no_meta = 0
    n_no_sites = 0
    last_report = 0
    start = time.time()

    for subdir in ("EDITED", "NEWLY ADDED"):
        root = DIFF_DIR / subdir
        if not root.exists():
            log(f"[warn] missing {root}")
            continue

        cap = SAMPLE_CAPS.get(subdir, 0)
        cap_label = f"{cap:,}" if cap else "unlimited"
        log(f"[scan] {subdir}/  (cap={cap_label})")

        visited_here = 0
        for sig_dir in root.iterdir():
            if cap and visited_here >= cap:
                break
            visited_here += 1
            meta_file = sig_dir / "metadata.json"
            try:
                with open(meta_file, "r") as fh:
                    meta = json.load(fh)
            except FileNotFoundError:
                n_no_meta += 1
                continue
            except (json.JSONDecodeError, OSError):
                n_no_meta += 1
                continue

            sig_sites = extract_sites(meta.get("original_paths", ()))
            if not sig_sites:
                n_no_sites += 1
                continue

            all_sites.update(sig_sites)
            n_sigs += 1

            plugin_info = meta.get("plugin_info", {}) or {}
            for comp_name in plugin_info:
                plugin_sites[comp_name].update(sig_sites)

            theme_info = meta.get("theme_info", {}) or {}
            for comp_name in theme_info:
                plugin_sites[f"theme:{comp_name}"].update(sig_sites)

            if n_sigs - last_report >= PROGRESS_EVERY:
                elapsed = time.time() - start
                rate = n_sigs / elapsed if elapsed > 0 else 0
                log(
                    f"  [{subdir}] {n_sigs:>9,} sigs   "
                    f"{len(all_sites):>9,} unique sites   "
                    f"{len(plugin_sites):>6,} plugins   "
                    f"{elapsed:6.1f}s  ({rate:.0f}/s)"
                )
                last_report = n_sigs

    plugin_counts = {slug: len(sites) for slug, sites in plugin_sites.items()}
    total_sites = len(all_sites)

    output = {
        "total_sites": total_sites,
        "source": (
            f"diff {DIFF_DIR.name} full-population, unique-site dedup "
            f"({n_sigs:,} signatures)"
        ),
        "plugins": plugin_counts,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w") as fh:
        json.dump(output, fh, indent=2, sort_keys=True)

    elapsed = time.time() - start
    log("")
    log(f"[done] {OUTPUT_PATH}")
    log(f"  signatures read       : {n_sigs:>10,}")
    log(f"  signatures no sites   : {n_no_sites:>10,}")
    log(f"  dirs missing metadata : {n_no_meta:>10,}")
    log(f"  unique sites          : {total_sites:>10,}")
    log(f"  unique plugins/themes : {len(plugin_counts):>10,}")
    log(f"  elapsed               : {elapsed:>10.1f}s")

    log("")
    log("[top 25 plugins by site count]")
    for slug, count in sorted(plugin_counts.items(), key=lambda kv: -kv[1])[:25]:
        pct = 100.0 * count / total_sites if total_sites else 0.0
        log(f"  {slug:<48} {count:>8,}  ({pct:5.2f}%)")

    return 0

if __name__ == "__main__":
    sys.exit(main())

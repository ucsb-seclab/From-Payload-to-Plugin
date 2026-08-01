#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set

PLUGIN_SVN_URL = "https://plugins.svn.wordpress.org"
DEFAULT_RELEASE_COUNT = 5
DEFAULT_WORKERS = 10
STABLE_TAG_RE = re.compile(r"^\d+(?:\.\d+)*$")

def version_sort_key(value):
    parts = [part for part in value.split(".") if part]
    key = []
    for part in parts:
        if part.isdigit():
            key.append(int(part))
        else:
            key.append(0)
    return key

def sort_tags(tags):
    valid = [tag for tag in tags if isinstance(tag, str) and tag]
    return sorted(set(valid), key=version_sort_key)

def sort_hashes(hashes):
    valid = [hash_value for hash_value in hashes if isinstance(hash_value, str) and hash_value]
    return sorted(set(valid))

def parse_args(argv):
    parser = argparse.ArgumentParser(description="Compute JS SRI hashes for WordPress.org plugins.")
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Process only the first N plugin slugs (default: 0, meaning every slug)",
    )
    parser.add_argument(
        "--release-count",
        type=int,
        default=DEFAULT_RELEASE_COUNT,
        help=f"Number of most recent tags per plugin to scan (default: {DEFAULT_RELEASE_COUNT})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to write the resulting JSON payload; stdout when omitted",
    )
    parser.add_argument(
        "--checkpoint-interval",
        type=int,
        default=1000,
        help=(
            "When --output is set, write incremental checkpoints after this many processed plugins "
            "(default: 1000; 0 disables checkpoints)"
        ),
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"Maximum number of concurrent plugin jobs (default: {DEFAULT_WORKERS})",
    )
    return parser.parse_args(argv[1:])

class TermColors:
    BLUE = "\033[34m"
    GREEN = "\033[32m"
    CYAN = "\033[36m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    RESET = "\033[0m"

def _log(message, *, stream, color = None):
    use_color = color and hasattr(stream, "isatty") and stream.isatty()
    if use_color:
        print(f"{color}{message}{TermColors.RESET}", file=stream)
    else:
        print(message, file=stream)

def log_info(message):
    _log(message, stream=sys.stdout, color=TermColors.BLUE)

def log_success(message):
    _log(message, stream=sys.stdout, color=TermColors.GREEN)

def log_skip(message):
    _log(message, stream=sys.stdout, color=TermColors.CYAN)

def log_warn(message):
    _log(message, stream=sys.stderr, color=TermColors.YELLOW)

def log_error(message):
    _log(message, stream=sys.stderr, color=TermColors.RED)

def load_existing_results(path):
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        log_warn(f"[WARN] Failed to read existing results from {path}: {exc}")
        return {}
    if not isinstance(data, dict):
        log_warn(f"[WARN] Existing results in {path} are not a JSON object")
        return {}
    normalized = {}
    for slug, value in data.items():
        if not isinstance(slug, str) or not isinstance(value, dict):
            continue
        tags = value.get("tags")
        hashes = value.get("hashes")
        if not isinstance(tags, list) or not isinstance(hashes, list):
            continue
        normalized[slug] = {
            "tags": sort_tags(tags),
            "hashes": sort_hashes(hashes),
        }
    return normalized

def _run_svn_command(args, desc, capture_output = True):
    if capture_output:
        return subprocess.run(args, check=True, capture_output=True, text=True)
    return subprocess.run(args, check=True)

def fetch_plugin_slugs(limit):
    result = _run_svn_command(["svn", "ls", PLUGIN_SVN_URL], f"svn ls {PLUGIN_SVN_URL}")
    slugs = [line.strip().rstrip("/") for line in result.stdout.splitlines() if line.strip()]
    slugs = sorted(slug for slug in slugs if slug)
    if limit and limit > 0:
        return slugs[:limit]
    return slugs

def list_plugin_tags(plugin, release_count):
    url = f"{PLUGIN_SVN_URL}/{plugin}/tags"
    result = _run_svn_command(["svn", "ls", url], f"svn ls {url}")
    entries = [line.strip().rstrip("/") for line in result.stdout.splitlines() if line.strip()]
    stable = sort_tags(entry for entry in entries if STABLE_TAG_RE.match(entry))
    if release_count > 0:
        stable = stable[-release_count:]
    return stable

def export_plugin_tag(plugin, tag, destination):
    if destination.exists():
        shutil.rmtree(destination)
    url = f"{PLUGIN_SVN_URL}/{plugin}/tags/{tag}"
    _run_svn_command(["svn", "export", "-q", url, str(destination)], f"svn export {url}", capture_output=False)

def iter_js_files(root):
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            if filename.lower().endswith(".js"):
                yield Path(dirpath) / filename

def compute_sri(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    encoded = base64.b64encode(digest.digest()).decode("ascii")
    return f"sha256-{encoded}"

def process_plugin(plugin, tags, working_dir):
    if not tags:
        raise RuntimeError("no tags selected for processing")

    hashes = set()
    processed_tags = []
    for tag in tags:
        export_path = working_dir / f"{plugin}-{tag}"
        export_plugin_tag(plugin, tag, export_path)
        for js_file in iter_js_files(export_path):
            hashes.add(compute_sri(js_file))
        shutil.rmtree(export_path, ignore_errors=True)
        processed_tags.append(tag)

    if not hashes:
        raise RuntimeError("no JavaScript files detected in exported tags")

    return {
        "tags": sort_tags(processed_tags),
        "hashes": sort_hashes(hashes),
    }

def _write_checkpoint(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))

def generate_hashes(
    limit,
    release_count,
    checkpoint_path = None,
    checkpoint_interval = 1000,
    existing_results = None,
    worker_count = DEFAULT_WORKERS,
):
    slugs = fetch_plugin_slugs(limit)
    if not slugs:
        raise RuntimeError("No plugin slugs found at plugins.svn.wordpress.org")

    base_results = existing_results or {}
    results = {
        slug: {"tags": list(value.get("tags", [])), "hashes": list(value.get("hashes", []))}
        for slug, value in base_results.items()
    }
    total = len(slugs)
    already_processed = len(results)
    if already_processed:
        log_info(f"[INFO] Loaded {already_processed} plugin entries from existing results.")
    processed_counter = 0
    with tempfile.TemporaryDirectory(prefix="plugins-js-") as tmp_dir_raw:
        tmp_dir = Path(tmp_dir_raw)
        with ThreadPoolExecutor(max_workers=worker_count or 1) as executor:
            future_to_meta = {}
            for idx, plugin in enumerate(slugs, start=1):
                try:
                    tags = list_plugin_tags(plugin, release_count)
                except subprocess.CalledProcessError as exc:
                    log_warn(f"[WARN] ({idx}/{total}) {plugin}: svn command failed ({exc})")
                    continue
                if not tags:
                    log_skip(f"[SKIP] ({idx}/{total}) {plugin}: no stable tags found")
                    continue
                existing_entry = results.get(plugin)
                known_tags = set(existing_entry.get("tags", [])) if existing_entry else set()
                tags_to_process = [tag for tag in tags if tag not in known_tags]
                if not tags_to_process:
                    log_skip(f"[SKIP] ({idx}/{total}) {plugin}: already processed latest tags")
                    continue
                future = executor.submit(process_plugin, plugin, tags_to_process, tmp_dir)
                future_to_meta[future] = (idx, plugin)

            if not future_to_meta:
                return results

            for future in as_completed(future_to_meta):
                idx, plugin = future_to_meta[future]
                try:
                    plugin_result = future.result()
                except subprocess.CalledProcessError as exc:
                    log_warn(f"[WARN] ({idx}/{total}) {plugin}: svn command failed ({exc})")
                    plugin_result = None
                except RuntimeError as exc:
                    log_warn(f"[WARN] ({idx}/{total}) {plugin}: {exc}")
                    plugin_result = None
                else:
                    existing_entry = results.get(plugin)
                    existing_tags = existing_entry.get("tags", []) if existing_entry else []
                    existing_hashes = existing_entry.get("hashes", []) if existing_entry else []
                    merged_tags = sort_tags([*existing_tags, *plugin_result["tags"]])
                    merged_hashes = sort_hashes([*existing_hashes, *plugin_result["hashes"]])
                    results[plugin] = {"tags": merged_tags, "hashes": merged_hashes}
                    hash_count = len(plugin_result["hashes"])
                    tags = ", ".join(plugin_result["tags"])
                    log_success(f"[HASH] ({idx}/{total}) {plugin}: {hash_count} unique hashes from tags {tags}")

                processed_counter += 1
                if checkpoint_path and checkpoint_interval > 0 and processed_counter % checkpoint_interval == 0:
                    _write_checkpoint(checkpoint_path, results)
                    log_info(
                        f"[INFO] Checkpoint: wrote {len(results)} plugin entries "
                        f"after processing {processed_counter} plugins to {checkpoint_path}"
                    )
    return results

def main(argv):
    args = parse_args(argv)
    if args.limit < 0:
        log_error("Limit cannot be negative")
        sys.exit(1)
    if args.release_count <= 0:
        log_error("Release count must be positive")
        sys.exit(1)
    if args.checkpoint_interval < 0:
        log_error("Checkpoint interval cannot be negative")
        sys.exit(1)
    if args.workers <= 0:
        log_error("Workers must be positive")
        sys.exit(1)

    checkpoint_interval = 0
    existing_results = {}
    if args.output:
        existing_results = load_existing_results(args.output)
        if args.checkpoint_interval != 0:
            checkpoint_path = args.output
            checkpoint_interval = args.checkpoint_interval or 1000
        else:
            checkpoint_path = None
    else:
        checkpoint_path = None

    try:
        hashes = generate_hashes(
            args.limit,
            args.release_count,
            checkpoint_path=checkpoint_path,
            checkpoint_interval=checkpoint_interval,
            existing_results=existing_results,
            worker_count=args.workers,
        )
    except subprocess.CalledProcessError as exc:
        log_error(f"svn command failed: {exc}")
        sys.exit(2)
    except RuntimeError as exc:
        log_error(str(exc))
        sys.exit(3)

    if args.output:
        args.output.write_text(json.dumps(hashes, indent=2))
        log_info(f"[INFO] Wrote data for {len(hashes)} plugin(s) to {args.output}")
    else:
        json.dump(hashes, sys.stdout, indent=2)
        print()

if __name__ == "__main__":
    main(sys.argv)

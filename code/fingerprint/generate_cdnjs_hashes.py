#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

CDNJS_API = "https://api.cdnjs.com/libraries"
CDNJS_DOWNLOAD = "https://cdnjs.cloudflare.com/ajax/libs/{library}/{version}/{filename}"

def fetch_json(url: str):
    with urlopen(url) as response:
        return json.load(response)

def version_sort_key(version: str):
    parts = re.split(r"(\d+)", version)
    key: List[Tuple[int, Any]] = []
    for part in parts:
        if not part:
            continue
        if part.isdigit():
            key.append((0, int(part)))
        else:
            key.append((1, part))
    return key

def get_library_listing(limit: int, page: int = 1):
    params = f"?fields=name,filename&limit={limit}&page={page}"
    data = fetch_json(f"{CDNJS_API}{params}")
    results = data.get("results", [])
    return {entry["name"]: entry.get("filename") for entry in results if entry.get("name")}

def get_library_versions(name: str, version_count: int, file_override: Optional[str]):
    url = f"{CDNJS_API}/{name}?fields=versions,filename"
    data = fetch_json(url)
    filename = file_override or data.get("filename")
    versions = data.get("versions") or []
    versions = sorted(set(versions), key=version_sort_key)
    if version_count > 0:
        versions = versions[-version_count:]
    return versions, filename

def compute_sri(path: Path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return f"sha256-{base64.b64encode(digest.digest()).decode('ascii')}"

def download_file(url: str, destination: Path):
    with urlopen(url) as response:
        data = response.read()
    destination.write_bytes(data)

def sort_version_map(version_map: Dict[str, str]):
    return dict(sorted(version_map.items(), key=lambda item: version_sort_key(item[0])))

def load_existing_hashes(path: Path):
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        print(f"[WARN] Failed to load {path}: {exc}", file=sys.stderr)
        return {}
    if not isinstance(data, dict):
        print(f"[WARN] Existing hash file {path} is not a JSON object", file=sys.stderr)
        return {}
    normalized: Dict[str, Dict[str, str]] = {}
    for library, versions in data.items():
        if not isinstance(library, str) or not isinstance(versions, dict):
            continue
        normalized[library] = {str(version): str(hash_value) for version, hash_value in versions.items()}
    return normalized

def merge_hashes(
    existing: Dict[str, Dict[str, str]], updates: Dict[str, Dict[str, str]]
):
    merged: Dict[str, Dict[str, str]] = {library: dict(versions) for library, versions in existing.items()}
    for library, versions in updates.items():
        current = merged.setdefault(library, {})
        current.update(versions)
        merged[library] = sort_version_map(current)
    return merged

def process_library(
    name: str, filename: str, version_count: int, known_versions: Optional[Set[str]] = None
):
    versions, resolved_filename = get_library_versions(name, version_count, filename)
    if not versions or not resolved_filename:
        return {}
    if known_versions:
        versions = [version for version in versions if version not in known_versions]
        if not versions:
            print(f"[INFO] {name} already up to date", file=sys.stderr)
            return {}

    hashes: Dict[str, str] = {}
    temp_dir = Path(".cdnjs-cache")
    temp_dir.mkdir(exist_ok=True)

    for version in versions:
        url = CDNJS_DOWNLOAD.format(library=name, version=version, filename=resolved_filename)
        target = temp_dir / f"{name}-{version}.js"
        try:
            download_file(url, target)
        except (URLError, HTTPError, OSError) as exc:
            print(f"[WARN] Failed to download {url}: {exc}", file=sys.stderr)
            continue
        hashes[version] = compute_sri(target)
    return hashes

def generate_hashes(
    limit: int, versions: int, known_hashes: Optional[Dict[str, Dict[str, str]]] = None
):
    libraries = get_library_listing(limit)
    results: Dict[str, Dict[str, str]] = {}
    total = len(libraries)
    for idx, (name, filename) in enumerate(libraries.items(), start=1):
        print(f"[INFO] ({idx}/{total}) Processing {name}")
        known_versions: Optional[Set[str]] = None
        if known_hashes and name in known_hashes:
            known_versions = set(known_hashes.get(name, {}))
        try:
            hashes = process_library(name, filename, versions, known_versions)
        except (URLError, HTTPError, OSError, ValueError) as exc:
            print(f"[WARN] Skipping {name}: {exc}", file=sys.stderr)
            continue
        if hashes:
            results[name] = hashes
    return results

def parse_args(argv: Sequence[str]):
    parser = argparse.ArgumentParser(description="Generate SRI hashes for CDNJS libraries.")
    parser.add_argument("--limit", type=int, default=25, help="Number of libraries to fetch (default: 25)")
    parser.add_argument(
        "--versions",
        type=int,
        default=4,
        help="Number of recent versions per library to hash (default: 4)",
    )
    parser.add_argument("--output", type=Path, help="Optional JSON output path")
    return parser.parse_args(argv[1:])

def main(argv: Sequence[str]):
    args = parse_args(argv)
    if args.limit <= 0:
        print("Limit must be positive", file=sys.stderr)
        sys.exit(1)
    if args.versions <= 0:
        print("Versions must be positive", file=sys.stderr)
        sys.exit(1)

    existing_hashes: Dict[str, Dict[str, str]] = {}
    if args.output:
        existing_hashes = load_existing_hashes(args.output)

    hashes = generate_hashes(args.limit, args.versions, existing_hashes or None)
    if args.output:
        merged_hashes = merge_hashes(existing_hashes, hashes)
        if merged_hashes == existing_hashes:
            print(f"[INFO] No new versions detected. {args.output} unchanged.")
            return
        args.output.write_text(json.dumps(merged_hashes, indent=2))
        print(f"[INFO] Wrote {len(merged_hashes)} libraries to {args.output}")
    else:
        json.dump(hashes, sys.stdout, indent=2)
        print()

if __name__ == "__main__":
    main(sys.argv)

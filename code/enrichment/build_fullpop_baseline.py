#!/usr/bin/env python3

import json
import os
import re
import sys
import multiprocessing as mp
from collections import Counter

CRAWL_ROOT = os.environ.get("CRAWL_ROOT", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "crawls", "watchlist_batch_20260318_202935"))
HOST_ALLOWLIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "baselines", "unique_hosts.txt")
OUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "baselines", "baseline_plugins_fullpop.json")

_HOST_RE = re.compile(r"^[a-z0-9.\-]+$")

def normalize_host(h: str) -> str:
    if not h:
        return ""
    h = h.strip().lower()
    if h.startswith("http://"):
        h = h[7:]
    elif h.startswith("https://"):
        h = h[8:]
    h = h.split("/", 1)[0]
    h = h.split("?", 1)[0]
    h = h.split(":", 1)[0]
    if h.startswith("www."):
        h = h[4:]
    return h if _HOST_RE.match(h) else ""

def load_allowlist(path):
    s = set()
    with open(path) as f:
        for line in f:
            h = normalize_host(line)
            if h:
                s.add(h)
    return s

_ALLOWLIST = None

def _init_worker(allow):
    global _ALLOWLIST
    _ALLOWLIST = allow

def _site_host_from_meta(meta):
    u = meta.get("resolved_url") or meta.get("input") or ""
    return normalize_host(u)

def process_chunk(chunk_path):
    out = {}
    try:
        site_dirs = os.listdir(chunk_path)
    except FileNotFoundError:
        return out

    for sd in site_dirs:
        meta_path = os.path.join(chunk_path, sd, "metadata.json")
        if not os.path.isfile(meta_path):
            continue
        try:
            with open(meta_path) as f:
                meta = json.load(f)
        except Exception:
            continue

        host = _site_host_from_meta(meta)
        if not host or host not in _ALLOWLIST:
            continue
        if host in out:
            continue

        fp = meta.get("wordpress_fingerprints") or {}
        plugins = fp.get("plugins") or []
        themes = fp.get("themes") or []

        recs = []
        for p in plugins:
            slug = (p.get("name") or "").lower().strip()
            if not slug:
                continue
            vers = [str(v).strip() for v in (p.get("versions") or []) if v]
            recs.append((slug, vers))
        for t in themes:
            slug = (t.get("name") or "").lower().strip()
            if not slug:
                continue
            vers = [str(v).strip() for v in (t.get("versions") or []) if v]
            recs.append((f"theme:{slug}", vers))

        out[host] = recs

    return out

def main():
    print("Loading host allowlist...", flush=True)
    allowlist = load_allowlist(HOST_ALLOWLIST)
    print(f"  {len(allowlist):,} hosts", flush=True)

    print("Enumerating crawl chunks...", flush=True)
    chunks = sorted(
        os.path.join(CRAWL_ROOT, c)
        for c in os.listdir(CRAWL_ROOT)
        if c.startswith("chunk-")
    )
    print(f"  {len(chunks)} chunks", flush=True)

    debug = "--debug" in sys.argv
    if debug:
        chunks = chunks[:2]
        print("  DEBUG: first 2 chunks only", flush=True)

    nproc = min(len(chunks), max(1, os.cpu_count() or 4))
    print(f"Processing with {nproc} workers...", flush=True)

    pool = mp.Pool(
        processes=nproc,
        initializer=_init_worker,
        initargs=(allowlist,),
    )

    merged = {}
    done = 0
    for chunk_result in pool.imap_unordered(process_chunk, chunks):
        for host, recs in chunk_result.items():
            if host not in merged:
                merged[host] = recs
        done += 1
        print(
            f"  chunk {done}/{len(chunks)} unique_hosts={len(merged):,}",
            flush=True,
        )

    pool.close()
    pool.join()

    print(f"\nMerged {len(merged):,} unique hosts", flush=True)

    slug_sites = Counter()
    slug_version_sites = Counter()

    for host, recs in merged.items():
        seen_slugs = set()
        seen_sv = set()
        for key_slug, versions in recs:
            if key_slug not in seen_slugs:
                slug_sites[key_slug] += 1
                seen_slugs.add(key_slug)
            for v in versions:
                kv = f"{key_slug}@{v}"
                if kv not in seen_sv:
                    slug_version_sites[kv] += 1
                    seen_sv.add(kv)

    out = {
        "total_sites": len(merged),
        "source": "Mar 17->18 crawl, full-population, host-dedup",
        "crawl_dir": os.path.basename(CRAWL_ROOT),
        "plugins": dict(slug_sites),
        "plugin_versions": dict(slug_version_sites),
    }

    with open(OUT_PATH, "w") as f:
        json.dump(out, f)

    print(f"\ntotal_sites            : {len(merged):,}")
    print(f"distinct slugs         : {len(slug_sites):,}")
    print(f"distinct slug@version  : {len(slug_version_sites):,}")
    print(f"\nWrote {OUT_PATH}")

if __name__ == "__main__":
    main()

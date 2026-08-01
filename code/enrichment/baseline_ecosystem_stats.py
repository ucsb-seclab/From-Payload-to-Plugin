#!/usr/bin/env python3

import json
import os
import re
import sys
import multiprocessing as mp
from collections import Counter, defaultdict
from packaging.version import Version, InvalidVersion

CRAWL_ROOT = os.environ.get("CRAWL_ROOT", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "crawls", "watchlist_batch_20260318_202935"))
HOST_ALLOWLIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "baselines", "unique_hosts.txt")
FINDINGS_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "findings")
WORDFENCE_DB = os.environ.get("WORDFENCE_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "baselines", "wordfence_db.json"))
OUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "results", "baseline_ecosystem_stats.json")

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

def load_compromised(findings_root):
    s = set()
    for entry in os.listdir(findings_root):
        if not entry.startswith("find-"):
            continue
        fdir = os.path.join(findings_root, entry)
        if not os.path.isdir(fdir):
            continue
        for sub in os.listdir(fdir):
            if sub == "resch":
                continue
            doms = os.path.join(fdir, sub, "domains.txt")
            if not os.path.isfile(doms):
                continue
            with open(doms) as f:
                for line in f:
                    h = normalize_host(line)
                    if h:
                        s.add(h)
    return s

def parse_ver(v):
    try:
        return Version(str(v))
    except (InvalidVersion, TypeError, ValueError):
        return None

def build_cve_index(db_path):
    with open(db_path) as f:
        db = json.load(f)
    idx_plugin = defaultdict(list)
    idx_theme = defaultdict(list)
    all_plugin_slugs = set()
    all_theme_slugs = set()
    for uuid, entry in db.items():
        cve_id = entry.get("cve") or uuid
        for sw in entry.get("software", []) or []:
            slug = (sw.get("slug") or "").lower()
            if not slug:
                continue
            kind = (sw.get("type") or "plugin").lower()
            av_map = sw.get("affected_versions") or {}
            ranges = []
            for _, av in av_map.items():
                ranges.append((
                    (av.get("from_version") or "*"),
                    (av.get("to_version") or "*"),
                    bool(av.get("from_inclusive", True)),
                    bool(av.get("to_inclusive", True)),
                    cve_id,
                ))
            if kind == "theme":
                all_theme_slugs.add(slug)
                idx_theme[slug].extend(ranges)
            else:
                all_plugin_slugs.add(slug)
                idx_plugin[slug].extend(ranges)
    return dict(idx_plugin), dict(idx_theme), all_plugin_slugs, all_theme_slugs

def version_matches(obs_str, ranges):
    ov = parse_ver(obs_str)
    if ov is None:
        return False
    for from_v, to_v, fi, ti, _cve in ranges:
        lo_ok = True
        hi_ok = True
        if from_v and from_v != "*":
            fv = parse_ver(from_v)
            if fv is None:
                lo_ok = True
            else:
                lo_ok = (ov >= fv) if fi else (ov > fv)
        if to_v and to_v != "*":
            tv = parse_ver(to_v)
            if tv is None:
                hi_ok = True
            else:
                hi_ok = (ov <= tv) if ti else (ov < tv)
        if lo_ok and hi_ok:
            return True
    return False

_CVE_IDX_PLUGIN = None
_CVE_IDX_THEME = None
_PLUGIN_SLUGS_WITH_CVE = None
_THEME_SLUGS_WITH_CVE = None
_ALLOWLIST = None
_COMPROMISED = None

def _init_worker(cve_p, cve_t, slugs_p, slugs_t, allow, comp):
    global _CVE_IDX_PLUGIN, _CVE_IDX_THEME, _PLUGIN_SLUGS_WITH_CVE, _THEME_SLUGS_WITH_CVE, _ALLOWLIST, _COMPROMISED
    _CVE_IDX_PLUGIN = cve_p
    _CVE_IDX_THEME = cve_t
    _PLUGIN_SLUGS_WITH_CVE = slugs_p
    _THEME_SLUGS_WITH_CVE = slugs_t
    _ALLOWLIST = allow
    _COMPROMISED = comp

def _site_host_from_meta(meta):
    u = meta.get("resolved_url") or meta.get("input") or ""
    return normalize_host(u)

def process_chunk(chunk_path):
    out = {}
    seen = set()

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
        if host in seen:
            continue
        seen.add(host)

        is_comp = host in _COMPROMISED
        fp = meta.get("wordpress_fingerprints") or {}
        plugins = fp.get("plugins") or []
        themes = fp.get("themes") or []

        site_components = {}
        for p in plugins:
            slug = (p.get("name") or "").lower().strip()
            if not slug:
                continue
            vers = [str(v) for v in (p.get("versions") or []) if v]
            site_components.setdefault(("plugin", slug), []).extend(vers)
        for t in themes:
            slug = (t.get("name") or "").lower().strip()
            if not slug:
                continue
            vers = [str(v) for v in (t.get("versions") or []) if v]
            site_components.setdefault(("theme", slug), []).extend(vers)

        n_comp = 0
        n_ver = 0
        n_parse = 0
        n_cve_rec = 0
        n_inrange = 0
        has_inrange = False
        slugs_seen = []
        for (kind, slug), versions in site_components.items():
            n_comp += 1
            slugs_seen.append((kind, slug))
            has_any = bool(versions)
            has_parse = any(parse_ver(v) is not None for v in versions)
            if has_any:
                n_ver += 1
            if has_parse:
                n_parse += 1
            known_slug = (
                slug in _PLUGIN_SLUGS_WITH_CVE if kind == "plugin"
                else slug in _THEME_SLUGS_WITH_CVE
            )
            if known_slug:
                n_cve_rec += 1
            ranges = (
                _CVE_IDX_PLUGIN.get(slug) if kind == "plugin"
                else _CVE_IDX_THEME.get(slug)
            ) or []
            if has_parse and ranges:
                for v in versions:
                    if parse_ver(v) is None:
                        continue
                    if version_matches(v, ranges):
                        n_inrange += 1
                        has_inrange = True
                        break

        out[host] = (is_comp, n_comp, n_ver, n_parse, n_cve_rec, n_inrange, has_inrange, slugs_seen)

    return out

def merge_counters(dst, src):
    for k in (
        "sites_total", "sites_with_component", "component_occurrences",
        "occ_with_any_version", "occ_with_parseable_version",
        "occ_with_cve_record", "occ_with_inrange_cve", "sites_with_inrange_cve",
    ):
        dst[k] += src[k]
    dst["distinct_slugs"].update(src["distinct_slugs"])
    for k in (
        "per_site_components", "per_site_components_with_version",
        "per_site_components_parseable", "per_site_components_inrange_cve",
    ):
        dst[k].extend(src[k])

def summarize(c, label, wf_plugin_slugs=None, wf_theme_slugs=None):
    import statistics
    sites = c["sites_total"]
    occ = c["component_occurrences"]
    pct = lambda n, d: (100.0 * n / d) if d else 0.0
    distinct_in_wf = 0
    if wf_plugin_slugs is not None and wf_theme_slugs is not None:
        for (kind, slug), _ in c["distinct_slugs"].items():
            if kind == "plugin" and slug in wf_plugin_slugs:
                distinct_in_wf += 1
            elif kind == "theme" and slug in wf_theme_slugs:
                distinct_in_wf += 1
    per_site = c["per_site_components"]
    per_site_ver = c["per_site_components_with_version"]
    per_site_parse = c["per_site_components_parseable"]
    per_site_cve = c["per_site_components_inrange_cve"]

    def stats(arr):
        if not arr:
            return {"median": 0, "mean": 0.0, "p75": 0, "p90": 0}
        arr_s = sorted(arr)
        n = len(arr_s)
        return {
            "median": statistics.median(arr_s),
            "mean": round(statistics.fmean(arr_s), 2),
            "p75": arr_s[min(n - 1, int(n * 0.75))],
            "p90": arr_s[min(n - 1, int(n * 0.90))],
        }

    return {
        "label": label,
        "sites_total": sites,
        "sites_with_any_component": c["sites_with_component"],
        "pct_sites_with_any_component": round(pct(c["sites_with_component"], sites), 2),
        "component_occurrences": occ,
        "distinct_component_slugs": len(c["distinct_slugs"]),
        "distinct_component_slugs_in_wordfence": distinct_in_wf,
        "pct_distinct_slugs_in_wordfence": round(pct(distinct_in_wf, len(c["distinct_slugs"])), 2),
        "occ_with_any_version": c["occ_with_any_version"],
        "pct_occ_with_any_version": round(pct(c["occ_with_any_version"], occ), 2),
        "occ_with_parseable_version": c["occ_with_parseable_version"],
        "pct_occ_with_parseable_version": round(pct(c["occ_with_parseable_version"], occ), 2),
        "occ_with_cve_record": c["occ_with_cve_record"],
        "pct_occ_with_cve_record": round(pct(c["occ_with_cve_record"], occ), 2),
        "occ_with_inrange_cve": c["occ_with_inrange_cve"],
        "pct_occ_with_inrange_cve": round(pct(c["occ_with_inrange_cve"], occ), 2),
        "sites_with_inrange_cve": c["sites_with_inrange_cve"],
        "pct_sites_with_inrange_cve": round(pct(c["sites_with_inrange_cve"], sites), 2),
        "per_site_components": stats(per_site),
        "per_site_components_with_version": stats(per_site_ver),
        "per_site_components_parseable": stats(per_site_parse),
        "per_site_components_inrange_cve": stats(per_site_cve),
    }

def main():
    print("Loading host allowlist...", flush=True)
    allowlist = load_allowlist(HOST_ALLOWLIST)
    print(f"  {len(allowlist):,} normalized hosts")

    print("Loading compromised site set...", flush=True)
    compromised = load_compromised(FINDINGS_ROOT)
    print(f"  {len(compromised):,} unique compromised domains")

    in_allow = compromised & allowlist
    print(f"  {len(in_allow):,} of those also in host allowlist")

    print("Building Wordfence CVE index...", flush=True)
    idx_p, idx_t, slugs_p, slugs_t = build_cve_index(WORDFENCE_DB)
    print(f"  {len(idx_p):,} plugin slugs with CVE records, {len(idx_t):,} theme slugs")

    print("Enumerating crawl chunks...", flush=True)
    chunks = sorted(
        os.path.join(CRAWL_ROOT, c)
        for c in os.listdir(CRAWL_ROOT)
        if c.startswith("chunk-")
    )
    print(f"  {len(chunks)} chunks")

    debug = "--debug" in sys.argv
    if debug:
        chunks = chunks[:1]
        print("  DEBUG: using only first chunk")

    nproc = min(len(chunks), max(1, os.cpu_count() or 4))
    print(f"Processing with {nproc} workers...", flush=True)

    pool = mp.Pool(
        processes=nproc,
        initializer=_init_worker,
        initargs=(idx_p, idx_t, slugs_p, slugs_t, allowlist, compromised),
    )

    merged_hosts = {}
    done = 0
    for chunk_result in pool.imap_unordered(process_chunk, chunks):
        for host, rec in chunk_result.items():
            if host not in merged_hosts:
                merged_hosts[host] = rec
        done += 1
        print(f"  chunk {done}/{len(chunks)} done; unique_hosts={len(merged_hosts):,}", flush=True)

    pool.close()
    pool.join()

    print(f"\nMerged {len(merged_hosts):,} unique hosts across all chunks", flush=True)

    def empty_agg():
        return {
            "sites_total": 0,
            "sites_with_component": 0,
            "component_occurrences": 0,
            "occ_with_any_version": 0,
            "occ_with_parseable_version": 0,
            "occ_with_cve_record": 0,
            "occ_with_inrange_cve": 0,
            "sites_with_inrange_cve": 0,
            "distinct_slugs": Counter(),
            "per_site_components": [],
            "per_site_components_with_version": [],
            "per_site_components_parseable": [],
            "per_site_components_inrange_cve": [],
        }

    all_agg = empty_agg()
    comp_agg = empty_agg()

    def add_host(agg, rec):
        is_comp, n_comp, n_ver, n_parse, n_cve_rec, n_inrange, has_inrange, slugs_seen = rec
        agg["sites_total"] += 1
        if n_comp > 0:
            agg["sites_with_component"] += 1
        agg["component_occurrences"] += n_comp
        agg["occ_with_any_version"] += n_ver
        agg["occ_with_parseable_version"] += n_parse
        agg["occ_with_cve_record"] += n_cve_rec
        agg["occ_with_inrange_cve"] += n_inrange
        if has_inrange:
            agg["sites_with_inrange_cve"] += 1
        for pair in slugs_seen:
            agg["distinct_slugs"][pair] += 1
        agg["per_site_components"].append(n_comp)
        agg["per_site_components_with_version"].append(n_ver)
        agg["per_site_components_parseable"].append(n_parse)
        agg["per_site_components_inrange_cve"].append(n_inrange)

    for host, rec in merged_hosts.items():
        add_host(all_agg, rec)
        if rec[0]:
            add_host(comp_agg, rec)

    summary_all = summarize(all_agg, "All crawled WP sites (Mar 18)", slugs_p, slugs_t)
    summary_comp = summarize(comp_agg, "Compromised sites (in Mar 18 crawl)", slugs_p, slugs_t)

    out = {
        "crawl_window": os.path.basename(CRAWL_ROOT),
        "host_allowlist_size": len(allowlist),
        "compromised_set_size_total": len(compromised),
        "compromised_set_size_in_allowlist": len(compromised & allowlist),
        "wordfence_plugin_slugs": len(idx_p),
        "wordfence_theme_slugs": len(idx_t),
        "populations": {
            "all": summary_all,
            "compromised": summary_comp,
        },
    }

    with open(OUT_PATH, "w") as f:
        json.dump(out, f, indent=2)

    print("\n=== SUMMARY ===")
    for k, v in out.items():
        if k != "populations":
            print(f"{k}: {v}")
    for name, s in out["populations"].items():
        print(f"\n-- {name} --")
        for k, v in s.items():
            print(f"  {k}: {v}")

    print(f"\nWrote {OUT_PATH}")

if __name__ == "__main__":
    main()

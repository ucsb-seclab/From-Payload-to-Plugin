#!/usr/bin/env python3

from __future__ import annotations

import json
import math
import os
import re
import multiprocessing as mp
from collections import defaultdict

from campaign_mapping import CANONICAL_CAMPAIGNS

CRAWL_ROOT = os.environ.get("CRAWL_ROOT", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "crawls", "watchlist_batch_20260318_202935"))
HOST_ALLOWLIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "baselines", "unique_hosts.txt")
FINDINGS_BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "findings")
OUT_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "results", "table4_v3_rows.json")
OUT_TEX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "results", "table4_v3.tex")

_HOST_RE = re.compile(r"^[a-z0-9.\-]+$")

PAPER_ENTRIES = [
    ("HexArray-A",   "url-shortify",             "1.8.6", 63, 2.8,  "Known",   "Sto.\\ XSS: CVE-2025-32134"),
    ("HexArray-A",   "simple-tags",              "3.28.1",35, 2.2,  "Known",   "SQLi: CVE-2025-11972 / Sto.\\ XSS: CVE-2025-0627"),
    ("HexArray-A",   "ali-post-editor",          "6.9",   98, None, "Fake",    "attacker-planted"),
    ("HexArray-A",   "theme:enjoymini",          "6.9",   40, None, "Suspect", "attacker-planted theme"),
    ("HexArray-A",   "theme:visualblogger",      "6.9",   35, None, "Suspect", "attacker-planted theme"),
    ("HexArray-B",   "url-shortify",             "1.8.6", 57, 2.8,  "Known",   "Sto.\\ XSS: CVE-2025-32134"),
    ("HexArray-B",   "simple-tags",              "3.28.1",30, 2.2,  "Known",   "SQLi: CVE-2025-11972 / Sto.\\ XSS: CVE-2025-0627"),
    ("HexArray-B",   "ali-post-editor",          "6.9",   96, None, "Fake",    "attacker-planted"),
    ("HexArray-C",   "url-shortify",             "1.8.6", 60, 2.8,  "Known",   "Sto.\\ XSS: CVE-2025-32134"),
    ("HexArray-C",   "simple-tags",              "3.28.1",30, 2.2,  "Known",   "SQLi: CVE-2025-11972 / Sto.\\ XSS: CVE-2025-0627"),
    ("HexArray-C",   "ali-post-editor",          "6.9",   85, None, "Fake",    "attacker-planted"),
    ("GDPRInject",   "url-shortify",             "1.8.6", 61, 2.8,  "Known",   "Sto.\\ XSS: CVE-2025-32134"),
    ("GDPRInject",   "simple-tags",              "3.28.1",39, 2.3,  "Known",   "SQLi: CVE-2025-11972 / Sto.\\ XSS: CVE-2025-0627"),
    ("GDPRInject",   "ali-post-editor",          "6.9",   95, None, "Fake",    "attacker-planted"),
    ("GDPRInject",   "theme:enjoymini",          "6.9",   41, None, "Suspect", "attacker-planted theme"),
    ("SessHijack-A", "theme:oceanwp",            "3.5.8", 10, None, "Niche",   "Auth: CVE-2025-8944 / Sto.\\ XSS: CVE-2024-5647, CVE-2025-5524"),
    ("SessHijack-B", "sfwd-lms",                 "4.18.1", 8, None, "Niche",   "Auth: CVE-2025-24662"),
    ("FadeRedirect", "salient-core",             "1.0",    7, None, "Niche",   "File: CVE-2024-3812 / Refl.\\ XSS: CVE-2023-48748 / Sto.\\ XSS: CVE-2023-48749"),
    ("MultiC2",      "theme:diza",               "1.0.6",  3, None, "Niche",   "File: CVE-2025-52729, CVE-2025-49261"),
    ("JSFiretruck",  "fusion-builder",           "1",      5, None, "Niche",   "RCE: CVE-2024-13345 / Sto.\\ XSS: CVE-2024-12477, CVE-2025-1665"),
    ("MalvertKit",   "eventON",                  "3.1",    5, None, "Niche",   "Auth: CVE-2025-47565, CVE-2025-47564 / Sto.\\ XSS: CVE-2025-3527"),
    ("TagInject-A",  "add-to-any",               "1.1",   10, 1.0,  "Known",   "Host hdr: source audit, Section~\\ref{sec:res-casestudy}"),
    ("TagInject-A",  "theme:puca",               "2.1.4", 10, None, "Niche",   "premium, not auditable"),
    ("TagInject-B",  "theme:puca",               "2.1.4", 10, None, "Niche",   "premium, not auditable"),
    ("CSSInject",    "theme:astra",              "4.12.1",18, None, "Niche",   "Sto.\\ XSS: CVE-2024-2347, CVE-2024-29768"),
    ("PolyClickFix", "go_pricing",               "3.3.19", 1, None, "Niche",   "Auth: CVE-2023-2494, CVE-2023-2496 / Sto.\\ XSS: CVE-2023-2498"),
    ("PolyClickFix", "woolentor-addons",         "3.3.1",  6, 1.3,  "Suspect", "RCE via source audit, Section~\\ref{sec:res-casestudy}"),
    ("CookieLoader", "tablepress",               "1.9",  100, 1.7,  "Known",   "Sto.\\ XSS: CVE-2024-9595, CVE-2025-2685, CVE-2025-5096"),
    ("HexLoader",    "jet-elements",             "2.0.2", 50, 2.2,  "Known",   "Auth: CVE-2025-39447 / Sto.\\ XSS: CVE-2025-53982"),
    ("HexLoader",    "jet-search",               "1.0.0", 50, 2.2,  "Known",   "SQLi: CVE-2025-49931 / Sto.\\ XSS: CVE-2024-7136"),
    ("HexLoader",    "jet-engine",               "3.8.5", 50, 2.2,  "Suspect", "no published CVE"),
    ("HexLoader",    "jet-tabs",                 "2.2.14",50, 2.2,  "Suspect", "no published CVE"),
    ("TDSRedirect",  "goodlayers-core",          "1.3.9", 14, None, "Niche",   "Sto.\\ XSS: CVE-2024-12163, CVE-2024-11357"),
    ("TDSRedirect",  "download-monitor",         "5.1.8", 14, 1.7,  "Suspect", "XSS/CSRF via source audit, Section~\\ref{sec:res-casestudy}"),
    ("WooBackdoor",  "pixelyoursite-pro",        "2.1.3", 11, None, "Niche",   "Sto.\\ XSS: CVE-2023-2584"),
    ("OverlayInject","revslider",                "6.0",  100, None, "Niche",   "Auth: CVE-2025-10249 / Sto.\\ XSS: CVE-2024-8107"),
    ("OverlayInject","facebook-pagelike-widget", "1.0",   50, 2.4,  "Known",   "Sto.\\ XSS: CVE-2024-0973, CVE-2024-13207"),
]

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

        sv = set()
        for p in plugins:
            slug = (p.get("name") or "").lower().strip()
            if not slug:
                continue
            vers = [str(v).strip() for v in (p.get("versions") or []) if v]
            for v in vers:
                sv.add((slug, v))
            if not vers:
                sv.add((slug, None))
        for t in themes:
            slug = (t.get("name") or "").lower().strip()
            if not slug:
                continue
            vers = [str(v).strip() for v in (t.get("versions") or []) if v]
            for v in vers:
                sv.add((f"theme:{slug}", v))
            if not vers:
                sv.add((f"theme:{slug}", None))

        out[host] = sv

    return out

def build_host_fingerprints(allowlist):
    chunks = sorted(
        os.path.join(CRAWL_ROOT, c)
        for c in os.listdir(CRAWL_ROOT)
        if c.startswith("chunk-")
    )
    print(f"  {len(chunks)} chunks", flush=True)

    nproc = min(len(chunks), max(1, os.cpu_count() or 4))
    pool = mp.Pool(
        processes=nproc,
        initializer=_init_worker,
        initargs=(allowlist,),
    )

    merged = {}
    done = 0
    for chunk_result in pool.imap_unordered(process_chunk, chunks):
        for host, sv in chunk_result.items():
            if host not in merged:
                merged[host] = sv
        done += 1
        print(
            f"  chunk {done}/{len(chunks)} unique_hosts={len(merged):,}",
            flush=True,
        )
    pool.close()
    pool.join()
    return merged

def load_campaign_victims():
    out = {}
    for campaign, finds in CANONICAL_CAMPAIGNS.items():
        hosts = set()
        for fid in finds:
            d = f"{FINDINGS_BASE}/find-{fid}"
            if not os.path.isdir(d):
                continue
            for sub in os.listdir(d):
                if sub == "resch":
                    continue
                sp = f"{d}/{sub}"
                if not os.path.isdir(sp):
                    continue
                doms = f"{sp}/domains.txt"
                if not os.path.isfile(doms):
                    continue
                with open(doms) as f:
                    for line in f:
                        h = normalize_host(line)
                        if h:
                            hosts.add(h)
        out[campaign] = hosts
    return out

def main():
    print("Loading allowlist...", flush=True)
    allowlist = load_allowlist(HOST_ALLOWLIST)
    print(f"  {len(allowlist):,} hosts")

    print("Walking crawl and building host fingerprints...", flush=True)
    host_fp = build_host_fingerprints(allowlist)
    print(f"  {len(host_fp):,} unique hosts with fingerprints")

    print("Loading compromised victim sets per campaign...", flush=True)
    victims_by_campaign = load_campaign_victims()
    compromised_all = set()
    for hosts in victims_by_campaign.values():
        compromised_all |= hosts
    print(f"  {len(compromised_all):,} distinct compromised hosts across campaigns")

    background = set(host_fp.keys()) - compromised_all
    bg_total = len(background)
    print(f"Background population (baseline): {bg_total:,}")

    bg_sv = defaultdict(int)
    for host in background:
        for sv in host_fp[host]:
            slug, ver = sv
            if ver is not None:
                bg_sv[(slug, ver)] += 1

    bg_slug = defaultdict(int)
    for host in background:
        slugs_seen = set()
        for (slug, _ver) in host_fp[host]:
            slugs_seen.add(slug)
        for slug in slugs_seen:
            bg_slug[slug] += 1

    by_campaign = defaultdict(list)
    campaign_order = []
    for e in PAPER_ENTRIES:
        if e[0] not in by_campaign:
            campaign_order.append(e[0])
        by_campaign[e[0]].append(e)

    rows = []
    camp_summary = []

    for camp in campaign_order:
        entries = by_campaign[camp]
        victim_set = victims_by_campaign.get(camp, set())
        victim_crawled = victim_set & set(host_fp.keys())
        n_victim_total = len(victim_set)
        n_victim_crawled = len(victim_crawled)

        union_hosts = set()
        for (_, slug, version, paper_pct, paper_log10E, signal, cve) in entries:
            slug_lc = slug.lower()
            target = (slug_lc, version)
            bg_count = bg_sv.get(target, 0)

            if bg_count > 0 and paper_pct > 0:
                p_k = paper_pct / 100.0
                p_bg = bg_count / bg_total
                log10E = math.log10(p_k / p_bg)
            elif bg_count == 0 and paper_pct > 0:
                log10E = math.inf
            else:
                log10E = None

            for h in victim_crawled:
                if target in host_fp[h]:
                    union_hosts.add(h)

            rows.append({
                "campaign": camp,
                "slug": slug,
                "version": version,
                "paper_pct": paper_pct,
                "paper_log10_E": paper_log10E,
                "baseline_host_count": bg_count,
                "baseline_pct": round(100.0 * bg_count / bg_total if bg_total else 0, 6),
                "new_log10_E": (
                    None if log10E is None
                    else ("inf" if math.isinf(log10E) else round(log10E, 2))
                ),
                "signal_paper": signal,
                "cve_note": cve,
            })

        union_count = len(union_hosts)
        union_pct = (100.0 * union_count / n_victim_crawled) if n_victim_crawled else 0.0

        camp_summary.append({
            "campaign": camp,
            "victim_total_in_findings": n_victim_total,
            "victim_in_crawl": n_victim_crawled,
            "union_hosts_with_any_entry": union_count,
            "union_pct_of_crawled_victims": round(union_pct, 1),
        })

    print()
    print("=" * 120)
    print(f"{'Campaign':<13} {'Plugin:Version':<28} "
          f"{'Pap%':>5} {'BgHost':>9} {'Bg%':>8} "
          f"{'PapLogE':>8} {'NewLogE':>9}  CVE note")
    print("=" * 120)

    rows_by_camp = defaultdict(list)
    for r in rows:
        rows_by_camp[r["campaign"]].append(r)
    camp_by_name = {c["campaign"]: c for c in camp_summary}

    for camp in campaign_order:
        cs = camp_by_name[camp]
        print(f"-- {camp}  victims={cs['victim_total_in_findings']}, "
              f"in_crawl={cs['victim_in_crawl']}, "
              f"union={cs['union_hosts_with_any_entry']}/{cs['victim_in_crawl']} "
              f"({cs['union_pct_of_crawled_victims']:.1f}% of crawled)")
        def sk(r):
            v = r["new_log10_E"]
            if v is None:
                return (2, 0)
            if v == "inf":
                return (0, 1e9)
            return (1, -v)
        for r in sorted(rows_by_camp[camp], key=sk):
            slug_v = f"{r['slug']}:{r['version']}"
            pap_log = "---" if r["paper_log10_E"] is None else f"{r['paper_log10_E']:.2f}"
            if r["new_log10_E"] is None:
                new_log = "---"
            elif r["new_log10_E"] == "inf":
                new_log = "+inf"
            else:
                new_log = f"{r['new_log10_E']:.2f}"
            print(f"   {slug_v:<28} "
                  f"{r['paper_pct']:>4}% {r['baseline_host_count']:>9,} "
                  f"{r['baseline_pct']:>7.4f}% "
                  f"{pap_log:>8} {new_log:>9}  {r['cve_note'][:40]}")

    with open(OUT_JSON, "w") as f:
        json.dump({
            "baseline_background_hosts": bg_total,
            "compromised_excluded": len(compromised_all),
            "rows": rows,
            "campaign_summary": camp_summary,
        }, f, indent=2)
    print(f"\nWrote {OUT_JSON}")

    latex_lines = []
    for camp in campaign_order:
        def sk(r):
            v = r["new_log10_E"]
            if v is None:
                return (2, 0)
            if v == "inf":
                return (0, 1e9)
            return (1, -v)
        crows = sorted(rows_by_camp[camp], key=sk)
        cs = camp_by_name[camp]
        for i, r in enumerate(crows):
            slug_v = f"{r['slug']}:{r['version']}"
            slug_esc = slug_v.replace("_", r"\_")
            pct = f"{r['paper_pct']:.0f}"
            if r["new_log10_E"] is None:
                enr = "---"
            elif r["new_log10_E"] == "inf":
                enr = r"$\infty$"
            else:
                enr = f"{r['new_log10_E']:.1f}"
            label = camp if i == 0 else ""
            cve = r["cve_note"]
            latex_lines.append(
                f"{label:<13} & \\texttt{{{slug_esc}}} & {pct} & {enr} & {cve} \\\\"
            )
        latex_lines.append(
            f"            & \\emph{{union over listed plugins}} & "
            f"{cs['union_pct_of_crawled_victims']:.0f} & --- & "
            f"\\emph{{{cs['union_hosts_with_any_entry']} of {cs['victim_in_crawl']} "
            f"crawled victims}} \\\\"
        )
        latex_lines.append(r"\midrule")

    with open(OUT_TEX, "w") as f:
        f.write("\n".join(latex_lines))
    print(f"Wrote {OUT_TEX}")

if __name__ == "__main__":
    main()

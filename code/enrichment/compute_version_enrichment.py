#!/usr/bin/env python3
import json
import os
import sys
from collections import defaultdict
from packaging.version import Version, InvalidVersion
from campaign_mapping import CANONICAL_CAMPAIGNS, FINDINGS_BASE

BASELINE_PATH = os.path.join(os.path.dirname(__file__), "baseline_plugins.json")

def parse_ver(v):
    try:
        return Version(str(v))
    except (InvalidVersion, TypeError):
        return None

def parse_affected_range(ar):
    if not ar:
        return None
    parts = ar.split(' - ', 1)
    if len(parts) != 2:
        return None
    return parse_ver(parts[1].strip())

def load_baseline():
    with open(BASELINE_PATH) as f:
        data = json.load(f)
    return data['total_sites'], data['plugins']

def load_observation(fid):
    d = f"{FINDINGS_BASE}/find-{fid}"
    if not os.path.isdir(d):
        return None
    entries = [x for x in os.listdir(d) if x != "resch" and os.path.isdir(os.path.join(d, x))]
    if not entries:
        return None
    with open(os.path.join(d, entries[0], "metadata.json")) as f:
        return json.load(f)

def extract_plugin_versions(data):
    total_sites = data.get('distinct_sites', 0)
    results = []
    for section in ('plugin_info', 'theme_info'):
        prefix = "theme:" if section == 'theme_info' else ""
        for comp_name, comp_data in data.get(section, {}).items():
            slug = f"{prefix}{comp_name}"
            freq = comp_data.get('frequency', 0)
            versions = comp_data.get('versions', [])
            in_range_cves = []
            for vuln in comp_data.get('vulnerabilities_cve', []):
                obs_ver = parse_ver(vuln.get('version'))
                max_ver = parse_affected_range(vuln.get('affected_range'))
                if obs_ver is not None and max_ver is not None and obs_ver <= max_ver:
                    in_range_cves.append(vuln.get('cve', 'unknown'))
            for ver in versions:
                results.append({
                    'slug': slug,
                    'version': ver,
                    'slug_version': f"{slug}:{ver}",
                    'frequency': freq,
                    'total_sites': total_sites,
                    'cves': in_range_cves,
                })
    return results

def main():
    baseline_total, baseline_plugins = load_baseline()
    print(f"Baseline: {baseline_total} sites, {len(baseline_plugins)} plugins\n")

    thresholds = [2.0, 3.0, 5.0, 10.0, 20.0, 50.0, 100.0]

    all_results = {}

    for cname, finds in CANONICAL_CAMPAIGNS.items():
        if not finds:
            continue

        sv_freq = defaultdict(int)
        sv_cves = defaultdict(set)
        sv_slug = {}
        sv_ver = {}
        total_sites = 0

        for fid in finds:
            data = load_observation(fid)
            if not data:
                continue
            total_sites += data.get('distinct_sites', 0)
            entries = extract_plugin_versions(data)
            for e in entries:
                sv = e['slug_version']
                sv_freq[sv] += e['frequency']
                sv_cves[sv].update(e['cves'])
                sv_slug[sv] = e['slug']
                sv_ver[sv] = e['version']

        if total_sites == 0:
            continue

        candidates = []
        for sv, freq in sv_freq.items():
            slug = sv_slug[sv]
            version = sv_ver[sv]
            comp_pct = freq / total_sites

            bg_count = baseline_plugins.get(slug.replace('theme:', ''), 0)
            bg_pct = bg_count / baseline_total if baseline_total > 0 else 0

            if bg_pct > 0:
                enrichment = comp_pct / bg_pct
            else:
                enrichment = float('inf') if comp_pct > 0 else 0

            cves = sv_cves.get(sv, set())

            candidates.append({
                'slug': slug,
                'version': version,
                'slug_version': sv,
                'frequency': freq,
                'total_sites': total_sites,
                'comp_pct': comp_pct,
                'bg_pct': bg_pct,
                'enrichment': enrichment,
                'cves': sorted(cves),
                'n_cves': len(cves),
            })

        candidates.sort(key=lambda x: -x['enrichment'])
        all_results[cname] = candidates

    print("=" * 100)
    print(f"{'Campaign':<16} {'Plugin:Version':<35} {'Freq':>5} {'Sites':>6} {'Comp%':>7} {'Bg%':>7} {'Enrich':>8} {'CVEs':>5} {'Top CVE':<20}")
    print("=" * 100)

    threshold_counts = {t: 0 for t in thresholds}
    total_candidates_by_threshold = {t: [] for t in thresholds}

    for cname, candidates in all_results.items():
        if not candidates:
            continue
        print(f"\n--- {cname} ({candidates[0]['total_sites']} sites) ---")
        for c in candidates[:10]:
            enr_str = f"{c['enrichment']:.1f}x" if c['enrichment'] != float('inf') else "inf"
            top_cve = c['cves'][0] if c['cves'] else ""
            print(f"  {c['slug_version']:<35} {c['frequency']:>5} {c['total_sites']:>6} "
                  f"{c['comp_pct']:>6.1%} {c['bg_pct']:>6.1%} {enr_str:>8} {c['n_cves']:>5} {top_cve:<20}")

            for t in thresholds:
                if c['enrichment'] >= t:
                    total_candidates_by_threshold[t].append((cname, c))

    print("\n" + "=" * 80)
    print("THRESHOLD ANALYSIS")
    print("=" * 80)
    print(f"{'Threshold':>12} {'Total Candidates':>18} {'Campaigns Covered':>20} {'Avg per Campaign':>18}")
    print("-" * 70)
    for t in thresholds:
        cands = total_candidates_by_threshold[t]
        campaigns_with = len(set(c[0] for c in cands))
        avg = len(cands) / campaigns_with if campaigns_with > 0 else 0
        print(f"{t:>10.1f}x {len(cands):>18} {campaigns_with:>20} {avg:>18.1f}")

    output = {}
    for cname, candidates in all_results.items():
        output[cname] = []
        for c in candidates:
            entry = dict(c)
            entry['enrichment'] = c['enrichment'] if c['enrichment'] != float('inf') else 999999
            output[cname].append(entry)

    with open('version_enrichment_results.json', 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nFull results saved to version_enrichment_results.json")

if __name__ == "__main__":
    main()

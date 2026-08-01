#!/usr/bin/env python3

import json
import os
import sys
import time
import urllib.request
import urllib.error
from collections import defaultdict
from campaign_mapping import CANONICAL_CAMPAIGNS, FINDINGS_BASE
from packaging.version import Version, InvalidVersion

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "baseline_plugins.json")
WPORG_API = "https://api.wordpress.org/plugins/info/1.2/"

REFERENCE_TOTAL_SITES = 1000

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

def load_observation(fid):
    d = f"{FINDINGS_BASE}/find-{fid}"
    entries = [x for x in os.listdir(d) if x != "resch" and os.path.isdir(os.path.join(d, x))]
    if not entries:
        return None
    with open(os.path.join(d, entries[0], "metadata.json")) as f:
        return json.load(f)

def get_all_plugins():
    plugins = set()
    for cname, finds in CANONICAL_CAMPAIGNS.items():
        for fid in sorted(finds):
            data = load_observation(fid)
            if data is None:
                continue
            for section in ('plugin_info', 'theme_info'):
                for comp_name, comp_data in data.get(section, {}).items():
                    has_vuln = False
                    for vuln in comp_data.get('vulnerabilities_cve', []):
                        obs_ver = parse_ver(vuln.get('version'))
                        max_ver = parse_affected_range(vuln.get('affected_range'))
                        if obs_ver is not None and max_ver is not None and obs_ver <= max_ver:
                            has_vuln = True
                            break
                    if has_vuln:
                        if section == 'plugin_info':
                            plugins.add(comp_name)
    return plugins

def fetch_wporg_installs(slug):
    url = f"{WPORG_API}?action=plugin_information&slug={slug}&fields=active_installs"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            if isinstance(data, dict) and 'active_installs' in data:
                return data['active_installs']
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError,
            TimeoutError, OSError) as e:
        pass
    return None

def main():
    plugins = get_all_plugins()
    plugin_slugs = sorted([p for p in plugins if not p.startswith('theme:')])
    theme_slugs = sorted([p.replace('theme:', '') for p in plugins if p.startswith('theme:')])

    print(f"Found {len(plugin_slugs)} plugin slugs and {len(theme_slugs)} theme slugs")
    print(f"Fetching wordpress.org install counts for {len(plugin_slugs)} plugins...")

    installs = {}
    max_installs = 0
    failed = []

    for i, slug in enumerate(plugin_slugs):
        count = fetch_wporg_installs(slug)
        if count is not None:
            installs[slug] = count
            if count > max_installs:
                max_installs = count
            print(f"  [{i+1}/{len(plugin_slugs)}] {slug}: {count:,}")
        else:
            failed.append(slug)
            print(f"  [{i+1}/{len(plugin_slugs)}] {slug}: NOT FOUND")
        time.sleep(0.3)

    if failed:
        print(f"\nFailed to fetch {len(failed)} plugins: {', '.join(failed[:10])}...")

    if max_installs == 0:
        print("ERROR: No install data retrieved.")
        sys.exit(1)

    ANCHOR_PREVALENCE = 0.30
    scale_factor = ANCHOR_PREVALENCE * REFERENCE_TOTAL_SITES / max_installs

    baseline = {}
    for slug, count in installs.items():
        estimated_count = max(1, round(count * scale_factor))
        baseline[slug] = estimated_count

    for theme in theme_slugs:
        baseline[f"theme:{theme}"] = max(1, round(REFERENCE_TOTAL_SITES * 0.02))

    output = {
        "total_sites": REFERENCE_TOTAL_SITES,
        "source": "wordpress.org API (proxy estimate)",
        "anchor_plugin": "most popular",
        "anchor_prevalence": ANCHOR_PREVALENCE,
        "max_installs_observed": max_installs,
        "plugins": baseline
    }

    with open(OUTPUT_PATH, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\nWrote baseline to {OUTPUT_PATH}")
    print(f"  Total plugins: {len(baseline)}")
    print(f"  Reference total sites: {REFERENCE_TOTAL_SITES}")
    print(f"  Max installs (anchor): {max_installs:,}")
    print(f"  Scale factor: {scale_factor:.6f}")

    sorted_baseline = sorted(baseline.items(), key=lambda x: -x[1])
    print(f"\nTop-10 estimated baseline prevalence (out of {REFERENCE_TOTAL_SITES}):")
    for slug, count in sorted_baseline[:10]:
        print(f"  {slug}: {count} ({count/REFERENCE_TOTAL_SITES*100:.1f}%)")

    print(f"\nBottom-10 (campaign-characteristic candidates):")
    for slug, count in sorted_baseline[-10:]:
        print(f"  {slug}: {count} ({count/REFERENCE_TOTAL_SITES*100:.1f}%)")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import json
import os
import sys
from collections import defaultdict
from packaging.version import Version, InvalidVersion
from campaign_mapping import CANONICAL_CAMPAIGNS, CAMPAIGN_FAMILIES, FINDINGS_BASE

BASELINE_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "baselines", "baseline_plugins.json")

ALREADY_AUDITED = {
    "add-to-any",
    "woolentor-addons",
    "download-monitor",
    "ali-post-editor",
}

def parse_ver(v):
    try:
        return Version(str(v))
    except (InvalidVersion, TypeError):
        return None

def load_observation(fid):
    d = f"{FINDINGS_BASE}/find-{fid}"
    if not os.path.exists(d):
        return None
    entries = [x for x in os.listdir(d) if x != "resch" and os.path.isdir(os.path.join(d, x))]
    if not entries:
        return None
    with open(os.path.join(d, entries[0], "metadata.json")) as f:
        return json.load(f)

def load_baseline(path):
    with open(path) as f:
        data = json.load(f)
    return data['total_sites'], data['plugins']

def get_component_details(data):
    total_sites = data.get('distinct_sites', 0)
    result = {}
    for section in ('plugin_info', 'theme_info'):
        for comp_name, comp_data in data.get(section, {}).items():
            prefix = "theme:" if section == 'theme_info' else ""
            key = f"{prefix}{comp_name}"
            freq = comp_data.get('frequency', 0)
            has_vuln = False
            cves = []
            vuln_types = set()
            versions = set()

            for ver_entry in comp_data.get('versions', []):
                if isinstance(ver_entry, dict):
                    v = ver_entry.get('version', '')
                else:
                    v = str(ver_entry)
                if v:
                    versions.add(v)

            top_ver = comp_data.get('version', '')
            if top_ver:
                versions.add(str(top_ver))

            for vuln in comp_data.get('vulnerabilities_cve', []):
                obs_ver = parse_ver(vuln.get('version'))
                max_ver_str = vuln.get('affected_range', '')
                max_ver = None
                if max_ver_str and ' - ' in max_ver_str:
                    parts = max_ver_str.split(' - ', 1)
                    max_ver = parse_ver(parts[1].strip())

                cve_id = vuln.get('cve_id', vuln.get('id', 'unknown'))
                cve_type = vuln.get('vulnerability_type', vuln.get('type', 'unknown'))

                if obs_ver is not None and max_ver is not None and obs_ver <= max_ver:
                    has_vuln = True
                    cves.append(cve_id)
                    vuln_types.add(cve_type)

            result[key] = {
                'freq': freq,
                'total_sites': total_sites,
                'has_vuln': has_vuln,
                'versions': versions,
                'cves': cves,
                'vuln_types': vuln_types,
            }
    return result

def main():
    baseline_total, baseline_plugins = load_baseline(BASELINE_PATH)

    suspect_pool = defaultdict(lambda: {
        'campaigns': [],
        'total_freq': 0,
        'total_sites': 0,
        'versions': set(),
        'enrichment_values': [],
        'base_pct': 0,
    })

    fake_pool = defaultdict(lambda: {
        'campaigns': [],
        'total_freq': 0,
        'total_sites': 0,
        'versions': set(),
    })

    niche_no_cve_pool = defaultdict(lambda: {
        'campaigns': [],
        'total_freq': 0,
        'total_sites': 0,
        'versions': set(),
    })

    all_components = defaultdict(lambda: {
        'campaigns': set(),
        'has_vuln_ever': False,
        'cve_count': 0,
        'versions': set(),
    })

    for cname, finds in CANONICAL_CAMPAIGNS.items():
        comp_freq = defaultdict(int)
        comp_details = {}
        total_sites = 0

        for fid in sorted(finds):
            data = load_observation(fid)
            if data is None:
                continue
            obs_sites = data.get('distinct_sites', 0)
            total_sites += obs_sites
            details = get_component_details(data)
            for comp, info in details.items():
                comp_freq[comp] += info['freq']
                if comp not in comp_details:
                    comp_details[comp] = info
                else:
                    comp_details[comp]['versions'].update(info['versions'])
                    comp_details[comp]['cves'].extend(info['cves'])
                    comp_details[comp]['vuln_types'].update(info['vuln_types'])
                    if info['has_vuln']:
                        comp_details[comp]['has_vuln'] = True

        if total_sites == 0:
            continue

        for comp, freq in comp_freq.items():
            info = comp_details[comp]
            comp_pct = freq / total_sites * 100
            base_count = baseline_plugins.get(comp.replace("theme:", ""), 0)
            base_pct = base_count / baseline_total * 100 if baseline_total > 0 else 0

            if base_pct > 0:
                enrichment = comp_pct / base_pct
            elif comp_pct > 0:
                enrichment = float('inf')
            else:
                enrichment = 0.0

            all_components[comp]['campaigns'].add(cname)
            all_components[comp]['versions'].update(info['versions'])
            if info['has_vuln']:
                all_components[comp]['has_vuln_ever'] = True
            all_components[comp]['cve_count'] += len(info['cves'])

            has_vuln = info['has_vuln']
            in_baseline = base_count > 0

            slug = comp.replace("theme:", "")
            if slug in ALREADY_AUDITED:
                continue

            if not has_vuln and in_baseline and enrichment >= 5.0:
                pool = suspect_pool[comp]
                pool['campaigns'].append(cname)
                pool['total_freq'] += freq
                pool['total_sites'] += total_sites
                pool['versions'].update(info['versions'])
                pool['enrichment_values'].append(enrichment)
                pool['base_pct'] = base_pct

            elif not has_vuln and not in_baseline and comp_pct >= 3.0:
                pool = niche_no_cve_pool[comp]
                pool['campaigns'].append(cname)
                pool['total_freq'] += freq
                pool['total_sites'] += total_sites
                pool['versions'].update(info['versions'])

    print("=" * 100)
    print("SUSPECT-SIGNAL ZERO-DAY CANDIDATES (high enrichment, no known CVE, in baseline)")
    print("These are plugins/themes with disproportionate presence on compromised sites")
    print("but NO publicly disclosed vulnerability to explain their concentration.")
    print("=" * 100)

    suspect_rows = []
    for comp, info in suspect_pool.items():
        med_enr = sorted(info['enrichment_values'])[len(info['enrichment_values'])//2] if info['enrichment_values'] else 0
        max_enr = max(info['enrichment_values']) if info['enrichment_values'] else 0
        avg_pct = info['total_freq'] / info['total_sites'] * 100 if info['total_sites'] > 0 else 0
        suspect_rows.append((comp, len(set(info['campaigns'])), avg_pct, info['base_pct'], med_enr, max_enr, info['versions'], info['campaigns']))

    suspect_rows.sort(key=lambda x: (-x[5], -x[1], -x[2]))

    print(f"\n{'Component':<35} {'#Camp':>5} {'Comp%':>7} {'Base%':>7} {'MaxEnr':>9} {'Versions':<30} {'Campaigns'}")
    print("-" * 140)
    for comp, ncampaigns, avg_pct, base_pct, med_enr, max_enr, versions, campaigns in suspect_rows:
        ver_str = ', '.join(sorted(versions)[:3]) if versions else '?'
        camp_str = ', '.join(sorted(set(campaigns)))
        enr_str = f"{max_enr:.1f}x" if max_enr != float('inf') else ">>1"
        print(f"{comp:<35} {ncampaigns:>5} {avg_pct:>6.1f}% {base_pct:>6.1f}% {enr_str:>9} {ver_str:<30} {camp_str}")

    print(f"\nTotal Suspect candidates: {len(suspect_rows)}")

    print("\n" + "=" * 100)
    print("NICHE NO-CVE COMPONENTS (absent from baseline, no CVE, >= 3% prevalence)")
    print("Could be attacker-created fakes OR niche plugins with undisclosed vulns.")
    print("=" * 100)

    niche_rows = []
    for comp, info in niche_no_cve_pool.items():
        avg_pct = info['total_freq'] / info['total_sites'] * 100 if info['total_sites'] > 0 else 0
        niche_rows.append((comp, len(set(info['campaigns'])), avg_pct, info['versions'], info['campaigns']))

    niche_rows.sort(key=lambda x: (-x[1], -x[2]))

    print(f"\n{'Component':<35} {'#Camp':>5} {'Comp%':>7} {'Versions':<30} {'Campaigns'}")
    print("-" * 120)
    for comp, ncampaigns, avg_pct, versions, campaigns in niche_rows:
        ver_str = ', '.join(sorted(versions)[:3]) if versions else '?'
        camp_str = ', '.join(sorted(set(campaigns)))
        print(f"{comp:<35} {ncampaigns:>5} {avg_pct:>6.1f}% {ver_str:<30} {camp_str}")

    print(f"\nTotal Niche no-CVE candidates: {len(niche_rows)}")

    print("\n" + "=" * 100)
    print("PRIORITIZED INVESTIGATION LIST (combine Suspect + multi-campaign Niche)")
    print("=" * 100)

    priority = []
    for comp, ncampaigns, avg_pct, base_pct, med_enr, max_enr, versions, campaigns in suspect_rows:
        priority.append((comp, ncampaigns, avg_pct, max_enr, 'Suspect', versions, campaigns))
    for comp, ncampaigns, avg_pct, versions, campaigns in niche_rows:
        if ncampaigns >= 2 or avg_pct >= 5.0:
            priority.append((comp, ncampaigns, avg_pct, float('inf'), 'Niche-NoCVE', versions, campaigns))

    priority.sort(key=lambda x: (-x[1], -x[3] if x[3] != float('inf') else -1e9, -x[2]))

    print(f"\n{'#':>3} {'Component':<35} {'Signal':<12} {'#Camp':>5} {'Comp%':>7} {'Versions':<25} {'Campaigns'}")
    print("-" * 130)
    for i, (comp, ncampaigns, avg_pct, max_enr, signal, versions, campaigns) in enumerate(priority, 1):
        ver_str = ', '.join(sorted(versions)[:3]) if versions else '?'
        camp_str = ', '.join(sorted(set(campaigns)))
        print(f"{i:>3} {comp:<35} {signal:<12} {ncampaigns:>5} {avg_pct:>6.1f}% {ver_str:<25} {camp_str}")

    print(f"\nTotal prioritized candidates: {len(priority)}")

if __name__ == "__main__":
    main()

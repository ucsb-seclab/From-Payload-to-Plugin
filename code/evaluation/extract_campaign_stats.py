#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import json, os
from collections import Counter
from packaging.version import Version, InvalidVersion
from campaign_mapping import (CAMPAIGN_SUMMARY_FINDINGS, CAMPAIGN_FAMILIES,
                               FAMILY_COLORS, FINDINGS_BASE)
import numpy as np

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

def classify_vuln(title):
    t = title.lower()
    if 'stored' in t and ('xss' in t or 'cross-site scripting' in t):
        return 'Stored XSS'
    elif 'reflected' in t and ('xss' in t or 'cross-site scripting' in t):
        return 'Reflected XSS'
    elif 'sql injection' in t:
        return 'SQL Injection'
    elif any(x in t for x in ['privilege', 'authorization', 'access control',
                               'authentication', 'missing auth']):
        return 'Auth/Privilege'
    elif 'csrf' in t or 'cross-site request forgery' in t:
        return 'CSRF'
    elif any(x in t for x in ['file upload', 'file inclusion', 'lfi', 'rfi',
                               'arbitrary file']):
        return 'File Upload/Incl.'
    elif any(x in t for x in ['remote code', 'code execution', 'rce',
                               'code injection']):
        return 'RCE'
    elif any(x in t for x in ['information', 'disclosure', 'exposure']):
        return 'Info Disclosure'
    elif 'traversal' in t:
        return 'Path Traversal'
    return None

def load_find(fid):
    d = f"{FINDINGS_BASE}/find-{fid}"
    if not os.path.isdir(d):
        return None
    entries = [x for x in os.listdir(d) if x != "resch" and os.path.isdir(os.path.join(d, x))]
    if not entries:
        return None
    with open(os.path.join(d, entries[0], "metadata.json")) as f:
        return json.load(f)

def get_vuln_details(data):
    comps = set()
    cves = set()
    vuln_types = Counter()

    component_instances = data.get('component_instances')
    records = component_instances if component_instances is not None else [data]

    for record in records:
        for section in ('plugin_info', 'theme_info'):
            for comp_name, comp_data in record.get(section, {}).items():
                prefix = "theme:" if section == 'theme_info' else ""
                vulnerabilities = comp_data.get('vulnerabilities_cve', [])
                matched = []
                for vuln in vulnerabilities:
                    obs_ver = parse_ver(vuln.get('version'))
                    max_ver = parse_affected_range(vuln.get('affected_range'))
                    if obs_ver is not None and max_ver is not None and obs_ver <= max_ver:
                        matched.append(vuln)

                if not matched:
                    continue

                comps.add(f"{prefix}{comp_name}")
                cve_records = vulnerabilities if component_instances is not None else matched
                for vuln in cve_records:
                    if vuln.get('cve'):
                        cves.add(vuln['cve'])

                for vuln in matched:
                    vt = classify_vuln(vuln.get('title', ''))
                    if vt:
                        vuln_types[vt] += 1

    has_stoxss = vuln_types.get('Stored XSS', 0) > 0
    has_sqli = vuln_types.get('SQL Injection', 0) > 0
    has_auth = vuln_types.get('Auth/Privilege', 0) > 0

    return comps, cves, has_stoxss, has_sqli, has_auth

print("=" * 90)
print("UPDATED CAMPAIGN SUMMARY TABLE")
print(f"Total canonical campaigns: {len(CAMPAIGN_SUMMARY_FINDINGS)}")
total_obs = sum(len(v) for v in CAMPAIGN_SUMMARY_FINDINGS.values())
print(f"Total observations: {total_obs}")
print("=" * 90)

print(f"\n{'Campaign':<15} {'Family':<22} {'Obs':>4} {'Sites':>6} "
      f"{'V.Comp':>7} {'CVEs':>5} {'StoXSS':>7} {'SQLi':>5} {'Auth':>5}")
print("-" * 90)

campaign_data = []

agg_obs = 0
agg_sites = 0
all_comps = []
all_cves = []
stoxss_count = 0
sqli_count = 0
auth_count = 0

for cname, finds in CAMPAIGN_SUMMARY_FINDINGS.items():
    family = CAMPAIGN_FAMILIES[cname]
    total_sites = 0
    total_comps = set()
    total_cves = set()
    has_stoxss_any = False
    has_sqli_any = False
    has_auth_any = False

    site_list = []

    for fid in sorted(finds):
        data = load_find(fid)
        if data is None:
            continue
        sites = data.get('distinct_sites', 0)
        total_sites += sites
        site_list.append(sites)

        comps, cves, has_sx, has_sq, has_au = get_vuln_details(data)
        total_comps.update(comps)
        total_cves.update(cves)

        has_stoxss_any = has_stoxss_any or has_sx
        has_sqli_any = has_sqli_any or has_sq
        has_auth_any = has_auth_any or has_au

    obs_count = len(finds)
    vuln_comps_count = len(total_comps)
    cves_count = len(total_cves)

    sx = '\\cmark' if has_stoxss_any else '--'
    sq = '\\cmark' if has_sqli_any else '--'
    au = '\\cmark' if has_auth_any else '--'

    print(f"{cname:<15} {family:<22} {obs_count:>4} {total_sites:>6} "
          f"{vuln_comps_count:>7} {cves_count:>5} "
          f"{'Y' if has_stoxss_any else '-':>7} "
          f"{'Y' if has_sqli_any else '-':>5} "
          f"{'Y' if has_auth_any else '-':>5}")

    campaign_data.append({
        'name': cname,
        'family': family,
        'obs': obs_count,
        'sites': total_sites,
        'site_list': site_list,
        'vuln_comps': vuln_comps_count,
        'cves': cves_count,
        'has_stoxss': has_stoxss_any,
        'has_sqli': has_sqli_any,
        'has_auth': has_auth_any,
    })

    agg_obs += obs_count
    agg_sites += total_sites
    all_comps.append(vuln_comps_count)
    all_cves.append(cves_count)
    if has_stoxss_any:
        stoxss_count += 1
    if has_sqli_any:
        sqli_count += 1
    if has_auth_any:
        auth_count += 1

print("-" * 90)
print(f"{'TOTAL':<15} {'':<22} {agg_obs:>4} {agg_sites:>6} "
      f"{np.median(all_comps):>7.0f} {np.median(all_cves):>5.0f} "
      f"{stoxss_count:>4}/{len(CAMPAIGN_SUMMARY_FINDINGS)} "
      f"{sqli_count:>2}/{len(CAMPAIGN_SUMMARY_FINDINGS)} "
      f"{auth_count:>2}/{len(CAMPAIGN_SUMMARY_FINDINGS)}")

print(f"\nMedian vuln components: {np.median(all_comps):.0f}")
print(f"Median CVEs: {np.median(all_cves):.0f}")

families = Counter(CAMPAIGN_FAMILIES[c] for c in CAMPAIGN_SUMMARY_FINDINGS)
print(f"\nBehavioral families ({len(families)}):")
for fam, cnt in sorted(families.items(), key=lambda x: -x[1]):
    print(f"  {fam}: {cnt} campaigns")

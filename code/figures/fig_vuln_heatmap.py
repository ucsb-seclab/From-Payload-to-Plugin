#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np
import json
from collections import Counter
from packaging.version import Version, InvalidVersion
from campaign_mapping import (CANONICAL_CAMPAIGNS, CAMPAIGN_FAMILIES,
                               FAMILY_COLORS)

FINDINGS_BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "findings")


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


vuln_types_full = [
    'Stored XSS', 'Reflected XSS', 'SQL Injection', 'Auth/Privilege',
    'CSRF', 'File Upload/Incl.', 'RCE', 'Info Disclosure', 'Path Traversal',
    'Other'
]
vuln_labels = [
    'Sto. XSS', 'Ref. XSS', 'SQLi', 'Auth/Priv.',
    'CSRF', 'File Upl.', 'RCE', 'Info Disc.', 'Path Trav.',
    'Other'
]


def classify_vuln(title):
    title_lower = title.lower()
    if 'stored' in title_lower and ('xss' in title_lower or 'cross-site scripting' in title_lower):
        return 'Stored XSS'
    elif 'reflected' in title_lower and ('xss' in title_lower or 'cross-site scripting' in title_lower):
        return 'Reflected XSS'
    elif 'sql injection' in title_lower:
        return 'SQL Injection'
    elif any(x in title_lower for x in ['privilege', 'authorization', 'access control', 'authentication', 'missing auth']):
        return 'Auth/Privilege'
    elif 'csrf' in title_lower or 'cross-site request forgery' in title_lower:
        return 'CSRF'
    elif any(x in title_lower for x in ['file upload', 'file inclusion', 'lfi', 'rfi', 'arbitrary file']):
        return 'File Upload/Incl.'
    elif any(x in title_lower for x in ['remote code', 'code execution', 'rce']):
        return 'RCE'
    elif any(x in title_lower for x in ['information', 'disclosure', 'exposure']):
        return 'Info Disclosure'
    elif 'traversal' in title_lower:
        return 'Path Traversal'
    return None


EXCLUDE_CAMPAIGNS = {'YWXILoader'}
campaign_names = [c for c in CANONICAL_CAMPAIGNS.keys() if c not in EXCLUDE_CAMPAIGNS]
matrix = np.zeros((len(campaign_names), len(vuln_types_full)))

for ci, cname in enumerate(campaign_names):
    finds = CANONICAL_CAMPAIGNS[cname]
    type_counter = Counter()
    seen_vulns = set()
    for fid in finds:
        d = f"{FINDINGS_BASE}/find-{fid}"
        if not os.path.isdir(d):
            continue
        entries = [x for x in os.listdir(d) if x != "resch" and os.path.isdir(os.path.join(d, x))]
        if not entries:
            continue
        with open(os.path.join(d, entries[0], "metadata.json")) as f:
            data = json.load(f)
        for section in ('plugin_info', 'theme_info'):
            for slug, pdata in data.get(section, {}).items():
                for v in pdata.get('vulnerabilities_cve', []):
                    obs_ver = parse_ver(v.get('version'))
                    max_ver = parse_affected_range(v.get('affected_range'))
                    if obs_ver is not None and max_ver is not None and obs_ver <= max_ver:
                        cve_id = v.get('cve')
                        if not cve_id:
                            continue
                        if cve_id in seen_vulns:
                            continue
                        seen_vulns.add(cve_id)
                        vt = classify_vuln(v.get('title', '')) or 'Other'
                        type_counter[vt] += 1
    for ti, vtype in enumerate(vuln_types_full):
        matrix[ci, ti] = type_counter.get(vtype, 0)

row_sums = matrix.sum(axis=1, keepdims=True)
row_sums[row_sums == 0] = 1
matrix_norm = matrix / row_sums

fig, ax = plt.subplots(figsize=(3.45, 4.8))

im = ax.imshow(matrix_norm, cmap='YlOrRd', aspect='auto', vmin=0, vmax=0.6)

ax.set_yticks(np.arange(len(campaign_names)))
ax.set_yticklabels(campaign_names, fontsize=5.5, fontfamily='sans-serif')

ax.set_xticks(np.arange(len(vuln_labels)))
ax.set_xticklabels(vuln_labels, fontsize=5.5, rotation=45, ha='left',
                   rotation_mode='anchor', fontfamily='sans-serif')
ax.xaxis.set_ticks_position('top')
ax.xaxis.set_label_position('top')

for i in range(len(campaign_names)):
    for j in range(len(vuln_types_full)):
        val = int(matrix[i, j])
        if val > 0:
            color = 'white' if matrix_norm[i, j] > 0.35 else 'black'
            ax.text(j, i, str(val), ha='center', va='center',
                    fontsize=4.5, color=color, fontfamily='sans-serif')

ax.set_xticks(np.arange(len(vuln_labels) + 1) - 0.5, minor=True)
ax.set_yticks(np.arange(len(campaign_names) + 1) - 0.5, minor=True)
ax.grid(which='minor', color='white', linewidth=0.5)
ax.tick_params(which='minor', bottom=False, left=False, top=False)

cbar = plt.colorbar(im, ax=ax, orientation='horizontal', shrink=0.85,
                    pad=0.06, aspect=30)
cbar.set_label('Proportion within campaign', fontsize=5.5,
               fontfamily='sans-serif')
cbar.ax.tick_params(labelsize=5)
cbar.ax.xaxis.set_major_locator(mticker.MaxNLocator(5))

plt.tight_layout(pad=0.3)

plt.savefig('fig_vuln_heatmap.pdf',
            bbox_inches='tight', dpi=300)
plt.savefig('fig_vuln_heatmap.png',
            bbox_inches='tight', dpi=300)
print("Saved fig_vuln_heatmap.pdf (single-column) and .png")

#!/usr/bin/env python3

import json
import os
import sys
import numpy as np
from collections import defaultdict
from packaging.version import Version, InvalidVersion
from campaign_mapping import CANONICAL_CAMPAIGNS, CAMPAIGN_FAMILIES, FINDINGS_BASE

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

def load_observation(fid):
    d = f"{FINDINGS_BASE}/find-{fid}"
    entries = [x for x in os.listdir(d) if x != "resch" and os.path.isdir(os.path.join(d, x))]
    if not entries:
        return None
    with open(os.path.join(d, entries[0], "metadata.json")) as f:
        return json.load(f)

def get_plugin_prevalence(data):
    total_sites = data.get('distinct_sites', 0)
    result = {}
    for section in ('plugin_info', 'theme_info'):
        for comp_name, comp_data in data.get(section, {}).items():
            prefix = "theme:" if section == 'theme_info' else ""
            key = f"{prefix}{comp_name}"
            freq = comp_data.get('frequency', 0)
            has_vuln = False
            for vuln in comp_data.get('vulnerabilities_cve', []):
                obs_ver = parse_ver(vuln.get('version'))
                max_ver = parse_affected_range(vuln.get('affected_range'))
                if obs_ver is not None and max_ver is not None and obs_ver <= max_ver:
                    has_vuln = True
                    break
            result[key] = (freq, total_sites, has_vuln)
    return result

def load_baseline(path):
    with open(path) as f:
        data = json.load(f)
    total = data['total_sites']
    plugins = data['plugins']
    return total, plugins

def main():
    if not os.path.exists(BASELINE_PATH):
        print(f"ERROR: Baseline file not found at {BASELINE_PATH}")
        print(f"\nPlease create {BASELINE_PATH} with the following format:")
        print(json.dumps({
            "total_sites": 1000,
            "plugins": {
                "contact-form-7": 280,
                "elementor": 250,
                "url-shortify": 3,
                "...": "..."
            }
        }, indent=2))
        print("\nTo generate this, fingerprint ~1000 random non-compromised")
        print("sites from your 850K watchlist using the same frontend")
        print("fingerprinting as the campaign analysis.")

        print("\n" + "=" * 70)
        print("Compromised-side plugin prevalence (no baseline to compare against)")
        print("=" * 70)
        _print_compromised_only()
        sys.exit(1)

    baseline_total, baseline_plugins = load_baseline(BASELINE_PATH)
    print(f"Baseline: {baseline_total} sites, {len(baseline_plugins)} plugins")

    all_enrichments = {}

    campaign_tables = {}

    for cname, finds in CANONICAL_CAMPAIGNS.items():
        plugin_freq = defaultdict(int)
        plugin_vuln = {}
        total_sites = 0

        for fid in sorted(finds):
            data = load_observation(fid)
            if data is None:
                continue
            obs_sites = data.get('distinct_sites', 0)
            total_sites += obs_sites
            prev = get_plugin_prevalence(data)
            for plugin, (freq, _, has_vuln) in prev.items():
                plugin_freq[plugin] += freq
                if has_vuln:
                    plugin_vuln[plugin] = True

        if total_sites == 0:
            continue

        rows = []
        for plugin, freq in plugin_freq.items():
            comp_pct = freq / total_sites * 100
            base_count = baseline_plugins.get(plugin.replace("theme:", ""), 0)
            base_pct = base_count / baseline_total * 100 if baseline_total > 0 else 0

            if base_pct > 0:
                enrichment = comp_pct / base_pct
            elif comp_pct > 0:
                enrichment = float('inf')
            else:
                enrichment = 0.0

            has_vuln = plugin_vuln.get(plugin, False)
            rows.append((plugin, comp_pct, base_pct, enrichment, has_vuln))

            if plugin not in all_enrichments:
                all_enrichments[plugin] = []
            all_enrichments[plugin].append((cname, comp_pct, base_pct, enrichment))

        rows.sort(key=lambda x: (-x[3] if x[3] != float('inf') else -1e9, -x[1]))
        campaign_tables[cname] = rows

    print("\n" + "=" * 90)
    print("PER-CAMPAIGN TOP-3 ENRICHED VULNERABLE COMPONENTS")
    print("=" * 90)
    print(f"{'Campaign':<15} {'Plugin':<25} {'Comp%':>7} {'Base%':>7} {'Enrich':>8} {'Vuln':>5}")
    print("-" * 90)

    for cname in CANONICAL_CAMPAIGNS:
        rows = campaign_tables.get(cname, [])
        vuln_rows = [r for r in rows if r[4]]
        for i, (plugin, comp_pct, base_pct, enrichment, _) in enumerate(vuln_rows[:3]):
            label = cname if i == 0 else ""
            enr_str = f"{enrichment:.1f}x" if enrichment != float('inf') else ">>1"
            print(f"{label:<15} {plugin:<25} {comp_pct:>6.1f}% {base_pct:>6.1f}% {enr_str:>8} {'Y':>5}")
        if not vuln_rows:
            print(f"{cname:<15} {'(no vulnerable components)':<25}")
        print()

    print("\n" + "=" * 90)
    print("GLOBAL ENRICHMENT TABLE")
    print("=" * 90)

    top_plugins = set()
    for cname, rows in campaign_tables.items():
        vuln_rows = [r for r in rows if r[4]]
        for r in vuln_rows[:3]:
            top_plugins.add(r[0])

    global_rows = []
    for plugin in top_plugins:
        entries = all_enrichments.get(plugin, [])
        if not entries:
            continue
        comp_pcts = [e[1] for e in entries if e[1] > 0]
        base_pct = entries[0][2]
        enrichments = [e[3] for e in entries if e[3] > 0 and e[3] != float('inf')]
        n_campaigns = len(comp_pcts)
        median_comp = np.median(comp_pcts) if comp_pcts else 0
        median_enr = np.median(enrichments) if enrichments else float('inf')

        global_rows.append((plugin, n_campaigns, median_comp, base_pct, median_enr))

    global_rows.sort(key=lambda x: (-x[4] if x[4] != float('inf') else -1e9, -x[2]))

    print(f"{'Plugin':<25} {'#Camp':>6} {'MedComp%':>9} {'Base%':>7} {'MedEnrich':>10}")
    print("-" * 70)
    for plugin, n_camp, med_comp, base_pct, med_enr in global_rows[:20]:
        enr_str = f"{med_enr:.1f}x" if med_enr != float('inf') else ">>1"
        print(f"{plugin:<25} {n_camp:>6} {med_comp:>8.1f}% {base_pct:>6.1f}% {enr_str:>10}")

    print("\n" + "=" * 90)
    print("LATEX TABLE: Top enriched components (copy into paper)")
    print("=" * 90)
    _print_latex_table(global_rows)

    print("\n" + "=" * 90)
    print("COMPONENT CLASSIFICATION")
    print("=" * 90)
    ENRICHMENT_THRESHOLD = 2.0
    characteristic = [(p, n, mc, bp, me) for p, n, mc, bp, me in global_rows
                      if me >= ENRICHMENT_THRESHOLD or me == float('inf')]
    shared = [(p, n, mc, bp, me) for p, n, mc, bp, me in global_rows
              if me < ENRICHMENT_THRESHOLD and me != float('inf')]

    print(f"\nCampaign-characteristic (enrichment >= {ENRICHMENT_THRESHOLD}x): {len(characteristic)}")
    for p, n, mc, bp, me in characteristic[:10]:
        enr_str = f"{me:.1f}x" if me != float('inf') else ">>1"
        print(f"  {p}: {enr_str} ({n} campaigns)")

    print(f"\nShared-surface (enrichment < {ENRICHMENT_THRESHOLD}x): {len(shared)}")
    for p, n, mc, bp, me in shared:
        enr_str = f"{me:.1f}x"
        print(f"  {p}: {enr_str} ({n} campaigns)")

def _print_latex_table(global_rows):
    print(r"\begin{table}[t]")
    print(r"\centering")
    print(r"\small")
    print(r"\caption{Enrichment ratios for the most prevalent attributed components. "
          r"\emph{Comp.\%} is the median prevalence across campaigns where the component appears; "
          r"\emph{Base\%} is the prevalence in the non-compromised baseline sample. "
          r"Components with enrichment $\gg$1 are campaign-characteristic; "
          r"those near 1 reflect general WordPress popularity.}")
    print(r"\label{tab:enrichment}")
    print(r"\begin{tabular}{@{}l r r r r@{}}")
    print(r"\toprule")
    print(r"\textbf{Component} & \textbf{\#Camp.} & \textbf{Comp.\%} & \textbf{Base\%} & \textbf{Enrichment} \\")
    print(r"\midrule")

    for plugin, n_camp, med_comp, base_pct, med_enr in global_rows[:15]:
        name = plugin.replace("_", r"\_").replace("theme:", r"\textit{theme:}")
        enr_str = f"{med_enr:.1f}$\\times$" if med_enr != float('inf') else "$\\gg$1"
        print(f"{name} & {n_camp} & {med_comp:.1f} & {base_pct:.1f} & {enr_str} \\\\")

    print(r"\bottomrule")
    print(r"\end{tabular}")
    print(r"\end{table}")

def _print_compromised_only():
    plugin_campaigns = defaultdict(set)
    plugin_total_freq = defaultdict(int)
    plugin_total_sites = defaultdict(int)

    for cname, finds in CANONICAL_CAMPAIGNS.items():
        for fid in sorted(finds):
            data = load_observation(fid)
            if data is None:
                continue
            prev = get_plugin_prevalence(data)
            obs_sites = data.get('distinct_sites', 0)
            for plugin, (freq, _, has_vuln) in prev.items():
                if has_vuln:
                    plugin_campaigns[plugin].add(cname)
                    plugin_total_freq[plugin] += freq
                    plugin_total_sites[plugin] += obs_sites

    rows = []
    for plugin in plugin_campaigns:
        n_camp = len(plugin_campaigns[plugin])
        avg_pct = plugin_total_freq[plugin] / plugin_total_sites[plugin] * 100 if plugin_total_sites[plugin] > 0 else 0
        rows.append((plugin, n_camp, avg_pct))

    rows.sort(key=lambda x: (-x[1], -x[2]))
    print(f"\n{'Plugin':<25} {'#Camp':>6} {'AvgComp%':>9}")
    print("-" * 45)
    for plugin, n_camp, avg_pct in rows[:20]:
        print(f"{plugin:<25} {n_camp:>6} {avg_pct:>8.1f}%")

    needed = sorted(set(plugin_campaigns.keys()))
    print(f"\n── Plugins needing baseline data ({len(needed)}) ──")
    for p in needed:
        print(f"  {p}")

if __name__ == "__main__":
    main()

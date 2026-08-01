#!/usr/bin/env python3

import json, os, math
from collections import defaultdict
from pathlib import Path

DIFF = Path(os.environ.get("DIFF_RESULTS", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "data",
    "diff-20260220_035824-watchlist_batch_20260218_193004-watchlist_batch_20260219_210057"
)))

bg_plugin_sites = defaultdict(int)
bg_total_sites = 0
n_sigs = 0

for subdir in ["NEWLY ADDED", "EDITED"]:
    sig_root = DIFF / subdir
    if not sig_root.exists():
        continue
    for sig_dir in sorted(sig_root.iterdir()):
        meta_file = sig_dir / "metadata.json"
        if not meta_file.exists():
            continue
        try:
            with open(meta_file) as f:
                meta = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        distinct = meta.get("distinct_sites", 0)
        if distinct == 0:
            continue

        bg_total_sites += distinct
        n_sigs += 1

        for plugin, info in meta.get("plugin_info", {}).items():
            freq = info.get("frequency", 0)
            bg_plugin_sites[plugin] += freq

print(f"Background (single diff batch): {n_sigs:,} signatures, "
      f"{bg_total_sites:,} site-occurrences")
print(f"Unique plugins in background: {len(bg_plugin_sites)}")

bg_prev = {p: (f / bg_total_sites) * 100
            for p, f in bg_plugin_sites.items()}

print("\n── Top-25 background plugins (measured) ──")
for p, pct in sorted(bg_prev.items(), key=lambda x: -x[1])[:25]:
    print(f"  {p:30s} {pct:6.2f}%  ({bg_plugin_sites[p]:,} sites)")

CR = Path(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "results", "campaign_report.json"))
with open(CR) as f:
    cr = json.load(f)

campaign_plugins = {}
for cname, camp in cr["campaigns"].items():
    td = camp["total_unique_domains"]
    if td == 0:
        continue
    plugs = {}
    for obs in camp["observations"]:
        for pname, pinfo in obs.get("plugins", {}).items():
            if pname not in plugs or pinfo["freq"] > plugs[pname]["freq"]:
                plugs[pname] = {
                    "freq": pinfo["freq"],
                    "pct": (pinfo["freq"] / td) * 100,
                    "version": pinfo.get("version", "?"),
                    "cves": pinfo.get("cve_ids", []),
                }
    campaign_plugins[cname] = {"total": td, "plugins": plugs}

print(f"\nCampaigns loaded: {len(campaign_plugins)}")

paper_to_cr = {
    "HexArray-A": "EpomAd-A",
    "HexArray-B": "EpomAd-B",
    "HexArray-C": "EpomAd-C",
    "GDPRInject": "HexArray-D",
    "JSFiretruck": "J Fuck",
    "TagInject-A": "TagLoader-A",
    "TagInject-B": "TagLoader-B",
}

paper_only_campaigns = {
    "SessHijack-A":  {"total": 20, "top": [("elementor", 30), ("contact-form-7", 25), ("elementor-pro", 15)]},
    "SessHijack-B":  {"total": 24, "top": [("elementor", 46), ("contact-form-7", 38), ("elementor-pro", 29)]},
    "SessHijack-C":  {"total": 23, "top": [("contact-form-7", 13), ("woocommerce", 4), ("yith-wc-wishlist", 4)]},
    "FadeRedirect":  {"total": 41, "top": [("contact-form-7", 29), ("elementor", 20), ("js_composer", 17)]},
    "MultiC2":       {"total": 62, "top": [("contact-form-7", 55), ("elementor", 37), ("js_composer", 24)]},
    "MalvertKit":    {"total": 22, "top": [("contact-form-7", 50), ("elementor", 45), ("woocommerce", 36)]},
    "CSSInject":     {"total": 28, "top": [("elementor", 43), ("elementor-pro", 36), ("contact-form-7", 25)]},
    "PolyClickFix":  {"total": 70, "top": [("elementor", 32), ("elementor-pro", 26), ("contact-form-7", 22)]},
    "CookieLoader":  {"total": 2,  "top": [("tablepress", 100)]},
    "TDSRedirect":   {"total": 7,  "top": [("revslider", 29), ("contact-form-7", 29), ("js_composer", 29)]},
    "WooBackdoor":   {"total": 9,  "top": [("woocommerce", 100), ("contact-form-7", 56), ("elementor", 33)]},
    "OverlayInject":  {"total": 2,  "top": [("contact-form-7", 100), ("revslider", 100), ("woocommerce", 100)]},
    "YWXILoader":    {"total": 33, "top": [("elementor-pro", 27), ("js_composer", 9), ("elementor", 9)]},
}

plugin_campaigns = defaultdict(list)

for cname, cdata in campaign_plugins.items():
    for pname, pinfo in cdata["plugins"].items():
        plugin_campaigns[pname].append((cname, pinfo["pct"]))

for cname, cdata in paper_only_campaigns.items():
    for pname, pct in cdata["top"]:
        plugin_campaigns[pname].append((cname, pct))

key_plugins = [
    "url-shortify", "simple-tags", "ali-post-editor",
    "contact-form-7", "elementor", "elementor-pro",
    "js_composer", "woocommerce", "tablepress",
    "jet-elements", "revslider", "add-to-any",
    "puca", "yith-wc-wishlist", "jet-search",
    "td-composer",
]

print("\n" + "=" * 95)
print(f"{'ENRICHMENT TABLE':^95}")
print(f"{'(background: measured from diff_results, Feb 2026 snapshot)':^95}")
print("=" * 95)
print(f"  {'Plugin':25s} {'#Camp':>6s} {'BgMeas%':>9s} {'MedCamp%':>10s} "
      f"{'Enrich':>9s}  {'Tier':6s}")
print("-" * 95)

results = []

for plugin in key_plugins:
    if plugin not in plugin_campaigns:
        continue
    camps = plugin_campaigns[plugin]
    n_camps = len(camps)
    bg = bg_prev.get(plugin, 0)

    pcts = sorted([c[1] for c in camps])
    med_pct = pcts[len(pcts) // 2]

    if bg > 0:
        enrichment = med_pct / bg
    else:
        enrichment = float('inf') if med_pct > 0 else 0

    if enrichment == float('inf') or enrichment > 5.0:
        tier = "Tier-1"
    elif enrichment > 1.5:
        tier = "Tier-2"
    else:
        tier = "Tier-3"

    enr_str = f"{enrichment:.1f}×" if enrichment != float('inf') else "∞"
    print(f"  {plugin:25s} {n_camps:5d}  {bg:8.2f}% {med_pct:9.1f}%  "
          f"{enr_str:>8s}   {tier}")

    results.append({
        "plugin": plugin, "n_camps": n_camps, "bg_pct": round(bg, 3),
        "med_pct": round(med_pct, 1), "enrichment": round(enrichment, 2)
        if enrichment != float('inf') else "inf", "tier": tier,
    })

print("\n\n── Per-campaign top-5 plugins (with measured enrichment) ──\n")

for cname in sorted(campaign_plugins.keys()):
    cdata = campaign_plugins[cname]
    print(f"  {cname} ({cdata['total']} domains)")
    sp = sorted(cdata["plugins"].items(), key=lambda x: -x[1]["pct"])
    for pn, pi in sp[:5]:
        bg = bg_prev.get(pn, 0)
        enr = pi["pct"] / bg if bg > 0 else float('inf')
        enr_s = f"{enr:.1f}×" if enr != float('inf') else "∞"
        cve_s = ", ".join(pi["cves"][:2]) if pi["cves"] else "-"
        print(f"    {pn:25s} {pi['pct']:5.1f}%  bg={bg:.2f}%  enr={enr_s:>7s}  "
              f"ver={pi['version']}  CVE=[{cve_s}]")
    print()

for cname in sorted(paper_only_campaigns.keys()):
    cdata = paper_only_campaigns[cname]
    print(f"  {cname} ({cdata['total']} domains) [from paper]")
    for pn, pct in cdata["top"][:5]:
        bg = bg_prev.get(pn, 0)
        enr = pct / bg if bg > 0 else float('inf')
        enr_s = f"{enr:.1f}×" if enr != float('inf') else "∞"
        print(f"    {pn:25s} {pct:5.1f}%  bg={bg:.2f}%  enr={enr_s:>7s}")
    print()

output = {
    "background_source": str(DIFF),
    "background_stats": {
        "n_signatures": n_sigs,
        "total_site_occurrences": bg_total_sites,
    },
    "background_prevalence_top50": {
        k: round(v, 4) for k, v in
        sorted(bg_prev.items(), key=lambda x: -x[1])[:50]
    },
    "enrichment_results": results,
}

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "results", "tfidf_enrichment.json")
with open(out_path, "w") as f:
    json.dump(output, f, indent=2, default=str)
print(f"\nSaved to {out_path}")

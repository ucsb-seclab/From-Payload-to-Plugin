## Reproducibility tiers

The artifact scripts fall into two tiers based on what data they require.

### Campaign Findings
You can find the campaign findings in `data/campaigns`.


### Tier 1: Fully reproducible from bundled data

These scripts run entirely from the data bundled in the artifact directory. can execute every one of them without any external infrastructure.

**Evaluation scripts** (run from any directory):
```bash
python3 artifacts/code/evaluation/extract_campaign_stats.py     # Table 2
```

**Figure scripts** (generate PDFs and PNGs in the current directory):
```bash
python3 artifacts/code/figures/fig_detection_gap.py             # VT detection timeline
python3 artifacts/code/figures/fig_vuln_heatmap.py              # CVE type heatmap
```

Required packages: `numpy`, `matplotlib`, `packaging`. No GPU or special hardware needed.

### Tier 2: Data generation scripts (require crawl infrastructure)

These scripts generated the pre-computed JSON files bundled in `data/results/` and `data/baselines/`. They require the raw crawl data (a crawl window = ~100 GB) which was collected on a dedicated measurement node during the 84-day study period. An evaluator cannot re-run these without access to the crawl data. 

We deliberately exclude three categories of sensitive material from the public artifact upon publication.
First, the malicious JavaScript payloads themselves are withheld because redistributing live exploit code could enable reuse against unpatched sites. Second, victim domain lists are withheld to avoid directing attention to sites that may still be compromised. Third, the full crawl corpus (~100GB = a crawl window) is withheld because it contains live URLs that presently serve attacker-controlled content and could expose end users to harm.


| Script | Output (bundled in artifact) | Required external data |
|---|---|---|
| `code/enrichment/build_fullpop_baseline.py` | `data/baselines/baseline_plugins_fullpop.json` | Raw crawl snapshots (100+ GB) |
| `code/enrichment/compute_table4_v3.py` | `data/results/table4_v3_rows.json` | Crawl snapshots + host allowlist |
| `code/enrichment/baseline_ecosystem_stats.py` | `data/results/baseline_ecosystem_stats.json` | Crawl snapshots + Wordfence DB |
| `code/enrichment/compute_all_similarity.py` | `data/results/all_campaign_similarity.json` | Behavioral traces + raw JS payloads |
| `code/clustering/cluster_scripts.py` | HDBSCAN cluster assignments (Table 3) | Behavioral traces  |
| `code/clustering/visualize_clusters.py` | 3D t-SNE cluster visualization | Cluster output from `cluster_scripts.py` |


**NOTE:**

These scripts accept the `CRAWL_ROOT` environment variable to configure the path to crawl data when available. Enrichment and clustering scripts were executed on a GCP Compute Engine instance where the crawl data resides. The pre-computed outputs in `data/results/` allow all Tier 1 scripts to run without this data. 


### Dynamic execution tracer and crawler
Refer to `artifacts/code/crawling/README.md` for instructions on running the dynamic execution tracer and crawler.


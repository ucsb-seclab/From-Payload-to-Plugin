#!/usr/bin/env python3

import argparse
import json
import os
import random
import sys
import tarfile
from collections import Counter
from pathlib import Path

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from static_js_heuristics import (
    HEURISTICS as STATIC_HEURISTICS,
    MALICIOUS_THRESHOLD as STATIC_THRESHOLD,
    analyze as static_analyze,
)
from behavioral_trace_heuristics import (
    HEURISTICS as BEHAV_HEURISTICS,
    MALICIOUS_THRESHOLD as BEHAV_THRESHOLD,
    extract_monitoring_events,
    extract_network_requests,
    analyze_trace,
    load_trace,
)

def collect_scan_domains(scan_dir, sample_size, seed):
    random.seed(seed)
    dirs = sorted(d for d in os.listdir(scan_dir)
                  if os.path.isdir(os.path.join(scan_dir, d)))
    random.shuffle(dirs)
    valid = []
    for d in dirs:
        if len(valid) >= sample_size:
            break
        p = os.path.join(scan_dir, d)
        if (os.path.isfile(os.path.join(p, 'trace.json')) and
                os.path.isfile(os.path.join(p, 'loaded_js.tar.gz'))):
            valid.append(p)
    return valid

def collect_malicious():
    static_paths = []
    trace_paths = []
    seen = set()
    trace_dir = Path(os.environ.get('TRACES_DIR', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data', 'traces', 'full_campaign')))
    if not trace_dir.exists():
        trace_dir = Path(os.environ.get('TRACES_DIR', ''))
    for tb in trace_dir.rglob('triggered_by.json'):
        try:
            with open(tb) as f:
                d = json.load(f)
            js_path = d.get('original_file', '')
            trace_file = str(tb.parent / 'trace_v2.json.zst')
            if js_path and os.path.isfile(js_path) and os.path.isfile(trace_file):
                if js_path not in seen:
                    seen.add(js_path)
                    static_paths.append(js_path)
                    trace_paths.append(trace_file)
        except Exception:
            pass
    return static_paths, trace_paths

def extract_js_files(tar_path):
    files = []
    try:
        with tarfile.open(tar_path, 'r:gz') as tar:
            for m in tar.getmembers():
                if not m.name.endswith('.js') or not m.isfile() or m.size < 50:
                    continue
                f = tar.extractfile(m)
                if f:
                    code = f.read().decode('utf-8', errors='replace')
                    if len(code.strip()) >= 50:
                        files.append(code)
    except Exception:
        pass
    return files

def score_trace(path):
    try:
        if path.endswith('.zst'):
            trace = load_trace(path)
        else:
            with open(path) as f:
                raw = json.load(f)
            trace = raw.get('events', raw if isinstance(raw, list) else [])
        events = extract_monitoring_events(trace)
        net_reqs = extract_network_requests(trace)
        score, hits = analyze_trace(events, net_reqs)
        return score, hits, len(events)
    except Exception:
        return None, None, 0

def print_rule_table(rows, n_ben, n_mal):
    print(f"\n  Benign: {n_ben}  |  Malicious: {n_mal}")
    print(f"\n  {'Rule':<35} {'Wt':>4} {'FP#':>6} {'FP%':>7} {'TP#':>5} {'TP%':>7}")
    print("  " + "-" * 68)
    zero_fp = 0
    under_1 = 0
    for name, wt, fp, fpr, tp, tpr in rows:
        m = " *" if fp == 0 else ""
        if fp == 0: zero_fp += 1
        elif fpr < 1.0: under_1 += 1
        print(f"  {name:<35} {wt:>4.1f} {fp:>6} {fpr:>6.2f}% {tp:>5} {tpr:>6.1f}%{m}")
    max_fp = max(rows, key=lambda x: x[3])
    print(f"\n  Zero-FP: {zero_fp}/{len(rows)}  |  FP<1%: {zero_fp + under_1}/{len(rows)}  |  Max FP: {max_fp[0]} at {max_fp[3]:.2f}%")
    return zero_fp, under_1

def weight_sensitivity(all_hits_cache, heuristics, threshold, name_attr, weight_attr):
    orig_w = {getattr(fn, name_attr): getattr(fn, weight_attr) for fn in heuristics}
    configs = {
        'calibrated': orig_w,
        'uniform (all 1.0)': {n: 1.0 for n in orig_w},
        'binary': {n: (2.0 if w >= 3.0 else 1.0) for n, w in orig_w.items()},
    }
    for cname, weights in configs.items():
        tp = fp = fn_c = tn = 0
        for hits, lbl in all_hits_cache:
            score = sum(weights.get(h.rule, h.weight) for h in hits)
            if lbl == 'mal':
                if score >= threshold: tp += 1
                else: fn_c += 1
            else:
                if score >= threshold: fp += 1
                else: tn += 1
        nm = tp + fn_c
        nb = fp + tn
        rec = tp / nm if nm > 0 else 0
        fpr = fp / nb if nb > 0 else 0
        print(f"    {cname}: Recall={rec*100:.1f}% ({tp}/{nm})  FPR={fpr*100:.2f}% ({fp}/{nb})")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-dir", required=True,
                        help="scan-data directory with domain subdirs containing loaded_js.tar.gz and trace.json")
    parser.add_argument("--sample-size", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", default=None, help="Save results to JSON file")
    args = parser.parse_args()

    print("Collecting benign domains...", flush=True)
    domains = collect_scan_domains(args.scan_dir, args.sample_size, args.seed)
    print(f"  Benign domains with both JS + trace: {len(domains)}", flush=True)

    print("Collecting malicious payloads...", flush=True)
    mal_static, mal_traces = collect_malicious()
    print(f"  Malicious (paired static+trace): {len(mal_static)}", flush=True)

    print(f"\n{'='*70}", flush=True)
    print("STATIC HEURISTIC EVALUATION (per-file)", flush=True)
    print(f"{'='*70}", flush=True)

    print("\nScoring benign JS files (extracting from tar.gz)...", flush=True)
    ben_static = []
    total_js_files = 0
    for i, dp in enumerate(domains):
        if (i + 1) % 500 == 0:
            print(f"  [static] {i+1}/{len(domains)} domains, {total_js_files} JS files...", flush=True)
        js_files = extract_js_files(os.path.join(dp, 'loaded_js.tar.gz'))
        for code in js_files:
            score, hits = static_analyze(code)
            ben_static.append({'score': score, 'hits': hits,
                               'rules_fired': [h.rule for h in hits]})
            total_js_files += 1
    print(f"  Scored: {len(ben_static)} individual JS files from {len(domains)} domains", flush=True)

    print("Scoring malicious payloads...", flush=True)
    mal_static_res = []
    for path in mal_static:
        try:
            with open(path, 'r', errors='replace') as f:
                code = f.read(5_000_000)
            if len(code.strip()) < 10:
                continue
            score, hits = static_analyze(code)
            mal_static_res.append({'score': score, 'hits': hits,
                                   'rules_fired': [h.rule for h in hits]})
        except Exception:
            pass
    print(f"  Scored: {len(mal_static_res)}", flush=True)

    n_ben_s = len(ben_static)
    n_mal_s = len(mal_static_res)

    rule_fp_s = Counter()
    rule_tp_s = Counter()
    for r in ben_static:
        for rule in r['rules_fired']: rule_fp_s[rule] += 1
    for r in mal_static_res:
        for rule in r['rules_fired']: rule_tp_s[rule] += 1

    s_rows = []
    for fn in STATIC_HEURISTICS:
        name = fn._heuristic_name
        wt = fn._heuristic_weight
        fp = rule_fp_s.get(name, 0)
        tp = rule_tp_s.get(name, 0)
        fpr = fp / n_ben_s * 100 if n_ben_s > 0 else 0
        tpr = tp / n_mal_s * 100 if n_mal_s > 0 else 0
        s_rows.append((name, wt, fp, fpr, tp, tpr))
    s_rows.sort(key=lambda x: -x[1])

    print("\n  STATIC PER-RULE FP/TP (per individual JS file):")
    s_zero, s_under1 = print_rule_table(s_rows, n_ben_s, n_mal_s)

    ben_s_scores = np.array([r['score'] for r in ben_static])
    mal_s_scores = np.array([r['score'] for r in mal_static_res])
    print(f"\n  SCORE DISTRIBUTION:")
    print(f"    Benign:    median={np.median(ben_s_scores):.1f}  P75={np.percentile(ben_s_scores,75):.1f}  P95={np.percentile(ben_s_scores,95):.1f}")
    print(f"    Malicious: median={np.median(mal_s_scores):.1f}  P25={np.percentile(mal_s_scores,25):.1f}")

    s_ben_above = int(np.sum(ben_s_scores >= STATIC_THRESHOLD))
    s_mal_above = int(np.sum(mal_s_scores >= STATIC_THRESHOLD))
    print(f"\n  AT THRESHOLD {STATIC_THRESHOLD}:")
    print(f"    Benign above:    {s_ben_above}/{n_ben_s} ({s_ben_above/n_ben_s*100:.2f}%)")
    print(f"    Malicious above: {s_mal_above}/{n_mal_s} ({s_mal_above/n_mal_s*100:.1f}%)")

    print(f"\n  WEIGHT SENSITIVITY:")
    s_cache = [(r['hits'], 'mal') for r in mal_static_res] + [(r['hits'], 'ben') for r in ben_static]
    weight_sensitivity(s_cache, STATIC_HEURISTICS, STATIC_THRESHOLD, '_heuristic_name', '_heuristic_weight')

    print(f"\n{'='*70}", flush=True)
    print("BEHAVIORAL HEURISTIC EVALUATION (per-trace)", flush=True)
    print(f"{'='*70}", flush=True)

    print("\nScoring benign traces...", flush=True)
    ben_behav = []
    for i, dp in enumerate(domains):
        if (i + 1) % 500 == 0:
            print(f"  [behav] {i+1}/{len(domains)}...", flush=True)
        score, hits, n_ev = score_trace(os.path.join(dp, 'trace.json'))
        if score is not None:
            ben_behav.append({'score': score, 'hits': hits,
                              'rules_fired': [h.rule for h in hits]})
    print(f"  Scored: {len(ben_behav)} traces", flush=True)

    print("Scoring malicious traces...", flush=True)
    mal_behav_res = []
    for path in mal_traces:
        score, hits, n_ev = score_trace(path)
        if score is not None:
            mal_behav_res.append({'score': score, 'hits': hits,
                                  'rules_fired': [h.rule for h in hits]})
    print(f"  Scored: {len(mal_behav_res)}", flush=True)

    n_ben_b = len(ben_behav)
    n_mal_b = len(mal_behav_res)

    rule_fp_b = Counter()
    rule_tp_b = Counter()
    for r in ben_behav:
        for rule in r['rules_fired']: rule_fp_b[rule] += 1
    for r in mal_behav_res:
        for rule in r['rules_fired']: rule_tp_b[rule] += 1

    b_rows = []
    for fn in BEHAV_HEURISTICS:
        name = fn._h_name
        wt = fn._h_weight
        fp = rule_fp_b.get(name, 0)
        tp = rule_tp_b.get(name, 0)
        fpr = fp / n_ben_b * 100 if n_ben_b > 0 else 0
        tpr = tp / n_mal_b * 100 if n_mal_b > 0 else 0
        b_rows.append((name, wt, fp, fpr, tp, tpr))
    b_rows.sort(key=lambda x: -x[1])

    print("\n  BEHAVIORAL PER-RULE FP/TP (per-trace):")
    b_zero, b_under1 = print_rule_table(b_rows, n_ben_b, n_mal_b)

    ben_b_scores = np.array([r['score'] for r in ben_behav])
    mal_b_scores = np.array([r['score'] for r in mal_behav_res])
    print(f"\n  SCORE DISTRIBUTION:")
    print(f"    Benign:    median={np.median(ben_b_scores):.1f}  P75={np.percentile(ben_b_scores,75):.1f}  P95={np.percentile(ben_b_scores,95):.1f}")
    print(f"    Malicious: median={np.median(mal_b_scores):.1f}  P25={np.percentile(mal_b_scores,25):.1f}")

    b_ben_above = int(np.sum(ben_b_scores >= BEHAV_THRESHOLD))
    b_mal_above = int(np.sum(mal_b_scores >= BEHAV_THRESHOLD))
    print(f"\n  AT THRESHOLD {BEHAV_THRESHOLD}:")
    print(f"    Benign above:    {b_ben_above}/{n_ben_b} ({b_ben_above/n_ben_b*100:.2f}%)")
    print(f"    Malicious above: {b_mal_above}/{n_mal_b} ({b_mal_above/n_mal_b*100:.1f}%)")

    print(f"\n  WEIGHT SENSITIVITY:")
    b_cache = [(r['hits'], 'mal') for r in mal_behav_res] + [(r['hits'], 'ben') for r in ben_behav]
    weight_sensitivity(b_cache, BEHAV_HEURISTICS, BEHAV_THRESHOLD, '_h_name', '_h_weight')

    print(f"\n{'='*70}")
    print("COMBINED SUMMARY")
    print(f"{'='*70}")
    print(f"  Data source: {args.scan_dir} ({len(domains)} domains)")
    print(f"  Static benign: {n_ben_s} individual JS files from {len(domains)} domains")
    print(f"  Behavioral benign: {n_ben_b} traces from {len(domains)} domains")
    print(f"  Malicious: {n_mal_s} static payloads, {n_mal_b} behavioral traces")
    print(f"")
    print(f"  {'Metric':<40} {'Static (37)':>15} {'Behavioral (33)':>18}")
    print(f"  {'-'*75}")
    print(f"  {'Zero-FP rules':<40} {s_zero:>15} {b_zero:>18}")
    print(f"  {'FP < 1% rules':<40} {s_zero+s_under1:>15} {b_zero+b_under1:>18}")
    print(f"  {'Benign score median':<40} {np.median(ben_s_scores):>15.1f} {np.median(ben_b_scores):>18.1f}")
    print(f"  {'Malicious score median':<40} {np.median(mal_s_scores):>15.1f} {np.median(mal_b_scores):>18.1f}")
    print(f"  {'Recall (calibrated)':<40} {s_mal_above/n_mal_s*100:>14.1f}% {b_mal_above/n_mal_b*100:>17.1f}%")
    print(f"  {'FPR (calibrated)':<40} {s_ben_above/n_ben_s*100:>14.2f}% {b_ben_above/n_ben_b*100:>17.2f}%")

    if args.output:
        results = {
            'data_source': args.scan_dir,
            'n_domains': len(domains),
            'seed': args.seed,
            'static': {
                'n_benign': n_ben_s, 'n_malicious': n_mal_s,
                'benign_median': float(np.median(ben_s_scores)),
                'benign_p95': float(np.percentile(ben_s_scores, 95)),
                'malicious_median': float(np.median(mal_s_scores)),
                'malicious_p25': float(np.percentile(mal_s_scores, 25)),
                'recall': s_mal_above / n_mal_s,
                'fpr': s_ben_above / n_ben_s,
                'threshold': STATIC_THRESHOLD,
                'zero_fp_rules': s_zero,
                'fp_under_1pct_rules': s_zero + s_under1,
                'per_rule': [{'rule': n, 'weight': w, 'fp_count': fp, 'fp_pct': fpr, 'tp_count': tp, 'tp_pct': tpr}
                             for n, w, fp, fpr, tp, tpr in s_rows],
            },
            'behavioral': {
                'n_benign': n_ben_b, 'n_malicious': n_mal_b,
                'benign_median': float(np.median(ben_b_scores)),
                'benign_p95': float(np.percentile(ben_b_scores, 95)),
                'malicious_median': float(np.median(mal_b_scores)),
                'malicious_p25': float(np.percentile(mal_b_scores, 25)),
                'recall': b_mal_above / n_mal_b,
                'fpr': b_ben_above / n_ben_b,
                'threshold': BEHAV_THRESHOLD,
                'zero_fp_rules': b_zero,
                'fp_under_1pct_rules': b_zero + b_under1,
                'per_rule': [{'rule': n, 'weight': w, 'fp_count': fp, 'fp_pct': fpr, 'tp_count': tp, 'tp_pct': tpr}
                             for n, w, fp, fpr, tp, tpr in b_rows],
            },
        }
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n  Results saved to {args.output}")

if __name__ == "__main__":
    main()

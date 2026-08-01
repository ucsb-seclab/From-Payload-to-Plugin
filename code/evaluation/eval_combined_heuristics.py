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

def collect_benign_domains(scan_dir, sample_size, seed):
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
    seen_static = set()
    for tb in Path(os.environ.get('TRACES_DIR', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data', 'traces', 'full_campaign'))).rglob('triggered_by.json'):
        try:
            with open(tb) as f:
                d = json.load(f)
            js_path = d.get('original_file', '')
            trace_dir = str(tb.parent)
            trace_file = os.path.join(trace_dir, 'trace_v2.json.zst')
            if js_path and os.path.isfile(js_path) and os.path.isfile(trace_file):
                if js_path not in seen_static:
                    seen_static.add(js_path)
                    static_paths.append(js_path)
                    trace_paths.append(trace_file)
        except Exception:
            pass
    return static_paths, trace_paths

def score_benign_domain_static(domain_path):
    tar_path = os.path.join(domain_path, 'loaded_js.tar.gz')
    all_hits = []
    total_score = 0
    n_files = 0
    try:
        with tarfile.open(tar_path, 'r:gz') as tar:
            for m in tar.getmembers():
                if not m.name.endswith('.js') or not m.isfile():
                    continue
                f = tar.extractfile(m)
                if not f:
                    continue
                code = f.read().decode('utf-8', errors='replace')
                if len(code.strip()) < 10:
                    continue
                score, hits = static_analyze(code)
                all_hits.extend(hits)
                total_score += score
                n_files += 1
    except Exception:
        pass
    return total_score, all_hits, n_files

def score_benign_domain_behavioral(domain_path):
    trace_path = os.path.join(domain_path, 'trace.json')
    try:
        with open(trace_path) as f:
            raw = json.load(f)
        trace = raw.get('events', raw if isinstance(raw, list) else [])
        events = extract_monitoring_events(trace)
        net_reqs = extract_network_requests(trace)
        score, hits = analyze_trace(events, net_reqs)
        return score, hits, len(events)
    except Exception:
        return 0, [], 0

def read_js(path):
    try:
        with open(path, 'r', errors='replace') as f:
            return f.read(5_000_000)
    except Exception:
        return None

def print_rule_table(rows, n_ben, n_mal, label):
    print(f"\n  Benign: {n_ben}  |  Malicious: {n_mal}")
    print(f"\n  {'Rule':<35} {'Wt':>4} {'FP#':>5} {'FP%':>7} {'TP#':>5} {'TP%':>7}")
    print("  " + "-" * 68)
    zero_fp = 0
    under_1 = 0
    for name, wt, fp, fpr, tp, tpr in rows:
        m = " *" if fp == 0 else ""
        if fp == 0:
            zero_fp += 1
        elif fpr < 1.0:
            under_1 += 1
        print(f"  {name:<35} {wt:>4.1f} {fp:>5} {fpr:>6.2f}% {tp:>5} {tpr:>6.1f}%{m}")
    max_fp = max(rows, key=lambda x: x[3])
    print(f"\n  Zero-FP: {zero_fp}/{len(rows)}  |  FP<1%: {zero_fp + under_1}/{len(rows)}  |  Max FP: {max_fp[0]} at {max_fp[3]:.2f}%")
    return zero_fp, under_1

def weight_sensitivity(all_hits_cache, heuristics, threshold, label):
    orig_w = {}
    for fn in heuristics:
        name = getattr(fn, '_heuristic_name', None) or getattr(fn, '_h_name')
        weight = getattr(fn, '_heuristic_weight', None) or getattr(fn, '_h_weight')
        orig_w[name] = weight

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
    parser.add_argument("--scan-dir", required=True)
    parser.add_argument("--sample-size", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    print("Collecting benign domains...", flush=True)
    benign_domains = collect_benign_domains(args.scan_dir, args.sample_size, args.seed)
    print(f"  Benign domains: {len(benign_domains)}", flush=True)

    print("Collecting malicious payloads...", flush=True)
    mal_static_paths, mal_trace_paths = collect_malicious()
    print(f"  Malicious (paired static+trace): {len(mal_static_paths)}", flush=True)

    print(f"\n{'='*70}", flush=True)
    print("STATIC HEURISTIC EVALUATION", flush=True)
    print(f"{'='*70}", flush=True)

    print("\nScoring benign (static)...", flush=True)
    ben_static_res = []
    for i, dp in enumerate(benign_domains):
        if (i + 1) % 500 == 0:
            print(f"  [static-benign] {i+1}/{len(benign_domains)}...", flush=True)
        score, hits, n_files = score_benign_domain_static(dp)
        if n_files > 0:
            per_file_score = score / n_files
            ben_static_res.append({'path': dp, 'score': per_file_score,
                                   'total_score': score, 'hits': hits,
                                   'rules_fired': list(set(h.rule for h in hits)),
                                   'n_files': n_files})
    print(f"  Scored: {len(ben_static_res)} domains", flush=True)

    print("Scoring malicious (static)...", flush=True)
    mal_static_res = []
    for path in mal_static_paths:
        code = read_js(path)
        if not code or len(code.strip()) < 10:
            continue
        score, hits = static_analyze(code)
        mal_static_res.append({'path': path, 'score': score, 'hits': hits,
                               'rules_fired': [h.rule for h in hits]})
    print(f"  Scored: {len(mal_static_res)}", flush=True)

    n_ben_s = len(ben_static_res)
    n_mal_s = len(mal_static_res)

    rule_fp_s = Counter()
    rule_tp_s = Counter()
    for r in ben_static_res:
        for rule in r['rules_fired']:
            rule_fp_s[rule] += 1
    for r in mal_static_res:
        for rule in r['rules_fired']:
            rule_tp_s[rule] += 1

    static_rows = []
    for fn in STATIC_HEURISTICS:
        name = fn._heuristic_name
        wt = fn._heuristic_weight
        fp = rule_fp_s.get(name, 0)
        tp = rule_tp_s.get(name, 0)
        fpr = fp / n_ben_s * 100 if n_ben_s > 0 else 0
        tpr = tp / n_mal_s * 100 if n_mal_s > 0 else 0
        static_rows.append((name, wt, fp, fpr, tp, tpr))
    static_rows.sort(key=lambda x: -x[1])

    print("\n  STATIC PER-RULE FP/TP:")
    print_rule_table(static_rows, n_ben_s, n_mal_s, "static")

    ben_s_scores = np.array([r['score'] for r in ben_static_res])
    mal_s_scores = np.array([r['score'] for r in mal_static_res])
    print(f"\n  SCORE DISTRIBUTION (per-file avg for benign domains):")
    print(f"    Benign:    median={np.median(ben_s_scores):.1f}  P95={np.percentile(ben_s_scores,95):.1f}")
    print(f"    Malicious: median={np.median(mal_s_scores):.1f}  P25={np.percentile(mal_s_scores,25):.1f}")

    s_ben_above = int(np.sum(ben_s_scores >= STATIC_THRESHOLD))
    s_mal_above = int(np.sum(mal_s_scores >= STATIC_THRESHOLD))
    print(f"\n  AT THRESHOLD {STATIC_THRESHOLD}:")
    print(f"    Benign above:    {s_ben_above}/{n_ben_s} ({s_ben_above/n_ben_s*100:.2f}%)")
    print(f"    Malicious above: {s_mal_above}/{n_mal_s} ({s_mal_above/n_mal_s*100:.1f}%)")

    print(f"\n  WEIGHT SENSITIVITY:")
    s_hits_cache = [(r['hits'], 'mal') for r in mal_static_res] + [(r['hits'], 'ben') for r in ben_static_res]
    weight_sensitivity(s_hits_cache, STATIC_HEURISTICS, STATIC_THRESHOLD, "static")

    print(f"\n{'='*70}", flush=True)
    print("BEHAVIORAL HEURISTIC EVALUATION", flush=True)
    print(f"{'='*70}", flush=True)

    print("\nScoring benign (behavioral)...", flush=True)
    ben_behav_res = []
    for i, dp in enumerate(benign_domains):
        if (i + 1) % 500 == 0:
            print(f"  [behav-benign] {i+1}/{len(benign_domains)}...", flush=True)
        score, hits, n_ev = score_benign_domain_behavioral(dp)
        ben_behav_res.append({'path': dp, 'score': score, 'hits': hits,
                              'rules_fired': [h.rule for h in hits], 'n_events': n_ev})
    print(f"  Scored: {len(ben_behav_res)}", flush=True)

    print("Scoring malicious (behavioral)...", flush=True)
    mal_behav_res = []
    for path in mal_trace_paths:
        try:
            trace = load_trace(path)
            events = extract_monitoring_events(trace)
            net_reqs = extract_network_requests(trace)
            score, hits = analyze_trace(events, net_reqs)
            mal_behav_res.append({'path': path, 'score': score, 'hits': hits,
                                  'rules_fired': [h.rule for h in hits]})
        except Exception:
            pass
    print(f"  Scored: {len(mal_behav_res)}", flush=True)

    n_ben_b = len(ben_behav_res)
    n_mal_b = len(mal_behav_res)

    rule_fp_b = Counter()
    rule_tp_b = Counter()
    for r in ben_behav_res:
        for rule in r['rules_fired']:
            rule_fp_b[rule] += 1
    for r in mal_behav_res:
        for rule in r['rules_fired']:
            rule_tp_b[rule] += 1

    behav_rows = []
    for fn in BEHAV_HEURISTICS:
        name = fn._h_name
        wt = fn._h_weight
        fp = rule_fp_b.get(name, 0)
        tp = rule_tp_b.get(name, 0)
        fpr = fp / n_ben_b * 100 if n_ben_b > 0 else 0
        tpr = tp / n_mal_b * 100 if n_mal_b > 0 else 0
        behav_rows.append((name, wt, fp, fpr, tp, tpr))
    behav_rows.sort(key=lambda x: -x[1])

    print("\n  BEHAVIORAL PER-RULE FP/TP:")
    print_rule_table(behav_rows, n_ben_b, n_mal_b, "behavioral")

    ben_b_scores = np.array([r['score'] for r in ben_behav_res])
    mal_b_scores = np.array([r['score'] for r in mal_behav_res])
    print(f"\n  SCORE DISTRIBUTION:")
    print(f"    Benign:    median={np.median(ben_b_scores):.1f}  P95={np.percentile(ben_b_scores,95):.1f}")
    print(f"    Malicious: median={np.median(mal_b_scores):.1f}  P25={np.percentile(mal_b_scores,25):.1f}")

    b_ben_above = int(np.sum(ben_b_scores >= BEHAV_THRESHOLD))
    b_mal_above = int(np.sum(mal_b_scores >= BEHAV_THRESHOLD))
    print(f"\n  AT THRESHOLD {BEHAV_THRESHOLD}:")
    print(f"    Benign above:    {b_ben_above}/{n_ben_b} ({b_ben_above/n_ben_b*100:.2f}%)")
    print(f"    Malicious above: {b_mal_above}/{n_mal_b} ({b_mal_above/n_mal_b*100:.1f}%)")

    print(f"\n  WEIGHT SENSITIVITY:")
    b_hits_cache = [(r['hits'], 'mal') for r in mal_behav_res] + [(r['hits'], 'ben') for r in ben_behav_res]
    weight_sensitivity(b_hits_cache, BEHAV_HEURISTICS, BEHAV_THRESHOLD, "behavioral")

    print(f"\n{'='*70}")
    print("COMBINED SUMMARY")
    print(f"{'='*70}")
    s_zero = sum(1 for _, _, fp, _, _, _ in static_rows if fp == 0)
    s_under1 = sum(1 for _, _, _, fpr, _, _ in static_rows if fpr < 1.0)
    b_zero = sum(1 for _, _, fp, _, _, _ in behav_rows if fp == 0)
    b_under1 = sum(1 for _, _, _, fpr, _, _ in behav_rows if fpr < 1.0)
    print(f"  Benign corpus: {len(benign_domains)} WordPress domains (same for static + behavioral)")
    print(f"  Malicious corpus: {len(mal_static_paths)} campaigns (paired static+trace)")
    print(f"")
    print(f"  {'Metric':<40} {'Static (37)':>12} {'Behavioral (33)':>16}")
    print(f"  {'-'*70}")
    print(f"  {'Zero-FP rules':<40} {s_zero:>12} {b_zero:>16}")
    print(f"  {'FP < 1% rules':<40} {s_under1:>12} {b_under1:>16}")
    print(f"  {'Benign score median':<40} {np.median(ben_s_scores):>12.1f} {np.median(ben_b_scores):>16.1f}")
    print(f"  {'Malicious score median':<40} {np.median(mal_s_scores):>12.1f} {np.median(mal_b_scores):>16.1f}")
    print(f"  {'Recall (calibrated)':<40} {s_mal_above/n_mal_s*100:>11.1f}% {b_mal_above/n_mal_b*100:>15.1f}%")
    print(f"  {'FPR (calibrated)':<40} {s_ben_above/n_ben_s*100:>11.2f}% {b_ben_above/n_ben_b*100:>15.2f}%")

if __name__ == "__main__":
    main()

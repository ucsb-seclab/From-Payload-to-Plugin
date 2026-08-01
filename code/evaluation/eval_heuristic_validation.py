#!/usr/bin/env python3

import argparse
import json
import math
import os
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from static_js_heuristics import HEURISTICS, MALICIOUS_THRESHOLD, analyze, Hit

def collect_benign_payloads(delta_dir, sample_size, seed):
    random.seed(seed)
    all_dirs = []
    for entry in os.scandir(delta_dir):
        if entry.is_dir():
            payload = os.path.join(entry.path, 'payload.js')
            if os.path.isfile(payload):
                all_dirs.append(payload)

    print(f"  Total delta payloads found: {len(all_dirs)}")
    if len(all_dirs) > sample_size:
        sampled = random.sample(all_dirs, sample_size)
    else:
        sampled = all_dirs
    print(f"  Sampled: {len(sampled)}")
    return sampled

def collect_malicious_payloads(findings_dir):
    payloads = []
    if findings_dir is None or not os.path.isdir(findings_dir):
        triggered_by_files = list(Path(os.environ.get('TRACES_DIR', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data', 'traces', 'full_campaign'))).rglob('triggered_by.json'))
        seen = set()
        for tb in triggered_by_files:
            try:
                with open(tb) as f:
                    d = json.load(f)
                path = d.get('original_file', '')
                if path and os.path.isfile(path) and path not in seen:
                    seen.add(path)
                    payloads.append(path)
            except Exception:
                pass
        print(f"  Malicious payloads from triggered_by.json: {len(payloads)}")
        return payloads

    for find_dir in sorted(os.listdir(findings_dir)):
        find_path = os.path.join(findings_dir, find_dir)
        if not os.path.isdir(find_path):
            continue
        for hash_dir in os.listdir(find_path):
            payload = os.path.join(find_path, hash_dir, 'payload.js')
            if os.path.isfile(payload):
                payloads.append(payload)
    print(f"  Malicious payloads from findings: {len(payloads)}")
    return payloads

def read_js(path, max_bytes=5_000_000):
    try:
        with open(path, 'r', errors='replace') as f:
            return f.read(max_bytes)
    except Exception:
        return None

def score_corpus(paths, label):
    results = []
    for i, path in enumerate(paths):
        if (i + 1) % 500 == 0:
            print(f"    [{label}] Scored {i+1}/{len(paths)}...", flush=True)
        code = read_js(path)
        if code is None or len(code.strip()) < 10:
            continue
        score, hits = analyze(code)
        results.append({
            'path': path,
            'score': score,
            'hits': hits,
            'rules_fired': [h.rule for h in hits],
            'size': len(code),
        })
    return results

def experiment_1_fp_rates(benign_results, malicious_results):
    print("\n" + "=" * 70)
    print("EXPERIMENT 1: Per-Rule FP and TP Rates")
    print("=" * 70)

    all_rule_names = set()
    for fn in HEURISTICS:
        all_rule_names.add(fn._heuristic_name)

    rule_fp_count = Counter()
    rule_tp_count = Counter()

    for r in benign_results:
        for rule in r['rules_fired']:
            rule_fp_count[rule] += 1
    for r in malicious_results:
        for rule in r['rules_fired']:
            rule_tp_count[rule] += 1

    n_benign = len(benign_results)
    n_mal = len(malicious_results)

    rows = []
    for fn in HEURISTICS:
        name = fn._heuristic_name
        weight = fn._heuristic_weight
        fp = rule_fp_count.get(name, 0)
        tp = rule_tp_count.get(name, 0)
        fp_rate = fp / n_benign * 100 if n_benign > 0 else 0
        tp_rate = tp / n_mal * 100 if n_mal > 0 else 0
        rows.append((name, weight, fp, fp_rate, tp, tp_rate))

    rows.sort(key=lambda x: -x[1])

    print(f"\n  Benign corpus size: {n_benign}")
    print(f"  Malicious corpus size: {n_mal}")
    print(f"\n  {'Rule':<35} {'Wt':>4} {'FP#':>5} {'FP%':>7} {'TP#':>5} {'TP%':>7}")
    print("  " + "-" * 68)

    zero_fp_count = 0
    low_fp_count = 0
    for name, weight, fp, fp_rate, tp, tp_rate in rows:
        marker = ""
        if fp == 0:
            zero_fp_count += 1
            marker = " *"
        elif fp_rate < 1.0:
            low_fp_count += 1
        print(f"  {name:<35} {weight:>4.1f} {fp:>5} {fp_rate:>6.2f}% {tp:>5} {tp_rate:>6.1f}%{marker}")

    print(f"\n  * = zero FP rules: {zero_fp_count} / {len(rows)}")
    print(f"  Rules with FP < 1%: {zero_fp_count + low_fp_count} / {len(rows)}")

    max_fp_rule = max(rows, key=lambda x: x[3])
    print(f"  Highest FP rate: {max_fp_rule[0]} at {max_fp_rule[3]:.2f}%")

    benign_above = sum(1 for r in benign_results if r['score'] >= MALICIOUS_THRESHOLD)
    print(f"\n  Benign files exceeding threshold ({MALICIOUS_THRESHOLD}): {benign_above} / {n_benign} ({benign_above/n_benign*100:.2f}%)")
    mal_above = sum(1 for r in malicious_results if r['score'] >= MALICIOUS_THRESHOLD)
    print(f"  Malicious files exceeding threshold ({MALICIOUS_THRESHOLD}): {mal_above} / {n_mal} ({mal_above/n_mal*100:.1f}%)")

    return rows

def experiment_2_score_distribution(benign_results, malicious_results):
    print("\n" + "=" * 70)
    print("EXPERIMENT 2: Score Distribution")
    print("=" * 70)

    benign_scores = sorted([r['score'] for r in benign_results])
    mal_scores = sorted([r['score'] for r in malicious_results])

    def percentiles(scores, label):
        if not scores:
            return
        print(f"\n  {label} (n={len(scores)}):")
        for p in [25, 50, 75, 90, 95, 99, 100]:
            idx = min(int(len(scores) * p / 100), len(scores) - 1)
            print(f"    P{p:>3}: {scores[idx]:>6.1f}")

    percentiles(benign_scores, "Benign scores")
    percentiles(mal_scores, "Malicious scores")

    buckets = [0, 2, 4, 6, 8, 10, 15, 20, 30, 50, 100]
    print(f"\n  Score histogram (benign):")
    for i in range(len(buckets) - 1):
        lo, hi = buckets[i], buckets[i + 1]
        count = sum(1 for s in benign_scores if lo <= s < hi)
        bar = "#" * min(count * 50 // max(len(benign_scores), 1), 50)
        print(f"    [{lo:>5.0f}, {hi:>5.0f}): {count:>6}  {bar}")

    print(f"\n  Score histogram (malicious):")
    for i in range(len(buckets) - 1):
        lo, hi = buckets[i], buckets[i + 1]
        count = sum(1 for s in mal_scores if lo <= s < hi)
        bar = "#" * min(count * 50 // max(len(mal_scores), 1), 50)
        print(f"    [{lo:>5.0f}, {hi:>5.0f}): {count:>6}  {bar}")

def experiment_3_threshold_sweep(benign_results, malicious_results):
    print("\n" + "=" * 70)
    print("EXPERIMENT 3: Threshold Sweep (Precision / Recall)")
    print("=" * 70)

    thresholds = [2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0,
                  12.0, 14.0, 16.0, 18.0, 20.0, 25.0, 30.0]

    n_mal = len(malicious_results)
    n_ben = len(benign_results)

    print(f"\n  {'Threshold':>10} {'TP':>5} {'FP':>6} {'FN':>5} {'Precision':>10} {'Recall':>8} {'F1':>7}")
    print("  " + "-" * 55)

    best_f1 = 0
    best_thresh = 0

    for t in thresholds:
        tp = sum(1 for r in malicious_results if r['score'] >= t)
        fp = sum(1 for r in benign_results if r['score'] >= t)
        fn = n_mal - tp

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / n_mal if n_mal > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        if f1 > best_f1:
            best_f1 = f1
            best_thresh = t

        print(f"  {t:>10.1f} {tp:>5} {fp:>6} {fn:>5} {precision:>9.3f} {recall:>7.3f} {f1:>7.3f}")

    print(f"\n  Best F1: {best_f1:.3f} at threshold {best_thresh}")
    print(f"  Current threshold: {MALICIOUS_THRESHOLD}")

def experiment_4_weight_sensitivity(benign_paths, malicious_paths):
    print("\n" + "=" * 70)
    print("EXPERIMENT 4: Weight Sensitivity Analysis")
    print("=" * 70)

    original_weights = {}
    for fn in HEURISTICS:
        original_weights[fn._heuristic_name] = fn._heuristic_weight

    configs = {
        'calibrated': original_weights,
        'uniform': {name: 1.0 for name in original_weights},
        'binary': {name: (2.0 if w >= 3.0 else 1.0) for name, w in original_weights.items()},
    }

    all_paths = [(p, 'malicious') for p in malicious_paths] + [(p, 'benign') for p in benign_paths]
    codes = []
    for path, label in all_paths:
        code = read_js(path)
        if code and len(code.strip()) >= 10:
            codes.append((code, label))

    for config_name, weights in configs.items():
        for fn in HEURISTICS:
            fn._heuristic_weight = weights[fn._heuristic_name]

        tp = 0
        fp = 0
        fn_count = 0
        tn = 0
        mal_scores = []
        ben_scores = []

        for code, label in codes:
            score, hits = analyze(code)
            actual_score = sum(weights.get(h.rule, h.weight) for h in hits)

            if label == 'malicious':
                mal_scores.append(actual_score)
                if actual_score >= MALICIOUS_THRESHOLD:
                    tp += 1
                else:
                    fn_count += 1
            else:
                ben_scores.append(actual_score)
                if actual_score >= MALICIOUS_THRESHOLD:
                    fp += 1
                else:
                    tn += 1

        n_mal = tp + fn_count
        n_ben = fp + tn
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / n_mal if n_mal > 0 else 0

        print(f"\n  Config: {config_name}")
        print(f"    Threshold: {MALICIOUS_THRESHOLD}")
        print(f"    Malicious detected (TP): {tp}/{n_mal} ({recall*100:.1f}% recall)")
        print(f"    Benign flagged (FP): {fp}/{n_ben} ({fp/n_ben*100:.2f}% FP rate)")
        print(f"    Precision: {precision*100:.1f}%")
        if mal_scores:
            print(f"    Malicious score range: [{min(mal_scores):.1f}, {max(mal_scores):.1f}], median {sorted(mal_scores)[len(mal_scores)//2]:.1f}")
        if ben_scores:
            print(f"    Benign score range: [{min(ben_scores):.1f}, {max(ben_scores):.1f}], median {sorted(ben_scores)[len(ben_scores)//2]:.1f}")

    for fn in HEURISTICS:
        fn._heuristic_weight = original_weights[fn._heuristic_name]

def generate_latex_table(fp_rows, n_benign, n_mal):
    print("\n" + "=" * 70)
    print("LATEX TABLE: Per-Rule False Positive Rates")
    print("=" * 70)
    print()
    print(r"\begin{table}[tbp]")
    print(r"\centering")
    print(r"\small")
    print(r"\caption{Per-rule false positive rates evaluated against " + str(n_benign) + r" benign JavaScript files from the SRI-filtered delta corpus. \emph{FP\%} is the fraction of benign files triggering each rule. \emph{TP\%} is the detection rate against " + str(n_mal) + r" confirmed malicious payloads.}")
    print(r"\label{tab:fp-rates}")
    print(r"\begin{tabular}{@{}l r r r@{}}")
    print(r"\toprule")
    print(r"\textbf{Rule} & \textbf{Wt.} & \textbf{FP\%} & \textbf{TP\%} \\")
    print(r"\midrule")

    for name, weight, fp, fp_rate, tp, tp_rate in fp_rows:
        name_tex = name.replace('_', r'\_')
        fp_str = f"{fp_rate:.2f}" if fp_rate > 0 else "0.00"
        tp_str = f"{tp_rate:.1f}" if tp_rate > 0 else "0.0"
        print(f"\\texttt{{{name_tex}}} & {weight:.1f} & {fp_str} & {tp_str} \\\\")

    print(r"\bottomrule")
    print(r"\end{tabular}")
    print(r"\end{table}")

def main():
    parser = argparse.ArgumentParser(description="Heuristic validation suite")
    parser.add_argument("--delta-dir", required=True,
                        help="Directory containing delta hash subdirs with payload.js (e.g., diff-.../EDITED)")
    parser.add_argument("--malicious-dir", default=None,
                        help="Directory containing findings/ or will auto-detect from traces/full_campaign")
    parser.add_argument("--sample-size", type=int, default=10000,
                        help="Number of benign deltas to sample (default: 10000)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed for sampling")
    parser.add_argument("--latex", action="store_true",
                        help="Output LaTeX table for FP rates")
    args = parser.parse_args()

    print("Collecting benign (delta) payloads...")
    benign_paths = collect_benign_payloads(args.delta_dir, args.sample_size, args.seed)

    print("Collecting malicious (campaign) payloads...")
    if args.malicious_dir:
        malicious_paths = collect_malicious_payloads(args.malicious_dir)
    else:
        malicious_paths = collect_malicious_payloads(None)

    if not malicious_paths:
        print("ERROR: No malicious payloads found. Provide --malicious-dir or ensure traces/full_campaign exists.")
        sys.exit(1)

    print(f"\nScoring benign corpus ({len(benign_paths)} files)...")
    benign_results = score_corpus(benign_paths, "benign")
    print(f"  Scored: {len(benign_results)} (skipped {len(benign_paths) - len(benign_results)} empty/unreadable)")

    print(f"\nScoring malicious corpus ({len(malicious_paths)} files)...")
    malicious_results = score_corpus(malicious_paths, "malicious")
    print(f"  Scored: {len(malicious_results)} (skipped {len(malicious_paths) - len(malicious_results)} empty/unreadable)")

    fp_rows = experiment_1_fp_rates(benign_results, malicious_results)
    experiment_2_score_distribution(benign_results, malicious_results)
    experiment_3_threshold_sweep(benign_results, malicious_results)
    experiment_4_weight_sensitivity(benign_paths[:2000], malicious_paths)

    if args.latex:
        generate_latex_table(fp_rows, len(benign_results), len(malicious_results))

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    n_ben = len(benign_results)
    n_mal = len(malicious_results)
    ben_above = sum(1 for r in benign_results if r['score'] >= MALICIOUS_THRESHOLD)
    mal_above = sum(1 for r in malicious_results if r['score'] >= MALICIOUS_THRESHOLD)
    zero_fp = sum(1 for _, _, fp, _, _, _ in fp_rows if fp == 0)
    low_fp = sum(1 for _, _, _, fp_rate, _, _ in fp_rows if fp_rate < 1.0)
    max_fp = max(fp_rows, key=lambda x: x[3])

    print(f"  Benign corpus: {n_ben} files")
    print(f"  Malicious corpus: {n_mal} files")
    print(f"  Rules with zero FP: {zero_fp}/{len(fp_rows)}")
    print(f"  Rules with FP < 1%: {low_fp}/{len(fp_rows)}")
    print(f"  Highest per-rule FP: {max_fp[0]} at {max_fp[3]:.2f}%")
    print(f"  Benign exceeding threshold: {ben_above}/{n_ben} ({ben_above/n_ben*100:.3f}%)")
    print(f"  Malicious exceeding threshold: {mal_above}/{n_mal} ({mal_above/n_mal*100:.1f}%)")
    print()

if __name__ == "__main__":
    main()

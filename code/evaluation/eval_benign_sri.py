#!/usr/bin/env python3

import argparse
import json
import os
import random
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from static_js_heuristics import HEURISTICS, MALICIOUS_THRESHOLD, analyze

def collect_svn_js_files(svn_dir, sample_size, seed):
    random.seed(seed)

    print(f"  Scanning plugin directories in {svn_dir}...")
    plugins = [d for d in os.listdir(svn_dir)
               if os.path.isdir(os.path.join(svn_dir, d))]
    print(f"  Total plugins: {len(plugins)}")

    random.shuffle(plugins)

    js_files = []
    plugins_scanned = 0
    for plugin in plugins:
        if len(js_files) >= sample_size * 3:
            break
        tags_dir = os.path.join(svn_dir, plugin, "tags")
        if not os.path.isdir(tags_dir):
            continue
        try:
            tags = os.listdir(tags_dir)
        except PermissionError:
            continue
        if not tags:
            continue
        latest_tag = sorted(tags)[-1]
        tag_path = os.path.join(tags_dir, latest_tag)
        try:
            for root, _, files in os.walk(tag_path):
                for f in files:
                    if f.endswith('.js') and not f.endswith('.min.js.map'):
                        full = os.path.join(root, f)
                        try:
                            size = os.path.getsize(full)
                            if 100 < size < 5_000_000:
                                js_files.append(full)
                        except OSError:
                            pass
        except PermissionError:
            pass
        plugins_scanned += 1
        if plugins_scanned % 5000 == 0:
            print(f"    Scanned {plugins_scanned} plugins, found {len(js_files)} JS files so far...")

    print(f"  Total JS files found: {len(js_files)}")
    if len(js_files) > sample_size:
        js_files = random.sample(js_files, sample_size)
    print(f"  Sampled: {len(js_files)}")
    return js_files

def collect_malicious_payloads():
    payloads = []
    seen = set()
    trace_dir = Path(os.environ.get('TRACES_DIR', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data', 'traces', 'full_campaign')))
    if not trace_dir.exists():
        return payloads
    for tb in trace_dir.rglob('triggered_by.json'):
        try:
            with open(tb) as f:
                d = json.load(f)
            path = d.get('original_file', '')
            if path and os.path.isfile(path) and path not in seen:
                seen.add(path)
                payloads.append(path)
        except Exception:
            pass
    return payloads

def read_js(path, max_bytes=5_000_000):
    try:
        with open(path, 'r', errors='replace') as f:
            return f.read(max_bytes)
    except Exception:
        return None

def score_files(paths, label):
    results = []
    for i, path in enumerate(paths):
        if (i + 1) % 1000 == 0:
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

def main():
    parser = argparse.ArgumentParser(description="Evaluate heuristics against SRI benign corpus")
    parser.add_argument("--svn-dir", required=True,
                        help="Path to SVN plugin mirror")
    parser.add_argument("--sample-size", type=int, default=10000,
                        help="Number of benign JS files to sample (default: 10000)")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    print("=" * 70)
    print("COLLECTING BENIGN JS FROM SVN PLUGIN RELEASES (SRI GROUND TRUTH)")
    print("=" * 70)
    benign_paths = collect_svn_js_files(args.svn_dir, args.sample_size, args.seed)

    print("\nCOLLECTING MALICIOUS PAYLOADS FROM CONFIRMED CAMPAIGNS")
    malicious_paths = collect_malicious_payloads()
    print(f"  Malicious payloads: {len(malicious_paths)}")

    print(f"\nScoring benign corpus ({len(benign_paths)} files)...")
    benign_results = score_files(benign_paths, "benign-SRI")
    print(f"  Scored: {len(benign_results)}")

    print(f"\nScoring malicious corpus ({len(malicious_paths)} files)...")
    malicious_results = score_files(malicious_paths, "malicious")
    print(f"  Scored: {len(malicious_results)}")

    n_ben = len(benign_results)
    n_mal = len(malicious_results)

    print("\n" + "=" * 70)
    print("PER-RULE FALSE POSITIVE RATES (BENIGN = SRI PLUGIN RELEASES)")
    print("=" * 70)

    rule_fp = Counter()
    rule_tp = Counter()
    for r in benign_results:
        for rule in r['rules_fired']:
            rule_fp[rule] += 1
    for r in malicious_results:
        for rule in r['rules_fired']:
            rule_tp[rule] += 1

    rows = []
    for fn in HEURISTICS:
        name = fn._heuristic_name
        weight = fn._heuristic_weight
        fp = rule_fp.get(name, 0)
        tp = rule_tp.get(name, 0)
        fp_rate = fp / n_ben * 100 if n_ben > 0 else 0
        tp_rate = tp / n_mal * 100 if n_mal > 0 else 0
        rows.append((name, weight, fp, fp_rate, tp, tp_rate))

    rows.sort(key=lambda x: -x[1])

    print(f"\n  Benign SRI corpus: {n_ben}")
    print(f"  Malicious corpus: {n_mal}")
    print(f"\n  {'Rule':<35} {'Wt':>4} {'FP#':>5} {'FP%':>7} {'TP#':>5} {'TP%':>7}")
    print("  " + "-" * 68)

    zero_fp = 0
    under_1pct = 0
    for name, weight, fp, fp_rate, tp, tp_rate in rows:
        marker = ""
        if fp == 0:
            zero_fp += 1
            marker = " *"
        elif fp_rate < 1.0:
            under_1pct += 1
        print(f"  {name:<35} {weight:>4.1f} {fp:>5} {fp_rate:>6.2f}% {tp:>5} {tp_rate:>6.1f}%{marker}")

    print(f"\n  Zero-FP rules: {zero_fp}/{len(rows)}")
    print(f"  FP < 1% rules: {zero_fp + under_1pct}/{len(rows)}")
    max_fp = max(rows, key=lambda x: x[3])
    print(f"  Highest per-rule FP: {max_fp[0]} at {max_fp[3]:.2f}%")

    print("\n" + "=" * 70)
    print("WEIGHT TIER vs MEAN FALSE POSITIVE RATE")
    print("=" * 70)
    tiers = {
        'High (4.0-5.0)': [(n, fp_r) for n, w, _, fp_r, _, _ in rows if w >= 4.0],
        'Medium (2.5-3.5)': [(n, fp_r) for n, w, _, fp_r, _, _ in rows if 2.5 <= w < 4.0],
        'Low (1.0-2.0)': [(n, fp_r) for n, w, _, fp_r, _, _ in rows if w < 2.5],
    }
    for tier_name, tier_rules in tiers.items():
        if tier_rules:
            mean_fp = sum(r[1] for r in tier_rules) / len(tier_rules)
            print(f"  {tier_name}: mean FP = {mean_fp:.2f}% ({len(tier_rules)} rules)")

    print("\n" + "=" * 70)
    print("COMPOSITE SCORE DISTRIBUTION")
    print("=" * 70)

    ben_scores = sorted(r['score'] for r in benign_results)
    mal_scores = sorted(r['score'] for r in malicious_results)

    for label, scores in [("Benign (SRI)", ben_scores), ("Malicious", mal_scores)]:
        if not scores:
            continue
        print(f"\n  {label} (n={len(scores)}):")
        for p in [25, 50, 75, 90, 95, 99, 100]:
            idx = min(int(len(scores) * p / 100), len(scores) - 1)
            print(f"    P{p:>3}: {scores[idx]:>6.1f}")

    print("\n" + "=" * 70)
    print("THRESHOLD SWEEP")
    print("=" * 70)

    print(f"\n  {'Threshold':>10} {'TP':>5} {'FP':>6} {'Prec':>7} {'Recall':>7} {'FPR':>7}")
    print("  " + "-" * 48)

    for t in [4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 12.0, 14.0, 16.0, 20.0, 25.0]:
        tp = sum(1 for r in malicious_results if r['score'] >= t)
        fp = sum(1 for r in benign_results if r['score'] >= t)
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / n_mal if n_mal > 0 else 0
        fpr = fp / n_ben if n_ben > 0 else 0
        print(f"  {t:>10.1f} {tp:>5} {fp:>6} {prec:>6.3f} {recall:>6.3f} {fpr:>6.4f}")

    ben_above = sum(1 for r in benign_results if r['score'] >= MALICIOUS_THRESHOLD)
    mal_above = sum(1 for r in malicious_results if r['score'] >= MALICIOUS_THRESHOLD)

    print(f"\n  At current threshold ({MALICIOUS_THRESHOLD}):")
    print(f"    Benign above: {ben_above}/{n_ben} ({ben_above/n_ben*100:.3f}%)")
    print(f"    Malicious above: {mal_above}/{n_mal} ({mal_above/n_mal*100:.1f}%)")

    print("\n" + "=" * 70)
    print("WEIGHT SENSITIVITY (re-score under alternative configs)")
    print("=" * 70)

    original_weights = {fn._heuristic_name: fn._heuristic_weight for fn in HEURISTICS}

    configs = {
        'calibrated (original)': original_weights,
        'uniform (all 1.0)': {n: 1.0 for n in original_weights},
        'binary (1.0/<3.0, 2.0/>=3.0)': {n: (2.0 if w >= 3.0 else 1.0) for n, w in original_weights.items()},
    }

    all_codes = []
    for path in malicious_paths:
        code = read_js(path)
        if code and len(code.strip()) >= 10:
            all_codes.append((code, 'mal'))
    for r in benign_results:
        code = read_js(r['path'])
        if code and len(code.strip()) >= 10:
            all_codes.append((code, 'ben'))

    for cname, weights in configs.items():
        tp = fp = fn_c = tn = 0
        for code, label in all_codes:
            _, hits = analyze(code)
            score = sum(weights.get(h.rule, h.weight) for h in hits)
            if label == 'mal':
                if score >= MALICIOUS_THRESHOLD:
                    tp += 1
                else:
                    fn_c += 1
            else:
                if score >= MALICIOUS_THRESHOLD:
                    fp += 1
                else:
                    tn += 1
        n_m = tp + fn_c
        n_b = fp + tn
        recall = tp / n_m if n_m > 0 else 0
        fpr = fp / n_b if n_b > 0 else 0
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        print(f"\n  {cname}:")
        print(f"    Recall:    {tp}/{n_m} ({recall*100:.1f}%)")
        print(f"    FP rate:   {fp}/{n_b} ({fpr*100:.3f}%)")
        print(f"    Precision: {prec*100:.1f}%")

    print("\n" + "=" * 70)
    print("SUMMARY (numbers for paper)")
    print("=" * 70)
    print(f"  Benign corpus (SRI plugin releases): {n_ben} files")
    print(f"  Malicious corpus (confirmed campaigns): {n_mal} files")
    print(f"  Zero-FP rules: {zero_fp}/{len(rows)}")
    print(f"  FP < 1% rules: {zero_fp + under_1pct}/{len(rows)}")
    print(f"  Highest per-rule FP: {max_fp[0]} at {max_fp[3]:.2f}%")
    print(f"  Benign above threshold ({MALICIOUS_THRESHOLD}): {ben_above}/{n_ben} ({ben_above/n_ben*100:.3f}%)")
    print(f"  Malicious above threshold ({MALICIOUS_THRESHOLD}): {mal_above}/{n_mal} ({mal_above/n_mal*100:.1f}%)")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3

import argparse
import hashlib
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
    analyze_trace,
)

def load_domain_trace(trace_path):
    with open(trace_path) as f:
        data = json.load(f)
    return data.get('events', data if isinstance(data, list) else [])

def parse_script_map(trace):
    script_map = {}
    for entry in trace:
        ev = entry.get('event', {})
        if ev.get('method') == 'Debugger.scriptParsed':
            p = ev.get('params', {})
            sid = p.get('scriptId')
            if sid:
                script_map[sid] = {
                    'url': p.get('url', ''),
                    'length': p.get('length', 0),
                }
    return script_map

def extract_monitoring_events_for_script(trace, target_script_ids, harness_id):
    events = []
    for entry in trace:
        ev = entry.get('event', {})
        if ev.get('method') != 'Runtime.consoleAPICalled':
            continue
        params = ev.get('params', {})
        args = params.get('args', [])
        if not args or args[0].get('type') != 'string':
            continue
        val = args[0].get('value', '')
        if not val.startswith('{'):
            continue

        stack = params.get('stackTrace', {})
        frames = stack.get('callFrames', [])
        frame_sids = set(f.get('scriptId', '') for f in frames)

        if not (frame_sids & target_script_ids):
            continue
        if frame_sids == {harness_id}:
            continue

        try:
            parsed = json.loads(val)
            if 'type' in parsed:
                skip_types = {'Monitoring Started', 'Monitoring Script Fully Loaded',
                              'Synthetic Interaction'}
                if parsed['type'] not in skip_types:
                    events.append(parsed)
        except (json.JSONDecodeError, KeyError):
            pass
    return events

def extract_network_for_script(trace, target_script_ids):
    requests = []
    for entry in trace:
        ev = entry.get('event', {})
        if ev.get('method') == 'Network.requestWillBeSent':
            initiator = ev.get('params', {}).get('initiator', {})
            stack = initiator.get('stack', {})
            frames = stack.get('callFrames', [])
            frame_sids = set(f.get('scriptId', '') for f in frames)
            if frame_sids & target_script_ids:
                req = ev.get('params', {}).get('request', {})
                if req.get('url'):
                    requests.append(req)
    return requests

def process_domain(domain_path, seen_hashes, max_per_domain=3):
    tar_path = os.path.join(domain_path, 'loaded_js.tar.gz')
    trace_path = os.path.join(domain_path, 'trace.json')

    try:
        trace = load_domain_trace(trace_path)
    except Exception:
        return []

    script_map = parse_script_map(trace)

    harness_id = None
    for sid, info in script_map.items():
        if not info['url'] and info['length'] > 10000:
            harness_id = sid
            break

    js_files = []
    try:
        with tarfile.open(tar_path, 'r:gz') as tar:
            for m in tar.getmembers():
                if not m.name.endswith('.js') or not m.isfile() or m.size < 200:
                    continue
                f = tar.extractfile(m)
                if not f:
                    continue
                content = f.read()
                code = content.decode('utf-8', errors='replace')
                if len(code.strip()) < 200:
                    continue
                sha = hashlib.sha256(content).hexdigest()
                js_files.append((m.name, code, len(content), sha))
    except Exception:
        return []

    results = []
    added = 0
    for name, code, size, sha in js_files:
        if sha in seen_hashes:
            continue
        if added >= max_per_domain:
            break

        matched_sids = set()
        for sid, info in script_map.items():
            if sid == harness_id:
                continue
            if info['length'] == size:
                matched_sids.add(sid)

        if not matched_sids:
            continue

        mon_events = extract_monitoring_events_for_script(trace, matched_sids, harness_id)
        net_reqs = extract_network_for_script(trace, matched_sids)

        static_score, static_hits = static_analyze(code)
        behav_score, behav_hits = analyze_trace(mon_events, net_reqs)

        seen_hashes.add(sha)
        added += 1
        results.append({
            'sha': sha[:16],
            'size': size,
            'static_score': static_score,
            'static_hits': static_hits,
            'static_rules': [h.rule for h in static_hits],
            'behav_score': behav_score,
            'behav_hits': behav_hits,
            'behav_rules': [h.rule for h in behav_hits],
            'n_mon_events': len(mon_events),
            'n_net_reqs': len(net_reqs),
        })

    return results

def collect_malicious():
    from behavioral_trace_heuristics import load_trace, extract_monitoring_events, extract_network_requests
    static_results = []
    behav_results = []
    seen = set()
    trace_dir = Path(os.environ.get('TRACES_DIR', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data', 'traces', 'full_campaign')))
    if not trace_dir.exists():
        trace_dir = Path(os.environ.get('TRACES_DIR', ''))
        if not trace_dir.exists():
            return [], []

    for tb in trace_dir.rglob('triggered_by.json'):
        try:
            with open(tb) as f:
                d = json.load(f)
            js_path = d.get('original_file', '')
            trace_file = str(tb.parent / 'trace_v2.json.zst')
            if not (js_path and os.path.isfile(js_path) and os.path.isfile(trace_file)):
                continue
            if js_path in seen:
                continue
            seen.add(js_path)

            with open(js_path, 'r', errors='replace') as f:
                code = f.read(5_000_000)
            s_score, s_hits = static_analyze(code)
            static_results.append({'score': s_score, 'hits': s_hits,
                                   'rules_fired': [h.rule for h in s_hits]})

            trace = load_trace(trace_file)
            events = extract_monitoring_events(trace)
            net_reqs = extract_network_requests(trace)
            b_score, b_hits = analyze_trace(events, net_reqs)
            behav_results.append({'score': b_score, 'hits': b_hits,
                                  'rules_fired': [h.rule for h in b_hits]})
        except Exception:
            pass

    return static_results, behav_results

def print_table(rows, n_ben, n_mal, label):
    print(f"\n  {label}: Benign={n_ben}  Malicious={n_mal}")
    print(f"  {'Rule':<35} {'Wt':>4} {'FP#':>6} {'FP%':>7} {'TP#':>5} {'TP%':>7}")
    print("  " + "-" * 68)
    z = u = 0
    for name, wt, fp, fpr, tp, tpr in rows:
        m = " *" if fp == 0 else ""
        if fp == 0: z += 1
        elif fpr < 1.0: u += 1
        print(f"  {name:<35} {wt:>4.1f} {fp:>6} {fpr:>6.2f}% {tp:>5} {tpr:>6.1f}%{m}")
    mx = max(rows, key=lambda x: x[3])
    print(f"\n  Zero-FP: {z}/{len(rows)}  FP<1%: {z+u}/{len(rows)}  Max FP: {mx[0]} at {mx[3]:.2f}%")
    return z, u

def weight_sens(cache, heuristics, threshold, na, wa):
    orig = {getattr(f, na): getattr(f, wa) for f in heuristics}
    for cn, w in [('calibrated', orig),
                  ('uniform', {n: 1.0 for n in orig}),
                  ('binary', {n: (2.0 if v >= 3.0 else 1.0) for n, v in orig.items()})]:
        tp = fp = fn = tn = 0
        for hits, lbl in cache:
            s = sum(w.get(h.rule, h.weight) for h in hits)
            if lbl == 'mal':
                if s >= threshold: tp += 1
                else: fn += 1
            else:
                if s >= threshold: fp += 1
                else: tn += 1
        nm = tp + fn; nb = fp + tn
        print(f"    {cn}: Recall={tp/nm*100:.1f}% ({tp}/{nm})  FPR={fp/nb*100:.2f}% ({fp}/{nb})")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-dir", required=True)
    parser.add_argument("--sample-size", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    random.seed(args.seed)

    print("Collecting scan-data domains...", flush=True)
    all_dirs = sorted(d for d in os.listdir(args.scan_dir)
                      if os.path.isdir(os.path.join(args.scan_dir, d)))
    random.shuffle(all_dirs)

    valid_domains = []
    for d in all_dirs:
        p = os.path.join(args.scan_dir, d)
        if (os.path.isfile(os.path.join(p, 'trace.json')) and
                os.path.isfile(os.path.join(p, 'loaded_js.tar.gz'))):
            valid_domains.append(p)
    print(f"  Valid domains: {len(valid_domains)}", flush=True)

    print("\nExtracting unique JS files with isolated traces...", flush=True)
    seen_hashes = set()
    benign = []
    domains_processed = 0
    for dp in valid_domains:
        if len(benign) >= args.sample_size:
            break
        res = process_domain(dp, seen_hashes, max_per_domain=3)
        benign.extend(res)
        domains_processed += 1
        if domains_processed % 500 == 0:
            print(f"  [progress] {domains_processed} domains, {len(benign)} unique JS files...", flush=True)

    benign = benign[:args.sample_size]
    print(f"  Final: {len(benign)} unique JS files from {domains_processed} domains", flush=True)
    print(f"  Files with isolated behavioral events: {sum(1 for b in benign if b['n_mon_events'] > 0)}", flush=True)

    print("\nCollecting malicious samples...", flush=True)
    mal_static, mal_behav = collect_malicious()
    print(f"  Malicious: {len(mal_static)} static, {len(mal_behav)} behavioral", flush=True)

    n_ben = len(benign)
    n_mal_s = len(mal_static)
    n_mal_b = len(mal_behav)

    print(f"\n{'='*70}")
    print("STATIC HEURISTIC EVALUATION (per unique JS file)")
    print(f"{'='*70}")

    s_fp = Counter()
    s_tp = Counter()
    for r in benign:
        for rule in r['static_rules']: s_fp[rule] += 1
    for r in mal_static:
        for rule in r['rules_fired']: s_tp[rule] += 1

    s_rows = []
    for fn in STATIC_HEURISTICS:
        nm = fn._heuristic_name; wt = fn._heuristic_weight
        fp = s_fp.get(nm, 0); tp = s_tp.get(nm, 0)
        s_rows.append((nm, wt, fp, fp/n_ben*100 if n_ben else 0, tp, tp/n_mal_s*100 if n_mal_s else 0))
    s_rows.sort(key=lambda x: -x[1])

    sz, su = print_table(s_rows, n_ben, n_mal_s, "STATIC")

    bs = np.array([r['static_score'] for r in benign])
    ms = np.array([r['score'] for r in mal_static])
    sba = int(np.sum(bs >= STATIC_THRESHOLD))
    sma = int(np.sum(ms >= STATIC_THRESHOLD))

    print(f"\n  Score: benign median={np.median(bs):.1f} P95={np.percentile(bs,95):.1f}  malicious median={np.median(ms):.1f} P25={np.percentile(ms,25):.1f}")
    print(f"  At threshold {STATIC_THRESHOLD}: recall={sma/n_mal_s*100:.1f}% ({sma}/{n_mal_s})  FPR={sba/n_ben*100:.2f}% ({sba}/{n_ben})")
    print(f"\n  Weight sensitivity:")
    sc = [(r['hits'], 'mal') for r in mal_static] + [(r['static_hits'], 'ben') for r in benign]
    weight_sens(sc, STATIC_HEURISTICS, STATIC_THRESHOLD, '_heuristic_name', '_heuristic_weight')

    print(f"\n{'='*70}")
    print("BEHAVIORAL HEURISTIC EVALUATION (per isolated script trace)")
    print(f"{'='*70}")

    b_fp = Counter()
    b_tp = Counter()
    for r in benign:
        for rule in r['behav_rules']: b_fp[rule] += 1
    for r in mal_behav:
        for rule in r['rules_fired']: b_tp[rule] += 1

    b_rows = []
    for fn in BEHAV_HEURISTICS:
        nm = fn._h_name; wt = fn._h_weight
        fp = b_fp.get(nm, 0); tp = b_tp.get(nm, 0)
        b_rows.append((nm, wt, fp, fp/n_ben*100 if n_ben else 0, tp, tp/n_mal_b*100 if n_mal_b else 0))
    b_rows.sort(key=lambda x: -x[1])

    bz, bu = print_table(b_rows, n_ben, n_mal_b, "BEHAVIORAL (isolated)")

    bb = np.array([r['behav_score'] for r in benign])
    mb = np.array([r['score'] for r in mal_behav])
    bba = int(np.sum(bb >= BEHAV_THRESHOLD))
    bma = int(np.sum(mb >= BEHAV_THRESHOLD))

    print(f"\n  Score: benign median={np.median(bb):.1f} P95={np.percentile(bb,95):.1f}  malicious median={np.median(mb):.1f} P25={np.percentile(mb,25):.1f}")
    print(f"  At threshold {BEHAV_THRESHOLD}: recall={bma/n_mal_b*100:.1f}% ({bma}/{n_mal_b})  FPR={bba/n_ben*100:.2f}% ({bba}/{n_ben})")
    print(f"\n  Weight sensitivity:")
    bc = [(r['hits'], 'mal') for r in mal_behav] + [(r['behav_hits'], 'ben') for r in benign]
    weight_sens(bc, BEHAV_HEURISTICS, BEHAV_THRESHOLD, '_h_name', '_h_weight')

    print(f"\n{'='*70}")
    print("COMBINED SUMMARY")
    print(f"{'='*70}")
    print(f"  Benign: {n_ben} unique JS files with isolated script traces")
    print(f"  Malicious: {n_mal_s} static / {n_mal_b} behavioral")
    print(f"  {'Metric':<40} {'Static (37)':>15} {'Behavioral (33)':>18}")
    print(f"  {'-'*75}")
    print(f"  {'Zero-FP rules':<40} {sz:>15} {bz:>18}")
    print(f"  {'FP < 1% rules':<40} {sz+su:>15} {bz+bu:>18}")
    print(f"  {'Benign score median':<40} {np.median(bs):>15.1f} {np.median(bb):>18.1f}")
    print(f"  {'Malicious score median':<40} {np.median(ms):>15.1f} {np.median(mb):>18.1f}")
    print(f"  {'Recall (calibrated)':<40} {sma/n_mal_s*100:>14.1f}% {bma/n_mal_b*100:>17.1f}%")
    print(f"  {'FPR (calibrated)':<40} {sba/n_ben*100:>14.2f}% {bba/n_ben*100:>17.2f}%")

    if args.output:
        out = {
            'n_benign': n_ben, 'n_domains': domains_processed,
            'static': {
                'n_mal': n_mal_s, 'threshold': STATIC_THRESHOLD,
                'recall': sma/n_mal_s, 'fpr': sba/n_ben,
                'benign_median': float(np.median(bs)), 'benign_p95': float(np.percentile(bs,95)),
                'mal_median': float(np.median(ms)), 'mal_p25': float(np.percentile(ms,25)),
                'zero_fp': sz, 'under1pct': sz+su,
                'rules': [dict(zip(['rule','weight','fp','fpr','tp','tpr'], r)) for r in s_rows],
            },
            'behavioral': {
                'n_mal': n_mal_b, 'threshold': BEHAV_THRESHOLD,
                'recall': bma/n_mal_b, 'fpr': bba/n_ben,
                'benign_median': float(np.median(bb)), 'benign_p95': float(np.percentile(bb,95)),
                'mal_median': float(np.median(mb)), 'mal_p25': float(np.percentile(mb,25)),
                'zero_fp': bz, 'under1pct': bz+bu,
                'rules': [dict(zip(['rule','weight','fp','fpr','tp','tpr'], r)) for r in b_rows],
            },
        }
        with open(args.output, 'w') as f:
            json.dump(out, f, indent=2)
        print(f"\n  Saved to {args.output}")

if __name__ == "__main__":
    main()

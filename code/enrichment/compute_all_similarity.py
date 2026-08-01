#!/usr/bin/env python3

import json
import os
import re
import sys
import hashlib
from pathlib import Path
from itertools import combinations
from collections import defaultdict

import esprima

CLUSTER_RESULTS = Path("traces/full_campaign/cluster_output/cluster_results.json")
FULL_QUEUE = Path("full_campaign_queue.json")
MISSING_QUEUE = Path("missing_campaign_queue.json")

def load_queues():
    campaigns = defaultdict(list)
    for qf in [FULL_QUEUE, MISSING_QUEUE]:
        with open(qf) as f:
            for entry in json.load(f):
                campaigns[entry["campaign_name"]].append(entry)
    return campaigns

def load_behavioral():
    with open(CLUSTER_RESULTS) as f:
        traces = json.load(f)
    return traces

def byte_similarity(file_a, file_b):
    with open(file_a, 'rb') as f:
        a = f.read()
    with open(file_b, 'rb') as f:
        b = f.read()
    if a == b:
        return 1.0
    from difflib import SequenceMatcher
    return SequenceMatcher(None, a, b).ratio()

def tokenize_ast(js_code):
    try:
        tree = esprima.parseScript(js_code, tolerant=True)
    except:
        try:
            tree = esprima.parseModule(js_code, tolerant=True)
        except:
            return []
    
    tokens = []
    stack = [tree]
    count = 0
    while stack and count < 10000:
        node = stack.pop()
        if hasattr(node, 'type'):
            tokens.append(node.type)
            count += 1
        if hasattr(node, '__dict__'):
            for key, val in node.__dict__.items():
                if key in ('type', 'loc', 'range'):
                    continue
                if hasattr(val, 'type'):
                    stack.append(val)
                elif isinstance(val, list):
                    for item in reversed(val):
                        if hasattr(item, 'type'):
                            stack.append(item)
    return tokens

def ast_similarity(file_a, file_b):
    with open(file_a, 'r', errors='replace') as f:
        code_a = f.read()
    with open(file_b, 'r', errors='replace') as f:
        code_b = f.read()
    
    tokens_a = tokenize_ast(code_a)
    tokens_b = tokenize_ast(code_b)
    
    if not tokens_a and not tokens_b:
        return 1.0
    if not tokens_a or not tokens_b:
        return 0.0
    
    from difflib import SequenceMatcher
    MAX = 4000
    if len(tokens_a) > MAX:
        tokens_a = tokens_a[:MAX//2] + tokens_a[-MAX//2:]
    if len(tokens_b) > MAX:
        tokens_b = tokens_b[:MAX//2] + tokens_b[-MAX//2:]
    
    return SequenceMatcher(None, tokens_a, tokens_b).ratio()

def jaccard(set_a, set_b):
    if not set_a and not set_b:
        return 1.0
    intersection = set_a & set_b
    union = set_a | set_b
    return len(intersection) / len(union) if union else 1.0

def main():
    campaigns = load_queues()
    traces = load_behavioral()
    
    domain_tokens = defaultdict(list)
    for t in traces:
        domain_tokens[t["domain"]].append(set(t["tokens"]))
    
    domain_to_campaign = {}
    for cn, entries in campaigns.items():
        for e in entries:
            domain_to_campaign[e["domain"]] = cn
    
    results = {}
    
    for campaign_name in sorted(campaigns.keys()):
        entries = campaigns[campaign_name]
        
        js_files = []
        seen_hashes = set()
        for e in entries:
            fp = e["original_file"]
            if os.path.exists(fp):
                with open(fp, 'rb') as f:
                    h = hashlib.md5(f.read()).hexdigest()
                if h not in seen_hashes:
                    seen_hashes.add(h)
                    js_files.append(fp)
        
        behav_sets = []
        for e in entries:
            d = e["domain"]
            if d in domain_tokens:
                for ts in domain_tokens[d]:
                    if ts:
                        behav_sets.append(ts)
        
        n_js = len(js_files)
        n_behav = len(behav_sets)
        n_samples = max(n_js, n_behav)
        
        if n_js >= 2:
            byte_sims = []
            ast_sims = []
            for fa, fb in combinations(js_files, 2):
                byte_sims.append(byte_similarity(fa, fb))
                ast_sims.append(ast_similarity(fa, fb))
            avg_byte = sum(byte_sims) / len(byte_sims)
            avg_ast = sum(ast_sims) / len(ast_sims)
        elif n_js == 1:
            avg_byte = 1.0
            avg_ast = 1.0
        else:
            avg_byte = None
            avg_ast = None
        
        if n_behav >= 2:
            behav_sims = []
            for sa, sb in combinations(behav_sets, 2):
                behav_sims.append(jaccard(sa, sb))
            avg_behav = sum(behav_sims) / len(behav_sims)
        elif n_behav == 1:
            avg_behav = 1.0
        else:
            avg_behav = None
        
        results[campaign_name] = {
            "n_js_unique": n_js,
            "n_behav_traces": n_behav,
            "n_samples": n_samples,
            "byte_sim": avg_byte,
            "ast_sim": avg_ast,
            "behav_sim": avg_behav
        }
        
        byte_str = f"{avg_byte:.2f}" if avg_byte is not None else "N/A"
        ast_str = f"{avg_ast:.2f}" if avg_ast is not None else "N/A"
        behav_str = f"{avg_behav:.2f}" if avg_behav is not None else "N/A"
        
        print(f"{campaign_name:20s}  N_js={n_js:2d}  N_beh={n_behav:2d}  "
              f"Byte={byte_str:>5s}  AST={ast_str:>5s}  Behav={behav_str:>5s}")
    
    with open("all_campaign_similarity.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\nSaved to all_campaign_similarity.json")

if __name__ == "__main__":
    main()

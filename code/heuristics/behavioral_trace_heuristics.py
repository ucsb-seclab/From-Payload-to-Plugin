#!/usr/bin/env python3

import argparse
import io
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from urllib.parse import urlparse

def load_trace(path):
    if path.endswith('.zst'):
        import zstandard
        with open(path, 'rb') as f:
            dctx = zstandard.ZstdDecompressor()
            reader = dctx.stream_reader(f)
            text = io.TextIOWrapper(reader, encoding='utf-8').read()
            return json.loads(text)
    else:
        with open(path, 'r', errors='replace') as f:
            return json.load(f)

def extract_monitoring_events(trace):
    events = []
    for entry in trace:
        ev = entry.get('event', {})
        if ev.get('method') != 'Runtime.consoleAPICalled':
            continue
        args = ev.get('params', {}).get('args', [])
        if not args or args[0].get('type') != 'string':
            continue
        val = args[0].get('value', '')
        if not val.startswith('{'):
            continue
        try:
            parsed = json.loads(val)
            if 'type' in parsed:
                events.append(parsed)
        except (json.JSONDecodeError, KeyError):
            pass
    return events

def extract_network_requests(trace):
    requests = []
    for entry in trace:
        ev = entry.get('event', {})
        if ev.get('method') == 'Network.requestWillBeSent':
            req = ev.get('params', {}).get('request', {})
            if req.get('url'):
                requests.append(req)
    return requests

BASELINE = {
    'Object.defineProperty Called': 36,
    'DOM Property Read': 31,
    'DOM Mutation': 10,
    'Event Listener Added': 6,
    'setAttribute Called': 6,
    'Synthetic Interaction': 5,
    'Timeout (Function) Set': 1,
    'Monitoring Started': 1,
    'Monitoring Script Fully Loaded': 1,
}

@dataclass
class Hit:
    rule: str
    weight: float
    category: str
    description: str
    evidence: str = ""

HEURISTICS = []

def heuristic(name, weight, category, description):
    def decorator(fn):
        fn._h_name = name
        fn._h_weight = weight
        fn._h_cat = category
        fn._h_desc = description
        HEURISTICS.append(fn)
        return fn
    return decorator

@heuristic("net_xhr_external", 3.0, "Network",
           "XHR requests to external domains")
def check_xhr_external(events, net_reqs, **kw):
    xhr_evts = [e for e in events if e['type'] == 'XHR Request']
    if not xhr_evts:
        return []
    domains = set()
    for e in xhr_evts:
        url = e.get('url', '')
        parsed = urlparse(url)
        if parsed.hostname:
            domains.add(parsed.hostname)
    if domains:
        return [Hit("net_xhr_external", 3.0, "Network",
                     f"XHR to {len(domains)} external domain(s)",
                     ', '.join(sorted(domains)))]
    return []

@heuristic("net_xhr_multi_domain", 2.0, "Network",
           "XHR to 3+ distinct external domains (C2 fallback)")
def check_xhr_multi_domain(events, **kw):
    xhr_evts = [e for e in events if e['type'] == 'XHR Request']
    domains = set()
    for e in xhr_evts:
        parsed = urlparse(e.get('url', ''))
        if parsed.hostname:
            domains.add(parsed.hostname)
    if len(domains) >= 3:
        return [Hit("net_xhr_multi_domain", 2.0, "Network",
                     f"XHR to {len(domains)} distinct domains (C2 fallback pattern)",
                     ', '.join(sorted(domains)))]
    return []

@heuristic("net_fetch_external", 3.0, "Network",
           "Fetch requests to external domains")
def check_fetch_external(events, **kw):
    fetch_evts = [e for e in events if e['type'] in ('Fetch Request',)]
    if not fetch_evts:
        return []
    domains = set()
    for e in fetch_evts:
        parsed = urlparse(e.get('url', ''))
        if parsed.hostname:
            domains.add(parsed.hostname)
    if domains:
        return [Hit("net_fetch_external", 3.0, "Network",
                     f"Fetch to external domain(s)",
                     ', '.join(sorted(domains)))]
    return []

@heuristic("net_beacon", 3.0, "Network",
           "Beacon API call for data exfiltration")
def check_beacon(events, **kw):
    beacons = [e for e in events if e['type'] == 'Beacon API Call']
    if beacons:
        urls = [e.get('url', 'unknown') for e in beacons]
        return [Hit("net_beacon", 3.0, "Network",
                     f"sendBeacon to external endpoint ({len(beacons)} call(s))",
                     '; '.join(urls))]
    return []

@heuristic("net_script_src_external", 2.0, "Network",
           "External script loaded via .src property")
def check_script_src(events, **kw):
    src_evts = [e for e in events
                if e['type'] == 'Script Src Set' and e.get('isExternal')]
    if src_evts:
        urls = [e.get('src', '') for e in src_evts]
        return [Hit("net_script_src_external", 2.0, "Network",
                     f"External script injection via .src ({len(src_evts)} script(s))",
                     '; '.join(urls[:3]))]
    return []

@heuristic("net_script_src_php", 2.0, "Network",
           "Script src pointing to .php endpoint with data parameter")
def check_script_php(events, **kw):
    for e in events:
        if e['type'] == 'Script Src Set':
            src = e.get('src', '')
            if '.php' in src and ('data=' in src or 'host=' in src):
                return [Hit("net_script_src_php", 2.0, "Network",
                             "Script src to .php endpoint with host/data param",
                             src[:200])]
    return []

@heuristic("net_suspicious_tld", 1.0, "Network",
           "Communication with suspicious TLDs (.cfd, .shop, .top, .biz)")
def check_suspicious_tld(events, net_reqs, **kw):
    suspicious_tlds = {'.cfd', '.shop', '.top', '.biz', '.buzz', '.cyou'}
    found = set()
    for e in events:
        for key in ('url', 'src'):
            url = e.get(key, '')
            parsed = urlparse(url)
            host = parsed.hostname or ''
            for tld in suspicious_tlds:
                if host.endswith(tld):
                    found.add(host)
    for req in net_reqs:
        parsed = urlparse(req.get('url', ''))
        host = parsed.hostname or ''
        for tld in suspicious_tlds:
            if host.endswith(tld):
                found.add(host)
    if found:
        return [Hit("net_suspicious_tld", 1.0, "Network",
                     f"Suspicious TLD domain(s)",
                     ', '.join(sorted(found)))]
    return []

@heuristic("net_tds_params", 2.0, "Network",
           "TDS-style script parameters (se_referrer, default_keyword, landing_url)")
def check_tds_params(events, **kw):
    tds_keys = ['se_referrer', 'default_keyword', 'landing_url']
    for e in events:
        src = e.get('src', '') + e.get('url', '')
        found = [k for k in tds_keys if k in src]
        if len(found) >= 2:
            return [Hit("net_tds_params", 2.0, "Network",
                        f"TDS tracking parameters: {', '.join(found)}",
                        src[:200])]
    return []

@heuristic("net_blockchain_rpc", 3.0, "Network",
           "Blockchain RPC endpoint communication (PolyClickFix/CSSInject)")
def check_blockchain_rpc(events, net_reqs, **kw):
    rpc_keywords = ['rpc-mainnet', 'matic', 'quiknode', 'polygon', 'ethers',
                    'infura', 'alchemy', 'chainstack']
    for e in events:
        url = e.get('url', '')
        if any(k in url.lower() for k in rpc_keywords):
            return [Hit("net_blockchain_rpc", 3.0, "Network",
                        "Blockchain RPC endpoint communication", url[:200])]
    for req in net_reqs:
        url = req.get('url', '')
        if any(k in url.lower() for k in rpc_keywords):
            return [Hit("net_blockchain_rpc", 3.0, "Network",
                        "Blockchain RPC endpoint communication", url[:200])]
    return []

@heuristic("net_known_malicious", 4.0, "Network",
           "Known malicious domains from campaign IOCs")
def check_known_domains(events, net_reqs, **kw):
    known = [
        'goveanrs.org', 'govearali.org', 'ligovera.shop', 'alianzeg.shop',
        'getalia.org', 'ztdaliweb.shop', 'getfix.win',
        'doubleclicks.biz', 'cdnjslibraries.com', 'nulead.pl',
        '6opo.com', 'e2ertt.com', 'aj1559.online', 'dalecta.com',
        'hupe-wa.dz', 'usrpubtrk.com', 'cdnstats.top',
    ]
    found = set()
    all_urls = []
    for e in events:
        for key in ('url', 'src'):
            if key in e:
                all_urls.append(e[key])
    for req in net_reqs:
        all_urls.append(req.get('url', ''))
    for url in all_urls:
        host = urlparse(url).hostname or ''
        for d in known:
            if d in host:
                found.add(d)
    if found:
        return [Hit("net_known_malicious", 4.0, "Network",
                     f"Known malicious domain(s): {', '.join(sorted(found))}")]
    return []

@heuristic("inject_docwrite_iframe", 4.0, "CodeInjection",
           "document.write with full-page iframe overlay (JSFiretruck)")
def check_docwrite_iframe(events, **kw):
    for e in events:
        if e['type'] == 'Document.write Call':
            content = e.get('contentPreview', '')
            if '<iframe' in content.lower():
                return [Hit("inject_docwrite_iframe", 4.0, "CodeInjection",
                             "document.write injects iframe",
                             content[:200])]
    return []

@heuristic("inject_docwrite_script", 3.0, "CodeInjection",
           "document.write with <script src=external> (CookieLoader)")
def check_docwrite_script(events, **kw):
    for e in events:
        if e['type'] == 'Document.write Call':
            content = e.get('contentPreview', '')
            if '<script' in content.lower() and ('src=' in content or 'http' in content):
                return [Hit("inject_docwrite_script", 3.0, "CodeInjection",
                             "document.write injects external script",
                             content[:200])]
    return []

@heuristic("inject_docwrite_css_hide", 3.0, "CodeInjection",
           "CSS injection hiding page content via document.write (JSFiretruck)")
def check_docwrite_css_hide(events, **kw):
    for e in events:
        if e['type'] == 'Document.write Call':
            content = e.get('contentPreview', '')
            if 'opacity' in content and ('z-index' in content or 'visibility' in content
                                          or '2147483647' in content):
                return [Hit("inject_docwrite_css_hide", 3.0, "CodeInjection",
                             "CSS visibility takeover via document.write",
                             content[:200])]
    return []

@heuristic("inject_docwrite_multiple", 2.0, "CodeInjection",
           "Multiple document.write calls (page takeover sequence)")
def check_docwrite_multiple(events, **kw):
    dw_count = sum(1 for e in events if e['type'] == 'Document.write Call')
    if dw_count >= 3:
        return [Hit("inject_docwrite_multiple", 2.0, "CodeInjection",
                     f"{dw_count} document.write calls (page takeover sequence)")]
    return []

@heuristic("inject_eval", 2.0, "CodeInjection",
           "eval() call for dynamic code execution")
def check_eval(events, **kw):
    evals = [e for e in events if e['type'] == 'Eval Call']
    if evals:
        return [Hit("inject_eval", 2.0, "CodeInjection",
                     f"eval() call ({len(evals)} occurrence(s))")]
    return []

@heuristic("inject_function_constructor", 2.0, "CodeInjection",
           "new Function() constructor for dynamic code execution")
def check_func_constructor(events, **kw):
    fcs = [e for e in events if e['type'] == 'Function Constructor']
    if fcs:
        return [Hit("inject_function_constructor", 2.0, "CodeInjection",
                     f"Function constructor ({len(fcs)} occurrence(s))")]
    return []

@heuristic("inject_atob_deobfuscation", 1.5, "CodeInjection",
           "atob() base64 decoding for deobfuscation")
def check_atob(events, **kw):
    atobs = [e for e in events if e['type'] == 'atob De-obfuscation']
    if not atobs:
        return []
    hits = [Hit("inject_atob_deobfuscation", 1.5, "CodeInjection",
                f"atob de-obfuscation ({len(atobs)} call(s))")]
    if len(atobs) >= 3:
        hits.append(Hit("inject_atob_recursive", 1.5, "CodeInjection",
                        f"Recursive/layered atob ({len(atobs)} calls)"))
    return hits

@heuristic("fp_heavy_prop_read", 2.0, "Fingerprinting",
           "Excessive DOM property reads (above baseline)")
def check_heavy_prop_read(events, **kw):
    reads = [e for e in events if e['type'] == 'DOM Property Read']
    above = len(reads) - BASELINE.get('DOM Property Read', 0)
    if above > 30:
        return [Hit("fp_heavy_prop_read", 2.0, "Fingerprinting",
                     f"{len(reads)} property reads ({above} above baseline)")]
    return []

@heuristic("fp_hardware_fingerprint", 2.0, "Fingerprinting",
           "Hardware fingerprinting via navigator properties")
def check_hardware_fp(events, **kw):
    hw_props = {'hardwareConcurrency', 'deviceMemory', 'maxTouchPoints',
                'cpuClass', 'oscpu'}
    found = set()
    for e in events:
        if e['type'] == 'DOM Property Read':
            prop = e.get('property', '')
            if prop in hw_props:
                found.add(prop)
    if found:
        return [Hit("fp_hardware_fingerprint", 2.0, "Fingerprinting",
                     f"Hardware fingerprinting properties: {', '.join(sorted(found))}")]
    return []

@heuristic("fp_webgl", 2.0, "Fingerprinting",
           "WebGL context creation for GPU fingerprinting")
def check_webgl(events, **kw):
    wgl = [e for e in events if e['type'] == 'WebGL Context Creation']
    if wgl:
        return [Hit("fp_webgl", 2.0, "Fingerprinting",
                     "WebGL context creation (GPU fingerprinting)")]
    return []

@heuristic("fp_worker_blob", 1.5, "Fingerprinting",
           "Web Worker with Blob URL for off-thread fingerprint computation")
def check_worker_blob(events, **kw):
    has_worker = any(e['type'] == 'Web Worker Created' for e in events)
    has_blob = any(e['type'] == 'Blob URL Created' for e in events)
    if has_worker and has_blob:
        return [Hit("fp_worker_blob", 1.5, "Fingerprinting",
                     "Web Worker + Blob URL (off-thread computation)")]
    return []

@heuristic("fp_useragent_repeated", 1.0, "Fingerprinting",
           "navigator.userAgent read multiple times")
def check_ua_repeated(events, **kw):
    ua_count = sum(1 for e in events
                   if e['type'] == 'DOM Property Read'
                   and e.get('property') == 'userAgent')
    if ua_count >= 5:
        return [Hit("fp_useragent_repeated", 1.0, "Fingerprinting",
                     f"navigator.userAgent read {ua_count} times")]
    return []

@heuristic("hook_excessive_listeners", 2.0, "EventHooking",
           "Excessive event listener registration (above baseline)")
def check_excessive_listeners(events, **kw):
    listeners = [e for e in events if e['type'] == 'Event Listener Added']
    above = len(listeners) - BASELINE.get('Event Listener Added', 0)
    if above > 10:
        types = Counter(e.get('eventType', '') for e in listeners)
        return [Hit("hook_excessive_listeners", 2.0, "EventHooking",
                     f"{len(listeners)} listeners ({above} above baseline)",
                     ', '.join(f"{k}({v})" for k, v in types.most_common(5)))]
    return []

@heuristic("hook_interaction_hijack", 2.0, "EventHooking",
           "Click/mouse/keyboard listeners on document for interaction hijacking")
def check_interaction_hijack(events, **kw):
    hijack_types = {'click', 'mousedown', 'mousemove', 'mouseup', 'touchstart',
                    'touchend', 'keydown', 'keypress', 'keyup'}
    found = set()
    for e in events:
        if e['type'] == 'Event Listener Added':
            target = e.get('target', {})
            tag = target.get('tagName', '') if isinstance(target, dict) else str(target)
            evt = e.get('eventType', '')
            if evt in hijack_types and tag in ('#document', 'HTML', 'BODY', 'document'):
                found.add(evt)
    if len(found) >= 3:
        return [Hit("hook_interaction_hijack", 2.0, "EventHooking",
                     f"Interaction hijack listeners on document: {', '.join(sorted(found))}")]
    return []

@heuristic("hook_ad_network_events", 2.0, "EventHooking",
           "Ad network custom event listeners (impression, missclick)")
def check_ad_events(events, **kw):
    ad_keywords = ['impression', 'missclick', 'adcash', 'aclib', 'campaign']
    found = []
    for e in events:
        if e['type'] == 'Event Listener Added':
            evt = e.get('eventType', '').lower()
            if any(k in evt for k in ad_keywords):
                found.append(e.get('eventType', ''))
        if e['type'] == 'Object.defineProperty Called':
            prop = e.get('property', '').lower()
            if any(k in prop for k in ad_keywords):
                found.append(e.get('property', ''))
    if found:
        return [Hit("hook_ad_network_events", 2.0, "EventHooking",
                     f"Ad network indicators: {', '.join(set(found))}")]
    return []

@heuristic("hook_excessive_defineprop", 1.0, "EventHooking",
           "Excessive Object.defineProperty calls (above baseline)")
def check_excessive_defineprop(events, **kw):
    dps = [e for e in events if e['type'] == 'Object.defineProperty Called']
    above = len(dps) - BASELINE.get('Object.defineProperty Called', 0)
    if above > 15:
        props = [e.get('property', '') for e in dps]
        non_standard = [p for p in props if p and not p.startswith('_') and len(p) > 2]
        return [Hit("hook_excessive_defineprop", 1.0, "EventHooking",
                     f"{len(dps)} defineProperty ({above} above baseline)",
                     ', '.join(set(non_standard[:10])))]
    return []

@heuristic("hook_nonstandard_defineprop", 1.5, "EventHooking",
           "defineProperty on suspicious/non-standard names")
def check_nonstandard_defineprop(events, **kw):
    suspicious = {'BonServer', 'CaptchaPayload', 'Protection', 'TokenStorage',
                  'Adcash', 'aclib', 'AtcshAltNm', 'fetch', 'sha1',
                  'COOKIE_NAME', 'BotDetected'}
    found = set()
    for e in events:
        if e['type'] == 'Object.defineProperty Called':
            prop = e.get('property', '')
            if prop in suspicious:
                found.add(prop)
    if found:
        return [Hit("hook_nonstandard_defineprop", 1.5, "EventHooking",
                     f"Suspicious defineProperty targets: {', '.join(sorted(found))}")]
    return []

@heuristic("hook_timeout_cascade", 1.0, "EventHooking",
           "Excessive setTimeout calls (async execution chain)")
def check_timeout_cascade(events, **kw):
    timeouts = [e for e in events if e['type'] == 'Timeout (Function) Set']
    above = len(timeouts) - BASELINE.get('Timeout (Function) Set', 0)
    if above > 10:
        return [Hit("hook_timeout_cascade", 1.0, "EventHooking",
                     f"{len(timeouts)} setTimeout calls ({above} above baseline)")]
    return []

@heuristic("hook_interval_persistent", 1.0, "EventHooking",
           "setInterval for persistent monitoring")
def check_interval(events, **kw):
    intervals = [e for e in events if e['type'] == 'Interval (Function) Set']
    if intervals:
        delays = [e.get('delay', 0) for e in intervals]
        return [Hit("hook_interval_persistent", 1.0, "EventHooking",
                     f"setInterval ({len(intervals)} interval(s))",
                     f"delays: {delays}")]
    return []

@heuristic("hook_visibility_persistence", 1.0, "EventHooking",
           "visibilitychange/pageshow listeners for reactivation on tab return")
def check_visibility(events, **kw):
    persist_events = {'visibilitychange', 'pageshow', 'online'}
    found = set()
    for e in events:
        if e['type'] == 'Event Listener Added':
            if e.get('eventType', '') in persist_events:
                found.add(e['eventType'])
    if len(found) >= 2:
        return [Hit("hook_visibility_persistence", 1.0, "EventHooking",
                     f"Persistence listeners: {', '.join(sorted(found))}")]
    return []

@heuristic("exfil_cookie_read", 1.5, "Exfiltration",
           "Cookie read combined with network activity")
def check_cookie_read(events, **kw):
    has_cookie = any(e['type'] in ('Cookie Read', 'Cookie Update', 'Cookie Write')
                     for e in events)
    has_network = any(e['type'] in ('XHR Request', 'Fetch Request', 'Beacon API Call',
                                     'Script Src Set')
                      for e in events)
    if has_cookie and has_network:
        return [Hit("exfil_cookie_read", 1.5, "Exfiltration",
                     "Cookie access combined with network activity")]
    return []

@heuristic("exfil_cookie_gate", 1.5, "Exfiltration",
           "Cookie write followed by script injection (gate pattern)")
def check_cookie_gate(events, **kw):
    has_cookie_write = any(e['type'] in ('Cookie Update', 'Cookie Write') for e in events)
    has_inject = any(e['type'] in ('Document.write Call', 'Script Src Set') for e in events)
    if has_cookie_write and has_inject:
        return [Hit("exfil_cookie_gate", 1.5, "Exfiltration",
                     "Cookie write + script injection (gating pattern)")]
    return []

@heuristic("exfil_postmessage", 1.5, "Exfiltration",
           "Cross-origin postMessage communication")
def check_postmessage(events, **kw):
    msgs = [e for e in events if e['type'] in ('postMessage Called', 'postMessage Received')]
    if msgs:
        return [Hit("exfil_postmessage", 1.5, "Exfiltration",
                     f"postMessage communication ({len(msgs)} message(s))")]
    return []

MALICIOUS_THRESHOLD = 6.0

def analyze_trace(events, net_reqs):
    all_hits = []
    for fn in HEURISTICS:
        try:
            hits = fn(events=events, net_reqs=net_reqs)
            all_hits.extend(hits)
        except Exception:
            pass
    score = sum(h.weight for h in all_hits)
    return score, all_hits

def analyze_file(path, threshold = MALICIOUS_THRESHOLD):
    trace = load_trace(path)
    events = extract_monitoring_events(trace)
    net_reqs = extract_network_requests(trace)

    type_counts = Counter(e['type'] for e in events)
    above_baseline = {}
    for t, c in type_counts.items():
        base = BASELINE.get(t, 0)
        if c > base:
            above_baseline[t] = c - base

    score, hits = analyze_trace(events, net_reqs)
    verdict = "MALICIOUS" if score >= threshold else "BENIGN"

    return {
        "file": path,
        "total_cdp_events": len(trace),
        "monitoring_events": len(events),
        "network_requests": len(net_reqs),
        "event_type_counts": dict(type_counts.most_common()),
        "above_baseline": above_baseline,
        "verdict": verdict,
        "score": round(score, 1),
        "threshold": threshold,
        "hits": [
            {
                "rule": h.rule,
                "weight": h.weight,
                "category": h.category,
                "description": h.description,
                "evidence": h.evidence,
            }
            for h in sorted(hits, key=lambda x: -x.weight)
        ],
    }

def main():
    parser = argparse.ArgumentParser(
        description="Behavioral heuristic classifier for CDP execution traces"
    )
    parser.add_argument("path", help="Trace file (.json.zst or .json) or directory")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print detailed hit breakdown")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--threshold", "-t", type=float, default=MALICIOUS_THRESHOLD,
                        help=f"Score threshold for malicious verdict (default: {MALICIOUS_THRESHOLD})")
    args = parser.parse_args()

    threshold = args.threshold

    targets = []
    if os.path.isdir(args.path):
        for root, _, files in os.walk(args.path):
            for f in files:
                if f == 'trace_v2.json.zst' or (f.endswith('.json') and 'trace' in f):
                    targets.append(os.path.join(root, f))
    else:
        targets.append(args.path)

    results = []
    for path in sorted(targets):
        try:
            result = analyze_file(path, threshold=threshold)
            results.append(result)
        except Exception as e:
            results.append({"file": path, "error": str(e)})

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            if "error" in r:
                print(f"  ERROR  {r['file']}: {r['error']}")
                continue
            marker = "MAL" if r["verdict"] == "MALICIOUS" else "OK "
            evts = r.get("monitoring_events", 0)
            above = r.get("above_baseline", {})
            print(f"  [{marker}] {r['score']:5.1f}  {r['file']}  ({evts} events, {len(above)} types above baseline)")
            if args.verbose:
                if r["hits"]:
                    for h in r["hits"]:
                        ev = f" — {h['evidence']}" if h["evidence"] else ""
                        print(f"         +{h['weight']:.1f}  [{h['category']}] {h['rule']}{ev}")
                if above:
                    print(f"         above baseline: {above}")
                print()

        mal_count = sum(1 for r in results if r.get("verdict") == "MALICIOUS")
        err_count = sum(1 for r in results if "error" in r)
        print(f"\n  {len(results)} traces scanned, {mal_count} malicious, "
              f"{len(results) - mal_count - err_count} benign, {err_count} errors "
              f"(threshold={threshold})")

    has_mal = any(r.get("verdict") == "MALICIOUS" for r in results)
    sys.exit(1 if has_mal else 0)

if __name__ == "__main__":
    main()

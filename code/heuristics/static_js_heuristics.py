#!/usr/bin/env python3

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field

@dataclass
class Hit:
    rule: str
    weight: float
    description: str
    evidence: str = ""

HEURISTICS = []

def heuristic(name, weight, description):
    def decorator(fn):
        fn._heuristic_name = name
        fn._heuristic_weight = weight
        fn._heuristic_desc = description
        HEURISTICS.append(fn)
        return fn
    return decorator

@heuristic("obf_0x_naming", 3.0,
           "Obfuscator.io _0x hex variable naming (14/22 campaigns)")
def check_0x_naming(code):
    matches = re.findall(r'\b_0x[a-f0-9]{2,8}\b', code)
    if len(matches) >= 5:
        return [Hit("obf_0x_naming", 3.0,
                     f"_0x hex variable names ({len(matches)} occurrences)",
                     f"e.g. {matches[0]}, {matches[1]}")]
    return []

@heuristic("obf_string_rotation", 4.0,
           "String array rotation via push/shift with while(!![])")
def check_string_rotation(code):
    hits = []
    if re.search(r'while\s*\(\s*!!\s*\[\s*\]\s*\)', code):
        if re.search(r'\.push\s*\(\s*\w+\s*\.shift\s*\(\s*\)\s*\)', code):
            hits.append(Hit("obf_string_rotation", 4.0,
                            "String array rotation (push/shift in while(!![])) loop"))
    return hits

@heuristic("obf_jsfuck", 5.0,
           "JSFuck encoding using only []()!+ characters (JSFiretruck)")
def check_jsfuck(code):
    stripped = code.strip()
    if len(stripped) > 500:
        sample = stripped[:2000]
        jsfuck_chars = sum(1 for c in sample if c in '[]()!+')
        ratio = jsfuck_chars / len(sample) if sample else 0
        if ratio > 0.9:
            return [Hit("obf_jsfuck", 5.0,
                        f"JSFuck encoding ({ratio:.0%} of first 2K chars are []()!+)")]
    return []

@heuristic("obf_hex_escapes", 3.0,
           "Bulk hex escape sequences \\x.. for string hiding (CookieLoader, OverlayInject)")
def check_hex_escapes(code):
    matches = re.findall(r'\\x[0-9a-fA-F]{2}', code)
    if len(matches) >= 20:
        return [Hit("obf_hex_escapes", 3.0,
                     f"Hex escape sequences ({len(matches)} occurrences)")]
    return []

@heuristic("obf_xor_decrypt", 4.5,
           "XOR decryption loop with charCodeAt (CSSInject, PolyClickFix)")
def check_xor_decrypt(code):
    if re.search(r'charCodeAt\s*\([^)]*\)\s*\^\s*', code):
        if re.search(r'new\s+Function\s*\(', code) or re.search(r'\beval\s*\(', code):
            return [Hit("obf_xor_decrypt", 4.5,
                        "XOR decryption combined with new Function() or eval()")]
    return []

@heuristic("obf_custom_b64_alphabet", 2.5,
           "Custom base64 alphabet string literal (HexArray, GDPRInject)")
def check_custom_b64(code):
    if re.search(
        r'["\']ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[-_+/]["\']',
        code
    ):
        return [Hit("obf_custom_b64_alphabet", 2.5,
                     "Full base64 alphabet as string literal")]
    return []

@heuristic("obf_large_b64_blob", 3.0,
           "Large base64 blob stored as string constant")
def check_large_b64_blob(code):
    matches = re.findall(r"'[A-Za-z0-9+/=]{500,}'|\"[A-Za-z0-9+/=]{500,}\"", code)
    if matches:
        return [Hit("obf_large_b64_blob", 3.0,
                     f"Large base64 blob ({len(matches[0])} chars)")]
    return []

@heuristic("obf_bracket_prop_access", 2.0,
           "Property access via bracket notation with _0x decoder calls")
def check_bracket_prop(code):
    matches = re.findall(r'\[\s*_0x[a-f0-9]+\s*\(\s*0x[a-f0-9]+\s*\)\s*\]', code)
    if len(matches) >= 5:
        return [Hit("obf_bracket_prop_access", 2.0,
                     f"Bracket-notation property access via _0x decoder ({len(matches)} calls)")]
    return []

@heuristic("obf_parseint_checksum", 2.0,
           "parseInt checksum loop for string array ordering")
def check_parseint_checksum(code):
    count = len(re.findall(r'parseInt\s*\(\s*_0x', code))
    if count >= 4:
        return [Hit("obf_parseint_checksum", 2.0,
                     f"parseInt checksum calls ({count} occurrences)")]
    return []

@heuristic("obf_string_reverse", 2.5,
           "String reversal via split/reverse/join for API name hiding")
def check_string_reverse(code):
    if re.search(r"split\s*\(\s*['\"]\.?['\"]\s*\)\s*\.reverse\s*\(\s*\)\s*\.join\s*\(", code):
        return [Hit("obf_string_reverse", 2.5,
                     "String constructed via split('').reverse().join('')")]
    return []

@heuristic("obf_fromcharcode_loop", 2.5,
           "String.fromCharCode in a loop for string construction")
def check_fromcharcode_loop(code):
    count = len(re.findall(r'String\.fromCharCode', code))
    if count >= 3:
        return [Hit("obf_fromcharcode_loop", 2.5,
                     f"String.fromCharCode ({count} occurrences)")]
    return []

@heuristic("api_eval_function", 4.0,
           "eval() or new Function() for dynamic code execution")
def check_eval_function(code):
    hits = []
    if re.search(r'\beval\s*\(', code):
        hits.append(Hit("api_eval", 4.0, "eval() call detected"))
    if re.search(r'new\s+Function\s*\(', code):
        hits.append(Hit("api_new_function", 4.0, "new Function() constructor"))
    return hits

@heuristic("api_create_script", 3.0,
           "Dynamic script element creation (15+/22 campaigns)")
def check_create_script(code):
    if re.search(r'createElement\s*\(\s*[\'"]script[\'"]\s*\)', code):
        return [Hit("api_create_script", 3.0,
                     "document.createElement('script')")]
    if re.search(r'createElement\s*\(\s*_0x', code):
        return [Hit("api_create_script", 3.0,
                     "createElement with obfuscated tag name")]
    return []

@heuristic("api_document_write", 3.5,
           "document.write for injecting script tags (CookieLoader)")
def check_document_write(code):
    if re.search(r'document\s*[\[.]\s*(?:write|writeln)', code):
        if re.search(r'(?:unescape|script|src)', code):
            return [Hit("api_document_write", 3.5,
                        "document.write with script/unescape content")]
    if re.search(r'unescape\s*\(', code) and re.search(r'document\s*\[', code):
        return [Hit("api_document_write", 3.5,
                     "document[...](unescape(...)) pattern")]
    return []

@heuristic("api_atob", 2.5,
           "atob() base64 decoding (5/22 campaigns)")
def check_atob(code):
    matches = re.findall(r"atob\s*\(\s*['\"][A-Za-z0-9+/=]{10,}['\"]\s*\)", code)
    if matches:
        return [Hit("api_atob", 2.5,
                     f"atob() with inline base64 string ({len(matches)} calls)")]
    return []

@heuristic("api_cookie_manipulation", 2.0,
           "Cookie setting combined with script loading")
def check_cookie_manip(code):
    if re.search(r'document\s*[\[.]\s*(?:cookie|_0x)', code):
        if re.search(r'expires|setMinutes|setTime|toUTCString', code):
            return [Hit("api_cookie_manipulation", 2.0,
                        "Cookie manipulation with expiry")]
    return []

@heuristic("api_sendbeacon", 3.0,
           "navigator.sendBeacon for data exfiltration (TagInject)")
def check_sendbeacon(code):
    if re.search(r'navigator\s*\.\s*sendBeacon\s*\(', code):
        return [Hit("api_sendbeacon", 3.0,
                     "navigator.sendBeacon() call")]
    return []

@heuristic("api_insertbefore", 1.5,
           "insertBefore for script injection into DOM")
def check_insertbefore(code):
    if re.search(r'insertBefore\s*\(', code):
        if re.search(r'createElement|script', code, re.IGNORECASE):
            return [Hit("api_insertbefore", 1.5,
                        "insertBefore combined with script creation")]
    return []

@heuristic("api_innerhtml_write", 2.0,
           "innerHTML write with embedded HTML/script content")
def check_innerhtml(code):
    if re.search(r'innerHTML\s*[\+]?=', code):
        if re.search(r'<(?:script|iframe|div|style)', code, re.IGNORECASE):
            return [Hit("api_innerhtml_write", 2.0,
                        "innerHTML assignment with embedded HTML elements")]
    return []

@heuristic("evasion_wp_cookie_check", 5.0,
           "WordPress admin cookie detection (MultiC2)")
def check_wp_cookie(code):
    if re.search(r'wordpress_logged_in_|wp-settings-|wp-saving-|wp-postpass_', code):
        return [Hit("evasion_wp_cookie_check", 5.0,
                     "WordPress admin cookie detection regex")]
    return []

@heuristic("evasion_bot_ua_check", 4.0,
           "Bot/crawler user-agent detection (MultiC2)")
def check_bot_ua(code):
    if re.search(r'bot\|crawl\|slurp\|spider', code, re.IGNORECASE):
        return [Hit("evasion_bot_ua_check", 4.0,
                     "Bot user-agent regex for evasion")]
    if re.search(r'(?:phantomjs|headless|puppet|selenium)', code, re.IGNORECASE):
        return [Hit("evasion_bot_ua_check", 4.0,
                     "Headless browser detection strings")]
    return []

@heuristic("evasion_wp_path_filter", 3.0,
           "WordPress internal path exclusion (MultiC2)")
def check_wp_path_filter(code):
    wp_paths = ['wp-admin', 'wp-login', 'wp-cron', 'xmlrpc', 'wp-json']
    found = [p for p in wp_paths if p in code]
    if len(found) >= 3:
        return [Hit("evasion_wp_path_filter", 3.0,
                     f"WordPress path exclusions ({', '.join(found)})")]
    return []

@heuristic("evasion_session_gate", 3.5,
           "sessionStorage single-execution gating (SessHijack, FadeRedirect)")
def check_session_gate(code):
    if re.search(r'sessionStorage\s*[\[.]\s*(?:getItem|setItem)', code):
        if re.search(r'once|__sync|loaded|visited|_ssp_', code):
            return [Hit("evasion_session_gate", 3.5,
                        "sessionStorage-based single-execution gate")]
    return []

@heuristic("evasion_anti_debug", 4.0,
           "Anti-debugging via ReDoS or constructor checks")
def check_anti_debug(code):
    if re.search(r'\(\(\(\.?\+\)\+\)\+\)\$', code):
        return [Hit("evasion_anti_debug", 4.0,
                     "ReDoS-based anti-debugging pattern")]
    if re.search(r'\.constructor\s*\(\s*.*\)\s*\.search', code):
        return [Hit("evasion_anti_debug", 4.0,
                     "Constructor-based anti-debugging")]
    return []

@heuristic("evasion_timing_check", 2.0,
           "performance.now() timing checks (WooBackdoor)")
def check_timing(code):
    if re.search(r'performance\s*\.\s*now\s*\(\s*\)', code):
        if re.search(r'debug|detect|delay|threshold', code, re.IGNORECASE):
            return [Hit("evasion_timing_check", 2.0,
                        "Timing-based analysis detection")]
    return []

@heuristic("dom_css_fade", 3.5,
           "CSS fadeIn animation injection to mask redirect (SessHijack, FadeRedirect)")
def check_css_fade(code):
    if re.search(r'@keyframes\s+fadeIn', code):
        return [Hit("dom_css_fade", 3.5,
                     "@keyframes fadeIn CSS injection")]
    if re.search(r'opacity\s*:\s*0.*animation.*fadeIn', code):
        return [Hit("dom_css_fade", 3.5,
                     "Opacity + fadeIn animation pattern")]
    return []

@heuristic("dom_hidden_iframe", 3.0,
           "Hidden iframe creation")
def check_hidden_iframe(code):
    if re.search(r'createElement\s*\(\s*[\'"]iframe[\'"]\s*\)', code):
        if re.search(r'display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*0|height\s*:\s*0', code):
            return [Hit("dom_hidden_iframe", 3.0,
                        "Hidden iframe injection")]
    return []

@heuristic("dom_overlay_inject", 2.5,
           "Overlay or layer HTML injection (OverlayInject)")
def check_overlay(code):
    if re.search(r'(?:overlay|layer|modal|popup).*innerHTML', code, re.IGNORECASE):
        return [Hit("dom_overlay_inject", 2.5,
                     "Overlay/layer HTML injection")]
    return []

@heuristic("net_multi_c2", 5.0,
           "Multiple C2 fallback domains (MultiC2)")
def check_multi_c2(code):
    atob_urls = re.findall(r"atob\s*\(\s*['\"][A-Za-z0-9+/=]{20,}['\"]\s*\)", code)
    if len(atob_urls) >= 3:
        return [Hit("net_multi_c2", 5.0,
                     f"Multiple base64-encoded URLs ({len(atob_urls)} atob calls)")]
    return []

@heuristic("net_exfil_fingerprint", 3.0,
           "Browser fingerprint exfiltration via URL parameters")
def check_fingerprint_exfil(code):
    fp_keys = ['host', 'referrer', 'userAgent', 'screen', 'timezone',
               'language', 'platform', 'resolution']
    found = [k for k in fp_keys if k in code]
    if len(found) >= 3:
        if re.search(r'XMLHttpRequest|fetch\s*\(|sendBeacon|\.send\s*\(', code):
            return [Hit("net_exfil_fingerprint", 3.0,
                        f"Fingerprint collection + exfiltration ({', '.join(found)})")]
    return []

@heuristic("net_data_param_exfil", 3.0,
           "Data exfiltration via URL ?data= parameter with JSON.stringify")
def check_data_param(code):
    if re.search(r'JSON\.stringify', code) and re.search(r'encodeURIComponent', code):
        if re.search(r'\?\s*data\s*=|[&?]d=', code):
            return [Hit("net_data_param_exfil", 3.0,
                        "JSON-encoded data exfiltration via URL parameter")]
    return []

@heuristic("net_suspicious_domain", 4.0,
           "Known malicious or suspicious domain patterns")
def check_suspicious_domains(code):
    suspicious = [
        r'doubleclicks\.biz',
        r'cdnjslibraries\.com',
        r'api\.nulead\.pl',
        r'6opo\.com',
        r'e2ertt\.com',
        r'aj1559\.online',
        r'dalecta\.com',
        r'goveanrs\.org',
        r'govearali\.org',
        r'ligovera\.shop',
        r'alianzeg\.shop',
        r'ztdaliweb\.shop',
        r'hupe-wa\.dz',
    ]
    found = []
    for pat in suspicious:
        if re.search(pat, code, re.IGNORECASE):
            found.append(pat.replace('\\', ''))
    if found:
        return [Hit("net_suspicious_domain", 4.0,
                     f"Known malicious domains: {', '.join(found)}")]
    return []

@heuristic("wp_rogue_user", 5.0,
           "Rogue WordPress user creation (WooBackdoor)")
def check_rogue_user(code):
    if re.search(r'user-new\.php|wooconmerce1|administrator.*role|user_login', code):
        return [Hit("wp_rogue_user", 5.0,
                     "WordPress rogue user creation indicators")]
    return []

@heuristic("wp_rest_api_abuse", 3.0,
           "WordPress REST API abuse for credential harvesting")
def check_wp_rest_api(code):
    if re.search(r'wp-json/|rest_route=', code):
        if re.search(r'password|credential|token|nonce', code, re.IGNORECASE):
            return [Hit("wp_rest_api_abuse", 3.0,
                        "WordPress REST API access with credential keywords")]
    return []

@heuristic("anomaly_single_line", 2.0,
           "Entire payload on a single line (common in obfuscated malware)")
def check_single_line(code):
    lines = code.split('\n')
    non_empty = [l for l in lines if l.strip()]
    if len(non_empty) <= 3 and len(code) > 2000:
        return [Hit("anomaly_single_line", 2.0,
                     f"Payload is {len(code)} bytes on {len(non_empty)} line(s)")]
    return []

@heuristic("anomaly_high_entropy", 2.0,
           "High character entropy suggesting obfuscation or encoded data")
def check_entropy(code):
    import math
    if len(code) < 500:
        return []
    freq = {}
    for c in code[:10000]:
        freq[c] = freq.get(c, 0) + 1
    total = sum(freq.values())
    entropy = -sum((count / total) * math.log2(count / total) for count in freq.values())
    if entropy > 5.5:
        return [Hit("anomaly_high_entropy", 2.0,
                     f"High Shannon entropy: {entropy:.2f} bits/char")]
    return []

@heuristic("anomaly_low_whitespace", 1.5,
           "Extremely low whitespace ratio (packed/minified malware)")
def check_whitespace(code):
    if len(code) < 1000:
        return []
    ws = sum(1 for c in code if c in ' \t\n\r')
    ratio = ws / len(code)
    if ratio < 0.02:
        return [Hit("anomaly_low_whitespace", 1.5,
                     f"Whitespace ratio: {ratio:.1%} (packed code)")]
    return []

MALICIOUS_THRESHOLD = 8.0

def analyze(code):
    all_hits = []
    for fn in HEURISTICS:
        try:
            hits = fn(code)
            all_hits.extend(hits)
        except Exception:
            pass
    score = sum(h.weight for h in all_hits)
    return score, all_hits

def analyze_file(path, threshold = MALICIOUS_THRESHOLD):
    with open(path, 'r', errors='replace') as f:
        code = f.read()

    score, hits = analyze(code)
    verdict = "MALICIOUS" if score >= threshold else "BENIGN"

    return {
        "file": path,
        "size_bytes": len(code),
        "verdict": verdict,
        "score": round(score, 1),
        "threshold": threshold,
        "hits": [
            {
                "rule": h.rule,
                "weight": h.weight,
                "description": h.description,
                "evidence": h.evidence,
            }
            for h in sorted(hits, key=lambda x: -x.weight)
        ],
    }

def main():
    parser = argparse.ArgumentParser(
        description="Static heuristic classifier for malicious JavaScript"
    )
    parser.add_argument("path", help="JS file or directory to scan")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print detailed hit breakdown")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--threshold", "-t", type=float, default=MALICIOUS_THRESHOLD,
                        help=f"Score threshold for malicious verdict (default: {MALICIOUS_THRESHOLD})")
    args = parser.parse_args()

    _threshold = args.threshold

    targets = []
    if os.path.isdir(args.path):
        for root, _, files in os.walk(args.path):
            for f in files:
                if f.endswith('.js'):
                    targets.append(os.path.join(root, f))
    else:
        targets.append(args.path)

    results = []
    for path in sorted(targets):
        try:
            result = analyze_file(path, threshold=_threshold)
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
            print(f"  [{marker}] {r['score']:5.1f}  {r['file']}")
            if args.verbose and r["hits"]:
                for h in r["hits"]:
                    ev = f" — {h['evidence']}" if h["evidence"] else ""
                    print(f"         +{h['weight']:.1f}  {h['rule']}{ev}")
                print()

        mal_count = sum(1 for r in results if r.get("verdict") == "MALICIOUS")
        print(f"\n  {len(results)} files scanned, {mal_count} malicious, "
              f"{len(results) - mal_count} benign (threshold={_threshold})")

    has_mal = any(r.get("verdict") == "MALICIOUS" for r in results)
    sys.exit(1 if has_mal else 0)

if __name__ == "__main__":
    main()

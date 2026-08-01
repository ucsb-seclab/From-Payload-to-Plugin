FAMILY_COLORS = {
    "Ad Injection": "#4878D0",
    "Session Redirect": "#EE854A",
    "Multi-C2 Inject": "#D65F5F",
    "JSFiretruck Redirect": "#956CB4",
    "Malvertising": "#59A14F",
    "Tag Injection": "#8C8C8C",
    "Widget Loader": "#D4A6C8",
    "CSS Injection": "#82C6E2",
    "Blockchain ClickFix": "#E15759",
    "Cookie Loader": "#76B7B2",
    "TDS Redirect": "#F28E2B",
    "WooCommerce Backdoor": "#B07AA1",
    "Overlay Injector": "#9C755F",
    "CDN Loader": "#6A9F58",
}

CANONICAL_CAMPAIGNS = {
    "HexArray-A": [0, 27],
    "HexArray-B": [22, 26],
    "HexArray-C": [3],
    "GDPRInject": [34, 36, 39, 40, 51, 52],
    "SessHijack-A": [10],
    "SessHijack-B": [32],
    "SessHijack-C": [14],
    "FadeRedirect": [45, 49, 55, 61],
    "MultiC2": [2, 7, 13],
    "JSFiretruck": [
        4,
        5,
        6,
        8,
        9,
        11,
        12,
        15,
        16,
        17,
        18,
        19,
        21,
        23,
        24,
        25,
        28,
        33,
        35,
        37,
        42,
        43,
        47,
        50,
        54,
        56,
        57,
    ],
    "MalvertKit": [1],
    "TagInject-A": [20],
    "TagInject-B": [29],
    "CSSInject": [31],
    "PolyClickFix": [48, 53, 58],
    "CookieLoader": [41],
    "TDSRedirect": [46],
    "WooBackdoor": [59],
    "OverlayInject": [60],
    "YWXILoader": [],
}

CAMPAIGN_SUMMARY_FINDINGS = dict(CANONICAL_CAMPAIGNS)
CAMPAIGN_SUMMARY_FINDINGS.update(
    {
        "PolyClickFix": [48, 53, 58, 62],
        "YWXILoader": [63],
    }
)

CAMPAIGN_FAMILIES = {
    "HexArray-A": "Ad Injection",
    "HexArray-B": "Ad Injection",
    "HexArray-C": "Ad Injection",
    "GDPRInject": "Ad Injection",
    "SessHijack-A": "Session Redirect",
    "SessHijack-B": "Session Redirect",
    "SessHijack-C": "Session Redirect",
    "FadeRedirect": "Session Redirect",
    "MultiC2": "Multi-C2 Inject",
    "JSFiretruck": "JSFiretruck Redirect",
    "MalvertKit": "Malvertising",
    "TagInject-A": "Tag Injection",
    "TagInject-B": "Tag Injection",
    "CSSInject": "CSS Injection",
    "PolyClickFix": "Blockchain ClickFix",
    "CookieLoader": "Cookie Loader",
    "TDSRedirect": "TDS Redirect",
    "WooBackdoor": "WooCommerce Backdoor",
    "OverlayInject": "Overlay Injector",
    "YWXILoader": "CDN Loader",
}

import os as _os

FINDINGS_BASE = _os.path.join(
    _os.path.dirname(_os.path.abspath(__file__)), "..", "data", "findings"
)

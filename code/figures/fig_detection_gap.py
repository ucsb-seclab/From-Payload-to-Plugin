#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.lines import Line2D
from datetime import datetime, timedelta
import json
import numpy as np
import re
from campaign_mapping import CAMPAIGN_SUMMARY_FINDINGS, FINDINGS_BASE

CLR_PIPELINE  = '#2ca02c'
CLR_VT        = '#d62728'
CLR_UNDETECT  = '#888888'

RESULTS_BASE = os.path.join(os.path.dirname(FINDINGS_BASE), 'results')
VT_RESULTS_PATH = os.path.join(RESULTS_BASE, 'virustotal_first_detections.json')
CRAWL_DATE_RE = re.compile(r'watchlist_batch_(\d{8})_')


def parse_date(value, fmt='%Y-%m-%d'):
    return datetime.strptime(value, fmt)


def load_finding_metadata(finding_id):
    finding_dir = os.path.join(FINDINGS_BASE, f'find-{finding_id}')
    if not os.path.isdir(finding_dir):
        raise FileNotFoundError(f'Missing finding directory: {finding_dir}')

    metadata_paths = [
        os.path.join(finding_dir, entry, 'metadata.json')
        for entry in sorted(os.listdir(finding_dir))
        if entry != 'resch'
        and os.path.isfile(os.path.join(finding_dir, entry, 'metadata.json'))
    ]
    if len(metadata_paths) != 1:
        raise ValueError(
            f'Expected one metadata.json for finding {finding_id}, '
            f'found {len(metadata_paths)}'
        )

    with open(metadata_paths[0]) as f:
        return json.load(f)


def finding_observation_dates(metadata):
    dates = []
    if metadata.get('observation_date'):
        dates.append(parse_date(metadata['observation_date']))

    for path in metadata.get('original_paths', []):
        match = CRAWL_DATE_RE.search(path)
        if match:
            dates.append(parse_date(match.group(1), '%Y%m%d'))
    return dates


def load_pipeline_first_detections():
    first_detections = {}
    for campaign, finding_ids in CAMPAIGN_SUMMARY_FINDINGS.items():
        dates = []
        for finding_id in finding_ids:
            dates.extend(finding_observation_dates(
                load_finding_metadata(finding_id)
            ))
        if not dates:
            raise ValueError(
                f'No observation date found in raw findings for {campaign}'
            )
        first_detections[campaign] = min(dates)
    return first_detections


def load_virustotal_results():
    with open(VT_RESULTS_PATH) as f:
        raw = json.load(f)

    expected = set(CAMPAIGN_SUMMARY_FINDINGS)
    actual = set(raw.get('campaigns', {}))
    if expected != actual:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(
            f'VirusTotal campaign mismatch; missing={missing}, extra={extra}'
        )

    results = {}
    for campaign, result in raw['campaigns'].items():
        if result is None:
            results[campaign] = None
            continue
        results[campaign] = {
            **result,
            'date': parse_date(result['date']),
        }
    return parse_date(raw['study_end']), results


pipeline_dates = load_pipeline_first_detections()
end_date, vt_results = load_virustotal_results()
detection_data = [
    (campaign, pipeline_dates[campaign], vt_results[campaign])
    for campaign in CAMPAIGN_SUMMARY_FINDINGS
]

fig, ax = plt.subplots(figsize=(7.0, 3.6))

x_positions = np.arange(len(detection_data))

for i, (name, pipeline_date, vt_result) in enumerate(detection_data):
    ax.scatter(i, pipeline_date, color=CLR_PIPELINE, marker='D', s=55, zorder=5,
               edgecolors='black', linewidths=0.6)

    if vt_result:
        vt_date = vt_result['date']
        gap_days = (vt_date - pipeline_date).days
        if gap_days > 0:
            ax.scatter(i, vt_date, color=CLR_VT, marker='o', s=45, zorder=5,
                       edgecolors='black', linewidths=0.5)
            ax.annotate('', xy=(i, vt_date), xytext=(i, pipeline_date),
                        arrowprops=dict(arrowstyle='->', color='black', lw=1.0))
            ax.text(i + 0.18, vt_date, f'{gap_days}d', fontsize=6.5,
                    ha='left', va='center', color='black', fontweight='bold')
        else:
            marker_date = vt_date + timedelta(days=4)
            ax.scatter(i, marker_date, color=CLR_VT, marker='o',
                       s=45, zorder=5, edgecolors='black', linewidths=0.5)
            ratio = (f"{vt_result['detected_engines']}/"
                     f"{vt_result['total_engines']}")
            ax.text(i + 0.18, marker_date, ratio, fontsize=6,
                    ha='left', va='center', color='#555555')
    else:
        ax.plot([i, i], [pipeline_date, end_date], '--', color=CLR_UNDETECT,
                linewidth=0.8, alpha=0.7)

ax.set_xticks(x_positions)
ax.set_xticklabels([d[0] for d in detection_data], fontsize=7,
                   fontfamily='sans-serif', rotation=45, ha='right')

first_date = min(pipeline_dates.values())
ax.set_ylim(first_date - timedelta(days=2), end_date + timedelta(days=3))
ax.invert_yaxis()
ax.yaxis.set_major_formatter(mdates.DateFormatter('%b %d'))
ax.yaxis.set_major_locator(mdates.MonthLocator())
ax.tick_params(axis='y', labelsize=7)
ax.set_ylabel('Date (2025\u20132026)', fontsize=8, fontfamily='sans-serif')

ax.grid(True, axis='y', alpha=0.2, linewidth=0.3)

legend_elements = [
    Line2D([0], [0], marker='D', color='w', markerfacecolor=CLR_PIPELINE, markersize=7,
           markeredgecolor='black', markeredgewidth=0.5, label='Pipeline first detection'),
    Line2D([0], [0], marker='o', color='w', markerfacecolor=CLR_VT, markersize=7,
           markeredgecolor='black', markeredgewidth=0.5, label='VT first detection'),
    Line2D([0], [0], linestyle='--', color=CLR_UNDETECT, linewidth=1.0,
           label='Undetected throughout study'),
]
ax.legend(handles=legend_elements, loc='lower left', fontsize=6.5,
          frameon=True, framealpha=0.95, edgecolor='#aaaaaa',
          handlelength=1.5, handletextpad=0.4, borderpad=0.5,
          ncol=3)

plt.tight_layout()

plt.savefig('fig_detection_gap.pdf',
            bbox_inches='tight', dpi=300)
plt.savefig('fig_detection_gap.png',
            bbox_inches='tight', dpi=300)
print("Saved fig_detection_gap.pdf and .png")

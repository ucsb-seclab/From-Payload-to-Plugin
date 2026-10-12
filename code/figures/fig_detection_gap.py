#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.lines import Line2D
from datetime import datetime, timedelta
import numpy as np
import os

CLR_PIPELINE  = '#2ca02c'
CLR_VT        = '#d62728'
CLR_UNDETECT  = '#888888'

detection_data = [
    ("HexArray-A", "2025-12-28", None),
    ("HexArray-B", "2026-02-10", None),
    ("HexArray-C", "2025-12-29", None),
    ("GDPRInject", "2026-03-02", None),
    ("SessHijack-A", "2025-12-30", None),
    ("SessHijack-B", "2026-02-17", None),
    ("SessHijack-C", "2026-02-17", None),
    ("FadeRedirect", "2026-03-02", None),
    ("MultiC2", "2025-12-30", "2026-01-15"),
    ("JSFiretruck", "2026-01-01", "2026-01-01"),
    ("MalvertKit", "2026-01-16", None),
    ("TagInject-A", "2026-02-07", None),
    ("TagInject-B", "2026-02-17", None),
    ("CSSInject", "2026-02-17", None),
    ("PolyClickFix", "2026-03-02", None),
    ("CookieLoader", "2026-03-02", None),
    ("TDSRedirect", "2026-03-02", None),
    ("WooBackdoor", "2026-03-02", None),
    ("OverlayInject", "2026-03-02", None),
    ("YWXILoader", "2026-03-21", None),
]

fig, ax = plt.subplots(figsize=(7.0, 3.6))

x_positions = np.arange(len(detection_data))
end_date = datetime(2026, 3, 25)

for i, (name, our_date, vt_date) in enumerate(detection_data):
    our_dt = datetime.strptime(our_date, '%Y-%m-%d')

    ax.scatter(i, our_dt, color=CLR_PIPELINE, marker='D', s=55, zorder=5,
               edgecolors='black', linewidths=0.6)

    if vt_date:
        vt_dt = datetime.strptime(vt_date, '%Y-%m-%d')
        gap_days = (vt_dt - our_dt).days
        if gap_days > 0:
            ax.scatter(i, vt_dt, color=CLR_VT, marker='o', s=45, zorder=5,
                       edgecolors='black', linewidths=0.5)
            ax.annotate('', xy=(i, vt_dt), xytext=(i, our_dt),
                        arrowprops=dict(arrowstyle='->', color='black', lw=1.0))
            ax.text(i + 0.18, vt_dt, f'{gap_days}d', fontsize=6.5,
                    ha='left', va='center', color='black', fontweight='bold')
        else:
            ax.scatter(i, vt_dt + timedelta(days=4), color=CLR_VT, marker='o',
                       s=45, zorder=5, edgecolors='black', linewidths=0.5)
            ax.text(i + 0.18, vt_dt + timedelta(days=4), '1/62', fontsize=6,
                    ha='left', va='center', color='#555555')
    else:
        ax.plot([i, i], [our_dt, end_date], '--', color=CLR_UNDETECT,
                linewidth=0.8, alpha=0.7)

ax.set_xticks(x_positions)
ax.set_xticklabels([d[0] for d in detection_data], fontsize=7,
                   fontfamily='sans-serif', rotation=45, ha='right')

ax.set_ylim(datetime(2025, 12, 24), datetime(2026, 3, 28))
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

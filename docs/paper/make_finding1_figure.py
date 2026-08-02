"""
docs/paper/make_finding1_figure.py

Plots Figure 2 (Finding 1: cross-dataset domain shift vs. combined training)
from the already-verified numbers in docs/RESEARCH_PAPER_RESULTS_M1-M4.md
Tables 2-3. No new data -- pure visualization of existing ground truth.

Usage:
    python docs/paper/make_finding1_figure.py
"""
import matplotlib.pyplot as plt
import numpy as np

metrics = ["Precision", "Recall", "F1-score"]
cross_dataset = [74.18, 20.12, 31.66]
combined      = [100.00, 80.83, 89.40]

x = np.arange(len(metrics))
w = 0.35

fig, ax = plt.subplots(figsize=(5.2, 3.2))
b1 = ax.bar(x - w / 2, cross_dataset, w, label="Cross-dataset (2017$\\rightarrow$2018)",
            color="#888888", hatch="//", edgecolor="black")
b2 = ax.bar(x + w / 2, combined, w, label="Combined training (2017+2018$\\rightarrow$2018)",
            color="#dddddd", hatch="", edgecolor="black")

for bars in (b1, b2):
    for bar in bars:
        h = bar.get_height()
        ax.annotate(f"{h:.1f}", xy=(bar.get_x() + bar.get_width() / 2, h),
                    xytext=(0, 3), textcoords="offset points",
                    ha="center", va="bottom", fontsize=8)

ax.set_ylabel("Score (%)")
ax.set_xticks(x)
ax.set_xticklabels(metrics)
ax.set_ylim(0, 110)
ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.15), ncol=1, fontsize=8, frameon=False)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
fig.tight_layout()
fig.savefig("docs/paper/figures/finding1_bar_2017v2018.png", dpi=300, bbox_inches="tight")
print("Saved docs/paper/figures/finding1_bar_2017v2018.png")

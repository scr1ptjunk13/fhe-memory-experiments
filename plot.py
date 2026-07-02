"""bench-results.csv -> bench.png, log-log. Linear scaling shows as slope-1 lines."""
import csv
from collections import defaultdict

import matplotlib.pyplot as plt

series = defaultdict(list)
with open("bench-results.csv") as f:
    for row in csv.DictReader(f):
        series[row["op"]].append((int(row["n"]), float(row["mean_ns"]) / 1e9))

fig, ax = plt.subplots(figsize=(7, 5))
for op, pts in series.items():
    ns, secs = zip(*sorted(pts))
    ax.loglog(ns, secs, marker="o", label=op)
ax.set_xlabel("N (array length)")
ax.set_ylabel("seconds per op")
ax.set_title("Linear-scan encrypted read/write, tfhe-rs 1.6")
ax.grid(True, which="both", alpha=0.3)
ax.legend()
fig.tight_layout()
fig.savefig("bench.png", dpi=150)

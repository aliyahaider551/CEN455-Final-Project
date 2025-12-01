"""
Improved visualization for secure vs insecure MQTT metrics.
Option B: Outliers shown but de-cluttered (top 10% only).
"""

import json
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path

RESULTS_FILE = Path(__file__).parent.parent.parent / "logs" / "metrics_results.json"
OUTPUT_DIR = Path(__file__).parent.parent.parent / "docs"


# -------------------------------------------------------------
# Helper: Load JSON results
# -------------------------------------------------------------
def load_results():
    with open(RESULTS_FILE, "r") as f:
        return json.load(f)


# -------------------------------------------------------------
# Helper: trim outliers (show top 10% only)
# -------------------------------------------------------------
def keep_top_percent(data, pct=0.10):
    if len(data) == 0:
        return data
    cutoff_index = int(len(data) * (1 - pct))
    sorted_vals = sorted(data)
    return sorted_vals[:cutoff_index] + sorted_vals[-int(len(data) * pct):]


# -------------------------------------------------------------
# Attack success/block rates
# -------------------------------------------------------------
def plot_attack_rates(results):
    insecure = results["insecure"]
    secure = results["secure"]

    labels = ["Insecure", "Secure"]
    values = [
        insecure.get("attack_attempts", 0),
        secure.get("attacks_blocked", 0)
    ]

    plt.figure(figsize=(8, 5))
    plt.bar(labels, values, color=["#ff6b6b", "#51cf66"], alpha=0.8)
    plt.title("Attack Attempts vs Attack Blocks", fontsize=14, fontweight="bold")
    plt.ylabel("Count")
    plt.grid(axis="y", linestyle="--", alpha=0.3)

    out_file = OUTPUT_DIR / "attack_success_rates.png"
    plt.savefig(out_file, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"    Saved: {out_file}")


# -------------------------------------------------------------
# Boxplot with cleaned outliers
# -------------------------------------------------------------
def plot_latency(results):
    insecure_lat = results["insecure"]["latency_ms"]
    secure_lat = results["secure"]["latency_ms"]

    # Keep only top 10% outliers
    insecure_clean = keep_top_percent(insecure_lat, pct=0.10)
    secure_clean = keep_top_percent(secure_lat, pct=0.10)

    data = [insecure_clean, secure_clean]
    labels = ["Insecure", "Secure"]
    colors = ["#ffadad", "#c0f8c2"]

    fig, ax = plt.subplots(figsize=(12, 7))

    bp = ax.boxplot(
        data,
        labels=labels,
        patch_artist=True,
        showmeans=True,
        meanprops=dict(marker="D", markerfacecolor="red", markersize=8),
        medianprops=dict(color="black", linewidth=1.5),
        flierprops=dict(marker="o", markersize=4, alpha=0.4)  # fewer outliers
    )

    # Color boxes
    for patch, color in zip(bp["boxes"], colors):
        patch.set_facecolor(color)

    # Compute medians
    insecure_med = np.median(insecure_clean)
    secure_med = np.median(secure_clean)

    # Median labels
    ax.text(1, insecure_med, f"Median: {insecure_med:.2f} ms",
            ha="center", va="bottom",
            bbox=dict(boxstyle="round", facecolor="white", alpha=0.9))

    ax.text(2, secure_med, f"Median: {secure_med:.2f} ms",
            ha="center", va="bottom",
            bbox=dict(boxstyle="round", facecolor="white", alpha=0.9))

    ax.set_title("Message Processing Latency (Cleaned Outliers)", fontsize=15, fontweight="bold")
    ax.set_ylabel("Latency (ms)")
    ax.grid(axis="y", linestyle="--", alpha=0.3)

    out_file = OUTPUT_DIR / "latency_comparison.png"
    plt.savefig(out_file, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"   Saved: {out_file}")


# -------------------------------------------------------------
# Security overhead analysis
# -------------------------------------------------------------
def plot_overhead(results):
    insecure = results["insecure"]["latency_ms"]
    secure = results["secure"]["latency_ms"]

    if len(insecure) == 0 or len(secure) == 0:
        print("⚠️  Not enough data for overhead analysis.")
        return

    insecure_avg = np.mean(insecure)
    secure_avg = np.mean(secure)
    overhead = secure_avg - insecure_avg
    overhead_pct = (overhead / insecure_avg) * 100

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(["Insecure", "Secure"], [insecure_avg, secure_avg],
                  color=["#ff6b6b", "#51cf66"], alpha=0.8)

    for bar, val in zip(bars, [insecure_avg, secure_avg]):
        ax.text(bar.get_x() + bar.get_width() / 2, val,
                f"{val:.2f} ms", ha="center", va="bottom",
                fontsize=11, fontweight="bold")

    ax.set_title(f"Security Overhead (≈ {overhead_pct:.1f}%)", fontsize=14, fontweight="bold")
    ax.set_ylabel("Avg Latency (ms)")
    ax.grid(axis="y", linestyle="--", alpha=0.3)

    out_file = OUTPUT_DIR / "security_overhead.png"
    plt.savefig(out_file, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"   Saved: {out_file}")


# -------------------------------------------------------------
# MAIN EXECUTION
# -------------------------------------------------------------
def main():
    print("\n Generating plots...")

    OUTPUT_DIR.mkdir(exist_ok=True)

    results = load_results()

    plot_attack_rates(results)
    plot_latency(results)
    plot_overhead(results)

    print("\n Visualization complete! Files available in /docs/\n")


if __name__ == "__main__":
    main()

"""Report charts from evaluation results (static PNGs, light background).

Detector colors follow a fixed categorical order validated for colour-vision
deficiency; three of them sit below 3:1 contrast on the surface, so every
chart is paired with the summary table (summary.csv) and a legend.
"""

from __future__ import annotations

import random
from pathlib import Path

SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
SURFACE, INK, INK_2, GRID = "#fcfcfb", "#1f1e1d", "#5f5e5a", "#e4e3df"


def _style(plt) -> None:
    plt.rcParams.update({
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "axes.edgecolor": GRID, "axes.labelcolor": INK_2, "xtick.color": INK_2, "ytick.color": INK_2,
        "text.color": INK, "axes.spines.top": False, "axes.spines.right": False,
        "axes.grid": True, "axes.grid.axis": "y", "grid.color": GRID, "grid.linewidth": 0.8,
        "axes.axisbelow": True, "font.size": 10, "legend.frameon": False,
    })


def _colors(detectors: list[str]) -> dict[str, str]:
    if len(detectors) > len(SERIES):
        raise ValueError(f"at most {len(SERIES)} detectors per chart")
    return dict(zip(detectors, SERIES))


def _grouped_bars(ax, rows: list[dict], scenarios: list[str], detectors: list[str], metric: str,
                  colors: dict[str, str], top: float | None = None) -> None:
    """Bars per scenario and detector. A measured 0 gets a "0" label so it is not
    mistaken for a missing bar; scenarios without the measure stay empty.
    """
    width = 0.8 / len(detectors)
    by_key = {(r["scenario"], r["detector"]): r[metric] for r in rows}
    measured = [100 * v for v in by_key.values() if v is not None]
    ymax = top or max(10.0, 1.25 * max(measured, default=0))
    for i, det in enumerate(detectors):
        xs = [x + (i - (len(detectors) - 1) / 2) * width for x in range(len(scenarios))]
        values = [by_key.get((s, det)) for s in scenarios]
        ax.bar(xs, [100 * (v or 0) for v in values], width * 0.92, color=colors[det], label=det)
        for x, v in zip(xs, values):
            if v == 0:
                ax.text(x, ymax * 0.01, "0", ha="center", va="bottom", fontsize=7, color=INK_2)
    ax.set_xticks(range(len(scenarios)), [s.replace("_", " ") for s in scenarios])
    ax.set_ylim(0, ymax)
    ax.set_ylabel("%")


def detection_and_false_positives(summary: list[dict], out: Path) -> str:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    _style(plt)
    detectors = list(dict.fromkeys(r["detector"] for r in summary))
    colors = _colors(detectors)
    attack = sorted({r["scenario"] for r in summary if r["attack_sessions"] and r["scenario"] != "all"})
    every = sorted({r["scenario"] for r in summary if r["scenario"] != "all"}) + ["all"]

    fig, (top, bottom) = plt.subplots(2, 1, figsize=(max(6.5, 1.1 * len(every) + 2), 6.4))
    _grouped_bars(top, summary, attack + ["all"], detectors, "detection_rate", colors, top=105)
    top.set_title("Twin sightings flagged (detection rate), higher is better", loc="left", color=INK)
    _grouped_bars(bottom, summary, every, detectors, "false_positive_rate", colors)
    bottom.set_title("Benign sightings flagged (false-positive rate), lower is better", loc="left", color=INK)
    top.legend(loc="lower left", bbox_to_anchor=(0, 1.12), ncol=len(detectors))
    fig.tight_layout()
    name = "detection_false_positives.png"
    fig.savefig(out / name, dpi=150)
    plt.close(fig)
    return name


def time_to_alert(results, out: Path) -> str | None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    _style(plt)
    detectors = list(dict.fromkeys(r.detector for r in results))
    colors = _colors(detectors)
    delays = {d: [r.time_to_alert for r in results if r.detector == d and r.time_to_alert is not None]
              for d in detectors}
    if not any(delays.values()):
        return None

    rng = random.Random(0)  # fixed jitter, so the figure is reproducible
    fig, ax = plt.subplots(figsize=(max(5, 1.3 * len(detectors) + 1.5), 3.6))
    for i, det in enumerate(detectors):
        values = delays[det]
        if not values:
            continue
        xs = [i + rng.uniform(-0.15, 0.15) for _ in values]
        ax.scatter(xs, values, s=36, color=colors[det], edgecolor=SURFACE, linewidth=1.5, zorder=3)
        median = sorted(values)[len(values) // 2]
        ax.plot([i - 0.28, i + 0.28], [median, median], color=INK, linewidth=2, zorder=4)
    caught = [f"{d}\n{len(delays[d])} caught" for d in detectors]
    ax.set_xticks(range(len(detectors)), caught)
    ax.set_ylabel("seconds from twin in range to first alert")
    longest = max(v for vs in delays.values() for v in vs)
    ax.set_ylim(0, max(10.0, 1.15 * longest))  # at least one scan interval, so all-zero data still reads
    ax.set_title("Time to alert per attack session (bar = median)", loc="left", color=INK)
    fig.tight_layout()
    name = "time_to_alert.png"
    fig.savefig(out / name, dpi=150)
    plt.close(fig)
    return name


def write_all(summary: list[dict], results, out: Path) -> list[str]:
    try:
        import matplotlib  # noqa: F401
    except ImportError:
        print("matplotlib not installed (pip install -e '.[eval]'); skipping figures")
        return []
    names = [detection_and_false_positives(summary, out), time_to_alert(results, out)]
    return [n for n in names if n]

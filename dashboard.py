"""
Smart-IDS dashboard (Streamlit).

    streamlit run dashboard.py

Read-only: it only reads the files your IDS already writes, so main.py and the
rest of the original code do not need to change.

    data/results.txt   one JSON record per stats window {timestamp, features, predictions}
    alerts file        one JSON record per malicious window {timestamp, detections}

Paths come from config/paths.py (RESULTS_FILE, ALERTS_FILE) when available;
otherwise from IDS_RESULTS_FILE / IDS_ALERTS_FILE, or the sidebar.
Also understands the v2 record format ({"label", "confidence"} per model).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

try:
    #RESULTS_FILE = Path(os.getenv("IDS_RESULTS_FILE", "demo/results.txt"))
    #ALERTS_FILE = Path(os.getenv("IDS_ALERTS_FILE", "demo/alerts.jsonl"))
    from config.paths import ALERTS_FILE, RESULTS_FILE
except Exception:
    RESULTS_FILE = Path(os.getenv("IDS_RESULTS_FILE", "data/results.txt"))
    ALERTS_FILE = Path(os.getenv("IDS_ALERTS_FILE", "data/alerts.jsonl"))
try:
    from config.settings import BENIGN_LABEL
except Exception:
    BENIGN_LABEL = os.getenv("BENIGN_LABEL", "Benign")

ERROR_LABEL = "ERROR"
ATTACK_COLORS = ["#D85A30", "#BA7517", "#7F77DD", "#D4537E", "#378ADD", "#639922", "#993C1D"]


# ── Streamlit version compatibility ──────────────────────────────────────────

def show_chart(chart: alt.Chart) -> None:
    try:
        st.altair_chart(chart, width="stretch")
    except TypeError:                                   # older Streamlit
        st.altair_chart(chart, use_container_width=True)


def show_table(df: pd.DataFrame, **kw) -> None:
    try:
        st.dataframe(df, width="stretch", hide_index=True, **kw)
    except TypeError:
        st.dataframe(df, use_container_width=True, hide_index=True, **kw)


# ── Reading the files ────────────────────────────────────────────────────────

def tail_lines(path: Path, n: int, block: int = 65536) -> list[str]:
    """Last n lines of a file, reading from the end (fast on big files)."""
    if not path.is_file():
        return []
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        pos, data = f.tell(), b""
        while pos > 0 and data.count(b"\n") <= n:
            step = min(block, pos)
            pos -= step
            f.seek(pos)
            data = f.read(step) + data
    return [ln.decode("utf-8", errors="replace") for ln in data.splitlines()[-n:]]


def _json(line: str):
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def load_results(path: Path, max_windows: int):
    """-> (windows DataFrame, features DataFrame, model names)."""
    rows, feats, models = [], [], []
    # the original code writes 2 lines per window (bare features + full record)
    for line in tail_lines(path, max_windows * 2 + 20):
        rec = _json(line)
        if not isinstance(rec, dict) or not isinstance(rec.get("predictions"), dict):
            continue                                    # skip bare-feature lines

        row: dict = {"timestamp": rec.get("timestamp")}
        flagged, errors = [], 0
        for model, p in rec["predictions"].items():
            label, conf = (p.get("label"), p.get("confidence")) if isinstance(p, dict) else (p, None)
            row[model] = label
            if conf is not None:
                row[f"{model} conf"] = conf
            if label == ERROR_LABEL:
                errors += 1
            elif label != BENIGN_LABEL:
                flagged.append(f"{model}: {label}")
            if model not in models:
                models.append(model)

        is_mal = rec["malicious"] if "malicious" in rec else bool(flagged)
        row.update(verdict="Malicious" if is_mal else "Benign",
                   flagged_by=", ".join(flagged), errors=errors)
        for extra in ("sensor_id", "suricata_alert", "partial"):
            if extra in rec:
                row[extra] = rec[extra]
        rows.append(row)
        feats.append(rec.get("features") or {})

    if not rows:
        return pd.DataFrame(), pd.DataFrame(), []

    df, feat_df = pd.DataFrame(rows), pd.DataFrame(feats)
    df["time"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce", format="mixed")
    keep = df["time"].notna() & ~df["timestamp"].duplicated(keep="last")
    df, feat_df = df[keep].sort_values("time"), feat_df[keep]
    feat_df = feat_df.loc[df.index].apply(pd.to_numeric, errors="coerce")
    df, feat_df = df.tail(max_windows).reset_index(drop=True), feat_df.tail(max_windows).reset_index(drop=True)
    feat_df.index = df["time"].dt.tz_localize(None)
    return df, feat_df, models


def load_alerts(path: Path, n: int = 1000) -> pd.DataFrame:
    rows = []
    for line in tail_lines(path, n):
        rec = _json(line)
        if not isinstance(rec, dict):
            continue
        det = rec.get("detections") or {}
        rows.append({"timestamp": rec.get("timestamp"),
                     "models": ", ".join(det),
                     "detections": ", ".join(f"{m}: {l}" for m, l in det.items()),
                     "n_models": len(det)})
    if not rows:
        return pd.DataFrame(columns=["timestamp", "models", "detections", "n_models", "time"])
    out = pd.DataFrame(rows)
    out["time"] = pd.to_datetime(out["timestamp"], utc=True, errors="coerce", format="mixed")
    return out.sort_values("time", ascending=False).reset_index(drop=True)


# ── Charts ───────────────────────────────────────────────────────────────────

def label_scale(labels) -> alt.Scale:
    order = sorted(labels, key=lambda l: (l != BENIGN_LABEL, l == ERROR_LABEL, l))
    palette, rng = iter(ATTACK_COLORS), []
    for l in order:
        rng.append("#1D9E75" if l == BENIGN_LABEL else "#888780" if l == ERROR_LABEL else next(palette, "#534AB7"))
    return alt.Scale(domain=order, range=rng)


def swimlane(long: pd.DataFrame, n_models: int) -> alt.Chart:
    plot = long.assign(time=long["time"].dt.tz_localize(None))
    return (
        alt.Chart(plot)
        .mark_square(size=150)
        .encode(
            x=alt.X("time:T", title=None),
            y=alt.Y("model:N", title=None),
            color=alt.Color("label:N", scale=label_scale(plot["label"].unique()), legend=alt.Legend(title="Verdict")),
            tooltip=[alt.Tooltip("time:T", title="Window (UTC)", format="%Y-%m-%d %H:%M:%S"), "model:N", "label:N"],
        )
        .properties(height=46 * n_models + 40)
        .interactive(bind_y=False)
    )


# ── Page ─────────────────────────────────────────────────────────────────────

def render(results_path: str, alerts_path: str, max_windows: int, stale_after: int) -> None:
    df, feat_df, models = load_results(Path(results_path), max_windows)
    alerts = load_alerts(Path(alerts_path))

    if df.empty:
        st.info(
            f"No prediction records found in `{results_path}` yet.\n\n"
            "Start the IDS (`python main.py`) and wait for a Suricata stats event, "
            "or generate sample data with `python demo_data.py`."
        )
        return

    # status
    now = pd.Timestamp.now(tz="UTC")
    age = int((now - df["time"].iloc[-1]).total_seconds())
    if age > stale_after:
        st.warning(f"No new window for {age} s. Is the IDS running and Suricata emitting stats?")
    else:
        st.success(f"Live: last window {age} s ago")

    last = df.iloc[-1]
    n_mal = int((df["verdict"] == "Malicious").sum())

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Windows in view", f"{len(df):,}")
    c2.metric("Malicious windows", f"{n_mal:,}", f"{100 * n_mal / len(df):.1f}% of view", delta_color="off")
    c3.metric("Alerts logged", f"{len(alerts):,}")
    c4.metric("Model errors", f"{int(df['errors'].sum()):,}")
    c5.metric("Latest window", last["verdict"])

    with st.container(border=True):
        detail = last["flagged_by"] or "all models report " + BENIGN_LABEL
        st.markdown(f"**Latest:** `{last['timestamp']}`: {detail}")

    tab_over, tab_models, tab_feat, tab_alerts, tab_raw = st.tabs(
        ["Overview", "Models", "Features", "Alerts", "Raw data"]
    )

    long = df.melt(id_vars=["time"], value_vars=models, var_name="model", value_name="label").dropna(subset=["label"])

    # ── Overview ──
    with tab_over:
        st.caption("One square per window and model. Green = benign, other colours = detected class. Drag to pan, scroll to zoom.")
        show_chart(swimlane(long, len(models)))

        atk = long[(long["label"] != BENIGN_LABEL) & (long["label"] != ERROR_LABEL)]
        if atk.empty:
            st.success("No malicious windows in this view.")
        else:
            st.subheader("Detected classes")
            show_chart(
                alt.Chart(atk).mark_bar().encode(
                    x=alt.X("label:N", title=None, sort="-y"),
                    y=alt.Y("count():Q", title="Windows"),
                    color=alt.Color("model:N", title="Model"),
                    tooltip=["label:N", "model:N", "count():Q"],
                ).properties(height=240)
            )

    # ── Models ──
    with tab_models:
        counts = long.groupby(["model", "label"]).size().reset_index(name="windows")
        show_chart(
            alt.Chart(counts).mark_bar().encode(
                x=alt.X("model:N", title=None),
                y=alt.Y("windows:Q", title="Windows"),
                color=alt.Color("label:N", scale=label_scale(counts["label"].unique()), title="Verdict"),
                tooltip=["model:N", "label:N", "windows:Q"],
            ).properties(height=280)
        )

        def disagree(row) -> bool:
            return len({v for v in row if isinstance(v, str) and v != ERROR_LABEL}) > 1

        mask = df[models].apply(disagree, axis=1) if len(models) > 1 else pd.Series(False, index=df.index)
        st.metric("Agreement between models", f"{100 * (1 - mask.mean()):.1f}%",
                  f"{int(mask.sum())} windows disagree", delta_color="off")
        if mask.any():
            st.caption("Windows where models disagree are the most useful ones to review.")
            show_table(df.loc[mask, ["timestamp"] + models].iloc[::-1])

        conf_cols = [c for c in df.columns if c.endswith(" conf")]
        if conf_cols:
            st.subheader("Model confidence")
            st.line_chart(df.set_index(df["time"].dt.tz_localize(None))[conf_cols])

    # ── Features ──
    with tab_feat:
        if feat_df.empty or feat_df.dropna(how="all", axis=1).empty:
            st.info("No numeric features found in the records.")
        else:
            cols = list(feat_df.dropna(how="all", axis=1).columns)
            pick = st.multiselect("Features to plot", cols, default=cols[:3], key="feat_pick")
            if pick:
                st.line_chart(feat_df[pick])
            st.subheader("Latest window")
            latest = feat_df.iloc[-1].dropna().rename("value").reset_index().rename(columns={"index": "feature"})
            show_table(latest)

    # ── Alerts ──
    with tab_alerts:
        if alerts.empty:
            st.success("No alerts logged.")
        else:
            per_model = (alerts["models"].str.split(", ").explode().value_counts()
                         .rename_axis("model").reset_index(name="alerts"))
            a1, a2 = st.columns([1, 2])
            with a1:
                st.caption("Alerts per model")
                show_table(per_model)
            with a2:
                st.caption("Most recent alerts")
                show_table(alerts[["timestamp", "detections"]].head(200))

    # ── Raw ──
    with tab_raw:
        show_cols = [c for c in df.columns if c != "time"]
        recent = df[show_cols].iloc[::-1].head(500)
        show_table(recent)
        st.download_button("Download windows as CSV", df[show_cols].to_csv(index=False).encode(),
                           "smart_ids_windows.csv", "text/csv")
        with st.expander("Latest record as JSON"):
            st.json({**last.drop("time").to_dict(), "features": feat_df.iloc[-1].dropna().to_dict()})


def main() -> None:
    st.set_page_config(page_title="Smart-IDS", page_icon="🛡️", layout="wide")
    st.title("Smart-IDS dashboard")

    with st.sidebar:
        st.header("Settings")
        results_path = st.text_input("Results file", str(RESULTS_FILE))
        alerts_path = st.text_input("Alerts file", str(ALERTS_FILE))
        max_windows = st.slider("Windows to show", 20, 2000, 300, step=20)
        refresh = st.slider("Refresh every (s)", 2, 60, 5)
        interval = st.number_input("Suricata stats interval (s)", 1, 300, 8,
                                   help="Used to decide when the feed looks stale (5x this value).")
        paused = st.checkbox("Pause auto-refresh", value=False)
        st.caption("Times are UTC. Read-only: this page never modifies your IDS files.")

    view = st.fragment(run_every=None if paused else f"{refresh}s")(render)
    view(results_path, alerts_path, max_windows, int(interval) * 5)


main()

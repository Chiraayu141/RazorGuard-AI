import json

from pathlib import Path
from datetime import datetime


HISTORY_FILE = Path("data/history.json")


# =============================================================
# Save Analysis
# =============================================================

def save_analysis(text, result):
    """Save one analysis result to persistent history."""

    HISTORY_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    history = []

    if HISTORY_FILE.exists():
        try:
            with open(
                HISTORY_FILE,
                "r",
                encoding="utf-8",
            ) as file:
                history = json.load(file)

        except (json.JSONDecodeError, OSError):
            history = []

    entry = {
        "timestamp": datetime.now().isoformat(
            timespec="seconds"
        ),
        "text": text,
        "result": result,
    }

    history.append(entry)

    with open(
        HISTORY_FILE,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            history,
            file,
            indent=4,
            ensure_ascii=False,
        )


# =============================================================
# Load History
# =============================================================

def load_history():
    """Load all saved analysis results."""

    if not HISTORY_FILE.exists():
        return []

    try:
        with open(
            HISTORY_FILE,
            "r",
            encoding="utf-8",
        ) as file:

            history = json.load(file)

        if isinstance(history, list):
            return history

        return []

    except (json.JSONDecodeError, OSError):
        return []


# =============================================================
# Recent History
# =============================================================

def get_recent_history(limit=10):
    """
    Return the most recent analysis entries.

    The newest analysis appears first.
    """

    history = load_history()

    if not history:
        return []

    return list(reversed(history[-limit:]))


# =============================================================
# History Count
# =============================================================

def get_history_count():
    """Return the total number of saved analyses."""

    return len(load_history())


# =============================================================
# Risk Summary
# =============================================================

def get_risk_summary():
    """
    Return the number of analyses for each risk level.
    """

    history = load_history()

    summary = {
        "SAFE": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    for entry in history:

        result = entry.get("result", {})

        level = result.get("risk_level")

        if level in summary:
            summary[level] += 1

    return summary


# =============================================================
# Clear History
# =============================================================

def clear_history():
    """Delete all saved analysis history."""

    if HISTORY_FILE.exists():

        try:
            HISTORY_FILE.unlink()

        except OSError:
            pass
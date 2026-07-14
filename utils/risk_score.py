def assign_risk(prediction):
    """
    Assigns a risk level based on the ML model's prediction.

    Accepts either the raw Isolation Forest output (-1 for anomaly,
    1 for normal) or the human-readable label ("Suspicious" / "Normal")
    that the dashboards use after remapping those values. Handling both
    forms means this function gives correct results no matter which
    stage of the pipeline calls it.
    """

    if prediction in (-1, "Suspicious"):
        return "🔴 High"

    return "🟢 Low"
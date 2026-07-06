from reports.pdf_report import generate_report

generate_report(
    destination_port=443,
    flow_duration=761211,
    prediction="Suspicious",
    risk="High",
    explanation="""
The traffic appears suspicious because the
flow duration is unusually long and the
network behaviour differs from normal traffic.

Recommended Action:
Investigate the source immediately.
"""
)
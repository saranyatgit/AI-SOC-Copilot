from ai.gemini_explainer import explain_threat

response = explain_threat(
    destination_port=443,
    flow_duration=761211,
    prediction="Suspicious",
    risk="High"
)

print(response)
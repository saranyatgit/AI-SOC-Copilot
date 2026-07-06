import streamlit as st

from ml.anomaly_detector import (
    load_processed_data,
    prepare_features,
    load_model,
    predict_anomalies
)

from utils.risk_score import assign_risk


def show_incidents():

    st.title("🚨 Incident Management")

    df = load_processed_data()

    features = prepare_features(df)

    model = load_model()

    prediction = predict_anomalies(model, features)

    df["Prediction"] = prediction

    df["Prediction"] = df["Prediction"].replace({
        1: "Normal",
        -1: "Suspicious"
    })

    df["Risk"] = df["Prediction"].apply(assign_risk)

    incidents = df[df["Prediction"] == "Suspicious"]

    st.write(f"Total Incidents: {len(incidents)}")

    st.dataframe(incidents)
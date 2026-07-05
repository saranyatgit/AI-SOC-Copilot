import streamlit as st

from ml.anomaly_detector import (
    load_processed_data,
    prepare_features,
    load_model,
    predict_anomalies
)

from utils.risk_score import assign_risk


def show_anomaly_dashboard():

    st.title("🚨 AI Threat Detection")

    # Load dataset
    df = load_processed_data()

    # Prepare ML features
    features = prepare_features(df)

    # Load trained model
    model = load_model()

    # Predict anomalies
    predictions = predict_anomalies(model, features)

    # Add prediction column
    df["Prediction"] = predictions

    # Add risk score
    df["Risk"] = df["Prediction"].apply(assign_risk)

    # Dashboard metrics
    total_anomalies = (df["Prediction"] == -1).sum()
    total_normal = (df["Prediction"] == 1).sum()
    suspicious_percentage = (total_anomalies / len(df)) * 100

    col1, col2, col3 = st.columns(3)

    col1.metric("🚨 Total Anomalies", total_anomalies)
    col2.metric("🟢 Normal Traffic", total_normal)
    col3.metric("⚠️ Suspicious %", f"{suspicious_percentage:.2f}%")

    # Convert predictions to text
    df["Prediction"] = df["Prediction"].replace({
        1: "Normal",
        -1: "Suspicious"
    })

    st.subheader("Threat Detection Results")

    # Show whichever columns exist
    display_columns = []

    if "Destination Port" in df.columns:
        display_columns.append("Destination Port")

    if "Flow Duration" in df.columns:
        display_columns.append("Flow Duration")

    display_columns.extend([
        "Prediction",
        "Risk"
    ])
    df = df.reset_index(drop=True)

    st.dataframe(df[display_columns])
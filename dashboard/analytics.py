import streamlit as st
import matplotlib.pyplot as plt

from ml.anomaly_detector import (
    load_processed_data,
    prepare_features,
    load_model,
    predict_anomalies
)

from utils.risk_score import assign_risk


def show_analytics():

    st.title("📊 Security Analytics")

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

    # -----------------------------
    # Pie Chart
    # -----------------------------

    st.subheader("🥧 Normal vs Attack")

    if "Label" in df.columns:

        normal = (df["Label"] == "BENIGN").sum()

        attack = (df["Label"] != "BENIGN").sum()

        fig, ax = plt.subplots()

        ax.pie(
            [normal, attack],
            labels=["Normal", "Attack"],
            autopct="%1.1f%%"
        )

        st.pyplot(fig)

    # -----------------------------
    # Attack Types
    # -----------------------------

    st.subheader("📊 Attack Types")

    if "Label" in df.columns:

        attacks = df[df["Label"] != "BENIGN"]

        attack_counts = attacks["Label"].value_counts()

        fig, ax = plt.subplots(figsize=(10,4))

        ax.bar(
            attack_counts.index,
            attack_counts.values
        )

        plt.xticks(rotation=60)

        st.pyplot(fig)

    # -----------------------------
    # Destination Ports
    # -----------------------------

    st.subheader("🌐 Top Destination Ports")

    ports = df["Destination Port"].value_counts().head(10)

    fig, ax = plt.subplots(figsize=(8,4))

    ax.bar(
        ports.index.astype(str),
        ports.values
    )

    st.pyplot(fig)

    # -----------------------------
    # Flow Duration
    # -----------------------------

    st.subheader("📈 Flow Duration Distribution")

    fig, ax = plt.subplots()

    ax.hist(
        df["Flow Duration"],
        bins=20
    )

    st.pyplot(fig)
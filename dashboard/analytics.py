import streamlit as st
import plotly.express as px

from ml.anomaly_detector import (
    load_processed_data,
    prepare_features,
    load_model,
    predict_anomalies,
)
from utils.risk_score import assign_risk


def show_analytics():
    st.title("📊 Security Analytics")

    df = load_processed_data()
    features = prepare_features(df)
    model = load_model()

    pred = predict_anomalies(model, features)
    df["Prediction"] = ["Normal" if p == 1 else "Suspicious" for p in pred]
    df["Risk"] = df["Prediction"].apply(assign_risk)

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Flows", len(df))
    c2.metric("Suspicious", (df["Prediction"]=="Suspicious").sum())
    c3.metric("High Risk", (df["Risk"]=="🔴 High").sum())

    st.divider()

    if "Label" in df.columns:
        pie = df["Label"].replace({"BENIGN":"Normal"})
        fig = px.pie(
            names=pie.value_counts().index,
            values=pie.value_counts().values,
            title="Traffic Distribution"
        )
        st.plotly_chart(fig, use_container_width=True)

        attack_df = df[df["Label"]!="BENIGN"]["Label"].value_counts().reset_index()
        attack_df.columns=["Attack","Count"]
        fig2 = px.bar(
            attack_df,
            x="Attack",
            y="Count",
            title="Attack Categories"
        )
        st.plotly_chart(fig2, use_container_width=True)

    if "Destination Port" in df.columns:
        ports = df["Destination Port"].value_counts().head(10).reset_index()
        ports.columns=["Port","Count"]
        fig3 = px.bar(ports,x="Port",y="Count",title="Top Destination Ports")
        st.plotly_chart(fig3,use_container_width=True)

    fig4 = px.histogram(df,x="Flow Duration",nbins=30,title="Flow Duration Distribution")
    st.plotly_chart(fig4,use_container_width=True)

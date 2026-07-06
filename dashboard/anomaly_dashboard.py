import streamlit as st

from ai.gemini_explainer import explain_threat
from reports.pdf_report import generate_report
from threat_intelligence.mitre_mapper import get_attack_details
from ml.anomaly_detector import (
    load_processed_data,
    prepare_features,
    load_model,
    predict_anomalies,
)

from utils.risk_score import assign_risk


def show_anomaly_dashboard():

    st.title("🚨 AI Threat Detection")

    # ==========================================
    # Load Dataset
    # ==========================================

    df = load_processed_data()

    # ==========================================
    # Prepare Features
    # ==========================================

    features = prepare_features(df)

    # ==========================================
    # Load Model
    # ==========================================

    model = load_model()

    # ==========================================
    # Predict Anomalies
    # ==========================================

    predictions = predict_anomalies(model, features)

    df["Prediction"] = predictions

    df["Prediction"] = df["Prediction"].replace({1: "Normal", -1: "Suspicious"})

    # ==========================================
    # Assign Risk
    # ==========================================

    df["Risk"] = df["Prediction"].apply(assign_risk)

    # ==========================================
    # KPI Calculations
    # ==========================================

    total_flows = len(df)

    if "Label" in df.columns:
        attack_records = (df["Label"] != "BENIGN").sum()
        benign_records = (df["Label"] == "BENIGN").sum()
    else:
        attack_records = 0
        benign_records = 0

    high_risk_incidents = (df["Risk"] == "High").sum()

    anomalies_detected = (df["Prediction"] == "Suspicious").sum()

    total_normal = (df["Prediction"] == "Normal").sum()

    suspicious_percentage = (anomalies_detected / total_flows) * 100

    detection_rate = suspicious_percentage

    # ==========================================
    # KPI Cards
    # ==========================================

    st.subheader("📊 Security Dashboard")

    col1, col2, col3 = st.columns(3)

    col1.metric("🌐 Total Network Flows", total_flows)

    col2.metric("⚔️ Attack Records", attack_records)

    col3.metric("🟢 Benign Records", benign_records)

    col4, col5, col6 = st.columns(3)

    col4.metric("🔴 High Risk Incidents", high_risk_incidents)

    col5.metric("🚨 Anomalies Detected", anomalies_detected)

    col6.metric("📈 Detection Rate", f"{detection_rate:.2f}%")

    # ==========================================
    # Prediction Summary
    # ==========================================

    st.subheader("📈 Prediction Summary")

    col1, col2, col3 = st.columns(3)

    col1.metric("🚨 Total Anomalies", anomalies_detected)

    col2.metric("🟢 Normal Traffic", total_normal)

    col3.metric("⚠️ Suspicious %", f"{suspicious_percentage:.2f}%")

    # ==========================================
    # Threat Detection Table
    # ==========================================

    st.subheader("Threat Detection Results")

    display_columns = []

    if "Destination Port" in df.columns:
        display_columns.append("Destination Port")

    if "Flow Duration" in df.columns:
        display_columns.append("Flow Duration")

    display_columns.extend(["Prediction", "Risk"])

    df = df.reset_index(drop=True)

    st.dataframe(df[display_columns])

    # ==========================================
    # Gemini AI Explanation
    # ==========================================

    st.subheader("🤖 AI Threat Explanation")

    suspicious = df[df["Prediction"] == "Suspicious"]

    if suspicious.empty:
        st.success("✅ No suspicious traffic detected.")
        return

    row = suspicious.iloc[0]

    st.info("A suspicious network flow has been detected.")

    st.write("**Destination Port:**", row["Destination Port"])
    st.write("**Flow Duration:**", row["Flow Duration"])
    st.write("**Prediction:**", row["Prediction"])
    st.write("**Risk Level:**", row["Risk"])

    # ==========================================
    # Determine Attack Type
    # ==========================================

    # Example mapping (replace with your own logic later)
    if row["Prediction"] == "Suspicious":
        attack_name = "Port Scan"
    else:
        attack_name = None

    # ==========================================
    # MITRE ATT&CK Lookup
    # ==========================================

    mitre = None  # Instantiated to prevent potential UnboundLocalError
    if attack_name:
        mitre = get_attack_details(attack_name)

        if mitre:
            st.subheader("🛡 MITRE ATT&CK Mapping")

            st.write("### Attack")
            st.success(attack_name)

            st.write("### Tactic")
            st.info(mitre["tactic"])

            st.write("### Technique")
            st.info(mitre["technique"])

            st.write("### Technique ID")
            st.code(mitre["technique_id"])

            st.write("### Description")
            st.write(mitre["description"])

            st.write("### Mitigation")
            st.warning(mitre["mitigation"])

    # ==========================================
    # Analyze Button
    # ==========================================

    if st.button("🤖 Analyze with Gemini"):
        with st.spinner("Analyzing threat using Gemini AI..."):
            explanation = explain_threat(
                destination_port=row["Destination Port"],
                flow_duration=row["Flow Duration"],
                prediction=row["Prediction"],
                risk=row["Risk"],
                tactic=mitre["tactic"] if mitre else "N/A",
                technique=mitre["technique"] if mitre else "N/A",
                technique_id=mitre["technique_id"] if mitre else "N/A",
                description=mitre["description"] if mitre else "N/A",
                mitigation=mitre["mitigation"] if mitre else "N/A",
            )
            st.session_state["explanation"] = explanation

    # ==========================================
    # Display AI Explanation
    # ==========================================

    if "explanation" in st.session_state:
        st.subheader("📝 AI Analysis")
        st.success(st.session_state["explanation"])

        # ==========================================
        # PDF Report
        # ==========================================

        if st.button("📄 Generate Incident Report"):
            generate_report(
                destination_port=row["Destination Port"],
                flow_duration=row["Flow Duration"],
                prediction=row["Prediction"],
                risk=row["Risk"],
                explanation=st.session_state["explanation"],
            )

            st.success("✅ Incident Report Generated Successfully!")
            st.info("Saved at:\n\nreports/generated/Incident_Report.pdf")
            st.write("**Destination Port:**", row["Destination Port"])
            st.write("**Flow Duration:**", row["Flow Duration"])
            st.write("**Prediction:**", row["Prediction"])
            st.write("**Risk Level:**", row["Risk"])
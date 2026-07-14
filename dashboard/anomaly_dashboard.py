
import streamlit as st

from ai.gemini_explainer import explain_threat
from reports.pdf_report import generate_report
from threat_intelligence.mitre_mapper import get_attack_details
from utils.incident_db import insert_incident
from ml.anomaly_detector import (
    load_processed_data, prepare_features,
    load_model, predict_anomalies
)
from utils.risk_score import assign_risk

def show_anomaly_dashboard():
    st.title("🚨 AI Threat Detection")

    df = load_processed_data()
    features = prepare_features(df)
    model = load_model()

    pred = predict_anomalies(model, features)
    df["Prediction"] = ["Normal" if p == 1 else "Suspicious" for p in pred]
    df["Risk"] = df["Prediction"].apply(assign_risk)

    total=len(df)
    suspicious=df[df["Prediction"]=="Suspicious"]

    c1,c2,c3,c4=st.columns(4)
    c1.metric("Network Flows",total)
    c2.metric("Suspicious",len(suspicious))
    c3.metric("High Risk",(df["Risk"]=="🔴 High").sum())
    c4.metric("Detection Rate",f"{len(suspicious)/total*100:.2f}%")

    st.divider()

    st.dataframe(
        df[["Destination Port","Flow Duration","Prediction","Risk"]],
        use_container_width=True,
        height=350
    )

    if suspicious.empty:
        st.success("No suspicious traffic detected.")
        return

    row=suspicious.iloc[0]
    attack="Port Scan"
    mitre=get_attack_details(attack)

    st.subheader("🛡 Threat Summary")
    left,right=st.columns(2)
    with left:
        st.info(f"**Attack:** {attack}")
        st.write(f"Destination Port: {row['Destination Port']}")
        st.write(f"Flow Duration: {row['Flow Duration']}")
        st.write(f"Risk: {row['Risk']}")
    with right:
        st.write(f"**MITRE Tactic:** {mitre['tactic']}")
        st.write(f"**Technique:** {mitre['technique']}")
        st.code(mitre["technique_id"])

    if st.button("🤖 Analyze with Gemini",use_container_width=True):
        with st.spinner("Generating AI explanation..."):
            exp=explain_threat(
                row["Destination Port"],row["Flow Duration"],
                attack,row["Risk"],
                mitre["tactic"],mitre["technique"],
                mitre["technique_id"],mitre["description"],
                mitre["mitigation"]
            )
            st.session_state["exp"]=exp

            try:
                insert_incident(
                    destination_port=row["Destination Port"],
                    flow_duration=row["Flow Duration"],
                    prediction="Suspicious",
                    risk=row["Risk"],
                    attack_type=attack,
                    tactic=mitre["tactic"],
                    technique=mitre["technique"],
                    technique_id=mitre["technique_id"],
                    description=mitre["description"],
                    mitigation=mitre["mitigation"],
                    gemini_explanation=exp
                )
            except Exception:
                pass

    if "exp" in st.session_state:
        st.success(st.session_state["exp"])
        if st.button("📄 Generate PDF Report",use_container_width=True):
            generate_report(
                row["Destination Port"],row["Flow Duration"],
                "Suspicious",row["Risk"],st.session_state["exp"],
                mitre["tactic"],mitre["technique"],
                mitre["technique_id"],mitre["description"],
                mitre["mitigation"]
            )
            st.success("Report generated successfully.")

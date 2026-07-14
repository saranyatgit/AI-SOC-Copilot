import streamlit as st
import pandas as pd

from ml.anomaly_detector import prepare_features, load_model, predict_anomalies
from utils.risk_score import assign_risk
from threat_intelligence.mitre_mapper import get_attack_details
from ai.gemini_explainer import explain_threat
from utils.incident_db import init_db, insert_incident


def show_csv_upload():

    init_db()

    st.title("📂 CSV Upload & Analysis")

    st.write(
        "Upload a CICIDS2017-format network flow export (for example, a "
        "different capture window or a CSV from your own pipeline) and "
        "run it through the same Isolation Forest model and MITRE ATT&CK "
        "mapping used on the built-in dataset."
    )

    uploaded_file = st.file_uploader("Upload a CSV file", type=["csv"])

    if uploaded_file is None:
        st.info("Waiting for a CSV file to be uploaded.")
        return

    # ==========================================
    # Read & Normalize
    # ==========================================

    try:
        df = pd.read_csv(uploaded_file)
    except Exception as e:
        st.error(f"Could not read this file as CSV: {e}")
        return

    # CICIDS2017 exports commonly have leading/trailing spaces in headers
    df.columns = df.columns.str.strip()

    st.subheader("📄 Uploaded Data Preview")
    st.write(f"**Rows:** {len(df)}  |  **Columns:** {len(df.columns)}")
    st.dataframe(df.head(20))

    # ==========================================
    # Feature Preparation & Prediction
    # ==========================================

    st.subheader("🧠 Running Threat Detection")

    try:
        model = load_model()
    except Exception as e:
        st.error(f"Could not load the trained model: {e}")
        return

    try:
        raw_features = prepare_features(df)
    except Exception as e:
        st.error(f"Could not prepare features from this file: {e}")
        return

    # prepare_features() just grabs every numeric column in the uploaded
    # file, so it never fails on its own even if the file is the wrong
    # shape. The model, however, was trained on a specific set of numeric
    # columns in a specific order (model.feature_names_in_), so we check
    # against that explicitly rather than letting scikit-learn raise a
    # raw ValueError deep inside predict().
    expected_columns = list(model.feature_names_in_)

    missing_columns = [
        col for col in expected_columns if col not in raw_features.columns
    ]

    if missing_columns:
        st.error(
            "This CSV is missing columns the model was trained on: "
            f"{', '.join(missing_columns)}. Please upload a "
            "CICIDS2017-format flow export with the same numeric columns."
        )
        return

    # Reindex to the exact training column order. Any extra numeric
    # columns in the upload that the model wasn't trained on are simply
    # not passed in.
    features = raw_features[expected_columns]

    # Handle missing (NaN) values in required columns by filling with
    # each column's median, rather than failing the whole upload.
    missing_counts = features.isnull().sum()
    missing_counts = missing_counts[missing_counts > 0]

    if not missing_counts.empty:
        st.warning(
            f"Found {int(missing_counts.sum())} missing value(s) across "
            f"{len(missing_counts)} column(s). Filling each with that "
            "column's median value so detection can continue."
        )

        st.subheader("Columns with Missing Values")
        st.dataframe(missing_counts.rename("Missing Values"))

        features = features.fillna(features.median())

    try:
        predictions = predict_anomalies(model, features)
    except Exception as e:
        st.error(f"Prediction failed: {e}")
        return

    df = df.reset_index(drop=True)

    df["Prediction"] = predictions
    df["Prediction"] = df["Prediction"].replace({1: "Normal", -1: "Suspicious"})

    df["Risk"] = df["Prediction"].apply(assign_risk)

    # ==========================================
    # Summary KPIs
    # ==========================================

    total_flows = len(df)
    anomalies_detected = int((df["Prediction"] == "Suspicious").sum())
    high_risk = int((df["Risk"] == "🔴 High").sum())
    anomaly_rate = (anomalies_detected / total_flows * 100) if total_flows else 0

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("🌐 Total Flows", total_flows)
    col2.metric("🚨 Anomalies Detected", anomalies_detected)
    col3.metric("🔴 High Risk", high_risk)
    col4.metric("📈 Anomaly Rate", f"{anomaly_rate:.2f}%")

    # ==========================================
    # Results Table
    # ==========================================

    st.subheader("📊 Results")

    show_only_suspicious = st.checkbox("Show only suspicious flows", value=True)

    display_columns = []

    if "Destination Port" in df.columns:
        display_columns.append("Destination Port")

    if "Flow Duration" in df.columns:
        display_columns.append("Flow Duration")

    display_columns.extend(["Prediction", "Risk"])

    results_df = df[df["Prediction"] == "Suspicious"] if show_only_suspicious else df

    st.dataframe(results_df[display_columns], use_container_width=True)

    st.download_button(
        "⬇️ Download Annotated Results (CSV)",
        data=df.to_csv(index=False).encode("utf-8"),
        file_name="threat_detection_results.csv",
        mime="text/csv",
    )

    if anomalies_detected == 0:
        st.success("✅ No suspicious traffic detected in this upload.")
        return

    # ==========================================
    # Investigate a Suspicious Flow
    # ==========================================

    st.divider()
    st.subheader("🤖 Investigate a Suspicious Flow")

    suspicious = df[df["Prediction"] == "Suspicious"].reset_index(drop=True)

    row_index = st.number_input(
        "Suspicious flow row #",
        min_value=0,
        max_value=max(len(suspicious) - 1, 0),
        value=0,
        step=1,
    )

    row = suspicious.iloc[int(row_index)]

    dest_port = row["Destination Port"] if "Destination Port" in row else "N/A"
    flow_duration = row["Flow Duration"] if "Flow Duration" in row else "N/A"

    st.write("**Destination Port:**", dest_port)
    st.write("**Flow Duration:**", flow_duration)
    st.write("**Risk Level:**", row["Risk"])

    # Same placeholder attack-type mapping used on the Threat Detection
    # page today (tracked as a known issue to improve later).
    attack_name = "Port Scan"
    mitre = get_attack_details(attack_name)

    if mitre:
        st.write("### 🛡 MITRE ATT&CK Mapping")
        st.info(f"{mitre['tactic']} — {mitre['technique']} ({mitre['technique_id']})")
        st.write(mitre["description"])
        st.warning(mitre["mitigation"])

    if st.button("🤖 Analyze with Gemini", key="csv_upload_analyze"):
        with st.spinner("Analyzing threat using Gemini AI..."):
            explanation = explain_threat(
                destination_port=dest_port,
                flow_duration=flow_duration,
                prediction=row["Prediction"],
                risk=row["Risk"],
                tactic=mitre["tactic"] if mitre else "N/A",
                technique=mitre["technique"] if mitre else "N/A",
                technique_id=mitre["technique_id"] if mitre else "N/A",
                description=mitre["description"] if mitre else "N/A",
                mitigation=mitre["mitigation"] if mitre else "N/A",
            )
            st.session_state["csv_upload_explanation"] = explanation

    if "csv_upload_explanation" in st.session_state:
        st.subheader("📝 AI Analysis")
        st.success(st.session_state["csv_upload_explanation"])

        if st.button("💾 Save Incident to Database", key="csv_upload_save"):
            incident_id = insert_incident(
                destination_port=int(dest_port) if dest_port != "N/A" else None,
                flow_duration=float(flow_duration) if flow_duration != "N/A" else None,
                prediction=row["Prediction"],
                risk=row["Risk"],
                attack_type=attack_name,
                tactic=mitre["tactic"] if mitre else None,
                technique=mitre["technique"] if mitre else None,
                technique_id=mitre["technique_id"] if mitre else None,
                description=mitre["description"] if mitre else None,
                mitigation=mitre["mitigation"] if mitre else None,
                gemini_explanation=st.session_state["csv_upload_explanation"],
            )
            st.success(
                f"✅ Incident #{incident_id} saved. View it under 📑 Incidents."
            )
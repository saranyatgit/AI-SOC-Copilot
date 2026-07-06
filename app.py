import streamlit as st

from dashboard.home import show_home
from dashboard.log_viewer import show_dashboard
from dashboard.anomaly_dashboard import show_anomaly_dashboard
from dashboard.analytics import show_analytics
from dashboard.incidents import show_incidents
from dashboard.reports import show_reports

from threat_intelligence.mitre_mapper import get_attack_details

# --------------------------------------------------
# Page Configuration
# --------------------------------------------------

st.set_page_config(
    page_title="AI-Powered SOC Analyst Assistant",
    page_icon="🛡️",
    layout="wide"
)

# --------------------------------------------------
# Sidebar
# --------------------------------------------------

st.sidebar.title("🛡️ AI SOC Copilot")

page = st.sidebar.radio(
    "Navigation",
    [
        "🏠 Home",
        "📋 Security Logs",
        "🚨 Threat Detection",
        "🎯 MITRE ATT&CK",
        "📊 Analytics",
        "📑 Incidents",
        "📄 Reports"
    ]
)

# --------------------------------------------------
# Navigation
# --------------------------------------------------

if page == "🏠 Home":
    show_home()

elif page == "📋 Security Logs":
    show_dashboard()

elif page == "🚨 Threat Detection":
    show_anomaly_dashboard()

elif page == "🎯 MITRE ATT&CK":

    st.title("🎯 MITRE ATT&CK Attack Mapping")

    st.write(
        "Select a cyber attack to view its MITRE ATT&CK tactic, technique, description, and mitigation."
    )

    attack = st.selectbox(
        "Select Attack",
        [
            "Port Scan",
            "DDoS",
            "Brute Force",
            "Web Attack",
            "Bot"
        ]
    )

    if st.button("Show MITRE Mapping"):

        result = get_attack_details(attack)

        if result:

            st.success("MITRE ATT&CK Mapping Found")

            col1, col2 = st.columns(2)

            with col1:
                st.metric("Attack", attack)

            with col2:
                st.metric("Technique ID", result["technique_id"])

            st.subheader("Tactic")
            st.info(result["tactic"])

            st.subheader("Description")
            st.write(result["description"])

            st.subheader("Recommended Mitigation")
            st.warning(result["mitigation"])

        else:
            st.error("Attack mapping not found.")

elif page == "📊 Analytics":
    show_analytics()

elif page == "📑 Incidents":
    show_incidents()

elif page == "📄 Reports":
    show_reports()
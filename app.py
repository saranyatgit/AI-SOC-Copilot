import streamlit as st

from dashboard.home import show_home
from dashboard.log_viewer import show_dashboard
from dashboard.anomaly_dashboard import show_anomaly_dashboard
from dashboard.analytics import show_analytics
from dashboard.incidents import show_incidents
from dashboard.reports import show_reports
from dashboard.csv_upload import show_csv_upload
from threat_intelligence.mitre_mapper import get_attack_details

st.set_page_config(
    page_title="AI-Powered SOC Copilot",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
section[data-testid="stSidebar"]{
    background:#0f172a;
}
section[data-testid="stSidebar"] *{
    color:white;
}
.block-container{
    padding-top:1.2rem;
    padding-bottom:1rem;
}
</style>
""", unsafe_allow_html=True)

st.sidebar.title("🛡️ AI SOC Copilot")
st.sidebar.caption("Threat Hunting & Incident Investigation")

page = st.sidebar.radio(
    "Navigation",
    [
        "🏠 Home",
        "📂 Upload CSV",
        "📋 Security Logs",
        "🚨 Threat Detection",
        "🎯 MITRE ATT&CK",
        "📊 Analytics",
        "📑 Incidents",
        "📄 Reports",
    ],
)

if page=="🏠 Home":
    show_home()

elif page=="📂 Upload CSV":
    show_csv_upload()

elif page=="📋 Security Logs":
    show_dashboard()

elif page=="🚨 Threat Detection":
    show_anomaly_dashboard()

elif page=="🎯 MITRE ATT&CK":
    st.title("🎯 MITRE ATT&CK Explorer")
    attack = st.selectbox(
        "Choose Attack",
        ["Port Scan","DDoS","Brute Force","Web Attack","Bot"]
    )
    if st.button("Show Mapping"):
        data=get_attack_details(attack)
        if data:
            c1,c2=st.columns(2)
            c1.metric("Attack",attack)
            c2.metric("Technique",data["technique_id"])
            st.info(f"**Tactic:** {data['tactic']}")
            st.success(f"**Technique:** {data['technique']}")
            st.write("### Description")
            st.write(data["description"])
            st.write("### Mitigation")
            st.warning(data["mitigation"])
        else:
            st.error("Mapping not found.")

elif page=="📊 Analytics":
    show_analytics()

elif page=="📑 Incidents":
    show_incidents()

elif page=="📄 Reports":
    show_reports()

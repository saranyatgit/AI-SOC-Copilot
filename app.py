import streamlit as st

from dashboard.log_viewer import show_dashboard
from dashboard.anomaly_dashboard import show_anomaly_dashboard

st.set_page_config(
    page_title="AI-Powered SOC Analyst Assistant",
    layout="wide"
)
st.sidebar.success("Navigation")

page = st.sidebar.selectbox(
    "Navigation",
    [
        "Security Log Viewer",
        "AI Threat Detection"
    ]
)

if page == "Security Log Viewer":
    show_dashboard()

elif page == "AI Threat Detection":
    show_anomaly_dashboard()
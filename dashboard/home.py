import streamlit as st
from utils.incident_db import get_incident_stats

def feature_card(icon, title, desc):
    st.markdown(f"""
    <div style="padding:18px;border-radius:12px;border:1px solid #ddd;background:#fafafa;height:140px">
        <h4>{icon} {title}</h4>
        <p style="font-size:14px">{desc}</p>
    </div>
    """, unsafe_allow_html=True)

def show_home():
    stats = get_incident_stats()

    st.markdown("""
    <style>
    .hero{
        background:linear-gradient(90deg,#0f172a,#1e3a8a);
        padding:30px;
        border-radius:15px;
        color:white;
        margin-bottom:20px;
    }
    .metric-box{
        border-radius:12px;
        padding:18px;
        background:#f7f7f7;
        border:1px solid #ddd;
        text-align:center;
    }
    </style>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="hero">
        <h1>🛡️ AI-Powered SOC Copilot</h1>
        <h3>Intelligent Threat Hunting & Incident Investigation</h3>
        <p>
        Machine Learning + MITRE ATT&CK + Google Gemini + SQLite + FastAPI
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.subheader("📊 Live Security Overview")

    c1,c2,c3,c4,c5 = st.columns(5)
    c1.metric("📁 Incidents", stats["total"])
    c2.metric("🟡 Open", stats["open"])
    c3.metric("🔎 Investigating", stats["investigating"])
    c4.metric("✅ Resolved", stats["resolved"])
    c5.metric("🔴 High Risk", stats["high_risk"])

    st.divider()

    st.subheader("🚀 Key Features")

    r1,r2,r3 = st.columns(3)
    with r1:
        feature_card("🤖","AI Threat Detection",
                     "Isolation Forest detects suspicious network traffic.")
    with r2:
        feature_card("🎯","MITRE ATT&CK",
                     "Maps attacks to tactics, techniques and mitigations.")
    with r3:
        feature_card("🧠","Gemini AI",
                     "Explains threats and recommends SOC actions.")

    r4,r5,r6 = st.columns(3)
    with r4:
        feature_card("🗄️","SQLite Incident DB",
                     "Persistent incident storage with search and status.")
    with r5:
        feature_card("⚡","FastAPI",
                     "REST API for incident retrieval and management.")
    with r6:
        feature_card("📄","PDF Reports",
                     "Generate professional incident investigation reports.")

    st.divider()

    st.subheader("🏗️ System Workflow")

    st.code(
"""CICIDS2017 Dataset
        │
        ▼
Data Preprocessing
        │
        ▼
Isolation Forest
        │
        ▼
Risk Scoring
        │
        ▼
MITRE ATT&CK Mapping
        │
        ▼
Gemini AI
        │
        ▼
SQLite Incident Management
        │
        ▼
FastAPI
        │
        ▼
Streamlit Dashboard""",
language="text")

    st.info("👈 Use the navigation panel on the left to explore Security Logs, Threat Detection, Analytics, Incident Management and Reports.")

import streamlit as st


def show_home():

    st.title("🛡️ AI-Powered SOC Analyst Assistant")

    st.markdown("---")

    st.header("Project Overview")

    st.write("""
This application helps Security Operations Center (SOC) analysts detect suspicious
network traffic using Machine Learning and explain threats using Google's Gemini AI.

### Features

✅ Security Log Viewer

✅ AI Threat Detection

✅ Risk Classification

✅ Gemini AI Explanation

✅ Analytics Dashboard

✅ PDF Incident Report
""")

    st.info("Use the left sidebar to navigate through the dashboard.")
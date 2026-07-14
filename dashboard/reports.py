import os
import streamlit as st

REPORT_PATH = "reports/generated/Incident_Report.pdf"

def show_reports():
    st.title("📄 Incident Reports")

    st.markdown("""
    Download the latest AI-generated investigation report.

    The report contains:
    - Incident details
    - Risk assessment
    - MITRE ATT&CK mapping
    - Gemini AI explanation
    - Recommended mitigation
    """)

    st.divider()

    if os.path.exists(REPORT_PATH):
        size = os.path.getsize(REPORT_PATH)/1024
        c1,c2=st.columns([3,1])
        with c1:
            st.success("Latest report available.")
            st.write(f"File: Incident_Report.pdf")
            st.write(f"Size: {size:.1f} KB")
        with c2:
            with open(REPORT_PATH,"rb") as f:
                st.download_button(
                    "⬇️ Download PDF",
                    f,
                    file_name="Incident_Report.pdf",
                    mime="application/pdf"
                )
    else:
        st.warning("No report has been generated yet. Visit Threat Detection and generate an incident report.")

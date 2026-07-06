import streamlit as st
import os


def show_reports():

    st.title("📄 Reports")

    pdf_path = "reports/generated/Incident_Report.pdf"

    if os.path.exists(pdf_path):

        with open(pdf_path, "rb") as file:

            st.download_button(
                "Download Incident Report",
                file,
                file_name="Incident_Report.pdf"
            )

    else:

        st.warning("No report generated yet.")
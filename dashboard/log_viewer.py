import streamlit as st
import pandas as pd


def load_logs():
    df = pd.read_csv("data/raw/security_logs.csv")
    return df


def show_dashboard():
    st.title("AI-Powered SOC Analyst Assistant")

    st.header("Security Log Viewer")

    df = load_logs()

    st.subheader("Dataset Information")

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Total Logs", len(df))

    with col2:
        st.metric("Number of Columns", len(df.columns))

    st.subheader("Dataset Preview")

    st.dataframe(df)
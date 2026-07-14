import streamlit as st
import pandas as pd

def load_logs():
    return pd.read_csv("data/raw/security_logs.csv")

def show_dashboard():
    st.title("📋 Security Log Viewer")

    df = load_logs()

    c1,c2,c3=st.columns(3)
    c1.metric("Total Logs",len(df))
    c2.metric("Columns",len(df.columns))
    c3.metric("Memory",f"{df.memory_usage(deep=True).sum()/1024:.1f} KB")

    st.divider()

    search = st.text_input("🔍 Search")

    if search:
        mask=df.astype(str).apply(lambda x:x.str.contains(search,case=False,na=False)).any(axis=1)
        df=df[mask]

    st.dataframe(df,use_container_width=True,height=500)

    st.download_button(
        "⬇️ Download Logs (CSV)",
        df.to_csv(index=False),
        "security_logs.csv",
        mime="text/csv"
    )

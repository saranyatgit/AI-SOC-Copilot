
import streamlit as st
import pandas as pd
from utils.incident_db import (
    init_db,get_all_incidents,
    update_incident_status,
    delete_incident,get_incident_stats
)

STATUS=["Open","Investigating","Resolved"]

def show_incidents():
    init_db()
    st.title("📑 Incident Management")

    stats=get_incident_stats()
    c1,c2,c3,c4,c5=st.columns(5)
    c1.metric("Total",stats["total"])
    c2.metric("Open",stats["open"])
    c3.metric("Investigating",stats["investigating"])
    c4.metric("Resolved",stats["resolved"])
    c5.metric("High Risk",stats["high_risk"])

    st.divider()

    search=st.text_input("🔍 Search Attack / Technique")
    status=st.selectbox("Status",["All"]+STATUS)

    rows=get_all_incidents(status=status)

    if search:
        rows=[r for r in rows if search.lower() in str(r).lower()]

    if not rows:
        st.info("No incidents found.")
        return

    df=pd.DataFrame(rows)
    st.dataframe(df,use_container_width=True,height=320)

    st.divider()

    ids=df["id"].tolist()
    iid=st.selectbox("Incident",ids)
    row=next(r for r in rows if r["id"]==iid)

    st.subheader(f"Incident #{iid}")
    st.json(row)

    new=st.selectbox("Update Status",STATUS,index=STATUS.index(row["status"]))
    col1,col2=st.columns(2)

    with col1:
        if st.button("💾 Save Status",use_container_width=True):
            update_incident_status(iid,new)
            st.success("Status updated.")
            st.rerun()

    with col2:
        if st.button("🗑 Delete",use_container_width=True):
            delete_incident(iid)
            st.success("Incident deleted.")
            st.rerun()

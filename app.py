from dotenv import load_dotenv
load_dotenv(override=True)  # Forces Python to read the new key from .env

import streamlit as st
import json
import re
from langchain_core.messages import HumanMessage, ToolMessage
from triage_agent import triage_app
from hunter_agent import hunter_app

st.set_page_config(page_title="SOC AI Agent Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ Autonomous SecOps Intelligence Dashboard")
st.markdown("Real-time multi-agent SOC investigation, RAG playbook compliance, SOAR ticketing, and Human-in-the-Loop containment.")

# Sidebar for Alert Simulator
st.sidebar.header("🚨 SOC Alert Simulator")
alert_id = st.sidebar.text_input("Alert ID", value="SOC-2026-8970")
endpoint = st.sidebar.text_input("Compromised Endpoint", value="DESKTOP-FIN-04")
dest_ip = st.sidebar.text_input("Destination / External IP", value="185.220.101.14")
severity = st.sidebar.selectbox("Severity", ["High", "Critical", "Medium"], index=0)

if st.sidebar.button("🚀 Run SOC Workflow", type="primary"):
    st.session_state["alert_payload"] = {
        "alert_id": alert_id,
        "title": "Suspicious Outbound Connection & Lateral Movement",
        "severity": severity,
        "endpoint": endpoint,
        "destination_ip": dest_ip,
        "timestamp": "2026-09-22T07:45:00Z"
    }
    st.session_state["investigation_started"] = True

if "investigation_started" in st.session_state:
    alert = st.session_state["alert_payload"]
    
    st.subheader(f"📌 Active Incident: {alert['alert_id']} ({alert['severity']} Severity)")
    
    # 1. Tier 1 Triage
    with st.status("Running Tier 1 Triage Agent...", expanded=False) as status:
        triage_input = {"messages": [HumanMessage(content=f"Current Alert Payload:\n{json.dumps(alert, indent=2)}")]}
        triage_final_state = triage_app.invoke(triage_input)
        triage_msg = triage_final_state["messages"][-1].content
        status.update(label="Tier 1 Triage Completed!", state="complete", expanded=False)
        
    st.markdown("### 📋 Tier 1 Triage Summary")
    st.info(triage_msg)
    
    if "ESCALATE" in triage_msg.upper():
        st.warning("⚠️ Escalation detected! Handoff initiated to Multi-Agent Incident Commander & Specialist Team...")
        
        config = {"configurable": {"thread_id": alert["alert_id"]}}
        current_state = hunter_app.get_state(config)
        
        # Check if paused for human approval before containment tools
        is_interrupted = bool(current_state.next and current_state.next[0] == "containment_tools")
        
        if not current_state.values:
            handoff_context = f"Original Alert:\n{json.dumps(alert, indent=2)}\n\nTier 1 Findings:\n{triage_msg}"
            hunter_input = {"messages": [HumanMessage(content=handoff_context)]}
        else:
            hunter_input = None  # Resuming existing session from SQLite checkpointer
            
        # Run or resume graph stream if not currently waiting for approval
        if not is_interrupted and not current_state.next:
            with st.spinner("Multi-agent team investigating logs, checking threat intel, and consulting playbooks..."):
                list(hunter_app.stream(hunter_input, config, stream_mode="values"))
        
        # Refresh state after stream
        current_state = hunter_app.get_state(config)
        
        # Display agent collaboration chat log
        if current_state.values and "messages" in current_state.values:
            st.markdown("### 💬 Agent Collaboration Log")
            for msg in current_state.values["messages"]:
                if msg.type == "ai" and msg.content:
                    clean_content = re.sub(r'<thought>.*?</thought>', '', msg.content, flags=re.DOTALL).strip()
                    if clean_content:
                        with st.chat_message("assistant", avatar="🤖"):
                            st.markdown(clean_content)
                elif msg.type == "human":
                    with st.chat_message("user", avatar="👤"):
                        st.markdown(msg.content)

        # Check if currently interrupted for containment
        current_state = hunter_app.get_state(config)
        if current_state.next and current_state.next[0] == "containment_tools":
            st.error("🛑 **SECURITY GUARDRAIL TRIGGERED: Containment Authorization Required**")
            st.markdown(f"The Incident Commander/Endpoint Specialist has requested network quarantine for endpoint: **{endpoint}**, along with perimeter firewall blocking and ServiceNow/Jira ticket creation.")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("✅ Authorize Containment & SOAR Actions", type="primary"):
                    with st.spinner("Executing quarantine, firewall block, and SOAR ticketing..."):
                        list(hunter_app.stream(None, config, stream_mode="values"))
                    st.success("Containment and SOAR actions executed successfully!")
                    st.rerun()
            with col2:
                if st.button("❌ Deny Authorization", type="secondary"):
                    last_msg = current_state.values["messages"][-1] if current_state.values and "messages" in current_state.values else None
                    tool_id = last_msg.tool_calls[0]["id"] if (last_msg and hasattr(last_msg, "tool_calls") and last_msg.tool_calls) else "call_unknown"
                    rejection = ToolMessage(
                        tool_call_id=tool_id,
                        content="ERROR: Human analyst DENIED the containment action. Do not attempt again. Compile final report.",
                        name="isolate_endpoint"
                    )
                    hunter_app.update_state(config, {"messages": [rejection]}, as_node="containment_tools")
                    list(hunter_app.stream(None, config, stream_mode="values"))
                    st.error("Containment denied by analyst.")
                    st.rerun()
        else:
            if current_state.values and not current_state.next:
                st.success("🎉 Investigation and Remediation Pipeline Completed Successfully!")
    else:
        st.success("🟢 Alert resolved at Tier 1. No deep investigation required.")
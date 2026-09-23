import json
import re
import sqlite3
from typing import Annotated, Literal, TypedDict
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
from langchain_groq import ChatGroq
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.sqlite import SqliteSaver

# Import all tools including the new proactive anomaly hunt tool
from tools import (
    hunter_tools, 
    query_security_database, 
    threat_intel_enrichment, 
    check_ip_reputation, 
    consult_playbook, 
    isolate_endpoint,
    create_soar_ticket,
    update_firewall_blocklist,
    proactive_anomaly_hunt
)

class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    next_agent: str

llm = ChatGroq(model="openai/gpt-oss-120b", temperature=0)

# ==========================================
# 1. DEFINE SPECIALIST AGENTS & THEIR TOOLS
# ==========================================

network_tools = [check_ip_reputation, threat_intel_enrichment]
network_llm = llm.bind_tools(network_tools)
network_prompt = SystemMessage(content="You are a Network Security Specialist. Analyze external IP reputations, check C2 infrastructure, and query network logs.")

def network_node(state: AgentState):
    messages = [network_prompt] + state["messages"]
    response = network_llm.invoke(messages)
    return {"messages": [response]}

endpoint_tools = [query_security_database, consult_playbook, isolate_endpoint, create_soar_ticket, update_firewall_blocklist]
endpoint_llm = llm.bind_tools(endpoint_tools)
endpoint_prompt = SystemMessage(content="You are an Endpoint Forensics Specialist and Playbook Compliance Officer. Use SQLite to hunt for process logs, consult the IR playbook, create ServiceNow/Jira tickets, enforce firewall blocks, and execute host containment when authorized.")

def endpoint_node(state: AgentState):
    messages = [endpoint_prompt] + state["messages"]
    response = endpoint_llm.invoke(messages)
    return {"messages": [response]}

identity_tools = [query_security_database]
identity_llm = llm.bind_tools(identity_tools)
identity_prompt = SystemMessage(content="You are an Identity and Access Management (IAM) Specialist. Query auth_logs to investigate service accounts, failed logins, and MFA bypasses.")

def identity_node(state: AgentState):
    messages = [identity_prompt] + state["messages"]
    response = identity_llm.invoke(messages)
    return {"messages": [response]}

# New Threat Hunter Specialist Node
threat_hunter_tools = [proactive_anomaly_hunt, query_security_database]
threat_hunter_llm = llm.bind_tools(threat_hunter_tools)
threat_hunter_prompt = SystemMessage(content="You are a Proactive Threat Hunter. Scan logs for unflagged anomalies, encoded commands, and hidden persistence mechanisms across the environment.")

def threat_hunter_node(state: AgentState):
    messages = [threat_hunter_prompt] + state["messages"]
    response = threat_hunter_llm.invoke(messages)
    return {"messages": [response]}

# ==========================================
# 2. BULLETPROOF TEXT-BASED SUPERVISOR ROUTER
# ==========================================
supervisor_prompt = SystemMessage(content=""""
You are the SOC Incident Commander (Supervisor). You manage four specialists:
1. `network_agent`: For IP reputation and network log correlation.
2. `endpoint_agent`: For EDR process logs, playbook compliance, SOAR ticketing, firewall blocking, and endpoint isolation.
3. `identity_agent`: For Active Directory authentication logs and credential checks.
4. `threat_hunter_agent`: For proactive anomaly hunting and scanning for hidden threats or persistence mechanisms.

Analyze the conversation history. Decide which specialist needs to act next. 
You must reply with ONLY ONE of these exact identifiers in your response:
- network_agent
- endpoint_agent
- identity_agent
- threat_hunter_agent
- FINISH
""")

def supervisor_node(state: AgentState):
    messages = [supervisor_prompt] + state["messages"]
    response = llm.invoke(messages)
    content = response.content.strip()
    
    next_step = "FINISH"
    if "network_agent" in content:
        next_step = "network_agent"
    elif "identity_agent" in content:
        next_step = "identity_agent"
    elif "endpoint_agent" in content:
        next_step = "endpoint_agent"
    elif "threat_hunter_agent" in content:
        next_step = "threat_hunter_agent"
    elif "FINISH" in content:
        next_step = "FINISH"
        
    return {"messages": [response], "next_agent": next_step}

def route_supervisor(state: AgentState):
    return state.get("next_agent", "FINISH")

# ==========================================
# 3. BUILD THE MULTI-AGENT GRAPH
# ==========================================
workflow = StateGraph(AgentState)

workflow.add_node("supervisor", supervisor_node)
workflow.add_node("network_agent", network_node)
workflow.add_node("endpoint_agent", endpoint_node)
workflow.add_node("identity_agent", identity_node)
workflow.add_node("threat_hunter_agent", threat_hunter_node)

workflow.add_node("network_tools", ToolNode(network_tools))
workflow.add_node("endpoint_tools", ToolNode(endpoint_tools))
workflow.add_node("identity_tools", ToolNode(identity_tools))
workflow.add_node("threat_hunter_tools", ToolNode(threat_hunter_tools))

workflow.add_edge(START, "supervisor")
workflow.add_conditional_edges(
    "supervisor",
    route_supervisor,
    {
        "network_agent": "network_agent",
        "endpoint_agent": "endpoint_agent",
        "identity_agent": "identity_agent",
        "threat_hunter_agent": "threat_hunter_agent",
        "FINISH": END
    }
)

workflow.add_conditional_edges("network_agent", lambda s: "network_tools" if s["messages"][-1].tool_calls else "supervisor", {"network_tools": "network_tools", "supervisor": "supervisor"})
workflow.add_conditional_edges("endpoint_agent", lambda s: "containment_tools" if any(t["name"] == "isolate_endpoint" for t in s["messages"][-1].tool_calls) else ("endpoint_tools" if s["messages"][-1].tool_calls else "supervisor"), {"containment_tools": "containment_tools", "endpoint_tools": "endpoint_tools", "supervisor": "supervisor"})
workflow.add_conditional_edges("identity_agent", lambda s: "identity_tools" if s["messages"][-1].tool_calls else "supervisor", {"identity_tools": "identity_tools", "supervisor": "supervisor"})
workflow.add_conditional_edges("threat_hunter_agent", lambda s: "threat_hunter_tools" if s["messages"][-1].tool_calls else "supervisor", {"threat_hunter_tools": "threat_hunter_tools", "supervisor": "supervisor"})

workflow.add_edge("network_tools", "network_agent")
workflow.add_edge("endpoint_tools", "endpoint_agent")
workflow.add_edge("identity_tools", "identity_agent")
workflow.add_edge("threat_hunter_tools", "threat_hunter_agent")

workflow.add_node("containment_tools", ToolNode([isolate_endpoint]))
workflow.add_edge("containment_tools", "endpoint_agent")

db_conn = sqlite3.connect("hunter_memory.sqlite", check_same_thread=False)
memory = SqliteSaver(db_conn)

hunter_app = workflow.compile(checkpointer=memory, interrupt_before=["containment_tools"])
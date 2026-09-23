import json
from typing import Annotated, TypedDict
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_groq import ChatGroq
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition

from tools import triage_tools

class AgentState(TypedDict):
    messages: Annotated[list, add_messages]

# Using the active, supported Groq model
llm = ChatGroq(model="openai/gpt-oss-120b", temperature=0)
llm_with_tools = llm.bind_tools(triage_tools)

SYSTEM_PROMPT = """
You are an expert Tier 1 Security Operations Center (SOC) Analyst. Your objective is to investigate security alerts, determine their validity, and decide on the next necessary actions.

You have access to a set of external tools to query logs, check IP reputations, and isolate hosts. 

When you receive an alert, follow this strict protocol:
1. REVIEW the provided alert payload carefully.
2. IDENTIFY all Indicators of Compromise (IOCs) such as IP addresses, file hashes, domains, and usernames.
3. PLAN your investigation. Determine which tools you need to call to gather missing context.
4. EXECUTE tool calls one at a time. Wait for the result before proceeding.
5. CONCLUDE only when you have sufficient evidence. Classify the alert as either [FALSE POSITIVE], [TRUE POSITIVE - LOW PRIORITY], or [TRUE POSITIVE - ESCALATE].

CRITICAL CONSTRAINTS:
- DO NOT hallucinate data, logs, or IP reputations. If a tool returns no data, state that explicitly.
- Base your final classification strictly on the evidence gathered from your tools.
- Never execute a containment tool (like host isolation) without explicit human approval.
"""

def reasoning_node(state: AgentState):
    messages = state["messages"]
    if not isinstance(messages[0], SystemMessage):
        messages = [SystemMessage(content=SYSTEM_PROMPT)] + messages
    
    response = llm_with_tools.invoke(messages)
    return {"messages": [response]}

workflow = StateGraph(AgentState)
workflow.add_node("agent", reasoning_node)
workflow.add_node("tools", ToolNode(triage_tools))
workflow.add_edge(START, "agent")
workflow.add_conditional_edges("agent", tools_condition)
workflow.add_edge("tools", "agent")

triage_app = workflow.compile()
from dotenv import load_dotenv
load_dotenv(override=True)  # Forces Python to read the new key from .env

import json
import re
from langchain_core.messages import HumanMessage, ToolMessage
from triage_agent import triage_app
from hunter_agent import hunter_app

def run_soc_workflow(alert_payload: dict):
    print("==================================================")
    print("🚨 [PHASE 1] TRIGGERING TIER 1 TRIAGE AGENT")
    print("==================================================\n")
    
    triage_input = {"messages": [HumanMessage(content=f"Current Alert Payload:\n{json.dumps(alert_payload, indent=2)}")]}
    triage_final_state = triage_app.invoke(triage_input)
    triage_final_message = triage_final_state["messages"][-1].content
    
    print("✅ TRIAGE CONCLUSION REACHED:")
    print(triage_final_message)
    print("\n--------------------------------------------------\n")
    
    if "ESCALATE" in triage_final_message.upper():
        print("⚠️ ESCALATION DETECTED! Multi-agent Incident Command handoff initiated...\n")
        
        handoff_context = f"Original Alert:\n{json.dumps(alert_payload, indent=2)}\n\nTier 1 Findings:\n{triage_final_message}"
        
        # Use the actual alert ID as the thread ID so state persists in SQLite
        incident_id = alert_payload.get("alert_id", "default-incident")
        config = {"configurable": {"thread_id": incident_id}}
        
        # Check if this incident was previously investigated
        current_state = hunter_app.get_state(config)
        is_resumed = bool(current_state.values)
        
        if not is_resumed:
            hunter_input = {"messages": [HumanMessage(content=f"Event Context:\n{handoff_context}")]}
        else:
            print(f"📁 [SYSTEM] Resuming existing multi-agent investigation for {incident_id} from database...\n")
            hunter_input = None
        
        while True:
            last_message = None
            
            # If resuming an existing case, pull the last message directly from checkpointed state
            if is_resumed and hunter_input is None:
                if current_state.values and "messages" in current_state.values:
                    last_message = current_state.values["messages"][-1]
                is_resumed = False
            else:
                # Stream the execution of the supervisor multi-agent graph
                for event in hunter_app.stream(hunter_input, config, stream_mode="values"):
                    if "messages" in event and event["messages"]:
                        last_message = event["messages"][-1]
                        
                        if last_message.type == "ai":
                            if last_message.content:
                                thoughts = re.findall(r'<thought>(.*?)</thought>', last_message.content, re.DOTALL)
                                for thought in thoughts:
                                    print(f"\n🧠 THOUGHT: {thought.strip()}")
                            if last_message.tool_calls:
                                for tool_call in last_message.tool_calls:
                                    # Skip printing the internal supervisor routing tool call to keep the UI clean
                                    if tool_call['name'] != 'route_to_agent':
                                        print(f"⚙️  REQUESTING [{tool_call['name']}]: {tool_call['args']}")
            
            # Check if execution paused before the containment guardrail
            current_state = hunter_app.get_state(config)
            if current_state.next and current_state.next[0] == "containment_tools":
                target = "unknown"
                tool_id = "unknown"
                if last_message and hasattr(last_message, "tool_calls") and last_message.tool_calls:
                    target = last_message.tool_calls[0]["args"].get("hostname", "unknown")
                    tool_id = last_message.tool_calls[0]["id"]
                
                print(f"\n🛑 [SECURITY GUARDRAIL TRIGGERED]")
                print(f"The Incident Commander/Endpoint Specialist wants to quarantine endpoint: {target}")
                ans = input("Do you authorize this action? (Y/N) > ")
                
                if ans.strip().lower() == 'y':
                    print("✅ Authorization accepted. Executing containment API...")
                    hunter_input = None  # Passing None resumes graph execution from the interrupt point
                    continue 
                else:
                    print("❌ Authorization denied. Informing the multi-agent team...")
                    rejection = ToolMessage(
                        tool_call_id=tool_id,
                        content="ERROR: Human analyst DENIED the containment action. Do not attempt again. Compile final report.",
                        name="isolate_endpoint"
                    )
                    hunter_app.update_state(config, {"messages": [rejection]}, as_node="containment_tools")
                    hunter_input = None
                    continue

            # Print agent response
            print("\n==================================================")
            print("✅ INCIDENT COMMANDER / SPECIALIST RESPONSE")
            print("==================================================")
            
            if last_message and last_message.content:
                clean_output = re.sub(r'<thought>.*?</thought>', '', last_message.content, flags=re.DOTALL).strip()
                if not clean_output:
                    clean_output = last_message.content.strip()
                print(clean_output)
            
            print("\n[Type 'exit' to close, or respond to the command team]")
            user_reply = input("Analyst Response > ")
            
            if user_reply.strip().lower() == 'exit':
                print("Closing investigation...")
                break
                
            hunter_input = {"messages": [HumanMessage(content=user_reply)]}
            print("\n--------------------------------------------------\n")
    else:
        print("🟢 Alert resolved at Tier 1. No deep investigation required.")

if __name__ == "__main__":
    sample_alert = {
        "alert_id": "SOC-2026-8999",  # Unique ID mapped to the new tool router test
        "title": "Suspicious Outbound Connection",
        "severity": "High",
        "endpoint": "DESKTOP-FIN-04",
        "destination_ip": "185.220.101.14", 
        "timestamp": "2026-09-22T07:45:00Z"
    }
    run_soc_workflow(sample_alert)
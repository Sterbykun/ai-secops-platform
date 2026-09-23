import json
import http.server
import socketserver
from langchain_core.messages import HumanMessage
from triage_agent import triage_app
from hunter_agent import hunter_app

PORT = 5000

class SIEMWebhookHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            alert = json.loads(post_data.decode('utf-8'))
            print(f"\n🚨 [SIEM WEBHOOK RECEIVED] Alert ID: {alert.get('alert_id', 'UNKNOWN')}")
            
            # Trigger Tier 1 Triage
            triage_input = {"messages": [HumanMessage(content=f"Incoming SIEM Alert Payload:\n{json.dumps(alert, indent=2)}")]}
            triage_final_state = triage_app.invoke(triage_input)
            triage_msg = triage_final_state["messages"][-1].content
            
            print(f"📋 Triage Result: {triage_msg[:100]}...")
            
            if "ESCALATE" in triage_msg.upper():
                print("⚠️ Escalation triggered! Initiating multi-agent response...")
                config = {"configurable": {"thread_id": alert.get("alert_id", "SOC-SIEM-01")}}
                handoff_context = f"Incoming Alert:\n{json.dumps(alert, indent=2)}\n\nTriage Findings:\n{triage_msg}"
                hunter_input = {"messages": [HumanMessage(content=handoff_context)]}
                
                # Run investigation stream
                for event in hunter_app.stream(hunter_input, config, stream_mode="values"):
                    pass
                print("✅ Multi-agent workflow completed successfully.")
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success", "message": "Alert processed by AI SOC"}).encode())
            
        except Exception as e:
            print(f"❌ Error processing webhook: {str(e)}")
            self.send_response(500)
            self.end_headers()

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), SIEMWebhookHandler) as httpd:
        print(f"🌐 SIEM Webhook Listener active on port {PORT}...")
        print("Ready to receive live alerts from Wazuh, Elastic, or custom scripts.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down webhook listener.")
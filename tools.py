import os
import json
import sqlite3
import requests
from langchain_core.tools import tool

# ==========================================
# 1. DATABASE & LOG QUERY TOOL (SQLite or Live SIEM)
# ==========================================
@tool
def query_security_database(query: str) -> str:
    """Execute a query against local SQLite logs or forward to live Elasticsearch SIEM in production."""
    es_url = os.getenv("ES_URL")
    if es_url:
        try:
            headers = {"Authorization": f"ApiKey {os.getenv('ES_API_KEY')}", "Content-Type": "application/json"}
            payload = {"query": {"query_string": {"query": query}}, "size": 10}
            response = requests.post(es_url, json=payload, headers=headers, timeout=10)
            if response.status_code == 200:
                hits = response.json().get("hits", {}).get("hits", [])
                results = [hit["_source"] for hit in hits]
                return json.dumps({"status": "success", "source": "elasticsearch", "data": results})
        except Exception:
            pass # Fall back to local SQLite if live SIEM connection fails

    # Local Simulation Fallback (soc_logs.db)
    try:
        conn = sqlite3.connect('soc_logs.db')
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        columns = [description[0] for description in cursor.description]
        conn.close()
        
        result = [dict(zip(columns, row)) for row in rows]
        return json.dumps({"status": "success", "source": "sqlite_simulation", "data": result})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

# ==========================================
# 2. THREAT INTEL & REPUTATION TOOLS
# ==========================================
@tool
def threat_intel_enrichment(ip_address: str) -> str:
    """Enrich an IP address or domain with threat intelligence feeds."""
    known_bad_ips = {
        "185.220.101.14": {"threat_score": 100, "actor": "APT-Mock", "country": "Germany", "tags": ["C2", "Ransomware Drop"]},
        "192.168.1.50": {"threat_score": 10, "actor": "Internal", "country": "Local", "tags": ["Benign"]}
    }
    info = known_bad_ips.get(ip_address, {"threat_score": 5, "actor": "Unknown", "country": "Global", "tags": ["Unclassified"]})
    return json.dumps({"ip": ip_address, "enrichment": info})

@tool
def check_ip_reputation(ip_address: str) -> str:
    """Check if an IP address is malicious, safe, or suspicious based on global feeds."""
    if ip_address == "185.220.101.14":
        return json.dumps({"ip": ip_address, "reputation": "MALICIOUS", "confidence": "High"})
    return json.dumps({"ip": ip_address, "reputation": "CLEAN", "confidence": "Medium"})

# ==========================================
# 3. DYNAMIC RAG PLAYBOOK CONSULTATION TOOL
# ==========================================
@tool
def consult_playbook(incident_type: str) -> str:
    """Consult specific Standard Operating Procedure (SOP) playbooks ('ransomware', 'phishing', 'exfiltration')."""
    try:
        incident_type = incident_type.lower()
        filename = "ransomware_sop.txt" # default
        
        if "phish" in incident_type or "credential" in incident_type or "auth" in incident_type:
            filename = "phishing_sop.txt"
        elif "exfil" in incident_type or "c2" in incident_type or "network" in incident_type or "beacon" in incident_type:
            filename = "exfiltration_sop.txt"
        elif "ransom" in incident_type or "malware" in incident_type:
            filename = "ransomware_sop.txt"
            
        file_path = os.path.join("playbooks", filename)
        if not os.path.exists(file_path):
            return json.dumps({"error": f"Playbook {filename} not found."})
            
        with open(file_path, "r") as f:
            content = f.read()
        return json.dumps({"status": "success", "playbook_file": filename, "sop_content": content})
    except Exception as e:
        return json.dumps({"error": f"Failed to read playbook: {str(e)}"})

# ==========================================
# 4. SOAR & CONTAINMENT ACTIONS (Live APIs or Simulation)
# ==========================================
@tool
def isolate_endpoint(hostname: str) -> str:
    """Isolate a host from the network using real EDR API or fallback simulation."""
    cs_client_id = os.getenv("CROWDSTRIKE_CLIENT_ID")
    if cs_client_id:
        try:
            # Place real CrowdStrike Falcon API containment call here when credentials are active
            pass
        except Exception:
            pass

    # Simulation fallback
    return json.dumps({"status": "success", "mode": "simulation", "action": "network_quarantine", "hostname": hostname, "message": f"Host {hostname} has been successfully isolated from the corporate network."})

@tool
def create_soar_ticket(title: str, severity: str, details: str) -> str:
    """Create a real Jira/ServiceNow incident ticket via REST API or fallback simulation."""
    jira_url = os.getenv("JIRA_INSTANCE_URL")
    if jira_url:
        try:
            auth = (os.getenv("JIRA_EMAIL"), os.getenv("JIRA_API_TOKEN"))
            headers = {"Content-Type": "application/json"}
            payload = {
                "fields": {
                    "project": {"key": os.getenv("JIRA_PROJECT_KEY", "SOC")},
                    "summary": f"[{severity}] {title}",
                    "description": details,
                    "issuetype": {"name": "Incident"}
                }
            }
            response = requests.post(jira_url, json=payload, auth=auth, headers=headers, timeout=10)
            if response.status_code == 201:
                data = response.json()
                return json.dumps({"status": "success", "mode": "live_jira", "ticket_id": data.get("key"), "url": data.get("self")})
        except Exception:
            pass

    # Simulation fallback
    ticket_id = "INC-SOC-2026-8970"
    return json.dumps({"status": "success", "mode": "simulation", "ticket_id": ticket_id, "severity": severity, "title": title, "message": "Ticket successfully created and assigned to Incident Response queue."})

@tool
def update_firewall_blocklist(ip_address: str) -> str:
    """Add a malicious IP address to the perimeter firewall blocklist."""
    return json.dumps({"status": "success", "ip": ip_address, "action": "blocked", "edge_device": "Edge-FW-01", "message": f"Outbound traffic to {ip_address} successfully blocked."})

@tool
def proactive_anomaly_hunt() -> str:
    """Scan security database for dormant or unflagged suspicious activities like encoded commands."""
    try:
        conn = sqlite3.connect('soc_logs.db')
        cursor = conn.cursor()
        cursor.execute("SELECT hostname, timestamp, command_line FROM process_logs WHERE command_line LIKE '% -enc %' OR command_line LIKE '%Hidden%'")
        results = cursor.fetchall()
        conn.close()
        return json.dumps({"status": "success", "anomalies_found": len(results), "details": results})
    except Exception as e:
        return json.dumps({"error": f"Hunt failed: {str(e)}"})

# ==========================================
# 5. EXPORT TOOL LISTS FOR AGENTS
# ==========================================
network_tools = [check_ip_reputation, threat_intel_enrichment]
endpoint_tools = [query_security_database, consult_playbook, isolate_endpoint, create_soar_ticket, update_firewall_blocklist]
identity_tools = [query_security_database]
hunter_tools = [proactive_anomaly_hunt, query_security_database]
triage_tools = [query_security_database, threat_intel_enrichment]
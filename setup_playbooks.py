import os

os.makedirs("playbooks", exist_ok=True)

# 1. Ransomware Playbook
ransomware_sop = """
STANDARD OPERATING PROCEDURE: RANSOMWARE & MALWARE CONTAINMENT (HIGH SEVERITY)
1. IMMEDIATE ISOLATION: Instantly isolate the compromised endpoint from the network using network quarantine tools to prevent lateral movement.
2. CREDENTIAL REVOCATION: Force a password reset for any service or user accounts compromised during the initial vector (e.g., svc_backup).
3. FORENSIC PRESERVATION: Capture full memory dumps and disk images for post-incident analysis.
4. PERIMETER DEFENSE: Block outbound connections to identified Command and Control (C2) IP addresses at the firewall level.
5. ESCALATION: Create an immediate high-priority ticket in ServiceNow/Jira and notify the on-call Incident Commander.
"""

# 2. Phishing & Credential Compromise Playbook
phishing_sop = """
STANDARD OPERATING PROCEDURE: PHISHING & CREDENTIAL COMPROMISE (MEDIUM/HIGH SEVERITY)
1. SESSION REVOCATION: Immediately revoke all active OAuth tokens and active sessions for the compromised user account.
2. IDENTITY AUDIT: Review auth_logs for unexpected multi-factor authentication (MFA) bypasses, impossible travel, or suspicious IP logins.
3. CREDENTIAL RESET: Enforce an immediate password reset and require temporary MFA re-enrollment.
4. EMAIL FILTERING: Check inbound email mailboxes for similar phishing payloads or malicious links and purge them globally.
5. TICKET CREATION: Log a security incident ticket detailing the compromised user principal and source IPs.
"""

# 3. Data Exfiltration Playbook
exfiltration_sop = """
STANDARD OPERATING PROCEDURE: DATA EXFILTRATION & C2 COMMUNICATIONS (CRITICAL SEVERITY)
1. TRAFFIC SEVERATION: Terminate all active external socket connections and isolate the source host immediately.
2. FIREWALL BLOCKLIST: Add destination external IPs and domains to the edge firewall blocklist.
3. DATA ACCESS AUDIT: Query database logs and file share access logs to determine what sensitive data or volumes were accessed prior to exfiltration.
4. FORENSIC TRIAGE: Inspect process command lines for encoded payloads, SFTP tools, or unauthorized cloud storage sync clients.
5. COMPLIANCE NOTIFICATION: Create an escalated incident ticket and notify the Data Protection Officer (DPO) if PII/regulated data was exposed.
"""

with open("playbooks/ransomware_sop.txt", "w") as f:
    f.write(ransomware_sop)

with open("playbooks/phishing_sop.txt", "w") as f:
    f.write(phishing_sop)

with open("playbooks/exfiltration_sop.txt", "w") as f:
    f.write(exfiltration_sop)

print("✅ Successfully generated all 3 enterprise security SOP playbooks in the 'playbooks/' folder!")
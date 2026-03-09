"""
FLARE - gen_one_per_stage.py
-----------------------------
Generates the minimum logs needed to trigger
exactly one alert per kill chain stage.

Each scenario is isolated — only enough events
to cross that stage's threshold, nothing more.

Usage:
    python gen_one_per_stage.py
"""

import json
from datetime import datetime
from pathlib import Path

INCOMING_FILE = r"C:\FLARE-data\Logs\incoming.json"

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def write(logs):
    Path(INCOMING_FILE).parent.mkdir(parents=True, exist_ok=True)
    existing = []
    try:
        content = Path(INCOMING_FILE).read_text(encoding="utf-8").strip()
        if content:
            existing = json.loads(content)
    except Exception:
        existing = []
    existing.extend(logs)
    Path(INCOMING_FILE).write_text(json.dumps(existing, indent=2))

# Each stage uses a unique attacker IP and unique victim/user
# so failures never bleed across stage counters in memory.

# ── Stage 1: Recon ── 4 distinct usernames from same IP
def stage1():
    return [{"Type":"System","Timestamp":ts(),"EventID":4625,
             "User":u,"LogonType":"3","Process":"N/A",
             "Source":"10.1.0.1","DestIP":"192.168.1.10"}
            for u in ["admin","administrator","guest","backup"]]

# ── Stage 2: Weaponization ── one staging tool executed
def stage2():
    return [{"Type":"System","Timestamp":ts(),"EventID":4688,
             "User":"user_s2","LogonType":"0",
             "Process":r"C:\Windows\System32\certutil.exe",
             "Source":"192.168.1.20","DestIP":"192.168.1.20"}]

# ── Stage 3: Delivery ── one suspicious process preceded by 1 failure → HIGH
def stage3():
    return [
        {"Type":"System","Timestamp":ts(),"EventID":4625,
         "User":"user_s3","LogonType":"3","Process":"N/A",
         "Source":"10.3.0.1","DestIP":"192.168.1.30"},
        {"Type":"System","Timestamp":ts(),"EventID":4688,
         "User":"user_s3","LogonType":"0",
         "Process":r"C:\Windows\System32\cmd.exe",
         "Source":"192.168.1.30","DestIP":"192.168.1.30"},
    ]

# ── Stage 4: Exploitation ── 5 failures from unique IP (brute force threshold)
def stage4():
    return [{"Type":"System","Timestamp":ts(),"EventID":4625,
             "User":"user_s4","LogonType":"3","Process":"N/A",
             "Source":"10.4.0.1","DestIP":"192.168.1.40"}
            for _ in range(5)]

# ── Stage 5: Installation ── new account created
def stage5():
    return [{"Type":"System","Timestamp":ts(),"EventID":4720,
             "User":"svc_backdoor","LogonType":"0","Process":"N/A",
             "Source":"192.168.1.50","DestIP":"192.168.1.50"}]

# ── Stage 6: C2 ── one connection to known bad port
def stage6():
    return [{"Type":"Network","Timestamp":ts(),"EventID":None,
             "User":"N/A","LogonType":"0","Process":"N/A",
             "Source":"192.168.1.60","DestIP":"10.10.10.99",
             "DestPort":4444,"FlowBytes":0}]

# ── Stage 7: Actions ── network logon to 3 distinct hosts (lateral movement)
def stage7():
    return [{"Type":"System","Timestamp":ts(),"EventID":4624,
             "User":"user_s7","LogonType":"3","Process":"N/A",
             "Source":"10.7.0.1","DestIP":f"192.168.1.{i}"}
            for i in range(70, 73)]

# ── Stage RDP: off-hours RDP login
def stage_rdp():
    return [{"Type":"System","Timestamp": datetime.now().replace(hour=3, minute=15).strftime("%Y-%m-%d %H:%M:%S"),
             "EventID":4624,"User":"Hacker_RDP","LogonType":"10","Process":"N/A",
             "Source":"10.9.0.1","DestIP":"192.168.1.90"}]

# ── Stage Exfiltration: large transfer to external IP on non-standard port
def stage_exfil():
    return [{"Type":"Network","Timestamp":ts(),"EventID":None,
             "User":"N/A","LogonType":"0","Process":"N/A",
             "Source":"192.168.1.50","DestIP":"203.0.113.5",
             "DestPort":2222,"FlowBytes":9999999}]

# ── Stage DDoS: 60 connections from same source to same dest port
def stage_ddos():
    return [{"Type":"Network","Timestamp":ts(),"EventID":None,
             "User":"N/A","LogonType":"0","Process":"N/A",
             "Source":"10.8.0.1","DestIP":"192.168.1.100",
             "DestPort":80,"FlowBytes":500000}
            for _ in range(60)]

# ── Stage Port Scan: 12 distinct ports from same source — use non-C2 ports
def stage_portscan():
    return [{"Type":"Network","Timestamp":ts(),"EventID":None,
             "User":"N/A","LogonType":"0","Process":"N/A",
             "Source":"10.6.0.1","DestIP":"192.168.1.10",
             "DestPort":p,"FlowBytes":64}
            for p in [21,22,23,25,53,110,139,143,389,636,3306,5432]]


if __name__ == "__main__":
    Path(INCOMING_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(INCOMING_FILE).write_text("[]")

    logs = (stage1() + stage2() + stage3() + stage4() +
            stage5() + stage6() + stage7() +
            stage_rdp() + stage_ddos() + stage_exfil() + stage_portscan())

    write(logs)
    print(f"\nWritten {len(logs)} logs to {INCOMING_FILE}")
    print("\nExpected alerts when agent.py reads this:")
    print("  Stage 1 — Reconnaissance    : Username Enumeration")
    print("  Stage 1 — Reconnaissance    : RDP Anomaly (off hours)")
    print("  Stage 1 — Reconnaissance    : Port Scan")
    print("  Stage 2 — Weaponization     : Payload Staging Tool")
    print("  Stage 3 — Delivery          : Suspicious Process Execution")
    print("  Stage 4 — Exploitation      : Brute Force")
    print("  Stage 5 — Installation      : New Account Created")
    print("  Stage 6 — C2               : C2 Port Connection")
    print("  Stage 7 — Actions           : Lateral Movement")
    print("  Stage 7 — Actions           : DDoS Attack")
    print("  Stage 7 — Actions           : Data Exfiltration")
    print("\nNow run: python agent.py")
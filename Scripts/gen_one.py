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

if __name__ == "__main__":
    Path(INCOMING_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(INCOMING_FILE).write_text("[]")

    logs = (stage1() + stage2() + stage3() +
            stage4() + stage5() + stage6() + stage7())

    write(logs)
    print(f"Written {len(logs)} logs to {INCOMING_FILE}")
    print("Expected: 1 alert per stage (7 total)")
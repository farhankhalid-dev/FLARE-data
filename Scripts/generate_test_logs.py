"""
FLARE - generate_test_logs.py
------------------------------
Synthetic log generator for testing all 7 kill chain stages.
Writes directly to incoming.json — bypasses collector.ps1.

Usage:
    python generate_test_logs.py                  # runs all scenarios
    python generate_test_logs.py --scenario 4a    # run one stage only
    python generate_test_logs.py --list           # list all scenarios
    python generate_test_logs.py --clean          # wipe incoming.json
"""

import json
import sys
import os
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from random import randint

# Mutable config — override via --output flag
CONFIG = {
    "output": r"C:\FLARE-data\Logs\incoming.json"
}

# ------------------------------------------------------------------ #
#  HELPERS                                                             #
# ------------------------------------------------------------------ #

def ts(offset_seconds=0):
    t = datetime.now() + timedelta(seconds=offset_seconds)
    return t.strftime("%Y-%m-%d %H:%M:%S")


def write_logs(logs):
    filepath = CONFIG["output"]
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    existing = []
    try:
        if Path(filepath).exists():
            content = Path(filepath).read_text(encoding="utf-8").strip()
            if content:
                existing = json.loads(content)
                if not isinstance(existing, list):
                    existing = [existing]
    except Exception:
        existing = []
    existing.extend(logs)
    Path(filepath).write_text(json.dumps(existing, indent=2))
    print(f"  → Wrote {len(logs)} log(s) to {filepath}")


def clean_incoming():
    filepath = CONFIG["output"]
    if Path(filepath).exists():
        Path(filepath).write_text("[]")
        print(f"  → Cleared {filepath}")
    else:
        print(f"  → {filepath} does not exist, nothing to clear")


# ------------------------------------------------------------------ #
#  SCENARIO 1 — RECONNAISSANCE                                        #
# ------------------------------------------------------------------ #

def gen_reconnaissance(attacker_ip="185.220.101.45", target="192.168.1.10"):
    print("\n[Scenario 1] Reconnaissance — Username Enumeration")
    usernames = ["admin", "administrator", "rehan", "farhan",
                 "guest", "service", "backup", "sysadmin"]
    logs = []
    for i, user in enumerate(usernames):
        logs.append({
            "Type": "System", "Timestamp": ts(i * 15),
            "EventID": 4625, "User": user, "LogonType": "3",
            "Process": "N/A", "Source": attacker_ip, "DestIP": target,
        })
    write_logs(logs)
    print(f"  → Simulated: {attacker_ip} probed {len(usernames)} usernames against {target}")


# ------------------------------------------------------------------ #
#  SCENARIO 2 — WEAPONIZATION                                         #
# ------------------------------------------------------------------ #

def gen_weaponization(target_user="rehan", host="192.168.1.10"):
    print("\n[Scenario 2] Weaponization — Payload Staging Tools")
    procs = [r"C:\Windows\System32\certutil.exe",
             r"C:\Windows\System32\mshta.exe",
             r"C:\Windows\System32\bitsadmin.exe"]
    logs = []
    for i, proc in enumerate(procs):
        logs.append({
            "Type": "System", "Timestamp": ts(i * 20),
            "EventID": 4688, "User": target_user, "LogonType": "0",
            "Process": proc, "Source": host, "DestIP": host,
        })
    write_logs(logs)
    print(f"  → Simulated: {len(procs)} staging tools executed as '{target_user}'")


# ------------------------------------------------------------------ #
#  SCENARIO 3 — DELIVERY                                              #
# ------------------------------------------------------------------ #

def gen_delivery(attacker_ip="185.220.101.45", target_user="rehan", host="192.168.1.10"):
    print("\n[Scenario 3] Delivery — Suspicious Process Execution")
    logs = []
    for i in range(3):
        logs.append({
            "Type": "System", "Timestamp": ts(i * 10),
            "EventID": 4625, "User": target_user, "LogonType": "3",
            "Process": "N/A", "Source": attacker_ip, "DestIP": host,
        })
    for i, proc in enumerate([
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"C:\Windows\System32\wmic.exe",
    ]):
        logs.append({
            "Type": "System", "Timestamp": ts(40 + i * 15),
            "EventID": 4688, "User": target_user, "LogonType": "0",
            "Process": proc, "Source": host, "DestIP": host,
        })
    write_logs(logs)
    print(f"  → Simulated: 3 failed logons then suspicious processes as '{target_user}'")


# ------------------------------------------------------------------ #
#  SCENARIO 4A — BRUTE FORCE                                          #
# ------------------------------------------------------------------ #

def gen_brute_force(attacker_ip="185.220.101.45", target="192.168.1.10",
                    target_user="administrator", succeed=True):
    print("\n[Scenario 4A] Exploitation — Vertical Brute Force")
    logs = []
    for i in range(10):
        logs.append({
            "Type": "System", "Timestamp": ts(i * 8),
            "EventID": 4625, "User": target_user, "LogonType": "3",
            "Process": "N/A", "Source": attacker_ip, "DestIP": target,
        })
    if succeed:
        logs.append({
            "Type": "System", "Timestamp": ts(90),
            "EventID": 4624, "User": target_user, "LogonType": "3",
            "Process": "N/A", "Source": attacker_ip, "DestIP": target,
        })
    write_logs(logs)
    status = "with successful logon at end" if succeed else "no success"
    print(f"  → Simulated: 10 failed logons from {attacker_ip} → {target} ({status})")


# ------------------------------------------------------------------ #
#  SCENARIO 4B — PASSWORD SPRAY                                       #
# ------------------------------------------------------------------ #

def gen_password_spray(attacker_ip="185.220.101.45"):
    print("\n[Scenario 4B] Exploitation — Horizontal Password Spray")
    targets = ["192.168.1.10", "192.168.1.11", "192.168.1.12",
               "192.168.1.13", "192.168.1.14", "192.168.1.15",
               "192.168.1.20", "192.168.1.21"]
    logs = []
    offset = 0
    for target in targets:
        for _ in range(randint(2, 3)):
            logs.append({
                "Type": "System", "Timestamp": ts(offset),
                "EventID": 4625, "User": "administrator", "LogonType": "3",
                "Process": "N/A", "Source": attacker_ip, "DestIP": target,
            })
            offset += randint(5, 15)
    write_logs(logs)
    print(f"  → Simulated: {attacker_ip} sprayed {len(targets)} devices")


# ------------------------------------------------------------------ #
#  SCENARIO 5 — INSTALLATION                                          #
# ------------------------------------------------------------------ #

def gen_installation(host="192.168.1.10"):
    print("\n[Scenario 5] Installation — Backdoor Account Creation")
    backdoor_user = "svc_update"
    logs = [
        {"Type": "System", "Timestamp": ts(0),  "EventID": 4720,
         "User": backdoor_user, "LogonType": "0", "Process": "N/A",
         "Source": host, "DestIP": host},
        {"Type": "System", "Timestamp": ts(5),  "EventID": 4672,
         "User": backdoor_user, "LogonType": "0", "Process": "N/A",
         "Source": host, "DestIP": host},
        {"Type": "System", "Timestamp": ts(10), "EventID": 4624,
         "User": backdoor_user, "LogonType": "3", "Process": "N/A",
         "Source": host, "DestIP": host},
    ]
    write_logs(logs)
    print(f"  → Simulated: account '{backdoor_user}' created + privileged + logged in")


# ------------------------------------------------------------------ #
#  SCENARIO 6A — C2 PORT                                              #
# ------------------------------------------------------------------ #

def gen_c2_port(victim="192.168.1.10", c2_server="10.10.10.99"):
    print("\n[Scenario 6A] C2 — Known Bad Port Connection")
    logs = []
    for i, port in enumerate([4444, 4445, 9001, 1234]):
        logs.append({
            "Type": "Network", "Timestamp": ts(i * 30), "EventID": None,
            "User": "N/A", "LogonType": "0", "Process": "N/A",
            "Source": victim, "DestIP": c2_server, "DestPort": port, "FlowBytes": 0,
        })
    write_logs(logs)
    print(f"  → Simulated: {victim} connecting to {c2_server} on C2 ports")


# ------------------------------------------------------------------ #
#  SCENARIO 6B — BEACONING                                            #
# ------------------------------------------------------------------ #

def gen_beaconing(victim="192.168.1.10", c2_server="203.0.113.77"):
    print("\n[Scenario 6B] C2 — Beaconing Pattern")
    logs = []
    for i in range(8):
        logs.append({
            "Type": "Network", "Timestamp": ts(i * 60), "EventID": None,
            "User": "N/A", "LogonType": "0", "Process": "N/A",
            "Source": victim, "DestIP": c2_server,
            "DestPort": 443, "FlowBytes": randint(200, 600),
        })
    write_logs(logs)
    print(f"  → Simulated: {victim} beaconing to {c2_server} 8x over ~8 minutes")


# ------------------------------------------------------------------ #
#  SCENARIO 7A — LATERAL MOVEMENT                                     #
# ------------------------------------------------------------------ #

def gen_lateral_movement(attacker_ip="185.220.101.45", compromised_user="rehan"):
    print("\n[Scenario 7A] Actions on Objectives — Lateral Movement")
    targets = ["192.168.1.20", "192.168.1.21", "192.168.1.22", "192.168.1.23"]
    logs = []
    for i, target in enumerate(targets):
        logs.append({
            "Type": "System", "Timestamp": ts(i * 45),
            "EventID": 4624, "User": compromised_user, "LogonType": "3",
            "Process": "N/A", "Source": attacker_ip, "DestIP": target,
        })
    write_logs(logs)
    print(f"  → Simulated: '{compromised_user}' network-logged into {len(targets)} hosts")


# ------------------------------------------------------------------ #
#  SCENARIO 7B — PRIVILEGE ESCALATION                                 #
# ------------------------------------------------------------------ #

def gen_privilege_escalation(attacker_ip="185.220.101.45",
                               target_user="rehan", host="192.168.1.10"):
    print("\n[Scenario 7B] Actions on Objectives — Privilege Escalation")
    logs = []
    for i in range(4):
        logs.append({
            "Type": "System", "Timestamp": ts(i * 10),
            "EventID": 4625, "User": target_user, "LogonType": "3",
            "Process": "N/A", "Source": attacker_ip, "DestIP": host,
        })
    logs.append({
        "Type": "System", "Timestamp": ts(45),
        "EventID": 4624, "User": target_user, "LogonType": "3",
        "Process": "N/A", "Source": attacker_ip, "DestIP": host,
    })
    logs.append({
        "Type": "System", "Timestamp": ts(50),
        "EventID": 4672, "User": target_user, "LogonType": "0",
        "Process": "N/A", "Source": host, "DestIP": host,
    })
    write_logs(logs)
    print(f"  → Simulated: 4 failures → success → privilege grant for '{target_user}'")


# ------------------------------------------------------------------ #
#  FULL KILL CHAIN                                                     #
# ------------------------------------------------------------------ #

def gen_full_kill_chain():
    print("\n" + "=" * 60)
    print("  FLARE — Full Kill Chain Simulation")
    print("=" * 60)
    clean_incoming()
    gen_reconnaissance()
    gen_weaponization()
    gen_delivery()
    gen_brute_force()
    gen_password_spray()
    gen_installation()
    gen_c2_port()
    gen_beaconing()
    gen_lateral_movement()
    gen_privilege_escalation()
    total = json.loads(Path(CONFIG["output"]).read_text())
    print(f"\n{'=' * 60}")
    print(f"  Total logs written: {len(total)}")
    print(f"  File: {CONFIG['output']}")
    print(f"  FLARE agent should detect alerts across all 7 stages.")
    print(f"{'=' * 60}\n")


# ------------------------------------------------------------------ #
#  SCENARIO MAP                                                        #
# ------------------------------------------------------------------ #

SCENARIOS = {
    1:    ("Reconnaissance — Username Enumeration",    gen_reconnaissance),
    2:    ("Weaponization — Payload Staging Tools",    gen_weaponization),
    3:    ("Delivery — Suspicious Process Execution",  gen_delivery),
    "4a": ("Exploitation — Vertical Brute Force",      gen_brute_force),
    "4b": ("Exploitation — Horizontal Password Spray", gen_password_spray),
    5:    ("Installation — Backdoor Account Creation", gen_installation),
    "6a": ("C2 — Known Bad Port",                      gen_c2_port),
    "6b": ("C2 — Beaconing",                           gen_beaconing),
    "7a": ("Lateral Movement",                         gen_lateral_movement),
    "7b": ("Privilege Escalation",                     gen_privilege_escalation),
    "all":("Full Kill Chain",                          gen_full_kill_chain),
}


# ------------------------------------------------------------------ #
#  CLI                                                                 #
# ------------------------------------------------------------------ #

def main():
    parser = argparse.ArgumentParser(
        description="FLARE Synthetic Log Generator",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--scenario", "-s", default="all",
        help=(
            "Scenario to run:\n"
            "  1   Reconnaissance       4a  Brute Force\n"
            "  2   Weaponization        4b  Password Spray\n"
            "  3   Delivery             5   Installation\n"
            "  6a  C2 Port              6b  Beaconing\n"
            "  7a  Lateral Movement     7b  Privilege Escalation\n"
            "  all Full kill chain (default)\n"
        ))
    parser.add_argument("--clean",  "-c", action="store_true",
        help="Wipe incoming.json before generating")
    parser.add_argument("--list",   "-l", action="store_true",
        help="List all available scenarios")
    parser.add_argument("--output", "-o", default=None,
        help="Output file path (default: C:\\FLARE-data\\Logs\\incoming.json)")

    args = parser.parse_args()

    if args.output:
        CONFIG["output"] = args.output

    if args.list:
        print("\nAvailable scenarios:\n")
        for key, (name, _) in SCENARIOS.items():
            print(f"  {str(key):>3}  {name}")
        print()
        return

    if args.clean:
        clean_incoming()

    key = args.scenario.lower()
    try:
        key = int(key)
    except ValueError:
        pass

    if key not in SCENARIOS:
        print(f"Unknown scenario '{args.scenario}'. Use --list to see options.")
        sys.exit(1)

    _, fn = SCENARIOS[key]
    fn()
    print(f"\nDone. Now run agent.py and check for alerts.\n")


if __name__ == "__main__":
    main()
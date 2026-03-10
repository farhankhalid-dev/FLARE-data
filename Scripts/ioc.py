"""
FLARE - ioc.py
--------------
Indicator of Compromise (IOC) matching engine.

Two layers:
  Layer 1 — Static IOC list  : bundled with FLARE, works offline
  Layer 2 — AbuseIPDB        : live threat intel, optional (requires API key)

Called by agent.py on every log batch, runs in parallel with rules.py.
Returns alert dicts in the same format as rules.py.
"""

import os
import json
import time
import urllib.request
import urllib.error
from datetime import datetime

# ------------------------------------------------------------------ #
#  CONFIGURATION                                                       #
# ------------------------------------------------------------------ #

# Set your AbuseIPDB API key here or as an environment variable
# Get a free key at https://www.abuseipdb.com/register
ABUSEIPDB_API_KEY  = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_ENABLED  = bool(ABUSEIPDB_API_KEY)

# Minimum abuse confidence score to fire an alert (0-100)
ABUSEIPDB_THRESHOLD = 50

# Cache API results to avoid hammering the API
# { ip: {"score": int, "checked_at": float} }
_abuseipdb_cache   = {}
CACHE_TTL_SECONDS  = 3600  # 1 hour


# ------------------------------------------------------------------ #
#  LAYER 1 — STATIC IOC LIST                                          #
# ------------------------------------------------------------------ #

# Known malware and attacker tool process names
MALICIOUS_PROCESSES = {
    # Credential dumping
    "mimikatz.exe",
    "wce.exe",
    "pwdump.exe",
    "fgdump.exe",
    "procdump.exe",
    "lsass.exe",          # legitimate but targeted by attackers

    # Remote access trojans / implants
    "meterpreter.exe",
    "beacon.exe",
    "cobaltstrike.exe",
    "empire.exe",
    "pupy.exe",
    "quasar.exe",
    "njrat.exe",
    "darkcomet.exe",
    "nanocore.exe",
    "remcos.exe",

    # Ransomware indicators
    "wannacry.exe",
    "notpetya.exe",
    "ryuk.exe",
    "conti.exe",
    "lockbit.exe",

    # Lateral movement tools
    "psexec.exe",
    "psexesvc.exe",
    "paexec.exe",
    "wmiexec.exe",
    "smbexec.exe",
    "crackmapexec.exe",

    # Reconnaissance tools
    "nmap.exe",
    "masscan.exe",
    "netscanner.exe",
    "advanced_ip_scanner.exe",

    # Exploitation frameworks
    "msfconsole.exe",
    "armitage.exe",

    # Data exfiltration tools
    "rclone.exe",
    "megasync.exe",
    "winscp.exe",         # legitimate but abused
}

# Known malicious or suspicious IP ranges/addresses
# Sources: public threat intel, Tor exit nodes, known C2 infrastructure
MALICIOUS_IPS = {
    # Tor exit nodes (commonly used by attackers)
    "185.220.101.45",
    "185.220.101.46",
    "185.220.101.47",
    "185.220.101.48",
    "185.220.101.34",
    "185.220.100.240",
    "185.220.100.241",
    "185.220.100.242",
    "185.220.100.243",
    "199.249.230.87",
    "199.249.230.113",
    "162.247.74.27",
    "162.247.74.74",
    "176.10.99.200",
    "176.10.99.201",

    # Known Metasploit/C2 test infrastructure (common in BOTSv3)
    "10.0.0.99",
    "23.22.63.114",
    "52.42.42.42",

    # Shodan scanning infrastructure
    "198.20.69.74",
    "198.20.69.98",
    "198.20.70.114",
    "198.20.70.130",
    "198.20.99.130",
    "198.20.99.194",
}

# Known malicious or suspicious domains / hostnames
MALICIOUS_DOMAINS = {
    "evildomain.com",
    "malware-c2.net",
    "update-windows-security.com",
    "secure-login-verify.com",
    "paypal-security-update.com",
}

# Suspicious usernames — common attacker-created backdoor account names
SUSPICIOUS_USERNAMES = {
    "backdoor",
    "hack",
    "hacker",
    "admin$",
    "support$",
    "helpdesk$",
    "svc_backdoor",
    "svcadmin",
    "iusr_",
    "test123",
    "temp_admin",
    "hidden",
    "ghost",
    "shadow",
}


# ------------------------------------------------------------------ #
#  ALERT BUILDER                                                       #
# ------------------------------------------------------------------ #

def make_ioc_alert(ioc_type, ioc_value, description, source_ip=None,
                   dest_ip=None, username=None, process=None,
                   confidence="HIGH", recommended_action=None, source="Static IOC List"):
    return {
        "timestamp":          datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "stage":              "IOC Match",
        "attack_type":        f"IOC — {ioc_type}",
        "confidence":         confidence,
        "description":        description,
        "source_ip":          source_ip,
        "dest_ip":            dest_ip,
        "username":           username,
        "process":            process,
        "ioc_value":          ioc_value,
        "ioc_source":         source,
        "recommended_action": recommended_action,
    }


# ------------------------------------------------------------------ #
#  LAYER 1 — STATIC MATCHING                                          #
# ------------------------------------------------------------------ #

def check_static_iocs(logs):
    """
    Match every log against the static IOC lists.
    Returns a list of alert dicts.
    """
    alerts = []
    seen   = set()   # deduplicate within this batch

    for log in logs:
        # --- Malicious process name ---
        process = (log.get("Process") or "").lower()
        process_name = process.split("\\")[-1].strip()
        if process_name and process_name in MALICIOUS_PROCESSES:
            key = f"ioc_process_{process_name}"
            if key not in seen:
                seen.add(key)
                alerts.append(make_ioc_alert(
                    ioc_type   = "Malicious Process",
                    ioc_value  = process_name,
                    description= (
                        f"Known malicious or attacker tool '{process_name}' "
                        f"executed by '{log.get('User', 'unknown')}'. "
                        f"Immediate investigation required."
                    ),
                    username   = log.get("User"),
                    process    = log.get("Process"),
                    recommended_action = (
                        f"Kill process immediately:\n"
                        f"  taskkill /IM {process_name} /F\n"
                        f"Isolate machine if ransomware or RAT suspected."
                    )
                ))

        # --- Malicious source IP ---
        source_ip = log.get("Source") or log.get("DestIP")
        if source_ip and source_ip in MALICIOUS_IPS:
            key = f"ioc_src_ip_{source_ip}"
            if key not in seen:
                seen.add(key)
                alerts.append(make_ioc_alert(
                    ioc_type   = "Malicious IP — Source",
                    ioc_value  = source_ip,
                    description= (
                        f"Traffic from known malicious IP {source_ip}. "
                        f"This IP appears on threat intelligence blacklists."
                    ),
                    source_ip  = source_ip,
                    recommended_action = (
                        f"Block immediately:\n"
                        f"  netsh advfirewall firewall add rule "
                        f"name=\"FLARE-IOC-{source_ip}\" "
                        f"dir=in action=block remoteip={source_ip}"
                    )
                ))

        # --- Malicious destination IP ---
        dest_ip = log.get("DestIP")
        if dest_ip and dest_ip in MALICIOUS_IPS:
            key = f"ioc_dst_ip_{dest_ip}"
            if key not in seen:
                seen.add(key)
                alerts.append(make_ioc_alert(
                    ioc_type   = "Malicious IP — Destination",
                    ioc_value  = dest_ip,
                    description= (
                        f"Outbound connection to known malicious IP {dest_ip}. "
                        f"Possible C2 communication or data exfiltration."
                    ),
                    dest_ip    = dest_ip,
                    recommended_action = (
                        f"Block outbound and investigate originating process:\n"
                        f"  netsh advfirewall firewall add rule "
                        f"name=\"FLARE-IOC-{dest_ip}\" "
                        f"dir=out action=block remoteip={dest_ip}"
                    )
                ))

        # --- Suspicious username ---
        username = (log.get("User") or "").lower()
        for sus in SUSPICIOUS_USERNAMES:
            if sus in username and username not in ("n/a", "system", ""):
                key = f"ioc_user_{username}"
                if key not in seen:
                    seen.add(key)
                    alerts.append(make_ioc_alert(
                        ioc_type   = "Suspicious Username",
                        ioc_value  = username,
                        description= (
                            f"Account '{log.get('User')}' matches known backdoor "
                            f"account naming pattern '{sus}'. "
                            f"Likely attacker-created persistence account."
                        ),
                        username   = log.get("User"),
                        confidence = "MEDIUM",
                        recommended_action = (
                            f"Investigate and disable if unauthorised:\n"
                            f"  net user {log.get('User')}\n"
                            f"  net user {log.get('User')} /active:no"
                        )
                    ))
                break

    return alerts


# ------------------------------------------------------------------ #
#  LAYER 2 — ABUSEIPDB LIVE LOOKUP                                    #
# ------------------------------------------------------------------ #

def _check_abuseipdb(ip):
    """
    Query AbuseIPDB for a single IP.
    Returns abuse confidence score (0-100) or None on failure.
    """
    # Check cache first
    cached = _abuseipdb_cache.get(ip)
    if cached and (time.time() - cached["checked_at"]) < CACHE_TTL_SECONDS:
        return cached["score"]

    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=30"
        req = urllib.request.Request(url, headers={
            "Key":    ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        })
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            score = data["data"]["abuseConfidenceScore"]
            _abuseipdb_cache[ip] = {"score": score, "checked_at": time.time()}
            return score
    except Exception:
        return None


def check_abuseipdb_iocs(logs):
    """
    Check all unique IPs in this log batch against AbuseIPDB.
    Only runs if ABUSEIPDB_ENABLED is True.
    Returns a list of alert dicts.
    """
    if not ABUSEIPDB_ENABLED:
        return []

    alerts = []
    checked = set()

    # Skip private/internal IP ranges
    def is_internal(ip):
        return any(ip.startswith(p) for p in [
            "192.168.", "10.", "172.16.", "172.17.", "172.18.",
            "172.19.", "172.20.", "127.", "0.", "::1"
        ])

    for log in logs:
        for field in ("Source", "DestIP"):
            ip = log.get(field)
            if not ip or ip in checked or is_internal(ip) or ip == "N/A":
                continue
            checked.add(ip)

            score = _check_abuseipdb(ip)
            if score is not None and score >= ABUSEIPDB_THRESHOLD:
                confidence = "HIGH" if score >= 80 else "MEDIUM"
                alerts.append(make_ioc_alert(
                    ioc_type   = "AbuseIPDB — Reported Malicious IP",
                    ioc_value  = ip,
                    description= (
                        f"IP {ip} has an AbuseIPDB confidence score of {score}/100. "
                        f"Reported as malicious by the threat intelligence community."
                    ),
                    source_ip  = ip if field == "Source" else None,
                    dest_ip    = ip if field == "DestIP"  else None,
                    confidence = confidence,
                    source     = f"AbuseIPDB (score: {score}/100)",
                    recommended_action = (
                        f"Block traffic to/from {ip}:\n"
                        f"  netsh advfirewall firewall add rule "
                        f"name=\"FLARE-ABUSEIPDB-{ip}\" "
                        f"dir=in action=block remoteip={ip}"
                    )
                ))

    return alerts


# ------------------------------------------------------------------ #
#  MAIN ENTRY POINT — called by agent.py                              #
# ------------------------------------------------------------------ #

def run_ioc_checks(logs):
    """
    Run all IOC checks against the current log batch.
    Returns a flat list of alert dicts.
    """
    alerts = []
    alerts += check_static_iocs(logs)
    alerts += check_abuseipdb_iocs(logs)
    return alerts


# ------------------------------------------------------------------ #
#  SMOKE TEST                                                          #
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    print("Running ioc.py smoke test...\n")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    test_logs = [
        # Known malicious IP as source
        {"Type":"Network", "Timestamp":now, "Source":"185.220.101.45",
         "DestIP":"192.168.1.10", "DestPort":445, "FlowBytes":0},

        # Known malicious IP as destination
        {"Type":"Network", "Timestamp":now, "Source":"192.168.1.10",
         "DestIP":"10.0.0.99", "DestPort":4444, "FlowBytes":0},

        # Malicious process
        {"Type":"System", "Timestamp":now, "EventID":4688,
         "User":"Farhan", "Process":"C:\\Users\\Farhan\\mimikatz.exe",
         "LogonType":"0"},

        # Suspicious username
        {"Type":"System", "Timestamp":now, "EventID":4624,
         "User":"backdoor_admin", "LogonType":"3",
         "Source":"10.5.0.1", "DestIP":"192.168.1.10"},

        # Clean log — should not fire
        {"Type":"System", "Timestamp":now, "EventID":4624,
         "User":"Farhan", "LogonType":"2",
         "Source":"192.168.1.10", "DestIP":"192.168.1.10"},
    ]

    alerts = run_ioc_checks(test_logs)

    print(f"IOC alerts fired: {len(alerts)}\n")
    for a in alerts:
        icon = "🔴" if a["confidence"] == "HIGH" else "🟡"
        print(f"  {icon} [{a['confidence']:<6}] {a['attack_type']}")
        print(f"           {a['description'][:80]}...")
        print(f"           Source: {a['ioc_source']}")
        print()

    print(f"AbuseIPDB enabled: {ABUSEIPDB_ENABLED}")
    if not ABUSEIPDB_ENABLED:
        print("  Set ABUSEIPDB_API_KEY env variable to enable live lookups.")
    print("\nSmoke test complete.")
"""
FLARE - rules.py
----------------
Deterministic detection rules for all 7 Cyber Kill Chain stages.
Each rule is a standalone function that takes a log window + memory
and returns an Alert dict or None.

Kill Chain Coverage:
    Stage 1 - Reconnaissance
    Stage 2 - Weaponization      (limited — pre-execution, hard to see)
    Stage 3 - Delivery
    Stage 4 - Exploitation
    Stage 5 - Installation
    Stage 6 - Command & Control
    Stage 7 - Actions on Objectives (Lateral Movement + Privilege Escalation)
"""

from datetime import datetime
from memory import FlareMemory

# ------------------------------------------------------------------ #
#  THRESHOLDS — tweak these to reduce false positives                 #
# ------------------------------------------------------------------ #

BRUTE_FORCE_THRESHOLD       = 5    # failed logons from same IP → same target
SPRAY_TARGET_THRESHOLD      = 3    # distinct targets from same IP
SPRAY_USERNAME_THRESHOLD    = 3    # distinct usernames from same IP
LATERAL_HOST_THRESHOLD      = 2    # distinct hosts via network logon
BEACONING_COUNT_THRESHOLD   = 5    # repeated connections to same external IP
WINDOW_MINUTES              = 10   # default lookback window


# ------------------------------------------------------------------ #
#  ALERT BUILDER                                                       #
# ------------------------------------------------------------------ #

def make_alert(stage, attack_type, confidence, description, source_ip=None,
               username=None, process=None, dest_ip=None, dest_port=None,
               recommended_action=None):
    return {
        "timestamp":          datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "stage":              stage,
        "attack_type":        attack_type,
        "confidence":         confidence,           # LOW / MEDIUM / HIGH
        "description":        description,
        "source_ip":          source_ip,
        "username":           username,
        "process":            process,
        "dest_ip":            dest_ip,
        "dest_port":          dest_port,
        "recommended_action": recommended_action,
    }


# ------------------------------------------------------------------ #
#  STAGE 1 — RECONNAISSANCE                                           #
#  Signal: many failed logons probing usernames before a real attack  #
# ------------------------------------------------------------------ #

def check_reconnaissance(logs, mem: FlareMemory):
    alerts = []

    # Collect unique source IPs from failed logons in this batch
    source_ips = set(
        log.get("Source") or log.get("DestIP")
        for log in logs
        if log.get("Type") == "System"
        and log.get("EventID") == 4625
        and (log.get("Source") or log.get("DestIP"))
    )

    for ip in source_ips:
        username_count = mem.get_spray_usernames(ip, within_minutes=WINDOW_MINUTES)

        if username_count >= SPRAY_USERNAME_THRESHOLD:
            alert_key = f"recon_username_enum_{ip}"
            if mem.should_fire_alert(alert_key, cooldown_minutes=10):
                alerts.append(make_alert(
                    stage             = "Stage 1 — Reconnaissance",
                    attack_type       = "Username Enumeration",
                    confidence        = "MEDIUM",
                    description       = (
                        f"{ip} probed {username_count} distinct usernames "
                        f"in the last {WINDOW_MINUTES} minutes. "
                        f"Likely enumerating valid accounts before brute force."
                    ),
                    source_ip         = ip,
                    recommended_action= (
                        f"Monitor {ip} closely. Consider blocking if brute force follows.\n"
                        f"  netsh advfirewall firewall add rule name=\"FLARE-BLOCK-{ip}\" "
                        f"dir=in action=block remoteip={ip}"
                    )
                ))

    return alerts


# ------------------------------------------------------------------ #
#  STAGE 2 — WEAPONIZATION                                            #
#  Largely pre-execution — minimal signal from Security logs alone.   #
#  We flag unusual process names that suggest payload staging.        #
# ------------------------------------------------------------------ #

def check_weaponization(logs, mem: FlareMemory):
    alerts = []

    staging_indicators = [
        "mshta.exe", "wscript.exe", "cscript.exe",
        "certutil.exe", "bitsadmin.exe", "msiexec.exe"
    ]

    for log in logs:
        if log.get("Type") != "System" or log.get("EventID") != 4688:
            continue

        process = (log.get("Process") or "").lower()
        process_name = process.split("\\")[-1]

        if process_name in staging_indicators:
            alert_key = f"weaponization_{process_name}_{log.get('User','unknown')}"
            if mem.should_fire_alert(alert_key, cooldown_minutes=15):
                alerts.append(make_alert(
                    stage             = "Stage 2 — Weaponization",
                    attack_type       = "Payload Staging Tool Detected",
                    confidence        = "MEDIUM",
                    description       = (
                        f"Process '{process_name}' executed by '{log.get('User')}'. "
                        f"Commonly used to download or execute malicious payloads."
                    ),
                    username          = log.get("User"),
                    process           = log.get("Process"),
                    recommended_action= (
                        f"Investigate what '{process_name}' was invoked with. "
                        f"Check command line arguments in Sysmon logs if available."
                    )
                ))

    return alerts


# ------------------------------------------------------------------ #
#  STAGE 3 — DELIVERY                                                 #
#  Signal: suspicious processes spawned — initial foothold            #
# ------------------------------------------------------------------ #

def check_delivery(logs, mem: FlareMemory):
    alerts = []

    # High-risk processes that indicate initial payload delivery
    delivery_processes = [
        "powershell.exe", "cmd.exe", "rundll32.exe",
        "regsvr32.exe", "wmic.exe"
    ]

    for log in logs:
        if log.get("Type") != "System" or log.get("EventID") != 4688:
            continue

        process = (log.get("Process") or "").lower()
        process_name = process.split("\\")[-1]

        if process_name in delivery_processes:
            # Cross-reference: did a failed logon from same user precede this?
            user = log.get("User", "unknown")
            prior_failures = mem.get_failed_logons_by_user(user, within_minutes=30)

            confidence = "HIGH" if prior_failures > 0 else "MEDIUM"

            alert_key = f"delivery_{process_name}_{user}"
            if mem.should_fire_alert(alert_key, cooldown_minutes=10):
                alerts.append(make_alert(
                    stage             = "Stage 3 — Delivery",
                    attack_type       = "Suspicious Process Execution",
                    confidence        = confidence,
                    description       = (
                        f"'{process_name}' spawned by user '{user}'. "
                        + (f"User had {prior_failures} prior failed logon(s) — "
                           f"possible unauthorized access." if prior_failures > 0
                           else "No prior failed logons — may be legitimate.")
                    ),
                    username          = user,
                    process           = log.get("Process"),
                    recommended_action= (
                        f"Verify if '{user}' should be running '{process_name}'. "
                        f"Check parent process and command line arguments."
                    )
                ))

    return alerts


# ------------------------------------------------------------------ #
#  STAGE 4 — EXPLOITATION                                             #
#  Signal: brute force + spray attacks — gaining initial access       #
# ------------------------------------------------------------------ #

def check_exploitation(logs, mem: FlareMemory):
    alerts = []

    source_ips = set(
        log.get("Source") or log.get("DestIP")
        for log in logs
        if log.get("Type") == "System"
        and log.get("EventID") in [4624, 4625]
        and (log.get("Source") or log.get("DestIP"))
    )

    for ip in source_ips:
        # --- Vertical Brute Force (one target, many attempts) ---
        fail_count = mem.get_failed_logons_by_source(ip, within_minutes=WINDOW_MINUTES)

        if fail_count >= BRUTE_FORCE_THRESHOLD:
            # Did it succeed?
            # Find the username being targeted
            username = next((
                log.get("User") for log in logs
                if log.get("EventID") == 4625
                and (log.get("Source") == ip or log.get("DestIP") == ip)
            ), "unknown")

            succeeded = mem.had_successful_logon_after_failures(ip, username)
            confidence = "HIGH" if succeeded else "MEDIUM"

            alert_key = f"brute_force_{ip}"
            if mem.should_fire_alert(alert_key, cooldown_minutes=5):
                alerts.append(make_alert(
                    stage             = "Stage 4 — Exploitation",
                    attack_type       = "Brute Force" + (" — SUCCEEDED" if succeeded else ""),
                    confidence        = confidence,
                    description       = (
                        f"{ip} made {fail_count} failed logon attempts in "
                        f"{WINDOW_MINUTES} minutes. "
                        + ("Followed by a SUCCESSFUL logon — account may be compromised."
                           if succeeded else "Attack ongoing.")
                    ),
                    source_ip         = ip,
                    username          = username,
                    recommended_action= (
                        f"Block {ip} immediately.\n"
                        f"  netsh advfirewall firewall add rule name=\"FLARE-BLOCK-{ip}\" "
                        f"dir=in action=block remoteip={ip}"
                        + (f"\n  Reset password for '{username}' immediately." if succeeded else "")
                    )
                ))
                if succeeded:
                    mem.add_to_blacklist(ip,
                        f"Brute force succeeded against '{username}'",
                        "Brute Force")

        # --- Horizontal Password Spray (one source, many targets) ---
        spray_targets = mem.get_spray_targets(ip, within_minutes=WINDOW_MINUTES)

        if spray_targets >= SPRAY_TARGET_THRESHOLD:
            alert_key = f"spray_{ip}"
            if mem.should_fire_alert(alert_key, cooldown_minutes=5):
                alerts.append(make_alert(
                    stage             = "Stage 4 — Exploitation",
                    attack_type       = "Password Spray",
                    confidence        = "HIGH",
                    description       = (
                        f"{ip} attempted logins against {spray_targets} distinct "
                        f"devices in {WINDOW_MINUTES} minutes. "
                        f"Classic horizontal password spray pattern."
                    ),
                    source_ip         = ip,
                    recommended_action= (
                        f"Block {ip} at the firewall immediately.\n"
                        f"  netsh advfirewall firewall add rule name=\"FLARE-BLOCK-{ip}\" "
                        f"dir=in action=block remoteip={ip}"
                    )
                ))
                mem.add_to_blacklist(ip,
                    f"Password spray across {spray_targets} devices",
                    "Password Spray")

    return alerts


# ------------------------------------------------------------------ #
#  STAGE 5 — INSTALLATION                                             #
#  Signal: new accounts created, persistence mechanisms               #
# ------------------------------------------------------------------ #

def check_installation(logs, mem: FlareMemory):
    alerts = []

    for log in logs:
        if log.get("Type") != "System":
            continue

        # New account creation
        if log.get("EventID") == 4720:
            user    = log.get("User", "unknown")
            alert_key = f"new_account_{user}_{log.get('Timestamp','')}"
            if mem.should_fire_alert(alert_key, cooldown_minutes=60):
                alerts.append(make_alert(
                    stage             = "Stage 5 — Installation",
                    attack_type       = "New Account Created",
                    confidence        = "MEDIUM",
                    description       = (
                        f"New user account '{user}' was created. "
                        f"Could indicate attacker establishing persistence."
                    ),
                    username          = user,
                    recommended_action= (
                        f"Verify if account '{user}' was created legitimately. "
                        f"If unknown, disable immediately:\n"
                        f"  net user {user} /active:no"
                    )
                ))

        # Privilege grant immediately after new account — high suspicion
        if log.get("EventID") == 4672:
            user = log.get("User", "unknown")
            new_accounts = mem.get_new_accounts(within_minutes=30)
            new_usernames = [a["username"] for a in new_accounts]

            if user in new_usernames:
                alert_key = f"new_account_priv_{user}"
                if mem.should_fire_alert(alert_key, cooldown_minutes=30):
                    alerts.append(make_alert(
                        stage             = "Stage 5 — Installation",
                        attack_type       = "New Account Given Privileges",
                        confidence        = "HIGH",
                        description       = (
                            f"Newly created account '{user}' was immediately "
                            f"granted special privileges (4672). "
                            f"Strong indicator of backdoor account creation."
                        ),
                        username          = user,
                        recommended_action= (
                            f"Disable account '{user}' immediately and investigate:\n"
                            f"  net user {user} /active:no"
                        )
                    ))

    return alerts


# ------------------------------------------------------------------ #
#  STAGE 6 — COMMAND & CONTROL                                        #
#  Signal: beaconing, connections to known C2 ports                   #
# ------------------------------------------------------------------ #

def check_c2(logs, mem: FlareMemory):
    alerts = []

    # Known C2 ports
    c2_hits = mem.get_c2_candidates(within_minutes=WINDOW_MINUTES)
    for hit in c2_hits:
        alert_key = f"c2_port_{hit['dest_ip']}_{hit['dest_port']}"
        if mem.should_fire_alert(alert_key, cooldown_minutes=15):
            alerts.append(make_alert(
                stage             = "Stage 6 — Command & Control",
                attack_type       = "C2 Port Connection",
                confidence        = "HIGH",
                description       = (
                    f"Connection to {hit['dest_ip']}:{hit['dest_port']} detected. "
                    f"Port {hit['dest_port']} is commonly used by C2 frameworks "
                    f"(Metasploit, Cobalt Strike, etc)."
                ),
                dest_ip           = hit["dest_ip"],
                dest_port         = hit["dest_port"],
                recommended_action= (
                    f"Block outbound traffic to {hit['dest_ip']}.\n"
                    f"  netsh advfirewall firewall add rule name=\"FLARE-BLOCK-{hit['dest_ip']}\" "
                    f"dir=out action=block remoteip={hit['dest_ip']}"
                )
            ))
            mem.add_to_blacklist(hit["dest_ip"],
                f"C2 connection on port {hit['dest_port']}",
                "Command & Control")

    # Beaconing — repeated connections to same external IP
    beacons = mem.get_repeated_external_connections(
        within_minutes=WINDOW_MINUTES,
        min_count=BEACONING_COUNT_THRESHOLD
    )
    for beacon in beacons:
        alert_key = f"beaconing_{beacon['dest_ip']}"
        if mem.should_fire_alert(alert_key, cooldown_minutes=15):
            alerts.append(make_alert(
                stage             = "Stage 6 — Command & Control",
                attack_type       = "Beaconing Detected",
                confidence        = "MEDIUM",
                description       = (
                    f"Host contacted {beacon['dest_ip']}:{beacon['dest_port']} "
                    f"{beacon['count']} times in {WINDOW_MINUTES} minutes. "
                    f"Regular interval connections suggest malware beaconing."
                ),
                dest_ip           = beacon["dest_ip"],
                dest_port         = beacon["dest_port"],
                recommended_action= (
                    f"Investigate process making connections to {beacon['dest_ip']}. "
                    f"Consider blocking outbound:\n"
                    f"  netsh advfirewall firewall add rule name=\"FLARE-BLOCK-{beacon['dest_ip']}\" "
                    f"dir=out action=block remoteip={beacon['dest_ip']}"
                )
            ))

    return alerts


# ------------------------------------------------------------------ #
#  STAGE 7 — ACTIONS ON OBJECTIVES                                    #
#  Signal: lateral movement, privilege escalation                     #
# ------------------------------------------------------------------ #

def check_actions_on_objectives(logs, mem: FlareMemory):
    alerts = []

    # Collect users seen in this batch
    users = set(
        log.get("User") for log in logs
        if log.get("Type") == "System"
        and log.get("User")
        and log.get("User") != "N/A"
    )

    for user in users:
        # --- Lateral Movement ---
        host_count = mem.get_lateral_movement_hosts(user, within_minutes=30)
        if host_count >= LATERAL_HOST_THRESHOLD:
            alert_key = f"lateral_movement_{user}"
            if mem.should_fire_alert(alert_key, cooldown_minutes=15):
                alerts.append(make_alert(
                    stage             = "Stage 7 — Actions on Objectives",
                    attack_type       = "Lateral Movement",
                    confidence        = "HIGH",
                    description       = (
                        f"User '{user}' authenticated to {host_count} distinct hosts "
                        f"via network logon (LogonType 3) in the last 30 minutes. "
                        f"Indicates lateral movement across the network."
                    ),
                    username          = user,
                    recommended_action= (
                        f"Investigate active sessions for '{user}'. "
                        f"Consider disabling account pending review:\n"
                        f"  net user {user} /active:no"
                    )
                ))

        # --- Privilege Escalation ---
        priv_count = mem.get_privilege_escalations(user, within_minutes=WINDOW_MINUTES)
        if priv_count > 0:
            # Is this user also appearing after a brute force?
            prior_failures = mem.get_failed_logons_by_user(user, within_minutes=30)
            confidence = "HIGH" if prior_failures >= 3 else "MEDIUM"

            alert_key = f"priv_esc_{user}"
            if mem.should_fire_alert(alert_key, cooldown_minutes=10):
                alerts.append(make_alert(
                    stage             = "Stage 7 — Actions on Objectives",
                    attack_type       = "Privilege Escalation",
                    confidence        = confidence,
                    description       = (
                        f"User '{user}' was assigned special privileges (Event 4672). "
                        + (f"Preceded by {prior_failures} failed logon attempts — "
                           f"likely unauthorized." if prior_failures >= 3
                           else "No prior failures — may be legitimate.")
                    ),
                    username          = user,
                    recommended_action= (
                        f"Verify if '{user}' should have elevated privileges. "
                        f"Review group memberships:\n"
                        f"  net user {user}"
                    )
                ))

    return alerts


# ------------------------------------------------------------------ #
#  MAIN ENTRY POINT — called by agent.py                              #
# ------------------------------------------------------------------ #

def run_all_rules(logs, mem: FlareMemory):
    """
    Run all 7 kill chain rules against the current log batch.
    Returns a flat list of alert dicts.
    """
    all_alerts = []
    all_alerts += check_reconnaissance(logs, mem)
    all_alerts += check_weaponization(logs, mem)
    all_alerts += check_delivery(logs, mem)
    all_alerts += check_exploitation(logs, mem)
    all_alerts += check_installation(logs, mem)
    all_alerts += check_c2(logs, mem)
    all_alerts += check_actions_on_objectives(logs, mem)
    return all_alerts


# ------------------------------------------------------------------ #
#  SMOKE TEST                                                          #
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    import tempfile, os
    from memory import FlareMemory

    print("Running rules.py smoke test...\n")
    test_db = os.path.join(tempfile.gettempdir(), "flare_rules_test.db")
    mem = FlareMemory(db_path=test_db)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    attacker = "185.220.101.45"
    victim   = "192.168.1.10"

    # --- Stage 1: Recon — enumerate 4 usernames ---
    for user in ["admin", "administrator", "rehan", "farhan"]:
        mem.record_failed_logon(now, attacker, victim, user, "3")

    # --- Stage 4: Brute force — 6 failures on one user ---
    for _ in range(6):
        mem.record_failed_logon(now, attacker, victim, "rehan", "3")

    # --- Stage 4: Spray — hit 4 devices ---
    for target in ["192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14"]:
        mem.record_failed_logon(now, attacker, target, "administrator", "3")

    # --- Stage 5: New account + privilege ---
    mem.record_account_creation(now, "backdoor_user", "PC-01")
    mem.record_privilege_event(now, "backdoor_user", "PC-01")

    # --- Stage 6: C2 port ---
    mem.record_network(now, victim, "10.0.0.99", 4444)

    # --- Stage 7: Lateral movement ---
    for host in ["192.168.1.20", "192.168.1.21", "192.168.1.22"]:
        mem.record_successful_logon(now, attacker, host, "rehan", "3")

    # Build a minimal log batch
    logs = [
        {"Type": "System", "EventID": 4625, "User": "rehan",         "LogonType": "3", "Source": attacker, "DestIP": victim,          "Timestamp": now},
        {"Type": "System", "EventID": 4625, "User": "administrator",  "LogonType": "3", "Source": attacker, "DestIP": "192.168.1.11",   "Timestamp": now},
        {"Type": "System", "EventID": 4688, "User": "rehan",          "LogonType": "0", "Process": "C:\\Windows\\System32\\cmd.exe",     "Timestamp": now},
        {"Type": "System", "EventID": 4720, "User": "backdoor_user",  "LogonType": "0", "Process": "N/A",                               "Timestamp": now},
        {"Type": "System", "EventID": 4672, "User": "backdoor_user",  "LogonType": "0", "Process": "N/A",                               "Timestamp": now},
        {"Type": "Network","EventID": None,  "Source": victim,         "DestIP": "10.0.0.99", "DestPort": 4444,                         "Timestamp": now},
    ]

    alerts = run_all_rules(logs, mem)

    print(f"Total alerts fired: {len(alerts)}\n")
    for a in alerts:
        print(f"  [{a['confidence']}] {a['stage']}")
        print(f"         {a['attack_type']}")
        print(f"         {a['description'][:80]}...")
        print()

    mem.close()
    os.remove(test_db)
    print("Smoke test complete. rules.py is ready.")
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

        event_id = log.get("EventID")
        user     = log.get("User", "unknown")
        ts       = log.get("Timestamp", "")

        # ── 4720: New account created ──────────────────────────────────
        if event_id == 4720:
            alert_key = f"new_account_{user}_{ts}"
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

        # ── 4672: Privilege grant on a newly created account ───────────
        if event_id == 4672:
            new_accounts  = mem.get_new_accounts(within_minutes=30)
            new_usernames = [a["username"] for a in new_accounts]
            if user in new_usernames:
                alert_key = f"new_account_priv_{user}"
                if mem.should_fire_alert(alert_key, cooldown_minutes=30):
                    alerts.append(make_alert(
                        stage             = "Stage 5 — Installation",
                        attack_type       = "Backdoor Account — New Account Given Privileges",
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

        # ── 4732: Account added to privileged group ────────────────────
        if event_id == 4732:
            group = log.get("Process", "unknown group")  # Group name in Process field
            alert_key = f"group_add_{user}_{group}"
            if mem.should_fire_alert(alert_key, cooldown_minutes=30):
                # Escalate to HIGH if the account was recently created
                new_accounts  = mem.get_new_accounts(within_minutes=60)
                new_usernames = [a["username"] for a in new_accounts]
                confidence    = "HIGH" if user in new_usernames else "MEDIUM"
                alerts.append(make_alert(
                    stage             = "Stage 5 — Installation",
                    attack_type       = "Backdoor Account — Added to Privileged Group",
                    confidence        = confidence,
                    description       = (
                        f"Account '{user}' was added to a privileged group '{group}'. "
                        + ("Account was recently created — likely backdoor setup."
                           if user in new_usernames
                           else "Verify this change was authorised.")
                    ),
                    username          = user,
                    recommended_action= (
                        f"Review group membership for '{user}':\n"
                        f"  net user {user}\n"
                        f"Remove from group if unauthorised:\n"
                        f"  net localgroup {group} {user} /delete"
                    )
                ))

        # ── 4722: Account re-enabled ───────────────────────────────────
        if event_id == 4722:
            alert_key = f"account_enabled_{user}"
            if mem.should_fire_alert(alert_key, cooldown_minutes=60):
                alerts.append(make_alert(
                    stage             = "Stage 5 — Installation",
                    attack_type       = "Backdoor Account — Disabled Account Re-enabled",
                    confidence        = "HIGH",
                    description       = (
                        f"Previously disabled account '{user}' was re-enabled. "
                        f"Attackers often re-enable dormant accounts to avoid "
                        f"detection from new account creation alerts."
                    ),
                    username          = user,
                    recommended_action= (
                        f"Verify if '{user}' should be active. "
                        f"If unexpected, disable again immediately:\n"
                        f"  net user {user} /active:no"
                    )
                ))

        # ── 4723/4724: Password reset ──────────────────────────────────
        if event_id in (4723, 4724):
            alert_key = f"password_reset_{user}"
            if mem.should_fire_alert(alert_key, cooldown_minutes=30):
                # HIGH if the account was recently created or just enabled
                new_accounts  = mem.get_new_accounts(within_minutes=60)
                new_usernames = [a["username"] for a in new_accounts]
                confidence    = "HIGH" if user in new_usernames else "MEDIUM"
                event_label   = "forced reset (4724)" if event_id == 4724 else "self-reset (4723)"
                alerts.append(make_alert(
                    stage             = "Stage 5 — Installation",
                    attack_type       = "Backdoor Account — Password Reset",
                    confidence        = confidence,
                    description       = (
                        f"Password {event_label} on account '{user}'. "
                        + ("Account was recently created — possible backdoor credential setup."
                           if user in new_usernames
                           else "Verify this reset was authorised.")
                    ),
                    username          = user,
                    recommended_action= (
                        f"Confirm '{user}' initiated this reset. "
                        f"If unexpected, disable account:\n"
                        f"  net user {user} /active:no"
                    )
                ))

        # ── 4698: Scheduled task created ──────────────────────────────
        if event_id == 4698:
            alert_key = f"sched_task_{user}_{ts}"
            if mem.should_fire_alert(alert_key, cooldown_minutes=30):
                # HIGH if preceded by failed logons or new account
                prior_failures = mem.get_failed_logons_by_user(user, within_minutes=30)
                new_accounts   = mem.get_new_accounts(within_minutes=60)
                new_usernames  = [a["username"] for a in new_accounts]
                suspicious     = prior_failures > 0 or user in new_usernames
                confidence     = "HIGH" if suspicious else "MEDIUM"
                alerts.append(make_alert(
                    stage             = "Stage 5 — Installation",
                    attack_type       = "Persistence — Scheduled Task Created",
                    confidence        = confidence,
                    description       = (
                        f"Scheduled task created by '{user}'. "
                        + ("Preceded by failed logons or new account — likely attacker persistence."
                           if suspicious
                           else "Verify this task was created intentionally.")
                    ),
                    username          = user,
                    recommended_action= (
                        f"Review scheduled tasks:\n"
                        f"  schtasks /query /fo LIST /v | findstr /i \"{user}\"\n"
                        f"Delete if unauthorised:\n"
                        f"  schtasks /delete /tn <taskname> /f"
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
#  NEW THRESHOLDS                                                      #
# ------------------------------------------------------------------ #

RDP_OFF_HOURS_START     = 22   # 10 PM
RDP_OFF_HOURS_END       = 6    # 6 AM
DDOS_CONNECTION_THRESHOLD = 50  # connections to same dest in 5 min
DDOS_BYTES_THRESHOLD    = 100000 # total bytes to same dest in 5 min
EXFIL_BYTES_THRESHOLD   = 1000000 # 1MB to external IP = suspicious
PORT_SCAN_THRESHOLD     = 10   # distinct ports in 5 min


# ------------------------------------------------------------------ #
#  RDP ANOMALY — LogonType 10 during off hours                        #
# ------------------------------------------------------------------ #

def check_rdp_anomaly(logs, mem: FlareMemory):
    alerts = []

    for log in logs:
        if log.get("Type") != "System" or log.get("EventID") != 4624:
            continue
        if str(log.get("LogonType", "0")) != "10":
            continue

        # Check if off hours
        try:
            hour = datetime.strptime(
                log.get("Timestamp", ""), "%Y-%m-%d %H:%M:%S"
            ).hour
        except Exception:
            hour = datetime.now().hour

        is_off_hours = hour >= RDP_OFF_HOURS_START or hour < RDP_OFF_HOURS_END
        confidence   = "HIGH" if is_off_hours else "MEDIUM"
        user         = log.get("User", "unknown")
        source       = log.get("Source", "N/A")
        dest         = log.get("DestIP", "N/A")

        alert_key = f"rdp_{user}_{source}"
        if mem.should_fire_alert(alert_key, cooldown_minutes=30):
            alerts.append(make_alert(
                stage             = "Stage 1 — Reconnaissance",
                attack_type       = "RDP Anomaly" + (" — Off Hours" if is_off_hours else ""),
                confidence        = confidence,
                description       = (
                    f"RDP login (LogonType 10) by '{user}' from {source} to {dest} "
                    f"at {hour:02d}:00. "
                    + ("Login occurred outside business hours — high suspicion."
                       if is_off_hours else "Login during business hours — verify if expected.")
                ),
                source_ip         = source,
                username          = user,
                dest_ip           = dest,
                recommended_action= (
                    f"Verify if '{user}' should have RDP access from {source}.\n"
                    f"If unexpected, terminate session and investigate:\n"
                    f"  query session /server:{dest}\n"
                    f"  logoff <session_id> /server:{dest}"
                )
            ))

    return alerts


# ------------------------------------------------------------------ #
#  DDOS — High volume connections to same dest IP + port              #
# ------------------------------------------------------------------ #

def check_ddos(logs, mem: FlareMemory):
    alerts = []

    # Collect unique dest IP+port pairs from network logs in this batch
    targets = set(
        (log.get("DestIP"), log.get("DestPort"))
        for log in logs
        if log.get("Type") == "Network"
        and log.get("DestIP")
        and log.get("DestPort")
    )

    for dest_ip, dest_port in targets:
        count, total_bytes = mem.get_high_volume_dest(
            dest_ip, dest_port, within_minutes=5
        )

        # Collect unique source IPs hitting this dest
        source_ips = set(
            log.get("Source") for log in logs
            if log.get("Type") == "Network"
            and log.get("DestIP") == dest_ip
            and log.get("DestPort") == dest_port
        )
        source_str = list(source_ips)[0] if len(source_ips) == 1 else "multi"

        if count >= DDOS_CONNECTION_THRESHOLD:
            alert_key = f"ddos_{dest_ip}_{dest_port}"
            if mem.should_fire_alert(alert_key, cooldown_minutes=5):
                alerts.append(make_alert(
                    stage             = "Stage 7 — Actions on Objectives",
                    attack_type       = "DDoS Attack",
                    confidence        = "HIGH",
                    description       = (
                        f"{count} connections and {int(total_bytes):,} bytes sent to "
                        f"{dest_ip}:{dest_port} in 5 minutes. "
                        f"Volumetric flood pattern detected."
                    ),
                    dest_ip           = dest_ip,
                    dest_port         = dest_port,
                    recommended_action= (
                        f"Rate-limit or block traffic to {dest_ip}:{dest_port}.\n"
                        f"  netsh advfirewall firewall add rule name=\"FLARE-DDOS-{dest_ip}\" "
                        f"dir=in action=block remoteip={dest_ip}"
                    )
                ))

    return alerts


# ------------------------------------------------------------------ #
#  DATA EXFILTRATION — Large outbound transfer to external IP         #
# ------------------------------------------------------------------ #

def check_exfiltration(logs, mem: FlareMemory):
    alerts = []

    # Check logs directly for large single transfers
    for log in logs:
        if log.get("Type") != "Network":
            continue

        flow_bytes = float(log.get("FlowBytes", 0) or 0)
        dest_ip    = log.get("DestIP", "")
        dest_port  = log.get("DestPort", 0)
        source     = log.get("Source", "N/A")

        # Skip internal IPs
        if any(dest_ip.startswith(p) for p in ["192.168.", "10.", "172.16.", "127."]):
            continue

        if flow_bytes >= EXFIL_BYTES_THRESHOLD:
            alert_key = f"exfil_{source}_{dest_ip}_{dest_port}"
            if mem.should_fire_alert(alert_key, cooldown_minutes=10):
                alerts.append(make_alert(
                    stage             = "Stage 7 — Actions on Objectives",
                    attack_type       = "Data Exfiltration",
                    confidence        = "HIGH",
                    description       = (
                        f"{int(flow_bytes):,} bytes sent from {source} to "
                        f"external IP {dest_ip}:{dest_port}. "
                        f"Unusually large outbound transfer — possible data theft."
                    ),
                    source_ip         = source,
                    dest_ip           = dest_ip,
                    dest_port         = dest_port,
                    recommended_action= (
                        f"Investigate process responsible for transfer from {source}.\n"
                        f"Block outbound to {dest_ip} immediately:\n"
                        f"  netsh advfirewall firewall add rule name=\"FLARE-EXFIL-{dest_ip}\" "
                        f"dir=out action=block remoteip={dest_ip}"
                    )
                ))
                mem.add_to_blacklist(dest_ip,
                    f"Exfiltration destination — {int(flow_bytes):,} bytes",
                    "Data Exfiltration")

    return alerts


# ------------------------------------------------------------------ #
#  PORT SCANNING — Same source hitting many distinct ports rapidly    #
# ------------------------------------------------------------------ #

def check_port_scan(logs, mem: FlareMemory):
    alerts = []

    source_ips = set(
        log.get("Source")
        for log in logs
        if log.get("Type") == "Network"
        and log.get("Source")
    )

    for ip in source_ips:
        port_count = mem.get_port_scan_ports(ip, within_minutes=5)

        if port_count >= PORT_SCAN_THRESHOLD:
            alert_key = f"portscan_{ip}"
            if mem.should_fire_alert(alert_key, cooldown_minutes=10):
                alerts.append(make_alert(
                    stage             = "Stage 1 — Reconnaissance",
                    attack_type       = "Port Scan",
                    confidence        = "HIGH",
                    description       = (
                        f"{ip} probed {port_count} distinct ports in 5 minutes. "
                        f"Classic network reconnaissance — attacker mapping open services."
                    ),
                    source_ip         = ip,
                    recommended_action= (
                        f"Block {ip} immediately — active scanning in progress.\n"
                        f"  netsh advfirewall firewall add rule name=\"FLARE-BLOCK-{ip}\" "
                        f"dir=in action=block remoteip={ip}"
                    )
                ))
                mem.add_to_blacklist(ip,
                    f"Port scan — {port_count} ports probed",
                    "Port Scan")

    return alerts


# ------------------------------------------------------------------ #
#  MAIN ENTRY POINT — called by agent.py                              #
# ------------------------------------------------------------------ #

def run_all_rules(logs, mem: FlareMemory):
    """
    Run all rules against the current log batch.
    Returns a flat list of alert dicts.
    """
    all_alerts = []
    all_alerts += check_reconnaissance(logs, mem)
    all_alerts += check_rdp_anomaly(logs, mem)
    all_alerts += check_weaponization(logs, mem)
    all_alerts += check_delivery(logs, mem)
    all_alerts += check_exploitation(logs, mem)
    all_alerts += check_installation(logs, mem)
    all_alerts += check_c2(logs, mem)
    all_alerts += check_ddos(logs, mem)
    all_alerts += check_exfiltration(logs, mem)
    all_alerts += check_port_scan(logs, mem)
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
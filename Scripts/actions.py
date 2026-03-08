"""
FLARE - actions.py
------------------
Handles all output from the FLARE agent.

Current modes:
    1. Console  — structured, color-coded terminal output
    2. Popup    — Windows dialog box with alert details
    3. Log file — appends every alert to alerts.json

Confidence color coding:
    HIGH   → Red
    MEDIUM → Yellow
    LOW    → Cyan
"""

import json
import os
import sys
import ctypes
from datetime import datetime
from pathlib import Path

ALERTS_FILE = r"C:\FLARE-data\Logs\alerts.json"
BLACKLIST_FILE = r"C:\FLARE-data\Data\blacklist.json"

# ------------------------------------------------------------------ #
#  ANSI COLOR CODES — work in Windows Terminal / PowerShell 7        #
# ------------------------------------------------------------------ #

class Color:
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

def _confidence_color(confidence):
    return {
        "HIGH":   Color.RED,
        "MEDIUM": Color.YELLOW,
        "LOW":    Color.CYAN,
    }.get(confidence.upper(), Color.WHITE)


# ------------------------------------------------------------------ #
#  CONSOLE OUTPUT                                                      #
# ------------------------------------------------------------------ #

def print_alert(alert: dict):
    """
    Print a structured, color-coded alert to the console.
    """
    color  = _confidence_color(alert.get("confidence", "LOW"))
    border = "═" * 60

    print(f"\n{color}{Color.BOLD}{border}{Color.RESET}")
    print(f"{color}{Color.BOLD}  ⚠  FLARE ALERT — {alert.get('attack_type', 'Unknown')}{Color.RESET}")
    print(f"{color}{border}{Color.RESET}")

    print(f"{Color.GRAY}  Time       :{Color.RESET} {alert.get('timestamp', 'N/A')}")
    print(f"{Color.GRAY}  Stage      :{Color.RESET} {alert.get('stage', 'N/A')}")
    print(f"{Color.GRAY}  Confidence :{Color.RESET} {color}{alert.get('confidence', 'N/A')}{Color.RESET}")
    print(f"{Color.GRAY}  Description:{Color.RESET} {alert.get('description', 'N/A')}")

    if alert.get("source_ip"):
        print(f"{Color.GRAY}  Source IP  :{Color.RESET} {alert['source_ip']}")
    if alert.get("dest_ip"):
        print(f"{Color.GRAY}  Dest IP    :{Color.RESET} {alert['dest_ip']}")
    if alert.get("dest_port"):
        print(f"{Color.GRAY}  Dest Port  :{Color.RESET} {alert['dest_port']}")
    if alert.get("username"):
        print(f"{Color.GRAY}  User       :{Color.RESET} {alert['username']}")
    if alert.get("process"):
        print(f"{Color.GRAY}  Process    :{Color.RESET} {alert['process']}")

    if alert.get("recommended_action"):
        print(f"\n{Color.BOLD}  Recommended Action:{Color.RESET}")
        for line in alert["recommended_action"].splitlines():
            print(f"    {line}")

    print(f"{color}{border}{Color.RESET}\n")


# ------------------------------------------------------------------ #
#  WINDOWS POPUP DIALOG                                               #
# ------------------------------------------------------------------ #

def show_popup(alert: dict):
    """
    Show a native Windows MessageBox popup.
    Non-blocking — uses a separate thread so the agent loop continues.

    Icon mapping:
        HIGH   → MB_ICONERROR (red X)
        MEDIUM → MB_ICONWARNING (yellow !)
        LOW    → MB_ICONINFORMATION (blue i)
    """
    if sys.platform != "win32":
        return  # Skip silently on non-Windows

    import threading

    confidence = alert.get("confidence", "LOW").upper()
    icon_map = {
        "HIGH":   0x10,  # MB_ICONERROR
        "MEDIUM": 0x30,  # MB_ICONWARNING
        "LOW":    0x40,  # MB_ICONINFORMATION
    }
    icon = icon_map.get(confidence, 0x40)
    flags = icon | 0x1000  # MB_SYSTEMMODAL — appears on top

    title = f"FLARE — {alert.get('attack_type', 'Security Alert')} [{confidence}]"

    body_lines = [
        f"Stage:       {alert.get('stage', 'N/A')}",
        f"Time:        {alert.get('timestamp', 'N/A')}",
        f"Confidence:  {confidence}",
        "",
        f"{alert.get('description', '')}",
    ]

    if alert.get("source_ip"):
        body_lines.append(f"\nSource IP:   {alert['source_ip']}")
    if alert.get("dest_ip"):
        body_lines.append(f"Dest IP:     {alert['dest_ip']}")
    if alert.get("username"):
        body_lines.append(f"User:        {alert['username']}")
    if alert.get("process"):
        body_lines.append(f"Process:     {alert['process']}")

    if alert.get("recommended_action"):
        body_lines.append("\n── Recommended Action ──")
        body_lines.append(alert["recommended_action"])

    body = "\n".join(body_lines)

    def _show():
        ctypes.windll.user32.MessageBoxW(0, body, title, flags)

    thread = threading.Thread(target=_show, daemon=True)
    thread.start()


# ------------------------------------------------------------------ #
#  FILE LOGGING                                                        #
# ------------------------------------------------------------------ #

def log_alert(alert: dict, filepath=ALERTS_FILE):
    """
    Append alert to alerts.json.
    Creates the file and directory if they don't exist.
    """
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)

    existing = []
    try:
        if Path(filepath).exists():
            content = Path(filepath).read_text()
            if content.strip():
                existing = json.loads(content)
                if not isinstance(existing, list):
                    existing = [existing]
    except Exception:
        existing = []

    existing.append(alert)

    try:
        Path(filepath).write_text(
            json.dumps(existing, indent=2)
        )
    except Exception as e:
        print(f"{Color.RED}[FLARE] Failed to write alert log: {e}{Color.RESET}")


def update_blacklist_file(ip, reason, attack_type, filepath=BLACKLIST_FILE):
    """
    Maintain a human-readable blacklist JSON file
    separate from the SQLite DB — easy to review or
    feed into a firewall script later.
    """
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)

    existing = {}
    try:
        if Path(filepath).exists():
            content = Path(filepath).read_text()
            if content.strip():
                existing = json.loads(content)
    except Exception:
        existing = {}

    existing[ip] = {
        "reason":      reason,
        "attack_type": attack_type,
        "flagged_at":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "firewall_command": (
            f"netsh advfirewall firewall add rule "
            f"name=\"FLARE-BLOCK-{ip}\" "
            f"dir=in action=block remoteip={ip}"
        )
    }

    try:
        Path(filepath).write_text(json.dumps(existing, indent=2))
    except Exception as e:
        print(f"{Color.RED}[FLARE] Failed to write blacklist: {e}{Color.RESET}")


# ------------------------------------------------------------------ #
#  MAIN DISPATCH — called by agent.py                                 #
# ------------------------------------------------------------------ #

def fire(alert: dict, popup=True):
    """
    Main entry point. For every alert:
        1. Print to console (always)
        2. Log to alerts.json (always)
        3. Show popup (if popup=True and on Windows)
    """
    print_alert(alert)
    log_alert(alert)

    # Update blacklist file if IP was flagged
    if alert.get("source_ip") and alert.get("confidence") == "HIGH":
        update_blacklist_file(
            alert["source_ip"],
            alert["description"],
            alert["attack_type"]
        )

    if popup:
        show_popup(alert)


def fire_all(alerts: list, popup=True):
    """Fire all alerts from a rule check pass."""
    for alert in alerts:
        fire(alert, popup=popup)


# ------------------------------------------------------------------ #
#  STARTUP BANNER                                                      #
# ------------------------------------------------------------------ #

def print_banner():
    print(f"""
{Color.CYAN}{Color.BOLD}
  ███████╗██╗      █████╗ ██████╗ ███████╗
  ██╔════╝██║     ██╔══██╗██╔══██╗██╔════╝
  █████╗  ██║     ███████║██████╔╝█████╗
  ██╔══╝  ██║     ██╔══██║██╔══██╗██╔══╝
  ██║     ███████╗██║  ██║██║  ██║███████╗
  ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
{Color.RESET}
  {Color.WHITE}Fast Log Anomaly & Response Engine{Color.RESET}
  {Color.GRAY}Watching for threats across all 7 Kill Chain stages{Color.RESET}
  {Color.GRAY}Press Ctrl+C to stop{Color.RESET}
""")


def print_status(message: str, level="info"):
    """Lightweight status line for the agent loop."""
    color = {
        "info":    Color.GRAY,
        "ok":      Color.CYAN,
        "warning": Color.YELLOW,
        "error":   Color.RED,
    }.get(level, Color.GRAY)
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{Color.GRAY}[{ts}]{Color.RESET} {color}{message}{Color.RESET}")


# ------------------------------------------------------------------ #
#  SMOKE TEST                                                          #
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    import tempfile

    print("Running actions.py smoke test...\n")

    # Override output paths to temp for testing
    test_alerts = os.path.join(tempfile.gettempdir(), "flare_test_alerts.json")
    test_bl     = os.path.join(tempfile.gettempdir(), "flare_test_blacklist.json")

    print_banner()

    # Simulate a HIGH brute force alert
    alert_high = {
        "timestamp":          "2024-11-15 14:23:05",
        "stage":              "Stage 4 — Exploitation",
        "attack_type":        "Brute Force — SUCCEEDED",
        "confidence":         "HIGH",
        "description":        "185.220.101.45 made 12 failed attempts then succeeded as 'rehan'.",
        "source_ip":          "185.220.101.45",
        "username":           "rehan",
        "process":            None,
        "dest_ip":            "192.168.1.10",
        "dest_port":          None,
        "recommended_action": (
            "Block 185.220.101.45 immediately.\n"
            "  netsh advfirewall firewall add rule name=\"FLARE-BLOCK-185.220.101.45\" "
            "dir=in action=block remoteip=185.220.101.45\n"
            "  Reset password for 'rehan' immediately."
        ),
    }

    # Simulate a MEDIUM spray alert
    alert_medium = {
        "timestamp":          "2024-11-15 14:25:00",
        "stage":              "Stage 1 — Reconnaissance",
        "attack_type":        "Username Enumeration",
        "confidence":         "MEDIUM",
        "description":        "185.220.101.45 probed 4 distinct usernames in 10 minutes.",
        "source_ip":          "185.220.101.45",
        "username":           None,
        "process":            None,
        "dest_ip":            None,
        "dest_port":          None,
        "recommended_action": "Monitor IP. Block if brute force follows.",
    }

    print_status("Processing log batch...", "info")
    print_status("2 alerts detected.", "warning")

    # Print to console (no popup in test — would need Windows)
    print_alert(alert_high)
    print_alert(alert_medium)

    # Log to temp files
    log_alert(alert_high,   filepath=test_alerts)
    log_alert(alert_medium, filepath=test_alerts)
    update_blacklist_file("185.220.101.45", "Brute force succeeded", "Brute Force", filepath=test_bl)

    # Verify files written
    alerts_written = json.loads(Path(test_alerts).read_text())
    bl_written     = json.loads(Path(test_bl).read_text())

    print(f"\n[+] Alerts logged to file:    {len(alerts_written)} (expect 2)")
    print(f"[+] Blacklist entries:         {len(bl_written)} (expect 1)")
    print(f"[+] Blacklisted IP:            {list(bl_written.keys())[0]}")
    print(f"[+] Firewall command present:  {'firewall_command' in list(bl_written.values())[0]}")

    os.remove(test_alerts)
    os.remove(test_bl)

    print("\nSmoke test complete. actions.py is ready.")
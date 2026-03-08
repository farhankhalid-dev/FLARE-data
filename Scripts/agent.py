"""
FLARE - agent.py
----------------
Main agent loop. Wires together:
    collector output  (incoming.json)
    memory            (memory.py)
    rules             (rules.py)
    actions           (actions.py)

Run:
    python agent.py

Stop:
    Ctrl+C
"""

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from memory  import FlareMemory
from rules   import run_all_rules
from actions import fire_all, print_banner, print_status

# ------------------------------------------------------------------ #
#  CONFIG                                                              #
# ------------------------------------------------------------------ #

INCOMING_FILE   = r"C:\FLARE-data\Logs\incoming.json"
PROCESSED_FILE  = r"C:\FLARE-data\Data\processed_ids.json"
DB_PATH         = r"C:\FLARE-data\Data\memory.db"
POLL_INTERVAL   = 30    # seconds between each check
PURGE_INTERVAL  = 3600  # purge old DB records every 1 hour
POPUP_ENABLED   = True  # set False to disable Windows popups


# ------------------------------------------------------------------ #
#  LOG INGESTION                                                       #
# ------------------------------------------------------------------ #

def load_incoming(filepath=INCOMING_FILE):
    """
    Read incoming.json written by collector.ps1.
    Returns list of log dicts, or empty list if file missing/corrupt.
    """
    try:
        if not Path(filepath).exists():
            return []
        content = Path(filepath).read_text(encoding="utf-8").strip()
        if not content:
            return []
        data = json.loads(content)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []
    except Exception as e:
        print_status(f"Failed to read incoming.json: {e}", "error")
        return []


def load_processed_ids(filepath=PROCESSED_FILE):
    """
    Load set of already-processed log fingerprints
    so we never double-process the same log.
    """
    try:
        if not Path(filepath).exists():
            return set()
        content = Path(filepath).read_text(encoding="utf-8").strip()
        if not content:
            return set()
        return set(json.loads(content))
    except Exception:
        return set()


def save_processed_ids(ids: set, filepath=PROCESSED_FILE):
    """Persist processed IDs. Cap at 10,000 to prevent unbounded growth."""
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    capped = list(ids)[-10_000:]
    try:
        Path(filepath).write_text(json.dumps(capped))
    except Exception as e:
        print_status(f"Failed to save processed IDs: {e}", "error")


def make_log_id(log: dict):
    """
    Create a unique fingerprint for a log entry.
    Timestamp + EventID + User + DestIP is unique enough.
    """
    return "|".join([
        str(log.get("Timestamp", "")),
        str(log.get("EventID",   "")),
        str(log.get("User",      "")),
        str(log.get("DestIP",    "")),
        str(log.get("Source",    "")),
        str(log.get("Process",   "")),
    ])


def get_new_logs(all_logs, processed_ids):
    """Filter to only logs we haven't seen before."""
    new = []
    for log in all_logs:
        lid = make_log_id(log)
        if lid not in processed_ids:
            new.append(log)
    return new


# ------------------------------------------------------------------ #
#  LOG → MEMORY INGESTION                                             #
#  Feed each new log into the appropriate memory table               #
# ------------------------------------------------------------------ #

def ingest_log(log: dict, mem: FlareMemory):
    """
    Route each log to the correct memory.record_* method.
    This is what builds up the state that rules query against.
    """
    t    = log.get("Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    eid  = log.get("EventID")
    user = log.get("User", "N/A")
    src  = log.get("Source",  log.get("DestIP",  "N/A"))
    dst  = log.get("DestIP",  log.get("Source",  "N/A"))
    lt   = str(log.get("LogonType", "0"))

    if log.get("Type") == "System":
        if eid == 4625:
            # Failed logon
            mem.record_failed_logon(t, src, dst, user, lt, eid)

        elif eid == 4624:
            # Successful logon
            mem.record_successful_logon(t, src, dst, user, lt)

        elif eid == 4688:
            # Process created
            process = log.get("Process", "N/A")
            mem.record_process(t, user, process, dst)

        elif eid == 4672:
            # Special privileges assigned
            mem.record_privilege_event(t, user, dst)

        elif eid == 4720:
            # New account created
            mem.record_account_creation(t, user, dst)

    elif log.get("Type") == "Network":
        src  = log.get("Source",  "N/A")
        dst  = log.get("DestIP",  "N/A")
        port = log.get("DestPort", 0)
        mem.record_network(t, src, dst, port)


# ------------------------------------------------------------------ #
#  MAIN AGENT LOOP                                                     #
# ------------------------------------------------------------------ #

def run_agent():
    print_banner()
    print_status("Initializing FLARE agent...", "info")

    # Ensure dirs exist
    Path(INCOMING_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(PROCESSED_FILE).parent.mkdir(parents=True, exist_ok=True)

    mem           = FlareMemory(db_path=DB_PATH)
    processed_ids = load_processed_ids()
    last_purge    = time.time()
    cycle         = 0

    print_status(f"Agent started. Polling every {POLL_INTERVAL}s.", "ok")
    print_status(f"Watching: {INCOMING_FILE}", "info")
    print_status(f"Popups:   {'enabled' if POPUP_ENABLED else 'disabled'}", "info")
    print()

    try:
        while True:
            cycle += 1
            print_status(f"Cycle #{cycle} — checking for new logs...", "info")

            # 1. Load and filter new logs
            all_logs = load_incoming()
            new_logs = get_new_logs(all_logs, processed_ids)

            if not new_logs:
                print_status("No new logs.", "info")
            else:
                print_status(f"{len(new_logs)} new log(s) found.", "ok")

                # 2. Ingest into memory
                for log in new_logs:
                    ingest_log(log, mem)

                # 3. Mark as processed
                for log in new_logs:
                    processed_ids.add(make_log_id(log))
                save_processed_ids(processed_ids)

                # 4. Run all rules against the new batch
                alerts = run_all_rules(new_logs, mem)

                # 5. Fire alerts
                if alerts:
                    print_status(
                        f"{len(alerts)} alert(s) detected!", "warning"
                    )
                    fire_all(alerts, popup=POPUP_ENABLED)
                else:
                    print_status("No threats detected in this batch.", "info")

            # 6. Periodic DB purge
            if time.time() - last_purge > PURGE_INTERVAL:
                mem.purge_old_records(older_than_hours=24)
                print_status("Memory purge complete.", "info")
                last_purge = time.time()

            # 7. Sleep until next cycle
            print_status(f"Next check in {POLL_INTERVAL}s...", "info")
            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print()
        print_status("Agent stopped by user.", "info")
        mem.close()
        sys.exit(0)

    except Exception as e:
        print_status(f"Unhandled error: {e}", "error")
        mem.close()
        raise


# ------------------------------------------------------------------ #
#  ENTRY POINT                                                         #
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    # Allow overriding popup flag from command line
    # Usage: python agent.py --no-popup
    if "--no-popup" in sys.argv:
        POPUP_ENABLED = False

    run_agent()
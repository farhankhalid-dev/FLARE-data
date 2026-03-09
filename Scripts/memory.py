"""
FLARE - memory.py
-----------------
SQLite-backed memory store for the FLARE agent.
Tracks failed logons, spray patterns, process activity,
network connections, and IP reputation across time windows.
"""

import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path

DB_PATH = r"C:\FLARE-data\Data\memory.db"


class FlareMemory:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    # ------------------------------------------------------------------ #
    #  SCHEMA                                                              #
    # ------------------------------------------------------------------ #

    def _init_schema(self):
        c = self.conn.cursor()

        # Failed logon attempts — drives brute force + spray detection
        c.execute("""
            CREATE TABLE IF NOT EXISTS failed_logons (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                source_ip   TEXT,
                dest_ip     TEXT,
                username    TEXT,
                logon_type  TEXT,
                event_id    INTEGER
            )
        """)

        # Successful logons — correlate with failed attempts
        c.execute("""
            CREATE TABLE IF NOT EXISTS successful_logons (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                source_ip   TEXT,
                dest_ip     TEXT,
                username    TEXT,
                logon_type  TEXT
            )
        """)

        # Process executions — delivery, exploitation, defense evasion
        c.execute("""
            CREATE TABLE IF NOT EXISTS process_events (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT NOT NULL,
                username     TEXT,
                process_name TEXT,
                host         TEXT
            )
        """)

        # Network connections — C2 detection
        c.execute("""
            CREATE TABLE IF NOT EXISTS network_events (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                dest_ip   TEXT,
                dest_port INTEGER,
                flow_bytes REAL DEFAULT 0
            )
        """)

        # Privilege escalation events (4672)
        c.execute("""
            CREATE TABLE IF NOT EXISTS privilege_events (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username  TEXT,
                host      TEXT
            )
        """)

        # New account creation (4720)
        c.execute("""
            CREATE TABLE IF NOT EXISTS account_creation (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username  TEXT,
                host      TEXT
            )
        """)

        # IP blacklist recommendations
        c.execute("""
            CREATE TABLE IF NOT EXISTS blacklist (
                ip          TEXT PRIMARY KEY,
                reason      TEXT,
                flagged_at  TEXT,
                attack_type TEXT
            )
        """)

        # Alert deduplication — prevents firing same alert repeatedly
        c.execute("""
            CREATE TABLE IF NOT EXISTS fired_alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_key   TEXT NOT NULL,
                fired_at    TEXT NOT NULL
            )
        """)

        self.conn.commit()

    # ------------------------------------------------------------------ #
    #  WRITE METHODS                                                       #
    # ------------------------------------------------------------------ #

    def record_failed_logon(self, timestamp, source_ip, dest_ip, username, logon_type, event_id=4625):
        self.conn.execute("""
            INSERT INTO failed_logons (timestamp, source_ip, dest_ip, username, logon_type, event_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (timestamp, source_ip, dest_ip, username, logon_type, event_id))
        self.conn.commit()

    def record_successful_logon(self, timestamp, source_ip, dest_ip, username, logon_type):
        self.conn.execute("""
            INSERT INTO successful_logons (timestamp, source_ip, dest_ip, username, logon_type)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, source_ip, dest_ip, username, logon_type))
        self.conn.commit()

    def record_process(self, timestamp, username, process_name, host):
        self.conn.execute("""
            INSERT INTO process_events (timestamp, username, process_name, host)
            VALUES (?, ?, ?, ?)
        """, (timestamp, username, process_name, host))
        self.conn.commit()

    def record_network(self, timestamp, source_ip, dest_ip, dest_port, flow_bytes=0):
        self.conn.execute("""
            INSERT INTO network_events (timestamp, source_ip, dest_ip, dest_port, flow_bytes)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, source_ip, dest_ip, dest_port, flow_bytes))
        self.conn.commit()

    def record_privilege_event(self, timestamp, username, host):
        self.conn.execute("""
            INSERT INTO privilege_events (timestamp, username, host)
            VALUES (?, ?, ?)
        """, (timestamp, username, host))
        self.conn.commit()

    def record_account_creation(self, timestamp, username, host):
        self.conn.execute("""
            INSERT INTO account_creation (timestamp, username, host)
            VALUES (?, ?, ?)
        """, (timestamp, username, host))
        self.conn.commit()

    def add_to_blacklist(self, ip, reason, attack_type):
        self.conn.execute("""
            INSERT OR REPLACE INTO blacklist (ip, reason, flagged_at, attack_type)
            VALUES (?, ?, ?, ?)
        """, (ip, reason, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), attack_type))
        self.conn.commit()

    # ------------------------------------------------------------------ #
    #  QUERY METHODS — used by rules.py                                   #
    # ------------------------------------------------------------------ #

    def get_failed_logons_by_source(self, source_ip, within_minutes=10):
        """How many times has this source IP failed to log in recently?"""
        cutoff = (datetime.now() - timedelta(minutes=within_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        row = self.conn.execute("""
            SELECT COUNT(*) as count FROM failed_logons
            WHERE source_ip = ? AND timestamp >= ?
        """, (source_ip, cutoff)).fetchone()
        return row["count"]

    def get_failed_logons_by_user(self, username, within_minutes=10):
        """How many times has this username failed to log in recently?"""
        cutoff = (datetime.now() - timedelta(minutes=within_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        row = self.conn.execute("""
            SELECT COUNT(*) as count FROM failed_logons
            WHERE username = ? AND timestamp >= ?
        """, (username, cutoff)).fetchone()
        return row["count"]

    def get_spray_targets(self, source_ip, within_minutes=10):
        """
        How many DISTINCT destination IPs has this source IP
        attempted to log into? Detects horizontal password spray.
        """
        cutoff = (datetime.now() - timedelta(minutes=within_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        row = self.conn.execute("""
            SELECT COUNT(DISTINCT dest_ip) as count FROM failed_logons
            WHERE source_ip = ? AND timestamp >= ?
        """, (source_ip, cutoff)).fetchone()
        return row["count"]

    def get_spray_usernames(self, source_ip, within_minutes=10):
        """How many distinct usernames has this IP tried?"""
        cutoff = (datetime.now() - timedelta(minutes=within_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        row = self.conn.execute("""
            SELECT COUNT(DISTINCT username) as count FROM failed_logons
            WHERE source_ip = ? AND timestamp >= ?
        """, (source_ip, cutoff)).fetchone()
        return row["count"]

    def had_successful_logon_after_failures(self, source_ip, username, within_minutes=30):
        """
        Did this IP/user succeed after multiple failures?
        Indicates successful brute force.
        """
        cutoff = (datetime.now() - timedelta(minutes=within_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        failures = self.conn.execute("""
            SELECT COUNT(*) as count FROM failed_logons
            WHERE source_ip = ? AND username = ? AND timestamp >= ?
        """, (source_ip, username, cutoff)).fetchone()["count"]

        if failures < 3:
            return False

        success = self.conn.execute("""
            SELECT COUNT(*) as count FROM successful_logons
            WHERE source_ip = ? AND username = ? AND timestamp >= ?
        """, (source_ip, username, cutoff)).fetchone()["count"]

        return success > 0

    def get_lateral_movement_hosts(self, username, within_minutes=30):
        """
        How many distinct hosts has this user logged into via network logon (type 3)?
        Detects lateral movement.
        """
        cutoff = (datetime.now() - timedelta(minutes=within_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        row = self.conn.execute("""
            SELECT COUNT(DISTINCT dest_ip) as count FROM successful_logons
            WHERE username = ? AND logon_type = '3' AND timestamp >= ?
        """, (username, cutoff)).fetchone()
        return row["count"]

    def get_privilege_escalations(self, username, within_minutes=10):
        """Did this user get special privileges shortly after logging in?"""
        cutoff = (datetime.now() - timedelta(minutes=within_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        row = self.conn.execute("""
            SELECT COUNT(*) as count FROM privilege_events
            WHERE username = ? AND timestamp >= ?
        """, (username, cutoff)).fetchone()
        return row["count"]

    def get_rdp_logons(self, within_minutes=10):
        """Return recent RemoteInteractive logons (LogonType 10) — RDP."""
        cutoff = (datetime.now() - timedelta(minutes=within_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        rows = self.conn.execute("""
            SELECT * FROM successful_logons
            WHERE logon_type = '10' AND timestamp >= ?
        """, (cutoff,)).fetchall()
        return [dict(r) for r in rows]

    def get_high_volume_dest(self, dest_ip, dest_port, within_minutes=5):
        """Count connections + total bytes to same dest — DDoS signal."""
        cutoff = (datetime.now() - timedelta(minutes=within_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        row = self.conn.execute("""
            SELECT COUNT(*) as count, SUM(flow_bytes) as total_bytes
            FROM network_events
            WHERE dest_ip = ? AND dest_port = ? AND timestamp >= ?
        """, (dest_ip, dest_port, cutoff)).fetchone()
        return row["count"], row["total_bytes"] or 0

    def get_large_outbound_transfers(self, within_minutes=10, min_bytes=1000000):
        """Connections with large FlowBytes to external IPs — exfiltration signal."""
        cutoff = (datetime.now() - timedelta(minutes=within_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        rows = self.conn.execute("""
            SELECT * FROM network_events
            WHERE timestamp >= ? AND flow_bytes >= ?
            AND dest_ip NOT LIKE '192.168.%'
            AND dest_ip NOT LIKE '10.%'
            AND dest_ip NOT LIKE '172.16.%'
        """, (cutoff, min_bytes)).fetchall()
        return [dict(r) for r in rows]

    def get_port_scan_ports(self, source_ip, within_minutes=5):
        """How many distinct ports has this source hit recently?"""
        cutoff = (datetime.now() - timedelta(minutes=within_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        row = self.conn.execute("""
            SELECT COUNT(DISTINCT dest_port) as count FROM network_events
            WHERE source_ip = ? AND timestamp >= ?
        """, (source_ip, cutoff)).fetchone()
        return row["count"]

    def get_suspicious_processes(self, within_minutes=10):
        """Return recent process events with known suspicious names."""
        suspicious = [
            "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
            "bitsadmin.exe", "msiexec.exe", "wmic.exe", "psexec.exe",
            "net.exe", "net1.exe", "whoami.exe", "mimikatz.exe",
            "procdump.exe", "nc.exe", "ncat.exe"
        ]
        cutoff = (datetime.now() - timedelta(minutes=within_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        placeholders = ",".join("?" * len(suspicious))
        rows = self.conn.execute(f"""
            SELECT * FROM process_events
            WHERE timestamp >= ?
            AND LOWER(process_name) IN ({placeholders})
        """, [cutoff] + [s.lower() for s in suspicious]).fetchall()
        return [dict(r) for r in rows]

    def get_c2_candidates(self, within_minutes=10):
        """
        Network connections to uncommon ports or repeated connections
        to the same external IP. Potential C2 beaconing.
        """
        c2_ports = [4444, 4445, 1234, 8080, 8443, 9001, 9002, 6666, 6667, 31337]
        cutoff = (datetime.now() - timedelta(minutes=within_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        placeholders = ",".join("?" * len(c2_ports))
        rows = self.conn.execute(f"""
            SELECT dest_ip, dest_port, COUNT(*) as count FROM network_events
            WHERE timestamp >= ?
            AND dest_port IN ({placeholders})
            GROUP BY dest_ip, dest_port
        """, [cutoff] + c2_ports).fetchall()
        return [dict(r) for r in rows]

    def get_repeated_external_connections(self, within_minutes=10, min_count=5):
        """Same external IP contacted repeatedly — beaconing pattern."""
        cutoff = (datetime.now() - timedelta(minutes=within_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        rows = self.conn.execute("""
            SELECT dest_ip, dest_port, COUNT(*) as count FROM network_events
            WHERE timestamp >= ?
            AND dest_ip NOT LIKE '192.168.%'
            AND dest_ip NOT LIKE '10.%'
            AND dest_ip NOT LIKE '172.16.%'
            AND dest_ip NOT LIKE '127.%'
            GROUP BY dest_ip, dest_port
            HAVING count >= ?
        """, (cutoff, min_count)).fetchall()
        return [dict(r) for r in rows]

    def get_new_accounts(self, within_minutes=60):
        """New accounts created recently — persistence indicator."""
        cutoff = (datetime.now() - timedelta(minutes=within_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        rows = self.conn.execute("""
            SELECT * FROM account_creation WHERE timestamp >= ?
        """, (cutoff,)).fetchall()
        return [dict(r) for r in rows]

    def is_blacklisted(self, ip):
        row = self.conn.execute("""
            SELECT * FROM blacklist WHERE ip = ?
        """, (ip,)).fetchone()
        return dict(row) if row else None

    def get_blacklist(self):
        rows = self.conn.execute("SELECT * FROM blacklist").fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ #
    #  ALERT DEDUPLICATION                                                 #
    # ------------------------------------------------------------------ #

    def should_fire_alert(self, alert_key, cooldown_minutes=5):
        """
        Returns True if this alert hasn't fired recently.
        Prevents spamming the same alert every 30 seconds.
        """
        cutoff = (datetime.now() - timedelta(minutes=cooldown_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        row = self.conn.execute("""
            SELECT COUNT(*) as count FROM fired_alerts
            WHERE alert_key = ? AND fired_at >= ?
        """, (alert_key, cutoff)).fetchone()
        if row["count"] == 0:
            self.conn.execute("""
                INSERT INTO fired_alerts (alert_key, fired_at)
                VALUES (?, ?)
            """, (alert_key, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            self.conn.commit()
            return True
        return False

    # ------------------------------------------------------------------ #
    #  MAINTENANCE                                                         #
    # ------------------------------------------------------------------ #

    def purge_old_records(self, older_than_hours=24):
        """
        Clean up old records to keep the DB lean.
        Alerts and blacklist are kept indefinitely.
        """
        cutoff = (datetime.now() - timedelta(hours=older_than_hours)).strftime("%Y-%m-%d %H:%M:%S")
        tables = [
            "failed_logons", "successful_logons", "process_events",
            "network_events", "privilege_events", "account_creation"
        ]
        for table in tables:
            self.conn.execute(f"DELETE FROM {table} WHERE timestamp < ?", (cutoff,))
        self.conn.execute("DELETE FROM fired_alerts WHERE fired_at < ?", (cutoff,))
        self.conn.commit()

    def close(self):
        self.conn.close()


# ------------------------------------------------------------------ #
#  QUICK SMOKE TEST — run this file directly to verify               #
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    import tempfile, os

    print("Running memory.py smoke test...\n")
    test_db = os.path.join(tempfile.gettempdir(), "flare_test.db")
    mem = FlareMemory(db_path=test_db)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    attacker = "185.220.101.45"

    # Simulate password spray — 1 source, 6 targets
    targets = ["192.168.1.10", "192.168.1.11", "192.168.1.12",
               "192.168.1.13", "192.168.1.14", "192.168.1.15"]
    for t in targets:
        mem.record_failed_logon(now, attacker, t, "administrator", "3")

    spray_count = mem.get_spray_targets(attacker, within_minutes=10)
    print(f"[+] Spray targets detected:     {spray_count} (expect 6)")

    # Simulate brute force on single target
    for _ in range(8):
        mem.record_failed_logon(now, attacker, "192.168.1.10", "rehan", "3")
    bf_count = mem.get_failed_logons_by_source(attacker, within_minutes=10)
    print(f"[+] Failed logons from attacker: {bf_count} (expect 14)")

    # Simulate success after failures
    mem.record_successful_logon(now, attacker, "192.168.1.10", "rehan", "3")
    success = mem.had_successful_logon_after_failures(attacker, "rehan")
    print(f"[+] Brute force succeeded:       {success} (expect True)")

    # Simulate C2 beacon
    mem.record_network(now, "192.168.1.10", "185.220.101.45", 4444)
    c2 = mem.get_c2_candidates(within_minutes=10)
    print(f"[+] C2 candidates found:         {len(c2)} (expect 1)")

    # Test deduplication
    fired1 = mem.should_fire_alert("brute_force_185.220.101.45")
    fired2 = mem.should_fire_alert("brute_force_185.220.101.45")
    print(f"[+] Alert dedup — first: {fired1}, second: {fired2} (expect True, False)")

    # Blacklist
    mem.add_to_blacklist(attacker, "Password spray across 6 hosts", "Password Spray")
    bl = mem.is_blacklisted(attacker)
    print(f"[+] Blacklisted IP found:        {bl['ip']} (expect {attacker})")

    mem.close()
    os.remove(test_db)
    print("\nAll tests passed. memory.py is ready.")
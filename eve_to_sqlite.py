#!/usr/bin/env python3
"""Load Suricata EVE JSON alert events into SQLite and run summary queries.

Usage:
    python3 eve_to_sqlite.py lan_eve.json lan2_eve.json [--db alerts.db]
"""
import argparse
import json
import sqlite3

SCHEMA = """
CREATE TABLE alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT,
    iface      TEXT,
    src_ip     TEXT,
    src_port   INTEGER,
    dest_ip    TEXT,
    dest_port  INTEGER,
    proto      TEXT,
    signature  TEXT,
    sid        INTEGER,
    category   TEXT,
    severity   INTEGER,
    action     TEXT
)
"""

QUERIES = [
    ("Top source IPs",
     "SELECT src_ip, COUNT(*) AS alerts FROM alerts "
     "GROUP BY src_ip ORDER BY alerts DESC LIMIT 5"),
    ("Top signatures",
     "SELECT signature, sid, COUNT(*) AS alerts FROM alerts "
     "GROUP BY signature, sid ORDER BY alerts DESC LIMIT 10"),
    ("Alerts by interface and target",
     "SELECT iface, dest_ip, COUNT(*) AS alerts FROM alerts "
     "GROUP BY iface, dest_ip ORDER BY alerts DESC"),
    ("Alerts per hour",
     "SELECT substr(timestamp, 1, 13) AS hour, COUNT(*) AS alerts FROM alerts "
     "GROUP BY hour ORDER BY hour"),
    ("Alerts per interface (which instance saw them)",
     "SELECT iface, COUNT(*) AS alerts FROM alerts "
     "GROUP BY iface ORDER BY alerts DESC"),
    ("Most targeted destination ports",
     "SELECT dest_port, COUNT(*) AS alerts FROM alerts "
     "GROUP BY dest_port ORDER BY alerts DESC LIMIT 5"),
]


def load_alerts(eve_path, conn):
    """Insert every alert event from the EVE file. Returns (loaded, skipped)."""
    loaded = skipped = 0
    with open(eve_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            if event.get("event_type") != "alert":
                continue
            alert = event.get("alert", {})
            conn.execute(
                "INSERT INTO alerts (timestamp, iface, src_ip, src_port, dest_ip, "
                "dest_port, proto, signature, sid, category, severity, action) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event.get("timestamp"),
                    event.get("in_iface"),
                    event.get("src_ip"),
                    event.get("src_port"),
                    event.get("dest_ip"),
                    event.get("dest_port"),
                    event.get("proto"),
                    alert.get("signature"),
                    alert.get("signature_id"),
                    alert.get("category"),
                    alert.get("severity"),
                    alert.get("action"),
                ),
            )
            loaded += 1
    conn.commit()
    return loaded, skipped


def print_query(conn, title, sql):
    cur = conn.execute(sql)
    headers = [d[0] for d in cur.description]
    rows = cur.fetchall()
    widths = [
        max(len(str(h)), *(len(str(r[i])) for r in rows)) if rows else len(str(h))
        for i, h in enumerate(headers)
    ]
    print(f"\n== {title} ==")
    print("  ".join(str(h).ljust(w) for h, w in zip(headers, widths)))
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print("  ".join(str(v).ljust(w) for v, w in zip(r, widths)))


def main():
    parser = argparse.ArgumentParser(
        description="Load Suricata EVE JSON alerts into SQLite and summarize them.")
    parser.add_argument("eve_files", nargs="+",
                        help="one or more eve.json files (for example LAN and LAN2)")
    parser.add_argument("--db", default="alerts.db", help="output database (default: alerts.db)")
    args = parser.parse_args()

    conn = sqlite3.connect(args.db)
    conn.execute("DROP TABLE IF EXISTS alerts")  # rebuild so reruns never duplicate rows
    conn.execute(SCHEMA)

    for eve_path in args.eve_files:
        loaded, skipped = load_alerts(eve_path, conn)
        print(f"{eve_path}: loaded {loaded} alerts ({skipped} malformed lines skipped)")
    print(f"Database written to {args.db}")

    for title, sql in QUERIES:
        print_query(conn, title, sql)
    conn.close()


if __name__ == "__main__":
    main()

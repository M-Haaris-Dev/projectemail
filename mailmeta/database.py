"""SQLite persistence for analyzed emails."""

import json
import os
import sqlite3
import threading
import time


SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account TEXT NOT NULL DEFAULT '',
    uid TEXT,
    message_id TEXT,
    subject TEXT,
    from_addr TEXT,
    from_name TEXT,
    reply_to TEXT,
    envelope_from TEXT,
    ip_address TEXT,
    from_domain TEXT,
    risk_score INTEGER DEFAULT 0,
    risk_level TEXT DEFAULT 'unknown',
    spf_status TEXT DEFAULT 'unknown',
    dkim_status TEXT DEFAULT 'unknown',
    dmarc_status TEXT DEFAULT 'unknown',
    date_ts INTEGER DEFAULT 0,
    analyzed_at INTEGER DEFAULT 0,
    size INTEGER DEFAULT 0,
    raw BLOB,
    data TEXT,
    geo TEXT,
    UNIQUE(account, uid)
);
CREATE INDEX IF NOT EXISTS idx_risk_level ON messages(risk_level);
CREATE INDEX IF NOT EXISTS idx_date_ts ON messages(date_ts);
CREATE INDEX IF NOT EXISTS idx_from_domain ON messages(from_domain);
"""


class Database:
    def __init__(self, path="mailmeta.db"):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True) if os.path.dirname(path) else None
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self._migrate()

    def close(self):
        with self._lock:
            self.conn.close()

    def delete_account_messages(self, account: str) -> int:
        """Delete all messages for an account (used for rescan)."""
        with self._lock:
            cur = self.conn.execute("DELETE FROM messages WHERE account=?", (account,))
            self.conn.commit()
        return cur.rowcount

    def _migrate(self):
        """Add missing columns for older databases."""
        with self._lock:
            cols = {r[1] for r in self.conn.execute("PRAGMA table_info(messages)").fetchall()}
            if "geo" not in cols:
                self.conn.execute("ALTER TABLE messages ADD COLUMN geo TEXT")
            self.conn.commit()

    def touched_uids(self, account: str) -> set:
        """Set of already-analyzed UIDs for an account."""
        with self._lock:
            rows = self.conn.execute("SELECT uid FROM messages WHERE account=?", (account,)).fetchall()
        return {str(r["uid"]) for r in rows}

    def upsert_message(self, account: str, uid, meta, raw: bytes) -> int:
        """Insert or replace an analyzed message. Returns row id."""
        from_domain = ""
        if meta.from_addr and "@" in meta.from_addr:
            from_domain = meta.from_addr.split("@")[-1]

        data = json.dumps(meta.to_dict())
        geo = json.dumps(meta.geo) if meta.geo else None
        with self._lock:
            row = self.conn.execute(
                """SELECT id FROM messages WHERE account=? AND uid=?""",
                (account, str(uid)),
            ).fetchone()
            ts = int(time.time())
            if row:
                self.conn.execute(
                    """UPDATE messages SET message_id=?, subject=?, from_addr=?, from_name=?,
                       reply_to=?, envelope_from=?, ip_address=?, from_domain=?, risk_score=?,
                       risk_level=?, spf_status=?, dkim_status=?, dmarc_status=?, date_ts=?,
                       analyzed_at=?, size=?, raw=?, data=?, geo=? WHERE id=?""",
                    (meta.message_id, meta.subject, meta.from_addr, meta.from_name,
                     meta.reply_to, meta.envelope_from, meta.ip_address, from_domain,
                     meta.risk_score, meta.risk_level, meta.spf.get("status", ""),
                     meta.dkim.get("status", ""), meta.dmarc.get("status", ""),
                     meta.date_ts, ts, len(raw), raw, data, geo, row["id"]),
                )
                row_id = row["id"]
            else:
                cur = self.conn.execute(
                    """INSERT INTO messages (account, uid, message_id, subject, from_addr, from_name,
                       reply_to, envelope_from, ip_address, from_domain, risk_score, risk_level,
                       spf_status, dkim_status, dmarc_status, date_ts, analyzed_at, size, raw, data, geo)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (account, str(uid), meta.message_id, meta.subject, meta.from_addr, meta.from_name,
                     meta.reply_to, meta.envelope_from, meta.ip_address, from_domain,
                     meta.risk_score, meta.risk_level, meta.spf.get("status", ""),
                     meta.dkim.get("status", ""), meta.dmarc.get("status", ""),
                     meta.date_ts, ts, len(raw), raw, data, geo),
                )
                row_id = cur.lastrowid
            self.conn.commit()
        return row_id

    def list_messages(self, limit=50, offset=0, risk_level=None, search=None, account=None, sort="date_ts"):
        """Paginated message listing."""
        sql = "SELECT id, account, uid, message_id, subject, from_addr, from_name, reply_to, envelope_from, ip_address, from_domain, risk_score, risk_level, spf_status, dkim_status, dmarc_status, date_ts, analyzed_at, size, geo FROM messages WHERE 1=1"
        params = []
        if risk_level and risk_level != "all":
            sql += " AND risk_level=?"
            params.append(risk_level)
        if account:
            sql += " AND account=?"
            params.append(account)
        if search:
            sql += " AND (subject LIKE ? OR from_addr LIKE ? OR from_name LIKE ? OR from_domain LIKE ?)"
            like = f"%{search}%"
            params += [like, like, like, like]

        valid_sorts = {"date_ts", "risk_score", "analyzed_at"}
        direction = "DESC"
        col = sort
        if sort.startswith("-"):
            col = sort[1:]
            direction = "ASC"
        if col not in valid_sorts:
            col = "date_ts"
            direction = "DESC"
        sql += f" ORDER BY {col} {direction} LIMIT ? OFFSET ?"
        params += [limit, offset]

        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
            count = self.count_messages(risk_level, search, account)
        out = []
        for r in rows:
            d = dict(r)
            if d.get("geo"):
                try:
                    d["geo"] = json.loads(d["geo"])
                except Exception:
                    d["geo"] = None
            out.append(d)
        return {"rows": out, "total": count}

    def count_messages(self, risk_level=None, search=None, account=None) -> int:
        sql = "SELECT COUNT(*) AS c FROM messages WHERE 1=1"
        params = []
        if risk_level and risk_level != "all":
            sql += " AND risk_level=?"
            params.append(risk_level)
        if account:
            sql += " AND account=?"
            params.append(account)
        if search:
            sql += " AND (subject LIKE ? OR from_addr LIKE ? OR from_name LIKE ? OR from_domain LIKE ?)"
            like = f"%{search}%"
            params += [like, like, like, like]
        row = self.conn.execute(sql, params).fetchone()
        return int(row["c"])

    def get_message(self, msg_id: int) -> dict | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["data"] = json.loads(row["data"]) if row["data"] else {}
        d["raw"] = row["raw"]
        return d

    def get_raw(self, msg_id: int) -> bytes | None:
        with self._lock:
            row = self.conn.execute("SELECT raw FROM messages WHERE id=?", (msg_id,)).fetchone()
        return row["raw"] if row else None

    def stats(self) -> dict:
        with self._lock:
            total = self.conn.execute("SELECT COUNT(*) c FROM messages").fetchone()["c"]
            by_level = {}
            for r in self.conn.execute("SELECT risk_level, COUNT(*) c FROM messages GROUP BY risk_level").fetchall():
                by_level[r["risk_level"]] = int(r["c"])
            by_account = {}
            for r in self.conn.execute("SELECT account, COUNT(*) c FROM messages GROUP BY account").fetchall():
                by_account[r["account"]] = int(r["c"])
            high = self.conn.execute("SELECT COUNT(*) c FROM messages WHERE risk_level='high'").fetchone()["c"]
            safe = self.conn.execute("SELECT COUNT(*) c FROM messages WHERE risk_level='safe'").fetchone()["c"]
        return {
            "total": int(total),
            "high": int(high),
            "safe": int(safe),
            "by_level": by_level,
            "by_account": by_account,
        }

    def delete_message(self, msg_id: int) -> bool:
        with self._lock:
            cur = self.conn.execute("DELETE FROM messages WHERE id=?", (msg_id,))
            self.conn.commit()
        return cur.rowcount > 0
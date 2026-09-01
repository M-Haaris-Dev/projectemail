"""IMAP-based email monitoring. Polls a mailbox, analyzes new messages, stores results."""

import email
import imaplib
import logging
import ssl
import threading
import time
from email.utils import parsedate_to_datetime

from .pipeline import analyze
from .database import Database

log = logging.getLogger("mailmeta.imap")


class IMAPMonitor:
    """Monitors one IMAP mailbox for new messages.

    Poll loop: connect -> select INBOX -> search for unseen/new UIDs -> analyze
    each -> store in DB -> backoff on errors -> repeat.
    """

    def __init__(self, config: dict, database: Database, stop_event: threading.Event):
        self.config = config
        self.db = database
        self.stop_event = stop_event
        self.thread = None
        self.status = "idle"
        self._lock = threading.Lock()
        self.rescan = config.get("rescan", False)

    # ---------- lifecycle ----------
    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.thread = threading.Thread(target=self._run, name=f"imap-{self.config.get('account','?')}", daemon=True)
        self.thread.start()
        log.info("monitor started for %s", self.account)

    def stop(self):
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)

    @property
    def account(self):
        return self.config.get("account", self.config.get("username", ""))

    def _set_status(self, s):
        with self._lock:
            self.status = s
            log.info("[%s] status -> %s", self.account, s)

    # ---------- main loop ----------
    def _run(self):
        backoff = 1
        while not self.stop_event.is_set():
            try:
                self._poll_once()
                backoff = 1
            except imaplib.IMAP4.error as e:
                self._set_status(f"error: {e}")
                time.sleep(min(backoff, 60))
                backoff *= 2
            except (ssl.SSLError, OSError, ConnectionError) as e:
                self._set_status(f"connection error: {e}")
                time.sleep(min(backoff, 60))
                backoff *= 2
            except Exception as e:
                log.exception("unexpected monitor error")
                self._set_status(f"error: {e}")
                time.sleep(min(backoff, 60))
                backoff *= 2

            # sleep until next poll or stop
            if self.stop_event.wait(timeout=self.config.get("poll_interval", 30)):
                break
        self._set_status("stopped")

    def _poll_once(self):
        self._set_status("connecting")
        conn = self._connect()
        try:
            self._set_status("connected")
            status, _ = conn.select(self.config.get("folder", "INBOX"))
            if status != "OK":
                raise imaplib.IMAP4.error(f"SELECT failed: {status}")

            if self.rescan:
                # clear history so every message is treated as new this run
                self.db.delete_account_messages(self.account)
                self.rescan = False

            touched = self.db.touched_uids(self.account)

            only_new = self.config.get("only_new", True)
            typ, data = conn.uid("search", None, "ALL")
            if typ != "OK":
                raise imaplib.IMAP4.error("SEARCH failed")
            uids = data[0].split() if data and data[0] else []
            uids = [u.decode() if isinstance(u, bytes) else u for u in uids]

            if only_new:
                newly = [u for u in uids if u not in touched]
            else:
                newly = uids
            total = len(newly)
            analyzed = 0

            self._set_status(f"polling {total} new messages")
            for i, uid in enumerate(newly):
                if self.stop_event.is_set():
                    break
                try:
                    self._process(conn, uid)
                    analyzed += 1
                except Exception as e:
                    log.exception("failed to process uid %s", uid)
            self._set_status(f"idle (processed {analyzed}/{total})")
        finally:
            try:
                conn.logout()
            except Exception:
                pass

    def _process(self, conn, uid: str):
        """Fetch, analyze, and store a single message."""
        typ, data = conn.uid("fetch", uid, "(RFC822)")
        if typ != "OK" or not data or not data[0]:
            log.warning("fetch failed for uid %s", uid)
            return
        raw = data[0][1]  # bytes RFC822 body
        meta = analyze(raw)
        self.db.upsert_message(self.account, uid, meta, raw)
        log.info("analyzed uid=%s risk=%s from=<%s> subject=%r",
                 uid, meta.risk_level, meta.from_addr, meta.subject[:60])

    # ---------- connection ----------
    def _connect(self) -> imaplib.IMAP4_SSL:
        host = self.config.get("host")
        port = self.config.get("port", 993)
        username = self.config.get("username")
        password = self.config.get("password")

        if not all([host, username, password]):
            raise ValueError(f"incomplete IMAP config for account {self.account}: need host/username/password")

        ctx = ssl.create_default_context()
        conn = imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
        conn.login(username, password)
        return conn

    # aliases for web status endpoint
    def snapshot(self) -> dict:
        return {
            "account": self.account,
            "host": self.config.get("host", ""),
            "status": self.status,
            "folder": self.config.get("folder", "INBOX"),
            "poll_interval": self.config.get("poll_interval", 30),
        }
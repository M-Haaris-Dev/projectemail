#!/usr/bin/env python3
"""mailMeta server entrypoint.

Starts the FastAPI web dashboard and (optionally) IMAP monitors for each
configured account.

Usage:
    python3 main.py                  # web + monitors
    python3 main.py --web-only       # dashboard only
    python3 main.py --monitor-only   # monitors only, no web
    python3 main.py --config /path/mailmeta.json
"""

import argparse
import logging
import sys
import threading

from mailmeta.config import load_config
from mailmeta.database import Database
from mailmeta.imap_monitor import IMAPMonitor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("mailmeta")


def main():
    parser = argparse.ArgumentParser(description="mailMeta — email forensics server")
    parser.add_argument("--config", default=None, help="path to config json")
    parser.add_argument("--web-only", action="store_true", help="run dashboard only, no IMAP")
    parser.add_argument("--monitor-only", action="store_true", help="run IMAP monitors only, no web")
    parser.add_argument("--test-connection", action="store_true", help="connect to each configured account then exit")
    parser.add_argument("--rescan", action="store_true", help="re-analyze ALL messages in the mailbox, not just new ones")
    parser.add_argument("--host", default=None, help="web bind host (overrides config)")
    parser.add_argument("--port", type=int, default=None, help="web bind port (overrides config)")
    args = parser.parse_args()

    cfg = load_config(args.config)
    db_path = cfg.get("database", "mailmeta.db")
    log.info("database: %s", db_path)
    db = Database(db_path)

    if args.test_connection:
        from mailmeta.imap_monitor import IMAPMonitor
        ok_all = True
        for acct in cfg.get("accounts", []):
            acct = dict(acct)
            m = IMAPMonitor(acct, db, threading.Event())
            log.info("testing account %s @ %s...", acct.get("username"), acct.get("host"))
            try:
                conn = m._connect()
                typ, data = conn.select(acct.get("folder", "INBOX"))
                if typ == "OK":
                    n = data[0].decode() if isinstance(data[0], bytes) else str(data[0])
                    log.info("OK  %s  connected, folder has %s messages", acct.get("username"), n)
                else:
                    log.error("FAIL %s  SELECT failed: %s", acct.get("username"), typ)
                    ok_all = False
                conn.logout()
            except Exception as e:
                log.error("FAIL %s  %s", acct.get("username"), e)
                ok_all = False
        sys.exit(0 if ok_all else 1)

    stop_event = threading.Event()
    monitors = []

    run_web = not args.monitor_only
    run_monitors = (not args.web_only) and bool(cfg.get("accounts"))

    if run_monitors:
        for acct in cfg.get("accounts", []):
            if not acct.get("active", True):
                log.info("skipping disabled account %s", acct.get("username"))
                continue
            acct = dict(acct)
            acct["rescan"] = args.rescan
            mon = IMAPMonitor(acct, db, stop_event)
            mon.start()
            monitors.append(mon)

    if not run_web:
        log.info("web disabled (--monitor-only). Press Ctrl+C to stop.")
        try:
            while True:
                stop_event.wait(timeout=1)
        except KeyboardInterrupt:
            log.info("shutting down")
            for m in monitors:
                m.stop()
            sys.exit(0)

    # web
    from web.app import create_app
    import uvicorn

    host = args.host or cfg.get("web", {}).get("host", "0.0.0.0")
    port = args.port or int(cfg.get("web", {}).get("port", 8000))
    app = create_app(db, monitors=monitors, config=cfg)

    log.info("dashboard at http://%s:%s", "localhost" if host == "0.0.0.0" else host, port)
    try:
        uvicorn.run(app, host=host, port=port, log_level="info")
    finally:
        log.info("stopping monitors")
        stop_event.set()
        for m in monitors:
            m.stop()
        db.close()


if __name__ == "__main__":
    main()
"""FastAPI web dashboard for mailMeta."""

import json
import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from mailmeta.database import Database
from mailmeta.pipeline import analyze

log = logging.getLogger("mailmeta.web")

SITE_DIR = Path(__file__).resolve().parent


def create_app(database: Database, monitors=None, config=None) -> FastAPI:
    app = FastAPI(title="mailMeta", version="2.0.0")
    app.state.db = database
    app.state.monitors = monitors or []
    app.state.config = config or {}

    # ---------- pages ----------
    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def index():
        html = (SITE_DIR / "templates" / "dashboard.html").read_text()
        return html

    # ---------- API ----------
    @app.get("/api/stats")
    def api_stats():
        return app.state.db.stats()

    @app.get("/api/monitors")
    def api_monitors():
        return [m.snapshot() for m in app.state.monitors]

    @app.get("/api/emails")
    def api_emails(
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
        risk_level: str = Query("all"),
        search: str = Query(""),
        account: str = Query(""),
        sort: str = Query("date_ts"),
    ):
        valid_sorts = {"date_ts", "risk_score", "analyzed_at"}
        if sort.startswith("-"):
            order = sort[1:]
            order = order if order in valid_sorts else "date_ts"
            sort = f"-{order}"
        else:
            order = sort if sort in valid_sorts else "date_ts"
        return app.state.db.list_messages(
            limit=limit,
            offset=offset,
            risk_level=risk_level,
            search=search,
            account=account,
            sort=sort,
        )

    @app.get("/api/emails/{msg_id}")
    def api_email_detail(msg_id: int):
        msg = app.state.db.get_message(msg_id)
        if not msg:
            raise HTTPException(404, "message not found")
        return msg

    @app.get("/api/emails/{msg_id}/raw")
    def api_email_raw(msg_id: int):
        raw = app.state.db.get_raw(msg_id)
        if raw is None:
            raise HTTPException(404, "raw body not found")
        return JSONResponse({"raw": raw.decode("utf-8", "replace")})

    @app.delete("/api/emails/{msg_id}")
    def api_email_delete(msg_id: int):
        ok = app.state.db.delete_message(msg_id)
        if not ok:
            raise HTTPException(404, "message not found")
        return {"deleted": msg_id}

    @app.get("/api/analyze/url")
    def api_analyze_url(url: str = Query(...)):
        """Sanity check endpoint: CLI/IPython use `url` field optionally. Kept for API completeness."""
        raise HTTPException(400, "use /api/analyze with raw eml body")

    # mount static
    app.mount("/static", StaticFiles(directory=str(SITE_DIR / "static")), name="static")

    return app
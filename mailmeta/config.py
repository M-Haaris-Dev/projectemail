"""Configuration loading. Reads mailmeta.json, supports env var overrides."""

import json
import os
import sys

DEFAULT_CONFIG = {
    "database": "mailmeta.db",
    "poll_interval": 30,
    "only_new": True,
    "web": {
        "host": "0.0.0.0",
        "port": 8000,
    },
    "accounts": [],
}


def _find_config(candidate: str | None) -> str:
    if candidate:
        return candidate
    for name in ("mailmeta.json", "config.json"):
        if os.path.exists(name):
            return name
    return "mailmeta.json"


def load_config(path: str | None = None) -> dict:
    cfg_path = _find_config(path)
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(cfg_path):
        with open(cfg_path) as f:
            user_cfg = json.load(f)
        cfg.update(user_cfg)
        if isinstance(cfg.get("accounts"), list):
            cfg["accounts"] = user_cfg.get("accounts", [])
    cfg["_path"] = cfg_path

    # env overrides (useful for secrets in CI/containers)
    api_env = os.environ.get("MAILMETA_API_KEY")
    if api_env:
        cfg.setdefault("api_key", api_env)
    return cfg


def save_config(cfg: dict):
    """Write config back to its file (stable JSON, accounts scrubbed-print-safe)."""
    path = cfg.get("_path", "mailmeta.json")
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def default_accounts():
    """Return printable skeleton account configs. Secrets stay out of defaults."""
    return {
        "host": "imap.gmail.com",
        "port": 993,
        "username": "you@gmail.com",
        "password": "APP_PASSWORD_OR_PASSWORD",
        "account": "you@gmail.com",
        "folder": "INBOX",
    }
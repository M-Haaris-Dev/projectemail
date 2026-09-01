"""Core email analysis: parse headers, structure detection, header-only heuristics."""

import re
from email import message_from_bytes
from email.header import decode_header
from email.utils import parsedate_to_datetime, parseaddr
from datetime import datetime, timezone


def decode_mime_word(val) -> str:
    """Decode RFC2047 encoded-words (e.g. =?UTF-8?B?...?=) to plain text."""
    if not val:
        return ""
    out = []
    try:
        parts = decode_header(val)
        for chunk, enc in parts:
            if isinstance(chunk, bytes):
                out.append(chunk.decode(enc or "utf-8", errors="replace"))
            else:
                out.append(chunk)
    except Exception:
        return str(val).strip()
    return "".join(out).strip()


class EmailMeta:
    """Data structure holding all metadata extracted from an email."""

    def __init__(self):
        self.message_id = ""
        self.subject = ""
        self.from_addr = ""
        self.from_name = ""
        self.sender_addr = ""
        self.reply_to = ""
        self.return_path = ""
        self.date = ""
        self.date_ts = 0
        self.content_type = ""
        self.received_chain = []
        self.ip_address = ""
        self.envelope_from = ""
        self.headers = {}
        self.raw = b""
        self.spf = {"status": "unknown"}
        self.dkim = {"status": "unknown"}
        self.dmarc = {"status": "unknown"}
        self.authentication_results = []
        self.risk_score = 0
        self.risk_level = "unknown"
        self.findings = []
        self.ptr = None
        self.geo = None
        self.chain_ips = []
        self.chain_geo = []

    def to_dict(self, include_raw=False):
        d = {
            "message_id": self.message_id,
            "subject": self.subject,
            "from_addr": self.from_addr,
            "from_name": self.from_name,
            "sender_addr": self.sender_addr,
            "reply_to": self.reply_to,
            "return_path": self.return_path,
            "date": self.date,
            "date_ts": self.date_ts,
            "content_type": self.content_type,
            "received_chain": self.received_chain,
            "ip_address": self.ip_address,
            "envelope_from": self.envelope_from,
            "spf": self.spf,
            "dkim": self.dkim,
            "dmarc": self.dmarc,
            "authentication_results": self.authentication_results,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "findings": self.findings,
            "ptr": self.ptr,
            "geo": self.geo,
            "chain_ips": self.chain_ips,
            "chain_geo": self.chain_geo,
        }
        if include_raw:
            d["raw"] = self.raw.decode("utf-8", errors="replace")
        return d


def parse_email(raw: bytes) -> EmailMeta:
    """Parse a raw eml message into an EmailMeta structure."""
    meta = EmailMeta()
    meta.raw = raw
    msg = message_from_bytes(raw)

    for key in msg.keys():
        meta.headers[key.lower()] = msg.get_all(key) or []

    # Message-ID
    mid = msg.get("Message-ID", "")
    meta.message_id = mid.strip()

    # Subject
    subj = msg.get("Subject", "")
    meta.subject = decode_mime_word(subj)

    # From
    frm = msg.get("From", "")
    fname, faddr = parseaddr(frm)
    meta.from_name = decode_mime_word(fname)
    meta.from_addr = faddr

    # Sender
    snd = msg.get("Sender", "")
    if snd:
        _, saddr = parseaddr(snd)
        meta.sender_addr = saddr

    # Reply-To
    rto = msg.get("Reply-To", "")
    if rto:
        _, raddr = parseaddr(rto)
        meta.reply_to = raddr

    # Return-Path / envelope from
    rp = msg.get("Return-Path", "")
    if rp:
        _, rpaddr = parseaddr(rp)
        meta.return_path = rpaddr
        meta.envelope_from = rpaddr

    # Date
    dt = msg.get("Date", "")
    meta.date = dt.strip()
    try:
        parsed = parsedate_to_datetime(dt)
        meta.date_ts = int(parsed.timestamp())
    except Exception:
        meta.date_ts = 0

    # Content-Type
    ct = msg.get("Content-Type", "")
    meta.content_type = ct.strip()

    # Received chain
    received = msg.get_all("Received")
    if received:
        meta.received_chain = [r.strip() for r in received]

    # Extract IP from Received chain (origin = last Received header typically)
    meta.ip_address = extract_recipient_ip(meta.received_chain)

    # Authentication-Results
    auth_res = msg.get_all("Authentication-Results")
    if auth_res:
        meta.authentication_results = [r.strip() for r in auth_res]

    return meta


IP4_RE = re.compile(r"\[(?:IPv6:)?\]|(?:\d{1,3}\.){3}\d{1,3}|\[IPv6:[0-9a-fA-F:]+\]")
IPV4 = re.compile(r"(?<!\d)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\d)")
IPV6 = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:]{2,39})\]")


def extract_chain_ips(received_chain) -> list[str]:
    """All valid IPs found across the Received chain, useful for hop tracing."""
    out = []
    if not received_chain:
        return out
    for header in received_chain:
        for m in IPV4.finditer(header):
            a, b, c, d = m.groups()
            if all(0 <= int(x) <= 255 for x in (a, b, c, d)):
                ip = m.group(0)
                if ip not in out:
                    out.append(ip)
        for m in IPV6.finditer(header):
            ip = m.group(1)
            if ip not in out:
                out.append(ip)
    return out


def extract_recipient_ip(received_chain) -> str:
    """Extract the origin IP. In a Received chain, headers appear newest-first,
    so the LAST Received header is the origin/edge hop (sender's IP)."""
    origin_ip = ""
    if not received_chain:
        return origin_ip
    # Iterate from last (oldest) header first - that's closest to sender
    for header in reversed(received_chain):
        candidates = []
        for m in IPV4.finditer(header):
            a, b, c, d = m.groups()
            if all(0 <= int(x) <= 255 for x in (a, b, c, d)):
                candidates.append(m.group(0))
        if not candidates:
            for m in IPV6.finditer(header):
                candidates.append(m.group(1))
        if candidates:
            origin_ip = candidates[0]
            break
    return origin_ip
#!/usr/bin/env python3
"""Unit tests for DNS verification and database layers."""

import ipaddress
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mailmeta.dns_verifier import DNSVerifier
from mailmeta.database import Database
from mailmeta.analyzer import extract_recipient_ip


def test_valid_ip_rejection():
    d = DNSVerifier()
    assert not d._valid_ip("999.999.999.999")
    assert not d._valid_ip("1.2.3")
    assert not d._valid_ip("a.2.3.4")
    assert d._valid_ip("192.168.1.1")


def test_spf_flat_ip4():
    d = DNSVerifier()
    ip = ipaddress.ip_address("192.0.2.10")
    r = d._evaluate_spf("v=spf1 ip4:192.0.2.0/24 -all", "example.com", ip)
    assert r["status"] == "pass"


def test_spf_all_fail():
    d = DNSVerifier()
    ip = ipaddress.ip_address("192.0.2.200")
    r = d._evaluate_spf("v=spf1 ip4:10.0.0.0/8 -all", "example.com", ip)
    assert r["status"] == "fail"
    assert "all" in r["explanation"]


def test_spf_softfail():
    d = DNSVerifier()
    ip = ipaddress.ip_address("9.9.9.9")
    r = d._evaluate_spf("v=spf1 ip4:10.0.0.0/8 ~all", "example.com", ip)
    assert r["status"] == "softfail"


def test_spf_neutral_no_match():
    d = DNSVerifier()
    ip = ipaddress.ip_address("9.9.9.9")
    r = d._evaluate_spf("v=spf1 ip4:10.0.0.0/8 ?all", "example.com", ip)
    assert r["status"] == "neutral"


def test_include_softfail_not_match():
    """include that returns softfail must NOT count as include match."""
    d = DNSVerifier()
    ip = ipaddress.ip_address("1.1.1.1")
    r = d._evaluate_spf("v=spf1 include:nonexistent.invalid ~all", "example.com", ip)
    assert r["status"] in ("softfail", "neutral", "none")


def test_extract_ip_from_chain():
    chain = [
        "from mail.example.com (mail.example.com [45.67.89.10]) by mx2.receiver.com with ESMTP",
        "by mx1.receiver.com (Postfix) with ESMTPS id X for <a@b.com>; Mon, 1 Jan 2025 00:00:00 +0000",
    ]
    assert extract_recipient_ip(chain) == "45.67.89.10"


def test_extract_ip_no_chain():
    assert extract_recipient_ip([]) == ""


def test_database_roundtrip():
    with tempfile.TemporaryDirectory() as td:
        db = Database(os.path.join(td, "test.db"))
        from mailmeta.analyzer import parse_email
        from mailmeta.risk import evaluate_risk
        raw = b"From: a@b.com\nTo: x@y.com\nSubject: t\nDate: Mon, 1 Jan 2025 00:00:00 +0000\n\nbody"
        meta = parse_email(raw)
        score, level, finds = evaluate_risk(meta)
        meta.risk_score, meta.risk_level, meta.findings = score, level, finds
        db.upsert_message("acct", "1", meta, raw)
        assert db.touched_uids("acct") == {"1"}
        rows = db.list_messages(limit=10)
        assert rows["total"] == 1
        got = db.get_message(rows["rows"][0]["id"])
        assert got["data"]["subject"] == "t"
        assert db.count_messages("high") == 1
        assert db.count_messages("safe") == 0
        # duplicate uid updates, no new row
        db.upsert_message("acct", "1", meta, raw)
        assert db.list_messages()["total"] == 1


if __name__ == "__main__":
    test_valid_ip_rejection()
    test_spf_flat_ip4()
    test_spf_all_fail()
    test_spf_softfail()
    test_spf_neutral_no_match()
    test_include_softfail_not_match()
    test_extract_ip_from_chain()
    test_extract_ip_no_chain()
    test_database_roundtrip()
    print("unit tests passed")
#!/usr/bin/env python3
"""End-to-end test: analyze the bundled sample emails."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mailmeta.pipeline import analyze
from mailmeta.dns_verifier import DNSVerifier

TEST_DIR = Path(__file__).resolve().parent


def make_eml() -> bytes:
    return b"""Return-Path: <scammer@evil-example.com>
Received: from mail.evil-example.com (mail.evil-example.com [198.51.100.7])
        by mail.gmail.com with SMTP id abc123
        for you@gmail.com; Mon, 1 Sep 2025 10:00:00 -0700
DKIM-Signature: v=1; a=rsa-sha256; d=evil-example.com; s=default;
        bh=aaaa; h=From:Subject; b=bbbb
Message-ID: <fake@evil-example.com>
Reply-To: "Payment Dept" <secure@evil-example.net>
From: "PayPal Security" <security@evil-example.com>
Subject: Your account has been suspended - verify now
Date: Mon, 1 Sep 2025 10:00:00 -0700
Content-Type: text/html

<html><body>Click this link now!</body></html>
"""


def test_parser_fields():
    meta = analyze(make_eml(), dns=DNSVerifier())
    assert meta.from_addr == "security@evil-example.com"
    assert meta.from_name == "PayPal Security"
    assert meta.reply_to == "secure@evil-example.net"
    assert "suspended" in meta.subject
    assert meta.message_id == "<fake@evil-example.com>"
    assert meta.ip_address == "198.51.100.7"


def test_risk_flags_spoof():
    meta = analyze(make_eml(), dns=DNSVerifier())
    assert meta.risk_level in ("high", "medium")
    assert any("paypal" in f.lower() for f in meta.findings)
    assert any("Reply-To" in f for f in meta.findings)


if __name__ == "__main__":
    test_parser_fields()
    test_risk_flags_spoof()
    print("tests passed")
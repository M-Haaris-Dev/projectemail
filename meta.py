#!/usr/bin/env python3
"""mailMeta — email header forensics CLI.

Analyzes a raw .eml file or a directory of them using live SPF/DKIM/DMARC
verification from DNS, plus header-anomaly heuristics.

Usage:
    python3 meta.py -f message.eml
    python3 meta.py -f message.eml -j          # JSON output
    python3 meta.py -d ./mailbox               # analyze all .eml in dir
    python3 meta.py -f message.eml --no-dns    # header-only (works offline)
"""

import argparse
import json
import sys
from pathlib import Path

from mailmeta.pipeline import analyze

BANNER = r"""
                     _ _ __  __      _
     _ __ ___   __ _(_) |  \/  | ___| |_ __ _
    | '_ ` _ \ / _` | | | |\/| |/ _ \ __/ _` |
    | | | | | | (_| | | | |  | |  __/ || (_| |
    |_| |_| |_|\__,_|_|_|_|  |_|\___|\__\__,_|

        email header forensics | live SPF/DKIM/DMARC v2
"""


def color(text: str, code: str) -> str:
    import colorama
    colorama.init()
    from colorama import Fore, Style
    codes = {
        "green": Fore.GREEN,
        "red": Fore.RED,
        "yellow": Fore.YELLOW,
        "cyan": Fore.CYAN,
        "dim": Style.DIM,
        "reset": Style.RESET_ALL,
    }
    return f"{codes.get(code, '')}{text}{codes['reset']}"


def print_report(meta, use_color=True):
    c = color if use_color else lambda t, _: t

    def status_word(record: dict):
        s = record.get("status", "unknown")
        if s == "pass":
            return c("[+] PASS", "green")
        if s in ("fail", "permerror"):
            return c("[!] FAIL", "red")
        if s == "softfail":
            return c("[~] SOFTFAIL", "yellow")
        return c("[?] " + s.upper(), "yellow")

    print(c("\n=========================== mailMeta report ===========================", "cyan"))
    print(c("Subject    : ", "dim") + meta.subject)
    print(c("From       : ", "dim") + (meta.from_name or "") + f" <{meta.from_addr}>")
    if meta.reply_to:
        print(c("Reply-To   : ", "dim") + meta.reply_to)
    if meta.envelope_from:
        print(c("Envelope   : ", "dim") + meta.envelope_from)
    print(c("Message-ID : ", "dim") + (meta.message_id or "(none)"))
    print(c("Date       : ", "dim") + meta.date)
    print(c("Retrieved IP: ", "dim") + (meta.ip_address or "(unknown)"))
    if meta.ptr:
        print(c("Reverse DNS: ", "dim") + meta.ptr)
    geo = meta.geo or {}
    if geo.get("status") == "success":
        loc = ", ".join([x for x in ([geo.get("city"), geo.get("regionName"), geo.get("country")] if geo.get("city") else [geo.get("country")]) if x])
        print(c("Location    : ", "dim") + (loc or "unknown") + f"  ({geo.get('lat', '?')}, {geo.get('lon', '?')})")
        if geo.get("isp"):
            print(c("ISP         : ", "dim") + geo["isp"])
    elif geo.get("note"):
        print(c("Location    : ", "dim") + geo["note"])
    print()
    print(c("SPF        : ", "dim") + status_word(meta.spf))
    if meta.spf.get("spf_record"):
        print(f"    record: {meta.spf['spf_record']}")
    if meta.spf.get("explanation"):
        print(f"    detail: {meta.spf['explanation']}")
    print(c("DKIM       : ", "dim") + status_word(meta.dkim))
    if meta.dkim.get("detail"):
        print(f"    detail: {meta.dkim['detail']}")
    print(c("DMARC      : ", "dim") + status_word(meta.dmarc))
    if meta.dmarc.get("policy"):
        print(f"    policy: {meta.dmarc['policy']}  sp={meta.dmarc.get('sp','-')}  pct={meta.dmarc.get('pct','100')}%")
    if meta.dmarc.get("detail"):
        print(f"    detail: {meta.dmarc['detail']}")

    print()
    print(c(f"VERDICT    : {meta.risk_score}/100 — {meta.risk_level.upper()} RISK", "cyan"))
    for f in meta.findings:
        icon = c("•", "yellow" if "differ" in f or "Missing" in f else "dim")
        print(f"   {icon} {f}")

    if meta.received_chain:
        print()
        print(c("Received path:", "dim"))
        for i, hop in enumerate(reversed(meta.received_chain), 1):
            print(f"  {i}. {hop}")
    print(c("========================================================================", "cyan"))


def main():
    p = argparse.ArgumentParser(description="mailMeta — email header forensics CLI")
    p.add_argument("-f", "--file", help="raw email (.eml) file to analyze")
    p.add_argument("-d", "--directory", help="directory of .eml files to analyze")
    p.add_argument("-j", "--json", action="store_true", help="output raw JSON")
    p.add_argument("--no-dns", action="store_true", help="skip live DNS verification (offline mode)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    args = p.parse_args()

    if not args.file and not args.directory:
        p.print_help()
        sys.exit(1)

    if args.no_dns:
        import importlib
        import mailmeta.pipeline as pipe
        from mailmeta.analyzer import parse_email
        from mailmeta.risk import evaluate_risk

        def analyze_offline(raw):
            meta = parse_email(raw)
            meta.spf = {"status": "unknown", "explanation": "offline mode"}
            meta.dkim = {"status": "unknown", "explanation": "offline mode"}
            meta.dmarc = {"status": "unknown", "explanation": "offline mode"}
            score, lvl, finds = evaluate_risk(meta)
            meta.risk_score, meta.risk_level, meta.findings = score, lvl, finds
            return meta

        fn = analyze_offline
    else:
        fn = analyze

    files = []
    if args.file:
        files.append(Path(args.file))
    else:
        files = sorted(Path(args.directory).glob("*.eml"))

    for f in files:
        if not f.exists():
            print(f"error: file not found: {f}", file=sys.stderr)
            sys.exit(1)
        raw = f.read_bytes()
        meta = fn(raw)
        if args.json:
            indent = None if len(files) > 1 else 2
            print(json.dumps(meta.to_dict(include_raw=False), indent=indent, default=str))
        else:
            print_report(meta, use_color=not args.no_color)
            if len(files) > 1:
                print("\n" + "#" * 70 + "\n")


if __name__ == "__main__":
    argv = sys.argv[1:]
    if "-j" not in argv and "--json" not in argv:
        print(BANNER)
    main()
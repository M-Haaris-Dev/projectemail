"""mailMeta - email header forensics with live SPF/DKIM/DMARC verification.

Pipeline: raw email -> parse -> verify SPF/DKIM/DMARC via DNS -> risk score.
"""

__version__ = "2.0.0"

from .analyzer import parse_email, EmailMeta, extract_chain_ips
from .dns_verifier import DNSVerifier
from .geo import geolocate
from .risk import evaluate_risk


def analyze(raw: bytes, dns: DNSVerifier | None = None) -> EmailMeta:
    """Full analysis pipeline. Returns EmileMeta with DNS results + risk score."""
    dns = dns or DNSVerifier()
    meta = parse_email(raw)

    from_addr = meta.from_addr
    from_domain = ""
    if from_addr and "@" in from_addr:
        from_domain = from_addr.split("@")[-1]

    sender_ip = meta.ip_address

    # SPF: use envelope-from/return-path if available, else From domain
    spf_domain = from_domain
    if meta.envelope_from and "@" in meta.envelope_from:
        spf_domain = meta.envelope_from.split("@")[-1]

    if sender_ip and spf_domain:
        meta.spf = dns.check_spf(sender_ip, spf_domain)
    else:
        meta.spf = {"status": "unknown", "explanation": f"no sender IP ({sender_ip!r}) or domain ({spf_domain!r})", "spf_record": None, "mechanisms": []}

    meta.dkim = dns.check_dkim(raw)

    meta.dmarc = dns.check_dmarc(from_domain, meta.spf.get("status"), meta.dkim.get("status")) if from_domain else {"status": "unknown", "policy": None, "detail": "no From domain", "record": None}

    if sender_ip:
        meta.ptr = dns.reverse_dns(sender_ip)
        meta.geo = geolocate(sender_ip)

    meta.chain_ips = extract_chain_ips(meta.received_chain)

    score, level, findings = evaluate_risk(meta)
    meta.risk_score = score
    meta.risk_level = level
    meta.findings = findings

    return meta
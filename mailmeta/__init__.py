"""mailmeta — email header forensics toolkit.

Public API:
    analyze(raw)            -> EmailMeta with DNS-verified SPF/DKIM/DMARC + risk score
    parse_email(raw)        -> EmailMeta (header parsing only)
    DNSVerifier()           -> low-level SPF/DKIM/DMARC DNS checks
    Database()              -> SQLite storage for analyzed messages
"""

from .analyzer import parse_email, EmailMeta
from .dns_verifier import DNSVerifier
from .risk import evaluate_risk, risk_plain_text, auth_plain_text
from .pipeline import analyze
from .geo import geolocate

__all__ = ["parse_email", "EmailMeta", "DNSVerifier", "evaluate_risk", "analyze",
           "risk_plain_text", "auth_plain_text", "geolocate"]
__version__ = "2.0.0"
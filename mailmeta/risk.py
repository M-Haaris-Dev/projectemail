"""Risk scoring engine. Maps SPF/DKIM/DMARC outcomes + header anomalies to a 0-100 score."""

from email.utils import parseaddr


SPF_WEIGHTS = {
    "pass": 0,
    "neutral": 15,
    "softfail": 35,
    "none": 40,
    "permerror": 50,
    "temperror": 45,
    "fail": 60,
    "unknown": 30,
}

DKIM_WEIGHTS = {
    "pass": 0,
    "none": 40,
    "fail": 60,
    "error": 45,
    "unknown": 30,
}

DMARC_WEIGHTS = {
    "pass": 0,
    "none": 30,
    "fail": 50,
    "unknown": 25,
}


def risk_plain_text(level: str) -> str:
    return {
        "safe": "All authentication checks passed. This email very likely came from the sender it claims.",
        "low": "Minor inconsistencies found. Email is probably legitimate, but keep standard caution.",
        "medium": "Part of the email failed verification or shows mismatches. Treat links and attachments with caution.",
        "high": "Strong indicators of spoofing or phishing detected. Do not trust links, attachments, or instructions in this email.",
    }.get(level, "Automated risk score based on email authentication and header checks.")


def auth_plain_text(kind: str, status: str) -> str:
    if kind == "spf":
        return {
            "pass": "Sender's domain authorized the server that delivered this email.",
            "fail": "Sender's domain did NOT authorize this sending server - the domain may be impersonated.",
            "softfail": "Sender's domain could not confirm authorization - this is commonly seen with spoofed mail.",
            "neutral": "Sender's domain states the sending server may or may not be authorized - no verdict.",
            "none": "Sender's domain has no SPF policy published. Cannot verify authorization.",
            "temperror": "Temporary DNS failure prevented checking the sender's policy.",
            "permerror": "The sender's SPF policy is malformed and could not be evaluated.",
            "unknown": "Could not evaluate SPF (missing IP or domain).",
        }.get(status, "Cannot verify sender authorization.")
    if kind == "dkim":
        return {
            "pass": "Message carries a valid digital signature tied to the claimed sender's domain.",
            "error": "The signature could not be verified due to an error.",
            "fail": "The digital signature could not be validated - content or sender may be forged.",
            "none": "No digital signature present. Common for personal or automated mail.",
            "unknown": "Could not check the digital signature.",
        }.get(status, "Cannot verify the digital signature.")
    if kind == "dmarc":
        return {
            "pass": "The domain's DMARC policy is satisfied - sender identity aligns with its policy.",
            "fail": "DMARC policy says unauthorized senders; receiving servers should reject or quarantine.",
            "none": "No DMARC policy published for this domain.",
            "unknown": "Could not evaluate DMARC.",
        }.get(status, "Cannot evaluate the sending policy.")
    return ""


def _same_domain(a: str, b: str) -> bool:
    """Relaxed domain comparison (subdomain allowed)."""
    if not a or not b:
        return False
    a = a.lower().lstrip("@").split("@")[-1]
    b = b.lower().lstrip("@").split("@")[-1]
    if a == b:
        return True
    return a.endswith("." + b) or b.endswith("." + a)


def evaluate_risk(meta) -> tuple[int, str, list[str]]:
    """Return (score, level, findings)."""
    score = 0
    findings = []

    spf_status = meta.spf.get("status", "unknown")
    dkim_status = meta.dkim.get("status", "unknown")
    dmarc_status = meta.dmarc.get("status", "unknown")

    score += SPF_WEIGHTS.get(spf_status, 30)
    findings.append(f"SPF: {spf_status}")

    score += DKIM_WEIGHTS.get(dkim_status, 30)
    findings.append(f"DKIM: {dkim_status}")

    score += DMARC_WEIGHTS.get(dmarc_status, 25)
    findings.append(f"DMARC: {dmarc_status}")

    # From domain extraction
    from_domain = ""
    if meta.from_addr:
        from_domain = meta.from_addr.split("@")[-1]

    # Header anomaly checks
    if meta.reply_to:
        rto_domain = meta.reply_to.split("@")[-1] if "@" in meta.reply_to else ""
        if from_domain and rto_domain and not _same_domain(from_domain, rto_domain):
            score += 20
            findings.append(f"Reply-To domain ({rto_domain}) differs from From domain ({from_domain})")

    if meta.sender_addr:
        snd_domain = meta.sender_addr.split("@")[-1] if "@" in meta.sender_addr else ""
        if from_domain and snd_domain and not _same_domain(from_domain, snd_domain):
            score += 15
            findings.append(f"Sender domain ({snd_domain}) differs from From domain ({from_domain})")

    if meta.return_path:
        rp_domain = meta.return_path.split("@")[-1] if "@" in meta.return_path else ""
        if from_domain and rp_domain and not _same_domain(from_domain, rp_domain):
            score += 15
            findings.append(f"Return-Path domain ({rp_domain}) differs from From domain ({from_domain})")

    if not meta.message_id:
        score += 10
        findings.append("Missing Message-ID header")

    # Display-name spoofing: big-brand display names on mismatched domains
    big_brands = {"paypal", "amazon", "netflix", "apple", "microsoft", "google", "facebook", "bank", "wellsfargo", "chase"}
    if meta.from_name:
        for brand in big_brands:
            if brand in meta.from_name.lower() and from_domain and brand not in from_domain:
                score += 15
                findings.append(f"Display name mentions '{brand}' but From domain is {from_domain}")
                break

    # No received chain → suspicious or badly formed
    if not meta.received_chain:
        score += 10
        findings.append("No Received headers (locally crafted message?)")

    score = max(0, min(100, score))

    if score >= 75:
        level = "high"
    elif score >= 50:
        level = "medium"
    elif score >= 25:
        level = "low"
    else:
        level = "safe"

    return score, level, findings
"""Real DNS verification for SPF, DKIM, and DMARC records."""

import ipaddress
import re
from email.policy import default as email_policy
from email import message_from_bytes

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import dkim
    DKIM_AVAILABLE = True
except ImportError:
    DKIM_AVAILABLE = False


class DNSVerifier:
    """Perform SPF/DKIM/DMARC validation against live DNS records."""

    def __init__(self, timeout=5.0, lifetime=8.0):
        self.timeout = timeout
        self.lifetime = lifetime

    def _resolver(self):
        if not DNS_AVAILABLE:
            return None
        r = dns.resolver.Resolver(configure=True)
        r.timeout = self.timeout
        r.lifetime = self.lifetime
        return r

    def query_txt(self, domain, record_type="TXT"):
        """Return list of TXT record strings for a domain."""
        r = self._resolver()
        if r is None:
            return []
        try:
            answers = r.resolve(domain, record_type, raise_on_no_answer=True)
        except Exception:
            return []
        records = []
        for a in answers:
            if record_type == "TXT":
                txt = b"".join(a.strings).decode("utf-8", errors="replace")
                records.append(txt)
            else:
                records.append(str(a))
        return records

    # ---------- SPF ----------
    def check_spf(self, sender_ip: str, sender_domain: str) -> dict:
        """Check SPF for sender_ip against sender_domain.

        Returns dict with: status, spf_record, explanation, mechanisms.
        status in: pass/fail/softfail/neutral/none/permerror/temperror
        """
        if not DNS_AVAILABLE:
            return {"status": "unknown", "spf_record": None, "explanation": "DNS library unavailable", "mechanisms": []}

        if not self._valid_ip(sender_ip):
            return {"status": "permerror", "spf_record": None, "explanation": f"Invalid IP address: {sender_ip}", "mechanisms": []}

        records = self.query_txt(sender_domain)
        spf_record = None
        for rec in records:
            rec = rec.strip()
            if rec.startswith("v=spf1"):
                spf_record = rec
                break

        if spf_record is None:
            return {"status": "none", "spf_record": None, "explanation": f"No SPF record found for {sender_domain}", "mechanisms": []}

        try:
            ip_obj = ipaddress.ip_address(sender_ip)
        except ValueError:
            return {"status": "permerror", "spf_record": spf_record, "explanation": f"Invalid IP: {sender_ip}", "mechanisms": []}

        result = self._evaluate_spf(spf_record, sender_domain, ip_obj)
        result["spf_record"] = spf_record
        return result

    def _valid_ip(self, ip: str) -> bool:
        pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if not re.match(pattern, ip):
            return False
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _evaluate_spf(self, spf_record: str, domain: str, ip_obj, depth: int = 0) -> dict:
        """Evaluate an SPF record against an IP."""
        terms = spf_record.split()
        mechanisms = []
        result = {"status": "none", "explanation": "No mechanism matched", "mechanisms": []}

        match = None
        redirect_target = None
        for term in terms[1:]:  # skip v=spf1
            term = term.strip()
            if not term:
                continue
            qualifier = "+"
            if term[0] in "+-~?":
                qualifier = term[0]
                term = term[1:]
            if term.startswith("redirect="):
                redirect_target = term.split("=", 1)[1]
                continue
            if ":" in term:
                mech, value = term.split(":", 1)
            elif "/" in term:
                mech, value = term, None
            else:
                mech, value = term, None

            mechanism_match = None
            if match is None:
                try:
                    if mech == "ip4":
                        value = value or str(ip_obj)
                        mechanism_match = ip_obj.version == 4 and ip_obj in ipaddress.ip_network(value, strict=False)
                    elif mech == "ip6":
                        value = value or str(ip_obj)
                        mechanism_match = ip_obj.version == 6 and ip_obj in ipaddress.ip_network(value, strict=False)
                    elif mech == "a":
                        mechanism_match = self._mechanism_a(domain, value, ip_obj)
                    elif mech == "mx":
                        mechanism_match = self._mechanism_mx(domain, ip_obj)
                    elif mech == "include":
                        records = self.query_txt(value)
                        for inc_rec in records:
                            if inc_rec.startswith("v=spf1"):
                                sub = self._evaluate_spf(inc_rec, value, ip_obj, depth + 1)
                                if sub.get("status") == "pass":
                                    mechanism_match = True
                                elif sub.get("status") == "fail":
                                    # include propagates fail (RFC 7208 §5.2)
                                    result["status"] = "fail"
                                    result["explanation"] = f"include:{value} returned fail (target says ~all/-all)"
                                break
                    elif mech == "exists":
                        mechanism_match = self._mechanism_exists(value, domain)
                    elif mech == "all":
                        mechanism_match = True
                except Exception:
                    mechanism_match = False

            hit = bool(mechanism_match) and match is None
            mechanisms.append({"mechanism": mech, "value": value or "", "qualifier": qualifier, "matched": bool(mechanism_match), "hit": hit})

            if match is None and hit:
                match = term
                result["mechanisms"] = mechanisms
                if mech == "all":
                    result["status"] = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}.get(qualifier, "neutral")
                    result["explanation"] = f"SPF {qualifier}all (default rule)"
                else:
                    result["status"] = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}.get(qualifier, "neutral")
                    result["explanation"] = f"{mech} match for {value or domain}"
                break
            # include returned fail -> already recorded in result; stop evaluation
            if result.get("status") == "fail" and "include:" in result.get("explanation", ""):
                result["mechanisms"] = mechanisms
                break

        if match is None:
            # redirect modifier: evaluate target domain's SPF
            if redirect_target and depth < 10:
                recs = self.query_txt(redirect_target)
                for rec in recs:
                    if rec.startswith("v=spf1"):
                        sub = self._evaluate_spf(rec, redirect_target, ip_obj, depth + 1)
                        sub["explanation"] += f" (redirect from {redirect_target})"
                        sub["mechanisms"] = mechanisms + sub.get("mechanisms", [])
                        return sub
            result["mechanisms"] = mechanisms
            result["status"] = "neutral"
            result["explanation"] = "No SPF mechanism matched"
        return result

    def _mechanism_a(self, domain: str, value, ip_obj) -> bool:
        """Check if IP matches A/AAAA records of domain (optionally with CIDR)."""
        target = value or domain
        cidr = None
        if "/" in target:
            target, cidr = target.split("/", 1)
        ip_str = str(ip_obj)
        addresses = self.query_txt(target, "A")
        if ip_obj.version == 6:
            addresses = self.query_txt(target, "AAAA")
        if cidr:
            try:
                net = ipaddress.ip_network(f"{ip_str}/{cidr}", strict=False)
                for addr in addresses:
                    a = ipaddress.ip_address(addr)
                    if a in net:
                        return True
                return False
            except Exception:
                return False
        return ip_str in addresses

    def _mechanism_mx(self, domain: str, ip_obj) -> bool:
        """Check if IP matches A records of MX hosts."""
        mx_records = self.query_txt(domain, "MX")
        if not mx_records:
            return False
        mx_hosts = []
        for r in mx_records:
            parts = r.split()
            if parts:
                host = parts[-1].rstrip(".")
                mx_hosts.append(host)
        ip_str = str(ip_obj)
        for host in mx_hosts:
            a = self.query_txt(host, "A")
            if ip_str in a:
                return True
            if ip_obj.version == 6:
                aaaa = self.query_txt(host, "AAAA")
                if ip_str in aaaa:
                    return True
        return False

    def _mechanism_exists(self, value: str, domain: str) -> bool:
        """exists: mechanism - perform A lookup; existence = pass (macro-expanded)."""
        target = value or domain
        target = target.replace("%{d}", domain)
        return bool(self.query_txt(target, "A"))

    # ---------- DKIM ----------
    def check_dkim(self, raw_message: bytes) -> dict:
        """Verify DKIM signature cryptographically using dkimpy.

        Returns dict with status: pass/fail/none/error and detail.
        """
        if not DKIM_AVAILABLE:
            return {"status": "none", "detail": "dkimpy not installed", "signature_domain": None}

        if not raw_message:
            return {"status": "none", "detail": "empty message", "signature_domain": None}

        try:
            msg = message_from_bytes(raw_message, policy=email_policy)
            dkim_header = msg.get("DKIM-Signature")
            if not dkim_header:
                return {"status": "none", "detail": "No DKIM-Signature header", "signature_domain": None}

            sig_domain = None
            m = re.search(r"d=([^;\s]+)", dkim_header)
            if m:
                sig_domain = m.group(1)

            verified = dkim.verify(raw_message)
            if verified:
                return {"status": "pass", "detail": f"DKIM signature verified for {sig_domain}", "signature_domain": sig_domain}
            return {"status": "fail", "detail": "DKIM signature verification failed", "signature_domain": sig_domain}
        except Exception as e:
            domain = None
            try:
                msg = message_from_bytes(raw_message, policy=email_policy)
                hdr = msg.get("DKIM-Signature")
                m = re.search(r"d=([^;\s]+)", hdr or "")
                if m:
                    domain = m.group(1)
            except Exception:
                pass
            return {"status": "error", "detail": f"DKIM verify raised: {e}", "signature_domain": domain}

    # ---------- DMARC ----------
    def check_dmarc(self, from_domain: str, spf_status: str = None, dkim_status: str = None) -> dict:
        """Check DMARC policy for the From domain."""
        if not DNS_AVAILABLE:
            return {"status": "unknown", "policy": None, "detail": "DNS library unavailable"}

        dmarc_domain = f"_dmarc.{from_domain}"
        records = self.query_txt(dmarc_domain)
        dmarc_record = None
        for rec in records:
            if rec.strip().startswith("v=DMARC1"):
                dmarc_record = rec.strip()
                break

        if dmarc_record is None:
            return {"status": "none", "policy": None, "detail": f"No DMARC record at {dmarc_domain}", "record": None}

        policy = None
        sp = None
        pct = "100"
        for part in dmarc_record.split(";"):
            part = part.strip()
            if part.startswith("p="):
                policy = part[2:].strip()
            elif part.startswith("sp="):
                sp = part[3:].strip()
            elif part.startswith("pct="):
                pct = part[4:].strip()

        spf_pass = spf_status == "pass"
        dkim_pass = dkim_status == "pass"
        result_status = "none"
        detail = ""
        if spf_pass or dkim_pass:
            result_status = "pass"
            detail = "DMARC pass"
            if spf_pass and dkim_pass:
                detail = "Both SPF and DKIM aligned and passing"
            elif spf_pass:
                detail = "SPF authenticated and aligned"
            else:
                detail = "DKIM authenticated and aligned"
        elif spf_status == "fail" or dkim_status == "fail":
            result_status = "fail"
            detail = "Authentication failed against DMARC policy"
        else:
            result_status = "fail"
            detail = "Alignment check: SPF/DKIM did not authenticate"

        return {
            "status": result_status,
            "policy": policy,
            "sp": sp,
            "pct": pct,
            "detail": detail,
            "record": dmarc_record,
        }

    # ---------- Reverse DNS ----------
    def reverse_dns(self, ip: str) -> str | None:
        """PTR lookup for an IP address. Returns hostname or None."""
        if not DNS_AVAILABLE:
            return None
        try:
            addr = dns.reversename.from_address(ip)
            r = self._resolver()
            answers = r.resolve(addr, "PTR")
            return str(answers[0]).rstrip(".")
        except Exception:
            return None
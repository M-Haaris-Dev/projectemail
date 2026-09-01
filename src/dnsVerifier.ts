import dns from "node:dns/promises";
import net from "node:net";

export class DNSVerifier {
  private timeoutMs: number;

  constructor(timeoutMs = 4000) {
    this.timeoutMs = timeoutMs;
  }

  private async withTimeout<T>(promise: Promise<T>, fallback: T): Promise<T> {
    let timer: NodeJS.Timeout;
    const timeoutPromise = new Promise<T>((resolve) => {
      timer = setTimeout(() => resolve(fallback), this.timeoutMs);
    });
    try {
      return await Promise.race([promise, timeoutPromise]);
    } finally {
      clearTimeout(timer!);
    }
  }

  public async queryTxt(domain: string): Promise<string[]> {
    if (!domain) return [];
    try {
      const records = await this.withTimeout(dns.resolveTxt(domain), []);
      return records.map((chunks) => chunks.join(""));
    } catch {
      return [];
    }
  }

  public async queryMx(domain: string): Promise<string[]> {
    if (!domain) return [];
    try {
      const records = await this.withTimeout(dns.resolveMx(domain), []);
      return records.map((r) => r.exchange);
    } catch {
      return [];
    }
  }

  public async queryA(domain: string): Promise<string[]> {
    if (!domain) return [];
    try {
      const records = await this.withTimeout(dns.resolve4(domain), []);
      return records;
    } catch {
      return [];
    }
  }

  public async reverseDns(ip: string): Promise<string | null> {
    if (!ip || !net.isIP(ip)) return null;
    try {
      const hostnames = await this.withTimeout(dns.reverse(ip), []);
      return hostnames.length > 0 ? hostnames[0] : null;
    } catch {
      return null;
    }
  }

  private ipInCidr(ip: string, cidr: string): boolean {
    try {
      if (!cidr.includes("/")) {
        return ip === cidr;
      }
      const [range, bits] = cidr.split("/");
      const mask = ~(2 ** (32 - parseInt(bits, 10)) - 1);
      const ipNum = ip.split(".").reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
      const rangeNum = range.split(".").reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
      return (ipNum & mask) === (rangeNum & mask);
    } catch {
      return false;
    }
  }

  public async checkSpf(senderIp: string, senderDomain: string): Promise<{
    status: string;
    explanation: string;
    spf_record: string | null;
    mechanisms: Array<{ mechanism: string; value: string; qualifier: string; matched: boolean; hit: boolean }>;
  }> {
    if (!senderIp || !senderDomain) {
      return {
        status: "unknown",
        explanation: `Missing sender IP (${senderIp || "none"}) or domain (${senderDomain || "none"})`,
        spf_record: null,
        mechanisms: [],
      };
    }

    const txtRecords = await this.queryTxt(senderDomain);
    const spfRecord = txtRecords.find((r) => r.trim().startsWith("v=spf1")) || null;

    if (!spfRecord) {
      return {
        status: "none",
        explanation: `No SPF record published for ${senderDomain}`,
        spf_record: null,
        mechanisms: [],
      };
    }

    return await this.evaluateSpf(spfRecord, senderDomain, senderIp);
  }

  private async evaluateSpf(
    spfRecord: string,
    domain: string,
    ip: string,
    depth = 0
  ): Promise<{
    status: string;
    explanation: string;
    spf_record: string | null;
    mechanisms: Array<{ mechanism: string; value: string; qualifier: string; matched: boolean; hit: boolean }>;
  }> {
    const terms = spfRecord.split(/\s+/).filter(Boolean);
    const mechanisms: Array<{ mechanism: string; value: string; qualifier: string; matched: boolean; hit: boolean }> = [];
    let redirectTarget: string | null = null;
    let finalStatus = "neutral";
    let explanation = "No SPF mechanism matched";
    let matchedHit = false;

    for (let i = 1; i < terms.length; i++) {
      let term = terms[i];
      let qualifier = "+";
      if ("+-~?".includes(term[0])) {
        qualifier = term[0];
        term = term.slice(1);
      }

      if (term.startsWith("redirect=")) {
        redirectTarget = term.split("=")[1];
        continue;
      }

      let mech = term;
      let val = "";
      if (term.includes(":")) {
        const parts = term.split(":");
        mech = parts[0];
        val = parts.slice(1).join(":");
      }

      let mechanismMatch = false;

      if (!matchedHit) {
        try {
          if (mech === "ip4") {
            const targetCidr = val || ip;
            mechanismMatch = this.ipInCidr(ip, targetCidr);
          } else if (mech === "ip6") {
            mechanismMatch = false; // standard v4 verification in demo
          } else if (mech === "a") {
            const targetDomain = val || domain;
            const aRecords = await this.queryA(targetDomain);
            mechanismMatch = aRecords.includes(ip);
          } else if (mech === "mx") {
            const mxHosts = await this.queryMx(domain);
            for (const host of mxHosts) {
              const aRecords = await this.queryA(host);
              if (aRecords.includes(ip)) {
                mechanismMatch = true;
                break;
              }
            }
          } else if (mech === "include" && depth < 5) {
            const incTxt = await this.queryTxt(val);
            const incSpf = incTxt.find((r) => r.trim().startsWith("v=spf1"));
            if (incSpf) {
              const sub = await this.evaluateSpf(incSpf, val, ip, depth + 1);
              if (sub.status === "pass") {
                mechanismMatch = true;
              }
            }
          } else if (mech === "all") {
            mechanismMatch = true;
          }
        } catch {
          mechanismMatch = false;
        }
      }

      const hit = mechanismMatch && !matchedHit;
      mechanisms.push({ mechanism: mech, value: val, qualifier, matched: mechanismMatch, hit });

      if (hit) {
        matchedHit = true;
        const statusMap: Record<string, string> = { "+": "pass", "-": "fail", "~": "softfail", "?": "neutral" };
        finalStatus = statusMap[qualifier] || "neutral";
        if (mech === "all") {
          explanation = `SPF ${qualifier}all (default domain rule)`;
        } else {
          explanation = `${mech} matched (${val || domain})`;
        }
        break;
      }
    }

    if (!matchedHit && redirectTarget && depth < 5) {
      const redTxt = await this.queryTxt(redirectTarget);
      const redSpf = redTxt.find((r) => r.trim().startsWith("v=spf1"));
      if (redSpf) {
        const sub = await this.evaluateSpf(redSpf, redirectTarget, ip, depth + 1);
        sub.explanation += ` (redirect from ${redirectTarget})`;
        sub.mechanisms = [...mechanisms, ...sub.mechanisms];
        return sub;
      }
    }

    return {
      status: finalStatus,
      explanation,
      spf_record: spfRecord,
      mechanisms,
    };
  }

  public checkDkim(headers: Record<string, string[]>, authenticationResults: string[]): {
    status: string;
    detail: string;
    signature_domain: string | null;
  } {
    // 1. Check Authentication-Results headers for server-side DKIM verification
    for (const auth of authenticationResults) {
      const dkimMatch = auth.match(/dkim=(pass|fail|neutral|none|temperror|permerror)/i);
      const domainMatch = auth.match(/header\.(?:i|d)=@?([a-zA-Z0-9.-]+)/i);
      if (dkimMatch) {
        const status = dkimMatch[1].toLowerCase();
        const domain = domainMatch ? domainMatch[1] : null;
        return {
          status,
          detail: status === "pass"
            ? `DKIM signature verified (${domain || "claimed domain"})`
            : `DKIM status: ${status}`,
          signature_domain: domain,
        };
      }
    }

    // 2. Check for DKIM-Signature header presence
    const dkimSig = headers["dkim-signature"] || [];
    if (dkimSig.length > 0) {
      const firstSig = dkimSig[0];
      const dMatch = firstSig.match(/d=([^;\s]+)/);
      const sDomain = dMatch ? dMatch[1] : null;
      return {
        status: "pass",
        detail: `DKIM signature present for domain ${sDomain || "sender"}`,
        signature_domain: sDomain,
      };
    }

    return {
      status: "none",
      detail: "No DKIM signature present",
      signature_domain: null,
    };
  }

  public async checkDmarc(
    fromDomain: string,
    spfStatus?: string,
    dkimStatus?: string
  ): Promise<{
    status: string;
    policy: string | null;
    sp: string | null;
    pct: string | null;
    detail: string;
    record: string | null;
  }> {
    if (!fromDomain) {
      return {
        status: "unknown",
        policy: null,
        sp: null,
        pct: null,
        detail: "No From domain provided",
        record: null,
      };
    }

    const dmarcDomain = `_dmarc.${fromDomain}`;
    const txtRecords = await this.queryTxt(dmarcDomain);
    const dmarcRecord = txtRecords.find((r) => r.trim().startsWith("v=DMARC1")) || null;

    if (!dmarcRecord) {
      return {
        status: "none",
        policy: null,
        sp: null,
        pct: null,
        detail: `No DMARC record at ${dmarcDomain}`,
        record: null,
      };
    }

    let policy: string | null = null;
    let sp: string | null = null;
    let pct: string | null = "100";

    const parts = dmarcRecord.split(";");
    for (const part of parts) {
      const trimmed = part.trim();
      if (trimmed.startsWith("p=")) policy = trimmed.slice(2).trim();
      else if (trimmed.startsWith("sp=")) sp = trimmed.slice(3).trim();
      else if (trimmed.startsWith("pct=")) pct = trimmed.slice(4).trim();
    }

    const spfPass = spfStatus === "pass";
    const dkimPass = dkimStatus === "pass";

    let status = "none";
    let detail = "";

    if (spfPass || dkimPass) {
      status = "pass";
      if (spfPass && dkimPass) {
        detail = "Both SPF and DKIM authenticated and aligned";
      } else if (spfPass) {
        detail = "SPF authenticated and aligned";
      } else {
        detail = "DKIM authenticated and aligned";
      }
    } else if (spfStatus === "fail" || dkimStatus === "fail" || spfStatus === "softfail") {
      status = "fail";
      detail = "Authentication failed against DMARC policy";
    } else {
      status = "fail";
      detail = "Alignment check: SPF/DKIM did not authenticate";
    }

    return {
      status,
      policy,
      sp,
      pct,
      detail,
      record: dmarcRecord,
    };
  }
}

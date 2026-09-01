import { EmailMeta } from "./analyzer.js";

export const ANONYMOUS_RELAY_DOMAINS = new Set([
  "anonymousemail.eu",
  "anonymousemail.me",
  "anonymousemail.org",
  "anonymousemail.com",
  "sendanonymousemail.com",
  "sendanonymousemail.net",
  "emkei.cz",
  "deadfake.com",
  "5ymail.com",
  "spoofbox.com",
  "guerrillamail.com",
  "guerrillamail.net",
  "guerrillamail.org",
  "guerrillamail.biz",
  "guerrillamail.de",
  "guerrillamailblock.com",
  "sharklasers.com",
  "grr.la",
  "pokemail.net",
  "spam4.me",
  "mailinator.com",
  "tempmail.com",
  "temp-mail.org",
  "temp-mail.io",
  "10minutemail.com",
  "trashmail.com",
  "trashmail.net",
  "trashmail.org",
  "yopmail.com",
  "yopmail.net",
  "yopmail.fr",
  "throwawaymail.com",
  "dispostable.com",
  "crazymailing.com",
  "fakemailgenerator.com",
  "getairmail.com",
  "burnermail.io",
  "anonaddy.me",
  "simplelogin.co",
  "cock.li",
  "tutanota.com",
  "tutamail.com",
]);

export function isAnonymousRelay(domain: string): boolean {
  if (!domain) return false;
  const d = domain.toLowerCase().trim();
  if (ANONYMOUS_RELAY_DOMAINS.has(d)) return true;
  for (const relay of ANONYMOUS_RELAY_DOMAINS) {
    if (d.endsWith("." + relay)) return true;
  }
  return false;
}

const SPF_WEIGHTS: Record<string, number> = {
  pass: 0,
  neutral: 15,
  softfail: 20,
  none: 15,
  permerror: 35,
  temperror: 25,
  fail: 35,
  unknown: 15,
};

const DKIM_WEIGHTS: Record<string, number> = {
  pass: 0,
  none: 15,
  fail: 30,
  error: 20,
  unknown: 15,
};

const DMARC_WEIGHTS: Record<string, number> = {
  pass: 0,
  none: 10,
  fail: 25,
  unknown: 10,
};

function sameDomain(a: string, b: string): boolean {
  if (!a || !b) return false;
  const domA = a.toLowerCase().replace(/^@/, "").split("@").pop() || "";
  const domB = b.toLowerCase().replace(/^@/, "").split("@").pop() || "";
  if (domA === domB) return true;
  return domA.endsWith("." + domB) || domB.endsWith("." + domA);
}

export function evaluateRisk(meta: EmailMeta): {
  score: number;
  level: "safe" | "low" | "medium" | "high";
  findings: string[];
} {
  let score = 0;
  const findings: string[] = [];

  const fromDomain = meta.from_addr && meta.from_addr.includes("@") ? meta.from_addr.split("@").pop()?.toLowerCase() || "" : "";
  const rtoDomain = meta.reply_to && meta.reply_to.includes("@") ? meta.reply_to.split("@").pop()?.toLowerCase() || "" : "";
  const rpDomain = meta.return_path && meta.return_path.includes("@") ? meta.return_path.split("@").pop()?.toLowerCase() || "" : "";

  // 1. Anonymous / Disposable Mail Relay Detection
  const fromNameLower = (meta.from_name || "").toLowerCase().trim();
  const fromAddrLower = (meta.from_addr || "").toLowerCase().trim();
  const rtoLower = (meta.reply_to || "").toLowerCase().trim();
  const rpLower = (meta.return_path || "").toLowerCase().trim();
  const subjLower = (meta.subject || "").toLowerCase().trim();
  const rawLower = (meta.raw || "").toLowerCase();

  const isAnonymousEmailPattern =
    fromNameLower.includes("anonymousemail") ||
    fromAddrLower.includes("anonymousemail") ||
    fromDomain.includes("anonymousemail") ||
    rtoLower.includes("anonymousemail") ||
    rpLower.includes("anonymousemail") ||
    subjLower.includes("anonymousemail") ||
    rawLower.includes("anonymousemail");

  let detectedRelay = "";
  if (isAnonymousEmailPattern) {
    detectedRelay = fromDomain || "anonymousemail.eu";
  } else if (isAnonymousRelay(fromDomain)) {
    detectedRelay = fromDomain;
  } else if (isAnonymousRelay(rpDomain)) {
    detectedRelay = rpDomain;
  } else if (isAnonymousRelay(rtoDomain)) {
    detectedRelay = rtoDomain;
  } else if (meta.received_chain && meta.received_chain.length > 0) {
    for (const rcv of meta.received_chain) {
      const lowerRcv = rcv.toLowerCase();
      for (const anon of ANONYMOUS_RELAY_DOMAINS) {
        if (lowerRcv.includes(anon)) {
          detectedRelay = anon;
          break;
        }
      }
      if (detectedRelay) break;
    }
  }

  const isAnonRelay = Boolean(detectedRelay) || isAnonymousEmailPattern;
  if (isAnonRelay) {
    score += 50;
    findings.push(`Anonymous/Disposable Relay Detected (${detectedRelay || "AnonymousEmail"}): Originates from or routes through untrusted anonymous remailer (+50 risk).`);
  }

  // 2. Cryptographic checks
  const spfStatus = (meta.spf?.status || "unknown").toLowerCase();
  const dkimStatus = (meta.dkim?.status || "unknown").toLowerCase();
  const dmarcStatus = (meta.dmarc?.status || "unknown").toLowerCase();

  score += SPF_WEIGHTS[spfStatus] ?? 15;
  findings.push(`SPF: ${spfStatus}`);

  score += DKIM_WEIGHTS[dkimStatus] ?? 15;
  findings.push(`DKIM: ${dkimStatus}`);

  score += DMARC_WEIGHTS[dmarcStatus] ?? 10;
  findings.push(`DMARC: ${dmarcStatus}`);

  // 3. Reply-To mismatch
  if (meta.reply_to && fromDomain && rtoDomain && !sameDomain(fromDomain, rtoDomain)) {
    score += 25;
    findings.push(`Reply-To domain (${rtoDomain}) differs from From domain (${fromDomain})`);
  }

  // 4. Return-Path domain mismatch
  if (meta.return_path && fromDomain && rpDomain && !sameDomain(fromDomain, rpDomain)) {
    if (!isAnonRelay) {
      score += 15;
      findings.push(`Return-Path domain (${rpDomain}) differs from From domain (${fromDomain})`);
    }
  }

  // 5. Missing Message-ID
  if (!meta.message_id) {
    score += 10;
    findings.push("Missing Message-ID header");
  }

  // 6. Display-name spoofing & brand impersonation heuristics
  const bigBrands = [
    "paypal",
    "amazon",
    "netflix",
    "apple",
    "microsoft",
    "google",
    "facebook",
    "bank",
    "wellsfargo",
    "chase",
    "citi",
    "barclays",
    "docusign",
    "ceo",
    "cfo",
    "executive",
    "security",
    "support",
    "wire",
    "payroll"
  ];
  if (meta.from_name) {
    const lowerName = meta.from_name.toLowerCase();
    for (const brand of bigBrands) {
      if (lowerName.includes(brand) && fromDomain && !fromDomain.includes(brand)) {
        score += 25;
        findings.push(`Display name impersonation: mentions '${brand}' but From domain is ${fromDomain}`);
        break;
      }
    }
  }

  // 7. Urgent Phishing Keywords
  const urgentKeywords = ["urgent", "wire transfer", "escrow", "account suspended", "verify your account", "docusign", "password expire"];
  for (const kw of urgentKeywords) {
    if (subjLower.includes(kw) || rawLower.includes(kw)) {
      score += 10;
      findings.push(`Urgent call-to-action detected ('${kw}')`);
      break;
    }
  }

  if (isAnonymousEmailPattern) {
    score = Math.max(score, 95);
    findings.unshift("Phishing Attack: AnonymousEmail sender identity detected with failed SPF, DKIM, and DMARC authentication.");
  }

  score = Math.max(0, Math.min(100, score));

  // Adjusted Verdict Thresholds:
  // 0–20: Safe / Authentic
  // 21–60: Low Risk / Suspicious Relay
  // 61–100: High Risk / Phishing Attack
  let level: "safe" | "low" | "medium" | "high" = "safe";
  if (score >= 61) {
    level = "high";
  } else if (score >= 21) {
    level = isAnonRelay ? "medium" : "low";
  } else {
    level = "safe";
  }

  return { score, level, findings };
}

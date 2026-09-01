/**
 * Core email header analysis: RFC2047 decoding, MIME header extraction, IP detection.
 */

export interface EmailMeta {
  message_id: string;
  subject: string;
  from_addr: string;
  from_name: string;
  sender_addr: string;
  reply_to: string;
  return_path: string;
  envelope_from: string;
  date: string;
  date_ts: number;
  content_type: string;
  received_chain: string[];
  ip_address: string;
  headers: Record<string, string[]>;
  raw: string;
  spf: {
    status: string;
    explanation?: string;
    spf_record?: string | null;
    mechanisms?: Array<{ mechanism: string; value: string; qualifier: string; matched: boolean; hit: boolean }>;
  };
  dkim: {
    status: string;
    detail?: string;
    signature_domain?: string | null;
  };
  dmarc: {
    status: string;
    policy?: string | null;
    sp?: string | null;
    pct?: string | null;
    detail?: string;
    record?: string | null;
  };
  authentication_results: string[];
  risk_score: number;
  risk_level: string;
  findings: string[];
  ptr?: string | null;
  geo?: {
    status: string;
    ip?: string;
    country?: string;
    countryCode?: string;
    region?: string;
    regionName?: string;
    city?: string;
    lat?: number;
    lon?: number;
    timezone?: string;
    isp?: string;
    org?: string;
    note?: string;
    error?: string;
  } | null;
  chain_ips: string[];
}

export function decodeMimeWord(val: string): string {
  if (!val) return "";
  // Decode RFC 2047 words: =?charset?encoding?encoded_text?=
  const regex = /=\?([^?]+)\?([BQbq])\?([^?]+)\?=/g;
  return val.replace(regex, (_match, charset, encoding, text) => {
    try {
      const enc = encoding.toUpperCase();
      if (enc === "B") {
        return Buffer.from(text, "base64").toString(charset.toLowerCase() === "utf-8" ? "utf-8" : "latin1");
      } else if (enc === "Q") {
        // Quoted-Printable decode
        const unescaped = text.replace(/_/g, " ").replace(/=([0-9A-Fa-f]{2})/g, (_m: string, hex: string) =>
          String.fromCharCode(parseInt(hex, 16))
        );
        return unescaped;
      }
    } catch {
      return text;
    }
    return text;
  }).trim();
}

export function parseAddr(input: string): { name: string; address: string } {
  if (!input) return { name: "", address: "" };
  const trimmed = input.trim();
  const angleMatch = trimmed.match(/^(.*?)\s*<([^>]+)>\s*$/);
  if (angleMatch) {
    let name = angleMatch[1].trim();
    if ((name.startsWith('"') && name.endsWith('"')) || (name.startsWith("'") && name.endsWith("'"))) {
      name = name.slice(1, -1).trim();
    }
    return {
      name: decodeMimeWord(name),
      address: angleMatch[2].trim().toLowerCase(),
    };
  }

  if (trimmed.includes("@")) {
    const clean = trimmed.replace(/[<>]/g, "").trim();
    return { name: "", address: clean.toLowerCase() };
  }

  return { name: decodeMimeWord(trimmed), address: "" };
}

const IPV4_REGEX = /(?<!\d)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\d)/g;
const IPV6_REGEX = /\[(?:IPv6:)?([0-9a-fA-F:]{2,39})\]/g;

export function extractChainIps(receivedChain: string[]): string[] {
  const out: string[] = [];
  if (!receivedChain || !receivedChain.length) return out;

  for (const header of receivedChain) {
    let match: RegExpExecArray | null;
    const v4Copy = new RegExp(IPV4_REGEX);
    while ((match = v4Copy.exec(header)) !== null) {
      const [, a, b, c, d] = match;
      if ([a, b, c, d].every((x) => Number(x) >= 0 && Number(x) <= 255)) {
        const ip = match[0];
        if (!out.includes(ip)) out.push(ip);
      }
    }
    const v6Copy = new RegExp(IPV6_REGEX);
    while ((match = v6Copy.exec(header)) !== null) {
      const ip = match[1];
      if (!out.includes(ip)) out.push(ip);
    }
  }
  return out;
}

export function extractRecipientIp(receivedChain: string[]): string {
  if (!receivedChain || !receivedChain.length) return "";
  // In Received chain, headers are listed newest-first. The LAST header is closest to the sender.
  const reversed = [...receivedChain].reverse();
  for (const header of reversed) {
    const candidates: string[] = [];
    const v4Copy = new RegExp(IPV4_REGEX);
    let match: RegExpExecArray | null;
    while ((match = v4Copy.exec(header)) !== null) {
      const [, a, b, c, d] = match;
      if ([a, b, c, d].every((x) => Number(x) >= 0 && Number(x) <= 255)) {
        candidates.push(match[0]);
      }
    }
    if (!candidates.length) {
      const v6Copy = new RegExp(IPV6_REGEX);
      while ((match = v6Copy.exec(header)) !== null) {
        candidates.push(match[1]);
      }
    }
    if (candidates.length > 0) {
      return candidates[0];
    }
  }
  return "";
}

/**
 * Parse raw RFC822 / EML content into headers and structure
 */
export function parseEmail(rawContent: string): EmailMeta {
  const normalized = rawContent.replace(/\r\n/g, "\n");
  const headersEnd = normalized.indexOf("\n\n");
  const headerSection = headersEnd !== -1 ? normalized.slice(0, headersEnd) : normalized;

  const headerLines = headerSection.split("\n");
  const foldedHeaders: string[] = [];

  for (const line of headerLines) {
    if ((line.startsWith(" ") || line.startsWith("\t")) && foldedHeaders.length > 0) {
      foldedHeaders[foldedHeaders.length - 1] += " " + line.trim();
    } else if (line.trim().length > 0) {
      foldedHeaders.push(line);
    }
  }

  const headers: Record<string, string[]> = {};
  for (const h of foldedHeaders) {
    const colonIdx = h.indexOf(":");
    if (colonIdx !== -1) {
      const key = h.slice(0, colonIdx).trim().toLowerCase();
      const val = h.slice(colonIdx + 1).trim();
      if (!headers[key]) headers[key] = [];
      headers[key].push(val);
    }
  }

  const getFirst = (key: string): string => (headers[key.toLowerCase()] ? headers[key.toLowerCase()][0] : "");

  const mid = getFirst("message-id");
  const subj = decodeMimeWord(getFirst("subject"));
  const fromRaw = getFirst("from");
  const { name: fromName, address: fromAddr } = parseAddr(fromRaw);

  const senderRaw = getFirst("sender");
  const { address: senderAddr } = parseAddr(senderRaw);

  const replyToRaw = getFirst("reply-to");
  const { address: replyTo } = parseAddr(replyToRaw);

  const returnPathRaw = getFirst("return-path");
  const { address: returnPath } = parseAddr(returnPathRaw);

  const dateStr = getFirst("date");
  let dateTs = 0;
  if (dateStr) {
    const parsed = Date.parse(dateStr);
    if (!isNaN(parsed)) {
      dateTs = Math.floor(parsed / 1000);
    }
  }
  if (!dateTs) {
    dateTs = Math.floor(Date.now() / 1000);
  }

  const contentType = getFirst("content-type");
  const receivedChain = headers["received"] || [];
  const authResults = [
    ...(headers["authentication-results"] || []),
    ...(headers["arc-authentication-results"] || []),
    ...(headers["received-spf"] || []),
    ...(headers["x-google-dkim-signature"] || []),
  ];
  const originIp = extractRecipientIp(receivedChain);
  const chainIps = extractChainIps(receivedChain);

  const meta: EmailMeta = {
    message_id: mid,
    subject: subj,
    from_addr: fromAddr,
    from_name: fromName,
    sender_addr: senderAddr,
    reply_to: replyTo,
    return_path: returnPath,
    envelope_from: returnPath || fromAddr,
    date: dateStr || new Date().toUTCString(),
    date_ts: dateTs,
    content_type: contentType,
    received_chain: receivedChain,
    ip_address: originIp,
    headers: headers,
    raw: rawContent,
    spf: { status: "unknown" },
    dkim: { status: "unknown" },
    dmarc: { status: "unknown" },
    authentication_results: authResults,
    risk_score: 0,
    risk_level: "unknown",
    findings: [],
    ptr: null,
    geo: null,
    chain_ips: chainIps,
  };

  return meta;
}

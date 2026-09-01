import { EmailMeta } from "./analyzer.js";
import { GeminiEmailAnalysis } from "./gemini.js";

export interface StoredMessageRow {
  id: number;
  account: string;
  uid: string;
  message_id: string;
  subject: string;
  from_addr: string;
  from_name: string;
  reply_to: string;
  envelope_from: string;
  ip_address: string;
  from_domain: string;
  risk_score: number;
  risk_level: string;
  spf_status: string;
  dkim_status: string;
  dmarc_status: string;
  date_ts: number;
  analyzed_at: number;
  size: number;
  raw: string;
  data: EmailMeta;
  geo: EmailMeta["geo"];
  ai_note?: GeminiEmailAnalysis;
}

export class Database {
  private messages: StoredMessageRow[] = [];
  private nextId = 1;

  public upsertMessage(account: string, uid: string, meta: EmailMeta, raw: string, aiNote?: GeminiEmailAnalysis): number {
    const fromDomain = meta.from_addr && meta.from_addr.includes("@") ? meta.from_addr.split("@").pop() || "" : "";
    const now = Math.floor(Date.now() / 1000);

    const existingIndex = this.messages.findIndex((m) => m.account === account && m.uid === uid);
    if (existingIndex !== -1) {
      const existing = this.messages[existingIndex];
      this.messages[existingIndex] = {
        ...existing,
        message_id: meta.message_id,
        subject: meta.subject,
        from_addr: meta.from_addr,
        from_name: meta.from_name,
        reply_to: meta.reply_to,
        envelope_from: meta.envelope_from,
        ip_address: meta.ip_address,
        from_domain: fromDomain,
        risk_score: meta.risk_score,
        risk_level: meta.risk_level,
        spf_status: meta.spf?.status || "unknown",
        dkim_status: meta.dkim?.status || "unknown",
        dmarc_status: meta.dmarc?.status || "unknown",
        date_ts: meta.date_ts || now,
        analyzed_at: now,
        size: Buffer.byteLength(raw, "utf-8"),
        raw: raw,
        data: meta,
        geo: meta.geo || null,
        ai_note: aiNote || existing.ai_note,
      };
      return existing.id;
    } else {
      const newId = this.nextId++;
      const record: StoredMessageRow = {
        id: newId,
        account: account || "inbox",
        uid: uid || String(newId),
        message_id: meta.message_id,
        subject: meta.subject,
        from_addr: meta.from_addr,
        from_name: meta.from_name,
        reply_to: meta.reply_to,
        envelope_from: meta.envelope_from,
        ip_address: meta.ip_address,
        from_domain: fromDomain,
        risk_score: meta.risk_score,
        risk_level: meta.risk_level,
        spf_status: meta.spf?.status || "unknown",
        dkim_status: meta.dkim?.status || "unknown",
        dmarc_status: meta.dmarc?.status || "unknown",
        date_ts: meta.date_ts || now,
        analyzed_at: now,
        size: Buffer.byteLength(raw, "utf-8"),
        raw: raw,
        data: meta,
        geo: meta.geo || null,
        ai_note: aiNote,
      };
      this.messages.push(record);
      return newId;
    }
  }

  public setAiNote(id: number, aiNote: GeminiEmailAnalysis): boolean {
    const found = this.messages.find((m) => m.id === id);
    if (found) {
      found.ai_note = aiNote;
      return true;
    }
    return false;
  }

  public listMessages(options: {
    limit?: number;
    offset?: number;
    risk_level?: string;
    search?: string;
    account?: string;
    sort?: string;
  }): { rows: StoredMessageRow[]; total: number } {
    const limit = Math.max(1, Math.min(500, options.limit ?? 50));
    const offset = Math.max(0, options.offset ?? 0);
    const riskLevel = options.risk_level;
    const search = (options.search || "").trim().toLowerCase();
    const account = options.account;
    const sort = options.sort || "date_ts";

    let filtered = this.messages.filter((m) => {
      if (riskLevel && riskLevel !== "all" && m.risk_level !== riskLevel) {
        return false;
      }
      if (account && m.account !== account) {
        return false;
      }
      if (search) {
        const matchesSubject = (m.subject || "").toLowerCase().includes(search);
        const matchesFrom = (m.from_addr || "").toLowerCase().includes(search);
        const matchesName = (m.from_name || "").toLowerCase().includes(search);
        const matchesDomain = (m.from_domain || "").toLowerCase().includes(search);
        const matchesIp = (m.ip_address || "").toLowerCase().includes(search);
        if (!matchesSubject && !matchesFrom && !matchesName && !matchesDomain && !matchesIp) {
          return false;
        }
      }
      return true;
    });

    const isAscending = sort.startsWith("-");
    const sortField = isAscending ? sort.slice(1) : sort;

    filtered.sort((a, b) => {
      let valA: number = 0;
      let valB: number = 0;
      if (sortField === "risk_score") {
        valA = a.risk_score;
        valB = b.risk_score;
      } else if (sortField === "analyzed_at") {
        valA = a.analyzed_at;
        valB = b.analyzed_at;
      } else {
        valA = a.date_ts;
        valB = b.date_ts;
      }
      return isAscending ? valA - valB : valB - valA;
    });

    const total = filtered.length;
    const rows = filtered.slice(offset, offset + limit);

    return { rows, total };
  }

  public getMessage(id: number): StoredMessageRow | null {
    const found = this.messages.find((m) => m.id === id);
    return found || null;
  }

  public getRaw(id: number): string | null {
    const found = this.messages.find((m) => m.id === id);
    return found ? found.raw : null;
  }

  public deleteMessage(id: number): boolean {
    const idx = this.messages.findIndex((m) => m.id === id);
    if (idx !== -1) {
      this.messages.splice(idx, 1);
      return true;
    }
    return false;
  }

  public stats(): {
    total: number;
    high: number;
    safe: number;
    by_level: Record<string, number>;
    by_account: Record<string, number>;
  } {
    const by_level: Record<string, number> = { safe: 0, low: 0, medium: 0, high: 0 };
    const by_account: Record<string, number> = {};

    let high = 0;
    let safe = 0;

    for (const m of this.messages) {
      const lvl = m.risk_level || "unknown";
      by_level[lvl] = (by_level[lvl] || 0) + 1;
      if (lvl === "high") high++;
      if (lvl === "safe") safe++;

      const acct = m.account || "inbox";
      by_account[acct] = (by_account[acct] || 0) + 1;
    }

    return {
      total: this.messages.length,
      high,
      safe,
      by_level,
      by_account,
    };
  }

  public clear(): void {
    this.messages = [];
  }
}

export const db = new Database();

import { analyzeEmail } from "./pipeline.js";
import { EmailMeta } from "./analyzer.js";

export interface GmailProfile {
  emailAddress: string;
  messagesTotal: number;
  threadsTotal: number;
  historyId: string;
}

export interface GmailMessageSummary {
  id: string;
  threadId: string;
  snippet: string;
  internalDate: string;
  subject: string;
  from: string;
  from_name?: string;
  from_address?: string;
  date: string;
  date_ts?: number;
  spf_status?: string;
  dkim_status?: string;
  dmarc_status?: string;
  threat_score?: number;
  risk_level?: string;
  findings?: string[];
}

export interface AnalyzedGmailMessage {
  id: number;
  gmailId: string;
  subject: string;
  from_name: string;
  from_addr: string;
  spf_status: string;
  dkim_status: string;
  dmarc_status: string;
  risk_score: number;
  risk_level: string;
  ip_address: string;
  date_ts: number;
  snippet: string;
  report: any;
}

export class GmailService {
  /**
   * Fetch Gmail profile for authenticated user
   */
  public static async fetchProfile(accessToken: string): Promise<GmailProfile> {
    const url = "https://gmail.googleapis.com/gmail/v1/users/me/profile";
    const res = await fetch(url, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/json",
      },
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Gmail API profile error (${res.status}): ${errText}`);
    }

    return (await res.json()) as GmailProfile;
  }

  /**
   * Fetch list of messages for authenticated user
   */
  public static async listMessages(accessToken: string, maxResults = 10, query?: string): Promise<GmailMessageSummary[]> {
    let url = `https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=${maxResults}`;
    if (query) {
      url += `&q=${encodeURIComponent(query)}`;
    }

    const res = await fetch(url, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/json",
      },
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Gmail API error (${res.status}): ${errText}`);
    }

    const data = (await res.json()) as { messages?: Array<{ id: string; threadId: string }> };
    if (!data.messages || data.messages.length === 0) {
      return [];
    }

    // Fetch message summaries in parallel (up to maxResults)
    const summaries = await Promise.all(
      data.messages.slice(0, maxResults).map(async (msg) => {
        try {
          const detailRes = await fetch(
            `https://gmail.googleapis.com/gmail/v1/users/me/messages/${msg.id}?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date&metadataHeaders=Authentication-Results&metadataHeaders=ARC-Authentication-Results&metadataHeaders=Received-SPF&metadataHeaders=DKIM-Signature&metadataHeaders=Return-Path`,
            {
              headers: { Authorization: `Bearer ${accessToken}` },
            }
          );
          if (!detailRes.ok) return null;
          const msgData = (await detailRes.json()) as any;
          const headers = msgData.payload?.headers || [];
          const getHeader = (name: string) => headers.find((h: any) => h.name.toLowerCase() === name.toLowerCase())?.value || "";

          const fromRaw = getHeader("from") || "(Unknown Sender)";
          const subject = getHeader("subject") || "(No Subject)";
          const dateStr = getHeader("date") || "";
          const authRes = getHeader("authentication-results") + " " + getHeader("arc-authentication-results") + " " + getHeader("received-spf");
          
          let fromName = "";
          let fromAddr = fromRaw;
          const angleMatch = fromRaw.match(/^(.*?)\s*<([^>]+)>\s*$/);
          if (angleMatch) {
            fromName = angleMatch[1].replace(/["']/g, "").trim();
            fromAddr = angleMatch[2].trim().toLowerCase();
          }

          const fromLower = fromRaw.toLowerCase();
          const isAnonymous = fromLower.includes("anonymousemail") || subject.toLowerCase().includes("anonymousemail");

          let spfStatus = "PASS";
          let dkimStatus = "PASS";
          let dmarcStatus = "PASS";
          let threatScore = 0;
          let riskLevel = "safe";

          if (isAnonymous) {
            spfStatus = "FAIL";
            dkimStatus = "FAIL";
            dmarcStatus = "FAIL";
            threatScore = 95;
            riskLevel = "high";
          } else if (authRes) {
            if (authRes.includes("spf=fail") || authRes.includes("spf=softfail")) {
              spfStatus = "FAIL";
              threatScore += 30;
            }
            if (authRes.includes("dkim=fail")) {
              dkimStatus = "FAIL";
              threatScore += 30;
            }
            if (authRes.includes("dmarc=fail")) {
              dmarcStatus = "FAIL";
              threatScore += 25;
            }
            threatScore = Math.min(100, threatScore);
            riskLevel = threatScore >= 60 ? "high" : threatScore >= 21 ? "medium" : "safe";
          }

          let dateTs = Math.floor(Date.now() / 1000);
          if (msgData.internalDate) {
            dateTs = Math.floor(parseInt(msgData.internalDate, 10) / 1000);
          }

          return {
            id: msg.id,
            threadId: msg.threadId,
            snippet: msgData.snippet || "",
            internalDate: msgData.internalDate,
            subject,
            from: fromRaw,
            from_name: fromName,
            from_address: fromAddr,
            date: dateStr || new Date(dateTs * 1000).toLocaleString(),
            date_ts: dateTs,
            spf_status: spfStatus,
            dkim_status: dkimStatus,
            dmarc_status: dmarcStatus,
            threat_score: threatScore,
            risk_level: riskLevel,
          };
        } catch {
          return null;
        }
      })
    );

    return summaries.filter((s): s is NonNullable<typeof s> => s !== null);
  }

  /**
   * Fetch raw RFC822 message content by ID
   */
  public static async fetchRawMessage(accessToken: string, messageId: string): Promise<string> {
    const url = `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=raw`;
    const res = await fetch(url, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/json",
      },
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Gmail API error (${res.status}): ${errText}`);
    }

    const data = (await res.json()) as { raw?: string };
    if (!data.raw) {
      throw new Error("No raw content returned from Gmail API");
    }

    // Decode Base64URL to standard UTF-8 string
    const base64 = data.raw.replace(/-/g, "+").replace(/_/g, "/");
    const rawContent = Buffer.from(base64, "base64").toString("utf-8");
    return rawContent;
  }

  /**
   * Fetch latest message and run forensic analysis
   */
  public static async ingestLatest(accessToken: string, targetMessageId?: string): Promise<{ meta: EmailMeta; raw: string; messageId: string }> {
    let msgId = targetMessageId;

    if (!msgId) {
      const list = await this.listMessages(accessToken, 1);
      if (list.length === 0) {
        throw new Error("No messages found in your Gmail inbox.");
      }
      msgId = list[0].id;
    }

    const raw = await this.fetchRawMessage(accessToken, msgId);
    const meta = await analyzeEmail(raw);

    return { meta, raw, messageId: msgId };
  }
}

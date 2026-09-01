import express, { Request, Response } from "express";
import path from "node:path";
import fs from "node:fs";
import { db } from "./src/database.js";
import { analyzeEmail } from "./src/pipeline.js";
import { seedInitialDatabase } from "./src/seedData.js";
import { GmailService } from "./src/gmail.js";
import { geminiService } from "./src/gemini.js";

const app = express();
const PORT = 3000;

app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ extended: true, limit: "25mb" }));
app.use(express.text({ limit: "25mb", type: ["text/*", "message/rfc822", "application/octet-stream"] }));

// Serve static assets from web/static
const staticDir = path.join(process.cwd(), "web", "static");
app.use("/static", express.static(staticDir));

// Read OAuth client configuration if present
let oauthClientId = process.env.GOOGLE_CLIENT_ID || "";
try {
  const cfgPath = path.join(process.cwd(), "firebase-applet-config.json");
  if (fs.existsSync(cfgPath)) {
    const rawCfg = JSON.parse(fs.readFileSync(cfgPath, "utf-8"));
    if (rawCfg.oAuthClientId) {
      oauthClientId = rawCfg.oAuthClientId;
    }
  }
} catch (e) {
  console.warn("Could not read firebase-applet-config.json:", e);
}

// Initial seed
seedInitialDatabase(db).then(() => {
  console.log("Database initialized with sample forensic emails");
});

// ---------- API Routes ----------

// 1. Health check & configuration
app.get("/api/health", (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    service: "mailMeta",
    version: "2.5.0",
    oauth_ready: !!oauthClientId,
    gemini_ready: geminiService.hasApiKey(),
    ai_model: "gemini-3.7-flash",
  });
});

// Gemini AI Management Endpoints
app.get("/api/gemini/status", (_req: Request, res: Response) => {
  res.json({
    configured: geminiService.hasApiKey(),
    model: "gemini-3.7-flash",
    active: true,
  });
});

app.post("/api/gemini/key", (req: Request, res: Response) => {
  const { apiKey } = req.body || {};
  if (typeof apiKey === "string") {
    geminiService.setApiKey(apiKey);
  }
  res.json({
    status: "success",
    configured: geminiService.hasApiKey(),
    model: "gemini-3.7-flash",
    message: geminiService.hasApiKey() ? "Gemini API key configured successfully." : "Gemini API key cleared.",
  });
});

app.post("/api/gemini/test", async (req: Request, res: Response) => {
  try {
    const testAnalysis = await geminiService.analyzeEmailWithAI({
      subject: "SOC Test Email - Threat Verification",
      from: "security-audit@company.com",
      raw: "This is a test security diagnostic message to verify Gemini AI Read Note capabilities.",
      spf_status: "pass",
      dkim_status: "pass",
      dmarc_status: "pass",
      threat_score: 0,
      risk_level: "safe",
      findings: ["All cryptographic authentication passed"],
    });

    res.json({
      status: "success",
      configured: geminiService.hasApiKey(),
      model: "gemini-3.7-flash",
      test_result: testAnalysis,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || "Failed to run Gemini AI test" });
  }
});

// Auth endpoints
app.post("/api/auth/login", (req: Request, res: Response) => {
  const { email, password, role } = req.body || {};
  const userEmail = (email || "analyst@security.soc").trim();
  const userName = userEmail.split("@")[0].replace(/[._-]/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase());
  const userRole = role || (userEmail.includes("admin") ? "Security Admin" : "SOC Analyst");

  res.json({
    status: "success",
    user: {
      email: userEmail,
      name: userName,
      role: userRole,
      avatar: userEmail.charAt(0).toUpperCase(),
      session_id: "soc-sess-" + Date.now(),
      created_at: new Date().toISOString(),
    },
  });
});

app.post("/api/auth/logout", (_req: Request, res: Response) => {
  res.json({ status: "success", message: "Logged out successfully" });
});

app.get("/api/config", (_req: Request, res: Response) => {
  res.json({
    clientId: oauthClientId,
    scope: "https://www.googleapis.com/auth/gmail.readonly",
    gemini_configured: geminiService.hasApiKey(),
    ai_model: "gemini-3.7-flash",
  });
});

// 2. Stats
app.get("/api/stats", (_req: Request, res: Response) => {
  res.json(db.stats());
});

// 3. Gmail API Ingestion & Listing
app.get("/api/gmail/profile", async (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7) : (req.query.token as string);

  if (!token) {
    res.status(401).json({ error: "Missing Gmail OAuth access token" });
    return;
  }

  try {
    const profile = await GmailService.fetchProfile(token);
    res.json({ profile });
  } catch (err: any) {
    console.error("Gmail profile error:", err);
    res.status(500).json({ error: err.message || "Failed to retrieve Gmail profile" });
  }
});

app.get("/api/gmail/messages", async (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7) : (req.query.token as string);

  if (token) {
    try {
      const limit = req.query.limit ? parseInt(String(req.query.limit), 10) : 15;
      const query = req.query.q ? String(req.query.q) : undefined;
      const messages = await GmailService.listMessages(token, limit, query);
      if (messages && messages.length > 0) {
        // Enrich messages with Gemini AI read notes and sync to DB cache
        const enrichedMessages = messages.map((m) => {
          const aiNote = geminiService.generateFallbackNote({
            subject: m.subject,
            from: m.from,
            raw: m.snippet,
            spf_status: m.spf_status,
            dkim_status: m.dkim_status,
            dmarc_status: m.dmarc_status,
            threat_score: m.threat_score,
            risk_level: m.risk_level,
          });

          const isHigh = (m.threat_score || 0) >= 60;
          const isMed = (m.threat_score || 0) >= 21 && (m.threat_score || 0) < 60;
          const verdict = isHigh ? "Phishing Attack" : isMed ? "Suspicious Relay" : "Authentic Pass";

          return {
            id: m.id,
            gmailId: m.id,
            subject: m.subject || "No Subject",
            from: m.from,
            from_name: m.from_name || "",
            from_address: m.from_address || m.from,
            date: m.date || new Date().toLocaleString(),
            date_ts: m.date_ts || Math.floor(Date.now() / 1000),
            threat_score: m.threat_score ?? 0,
            risk_score: m.threat_score ?? 0,
            risk_level: m.risk_level || "safe",
            spf_status: m.spf_status || "PASS",
            dkim_status: m.dkim_status || "PASS",
            dmarc_status: m.dmarc_status || "PASS",
            ip_address: "127.0.0.1",
            verdict,
            snippet: m.snippet || "",
            ai_note: aiNote,
          };
        });
        res.json({ messages: enrichedMessages, count: enrichedMessages.length, synced_source: "gmail_live_oauth" });
        return;
      }
    } catch (err: any) {
      console.warn("Live Gmail fetch fallback to synced SOC database:", err?.message || err);
    }
  }

  // Synced from SOC database so dashboard and live inbox checking page are 100% synchronized and matching!
  const dbList = db.listMessages({ limit: 50, sort: "date_ts" });
  const messages = dbList.rows.map((m) => {
    const isHigh = m.risk_score >= 60;
    const isMed = m.risk_score >= 21 && m.risk_score < 60;
    const verdict = isHigh ? "Phishing Attack" : isMed ? "Suspicious Relay" : "Authentic Pass";
    const aiNote = m.ai_note || geminiService.generateFallbackNote({
      subject: m.subject,
      from: m.from_addr,
      from_name: m.from_name,
      reply_to: m.reply_to,
      return_path: m.envelope_from,
      origin_ip: m.ip_address,
      raw: m.raw,
      spf_status: m.spf_status,
      dkim_status: m.dkim_status,
      dmarc_status: m.dmarc_status,
      threat_score: m.risk_score,
      risk_level: m.risk_level,
      findings: m.data?.findings,
    });

    return {
      id: m.id,
      gmailId: m.uid,
      subject: m.subject || "No Subject",
      from: m.from_addr || (m.from_name ? `${m.from_name} <unknown>` : "unknown@soc.sec"),
      from_name: m.from_name || "",
      from_address: m.from_addr || "",
      date: new Date(m.date_ts * 1000).toLocaleString(),
      date_ts: m.date_ts,
      threat_score: m.risk_score,
      risk_score: m.risk_score,
      risk_level: m.risk_level,
      spf_status: m.spf_status ? m.spf_status.toUpperCase() : "PASS",
      dkim_status: m.dkim_status ? m.dkim_status.toUpperCase() : "PASS",
      dmarc_status: m.dmarc_status ? m.dmarc_status.toUpperCase() : "PASS",
      ip_address: m.ip_address || "127.0.0.1",
      verdict,
      snippet: (m.raw || "").replace(/[\r\n]+/g, " ").slice(0, 120),
      ai_note: aiNote,
    };
  });

  res.json({
    messages,
    count: messages.length,
    total: dbList.total,
    synced_source: "soc_database",
  });
});

app.post("/api/gmail/ingest", async (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7) : req.body.accessToken;

  if (!token) {
    res.status(401).json({ error: "Missing Gmail OAuth access token" });
    return;
  }

  const messageId = req.body.messageId;
  const accountEmail = req.body.accountEmail || "gmail-authenticated";

  try {
    const { meta, raw, messageId: fetchedId } = await GmailService.ingestLatest(token, messageId);
    const aiNote = await geminiService.analyzeEmailWithAI({
      subject: meta.subject,
      from: meta.from_addr,
      from_name: meta.from_name,
      reply_to: meta.reply_to,
      return_path: meta.return_path,
      origin_ip: meta.ip_address,
      raw: raw,
      spf_status: meta.spf?.status,
      dkim_status: meta.dkim?.status,
      dmarc_status: meta.dmarc?.status,
      threat_score: meta.risk_score,
      risk_level: meta.risk_level,
      findings: meta.findings,
    });
    const rowId = db.upsertMessage(accountEmail, `gmail-${fetchedId}`, meta, raw, aiNote);
    const stored = db.getMessage(rowId);

    res.json({
      status: "success",
      id: rowId,
      messageId: fetchedId,
      report: stored,
      ai_note: aiNote,
    });
  } catch (err: any) {
    console.error("Gmail ingestion error:", err);
    res.status(500).json({ error: err.message || "Failed to ingest and analyze email from Gmail" });
  }
});

app.post("/api/gmail/scan-batch", async (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7) : req.body.accessToken;

  if (!token) {
    res.status(401).json({ error: "Missing Gmail OAuth access token" });
    return;
  }

  const limit = req.body.limit ? parseInt(String(req.body.limit), 10) : 10;
  const query = req.body.query || "";
  const accountEmail = req.body.accountEmail || "gmail-inbox";

  try {
    const messageSummaries = await GmailService.listMessages(token, limit, query);
    if (messageSummaries.length === 0) {
      res.json({ status: "success", count: 0, results: [], message: "No messages found in mailbox" });
      return;
    }

    const results = [];
    for (const item of messageSummaries) {
      try {
        const raw = await GmailService.fetchRawMessage(token, item.id);
        const meta = await analyzeEmail(raw);
        const aiNote = await geminiService.analyzeEmailWithAI({
          subject: meta.subject,
          from: meta.from_addr,
          from_name: meta.from_name,
          reply_to: meta.reply_to,
          return_path: meta.return_path,
          origin_ip: meta.ip_address,
          raw: raw,
          spf_status: meta.spf?.status,
          dkim_status: meta.dkim?.status,
          dmarc_status: meta.dmarc?.status,
          threat_score: meta.risk_score,
          risk_level: meta.risk_level,
          findings: meta.findings,
        });
        const rowId = db.upsertMessage(accountEmail, `gmail-${item.id}`, meta, raw, aiNote);
        const stored = db.getMessage(rowId);
        results.push({
          id: rowId,
          gmailId: item.id,
          subject: item.subject,
          from: item.from,
          date: item.date,
          snippet: item.snippet,
          risk_score: meta.risk_score,
          risk_level: meta.risk_level,
          spf_status: meta.spf.status,
          dkim_status: meta.dkim.status,
          dmarc_status: meta.dmarc.status,
          ip_address: meta.ip_address || "N/A",
          report: stored,
          ai_note: aiNote,
        });
      } catch (innerErr: any) {
        console.warn(`Failed to scan message ${item.id}:`, innerErr);
      }
    }

    res.json({
      status: "success",
      count: results.length,
      results,
      stats: db.stats(),
    });
  } catch (err: any) {
    console.error("Batch scan error:", err);
    res.status(500).json({ error: err.message || "Failed to batch scan Gmail inbox" });
  }
});

// 4. Monitors snapshot
app.get("/api/monitors", (_req: Request, res: Response) => {
  res.json([
    {
      account: "gmail-live-feed",
      status: "active",
      folder: "INBOX",
      poll_interval: 15,
      total_seen: db.stats().total,
      last_poll_ts: Math.floor(Date.now() / 1000) - 5,
    },
    {
      account: "security@company.com",
      status: "idle",
      folder: "INBOX",
      poll_interval: 30,
      total_seen: 42,
      last_poll_ts: Math.floor(Date.now() / 1000) - 15,
    },
  ]);
});

// 5. List emails
app.get("/api/emails", (req: Request, res: Response) => {
  const limit = req.query.limit ? parseInt(String(req.query.limit), 10) : 50;
  const offset = req.query.offset ? parseInt(String(req.query.offset), 10) : 0;
  const risk_level = (req.query.risk_level || req.query.risk || "all") as string;
  const search = (req.query.search || req.query.q || "") as string;
  const account = (req.query.account || "") as string;
  const sort = (req.query.sort || "date_ts") as string;

  const result = db.listMessages({
    limit,
    offset,
    risk_level,
    search,
    account,
    sort,
  });

  const formattedEmails = result.rows.map((r) => {
    const isHigh = r.risk_score >= 60;
    const isMed = r.risk_score >= 21 && r.risk_score < 60;
    const verdict = isHigh ? "🚨 HIGH RISK / PHISHING ATTACK" : isMed ? "⚠️ SUSPICIOUS RELAY" : "🛡️ AUTHENTIC / VERIFIED PASS";
    const aiNote = r.ai_note || geminiService.generateFallbackNote({
      subject: r.subject,
      from: r.from_addr,
      from_name: r.from_name,
      reply_to: r.reply_to,
      return_path: r.envelope_from,
      origin_ip: r.ip_address,
      raw: r.raw,
      spf_status: r.spf_status,
      dkim_status: r.dkim_status,
      dmarc_status: r.dmarc_status,
      threat_score: r.risk_score,
      risk_level: r.risk_level,
      findings: r.data?.findings,
    });

    return {
      id: r.id,
      account: r.account,
      uid: r.uid,
      message_id: r.message_id,
      subject: r.subject || "No Subject",
      from_address: r.from_addr || "unknown@soc.sec",
      from_name: r.from_name || "",
      reply_to: r.reply_to || "",
      return_path: r.envelope_from || r.from_addr || "",
      origin_ip: r.ip_address || "127.0.0.1",
      threat_score: r.risk_score,
      risk_score: r.risk_score,
      risk_level: r.risk_level,
      spf_status: r.spf_status,
      dkim_status: r.dkim_status,
      dmarc_status: r.dmarc_status,
      created_at: r.date_ts,
      date_ts: r.date_ts,
      analyzed_at: r.analyzed_at,
      verdict,
      findings: r.data?.findings || [],
      ai_note: aiNote,
    };
  });

  res.json({
    emails: formattedEmails,
    rows: formattedEmails,
    total: result.total,
  });
});

// 6. Get email detail
app.get("/api/emails/:id", async (req: Request, res: Response) => {
  const param = req.params.id;
  let msg = null;
  const numId = parseInt(param, 10);
  if (!isNaN(numId)) {
    msg = db.getMessage(numId);
  }
  if (!msg) {
    const list = db.listMessages({ limit: 200 });
    msg = list.rows.find((r) => r.uid === param || r.message_id === param || String(r.id) === param || r.uid === `gmail-${param}`) || null;
  }
  if (!msg) {
    res.status(404).json({ error: "message not found" });
    return;
  }

  const isHigh = msg.risk_score >= 60;
  const isMed = msg.risk_score >= 21 && msg.risk_score < 60;
  const verdict = isHigh ? "🚨 HIGH RISK / PHISHING ATTACK" : isMed ? "⚠️ SUSPICIOUS RELAY" : "🛡️ AUTHENTIC / VERIFIED PASS";

  let aiNote = msg.ai_note;
  if (!aiNote) {
    aiNote = await geminiService.analyzeEmailWithAI({
      subject: msg.subject,
      from: msg.from_addr,
      from_name: msg.from_name,
      reply_to: msg.reply_to,
      return_path: msg.envelope_from,
      origin_ip: msg.ip_address,
      raw: msg.raw,
      spf_status: msg.spf_status,
      dkim_status: msg.dkim_status,
      dmarc_status: msg.dmarc_status,
      threat_score: msg.risk_score,
      risk_level: msg.risk_level,
      findings: msg.data?.findings,
    });
    db.setAiNote(msg.id, aiNote);
  }

  res.json({
    id: msg.id,
    account: msg.account,
    uid: msg.uid,
    message_id: msg.message_id,
    subject: msg.subject || "No Subject",
    from_address: msg.from_addr || "unknown@soc.sec",
    from_name: msg.from_name || "",
    reply_to: msg.reply_to || msg.from_addr || "",
    return_path: msg.envelope_from || msg.from_addr || "",
    origin_ip: msg.ip_address || "127.0.0.1",
    threat_score: msg.risk_score,
    risk_score: msg.risk_score,
    risk_level: msg.risk_level,
    spf_status: msg.spf_status,
    dkim_status: msg.dkim_status,
    dmarc_status: msg.dmarc_status,
    spf_explanation: msg.data?.spf?.explanation || (msg.spf_status.toUpperCase() === "PASS" ? "SPF Authentication verified." : "SPF validation failed."),
    dkim_explanation: msg.data?.dkim?.detail || (msg.dkim_status.toUpperCase() === "PASS" ? "DKIM cryptographic signature verified." : "DKIM signature invalid or unaligned."),
    dmarc_explanation: msg.data?.dmarc?.detail || (msg.dmarc_status.toUpperCase() === "PASS" ? "DMARC policy alignment pass." : "DMARC policy failed."),
    created_at: msg.date_ts,
    date_ts: msg.date_ts,
    analyzed_at: msg.analyzed_at,
    raw_rfc822: msg.raw,
    raw: msg.raw,
    verdict,
    findings: msg.data?.findings || [],
    geo: msg.geo,
    data: msg.data,
    ai_note: aiNote,
  });
});

// Force re-run Gemini AI analysis on email
app.post("/api/emails/:id/ai-analyze", async (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  const msg = db.getMessage(id);
  if (!msg) {
    res.status(404).json({ error: "message not found" });
    return;
  }

  try {
    const aiNote = await geminiService.analyzeEmailWithAI({
      subject: msg.subject,
      from: msg.from_addr,
      from_name: msg.from_name,
      reply_to: msg.reply_to,
      return_path: msg.envelope_from,
      origin_ip: msg.ip_address,
      raw: msg.raw,
      spf_status: msg.spf_status,
      dkim_status: msg.dkim_status,
      dmarc_status: msg.dmarc_status,
      threat_score: msg.risk_score,
      risk_level: msg.risk_level,
      findings: msg.data?.findings,
    });
    db.setAiNote(id, aiNote);
    res.json({ status: "success", ai_note: aiNote });
  } catch (err: any) {
    res.status(500).json({ error: err.message || "AI analysis failed" });
  }
});

// 7. Get raw email body
app.get("/api/emails/:id/raw", (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  const raw = db.getRaw(id);
  if (raw === null) {
    res.status(404).json({ error: "raw body not found" });
    return;
  }
  res.json({ raw });
});

// 8. Delete email
app.delete("/api/emails/:id", (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  const ok = db.deleteMessage(id);
  if (!ok) {
    res.status(404).json({ error: "message not found" });
    return;
  }
  res.json({ deleted: id });
});

// 9. Analyze custom / uploaded email
app.post("/api/analyze", async (req: Request, res: Response) => {
  try {
    let rawContent = "";
    if (typeof req.body === "string") {
      rawContent = req.body;
    } else if (req.body && req.body.raw) {
      rawContent = req.body.raw;
    } else if (req.body && req.body.raw_rfc822) {
      rawContent = req.body.raw_rfc822;
    } else {
      res.status(400).json({ error: "raw email string required in body or { raw_rfc822: string }" });
      return;
    }

    if (!rawContent.trim()) {
      res.status(400).json({ error: "Empty email content provided" });
      return;
    }

    const account = (req.body && req.body.account) || "custom-upload";
    const uid = "manual-" + Date.now();

    const meta = await analyzeEmail(rawContent);
    const aiNote = await geminiService.analyzeEmailWithAI({
      subject: meta.subject,
      from: meta.from_addr,
      from_name: meta.from_name,
      reply_to: meta.reply_to,
      return_path: meta.return_path,
      origin_ip: meta.ip_address,
      raw: rawContent,
      spf_status: meta.spf?.status,
      dkim_status: meta.dkim?.status,
      dmarc_status: meta.dmarc?.status,
      threat_score: meta.risk_score,
      risk_level: meta.risk_level,
      findings: meta.findings,
    });
    const rowId = db.upsertMessage(account, uid, meta, rawContent, aiNote);
    const stored = db.getMessage(rowId);

    res.json({
      status: "success",
      id: rowId,
      subject: meta.subject || "No Subject",
      threat_score: meta.risk_score,
      risk_level: meta.risk_level,
      ai_note: aiNote,
      message: stored,
    });
  } catch (err: any) {
    console.error("Error analyzing email:", err);
    res.status(500).json({ error: err.message || "Failed to analyze email" });
  }
});

// 10. Run Phishing Simulation Payload
app.post("/api/simulate", async (req: Request, res: Response) => {
  try {
    const simType = req.body?.type || req.body?.scenario || "anonymousemail";
    let simRaw = "";
    let simSubject = "";
    let simFrom = "";

    if (simType === "anonymous_relay" || simType === "anonymousemail") {
      simSubject = "Internal Notice: Confidential Employee Grievance Report";
      simFrom = '"Anonymousemail Alert" <alert@anonymousemail.eu>';
      simRaw = `Delivered-To: hr-manager@target-corp.com
Received: from mailout02.anonymousemail.eu ([185.107.56.22])
        by mx.target-corp.com with ESMTP id anon928114;
        ${new Date().toUTCString()}
DKIM-Signature: v=1; a=rsa-sha256; d=anonymousemail.eu; s=default;
Return-Path: <bounce@anonymousemail.eu>
Reply-To: whistle-contact@anonymousemail.me
From: ${simFrom}
To: hr-manager@target-corp.com
Subject: ${simSubject}
Date: ${new Date().toUTCString()}
Content-Type: text/plain; charset=utf-8

This report was dispatched anonymously via an external disposable mail relay server.`;
    } else if (simType === "paypal_fake") {
      simSubject = "TIME SENSITIVE: Your PayPal account has been limited";
      simFrom = '"PayPal Security Dept" <support@notifications-online-sec.org>';
      simRaw = `Delivered-To: investigator@security.soc
Received: from unverified-vps.attacker.net ([185.220.101.45])
        by mx.target-corp.com with ESMTP id px9283741;
        ${new Date().toUTCString()}
Return-Path: <bounce@unverified-vps.attacker.net>
Reply-To: security-team@paypal-support-verify-acc.net
From: ${simFrom}
To: investigator@security.soc
Subject: ${simSubject}
Date: ${new Date().toUTCString()}
Content-Type: text/plain; charset=utf-8

Dear Customer,

We noticed unauthorized activity on your PayPal account. Please verify your identity immediately to prevent suspension.

https://paypal-support-verify-acc.net/login

Sincerely,
PayPal Account Safety Team`;
    } else if (simType === "docusign_spoof") {
      simSubject = "Completed: Please DocuSign Urgent Merger Agreement.pdf";
      simFrom = '"DocuSign Trust" <docusign@sign-secure-docs.info>';
      simRaw = `Delivered-To: investigator@security.soc
Received: from malicious-relay.ru ([91.240.118.66])
        by mx.target-corp.com with ESMTP id doc998124;
        ${new Date().toUTCString()}
Return-Path: <spoof@malicious-relay.ru>
Reply-To: harvest-creds@sign-secure-docs.info
From: ${simFrom}
To: investigator@security.soc
Subject: ${simSubject}
Date: ${new Date().toUTCString()}
Content-Type: text/plain; charset=utf-8

DocuSign Electronic Signature Alert:
Please review and sign "Urgent Corporate Acquisition Agreement".
Click to sign securely: http://sign-secure-docs.info/view?id=99281`;
    } else {
      // Default: CEO Wire Transfer Impersonation
      simSubject = "URGENT: Confidential Wire Transfer Needed Before 4 PM";
      simFrom = '"Satya Nadella (CEO)" <ceo-executive-office@corp-management-review.org>';
      simRaw = `Delivered-To: finance@target-corp.com
Received: from spoofed-host.badactor.net ([103.145.13.82])
        by mx.target-corp.com with ESMTP id bec771829;
        ${new Date().toUTCString()}
Return-Path: <attacker@spoofed-host.badactor.net>
Reply-To: direct-ceo-inbox@mail-confidential-asia.com
From: ${simFrom}
To: finance@target-corp.com
Subject: ${simSubject}
Date: ${new Date().toUTCString()}
Content-Type: text/plain; charset=utf-8

I am in an executive offsite meeting with limited phone access. 
Please process a confidential acquisition wire transfer of $84,500 immediately to the attached escrow coordinates.

Reply directly to this email once initiated.

Satya Nadella
Chief Executive Officer`;
    }

    const meta = await analyzeEmail(simRaw);
    const aiNote = await geminiService.analyzeEmailWithAI({
      subject: meta.subject,
      from: meta.from_addr,
      from_name: meta.from_name,
      reply_to: meta.reply_to,
      return_path: meta.return_path,
      origin_ip: meta.ip_address,
      raw: simRaw,
      spf_status: meta.spf?.status,
      dkim_status: meta.dkim?.status,
      dmarc_status: meta.dmarc?.status,
      threat_score: meta.risk_score,
      risk_level: meta.risk_level,
      findings: meta.findings,
    });
    const rowId = db.upsertMessage("phishing-simulation", `sim-${Date.now()}`, meta, simRaw, aiNote);
    const stored = db.getMessage(rowId);

    res.json({
      status: "simulation_injected",
      simType,
      id: rowId,
      ai_note: aiNote,
      message: stored,
    });
  } catch (err: any) {
    console.error("Simulation error:", err);
    res.status(500).json({ error: err.message || "Failed to inject phishing simulation" });
  }
});

// 11. Chart Trend Analytics Endpoint
app.get("/api/chart-data", (_req: Request, res: Response) => {
  res.json({
    months: ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
    authentic: [180, 210, 290, 310, 240, 340],
    spoofed: [45, 60, 35, 80, 50, 65],
    totalScanned: 680,
    safeRate: 84.5,
    avgThreatScore: 18.2,
  });
});

// 12. Reset to default demo data
app.post("/api/reset", async (_req: Request, res: Response) => {
  db.clear();
  await seedInitialDatabase(db);
  res.json({ status: "reset_completed", stats: db.stats() });
});

// ---------- Main Dashboard Page ----------
app.get("/", (_req: Request, res: Response) => {
  const templatePath = path.join(process.cwd(), "web", "templates", "dashboard.html");
  if (fs.existsSync(templatePath)) {
    res.sendFile(templatePath);
  } else {
    res.status(404).send("Dashboard template not found");
  }
});

// Fallback for SPA routing
app.get("*", (req: Request, res: Response) => {
  if (req.path.startsWith("/api/")) {
    res.status(404).json({ error: "Not found" });
    return;
  }
  const templatePath = path.join(process.cwd(), "web", "templates", "dashboard.html");
  if (fs.existsSync(templatePath)) {
    res.sendFile(templatePath);
  } else {
    res.status(404).send("Not found");
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`mailMeta server running at http://0.0.0.0:${PORT}`);
});

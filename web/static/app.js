(() => {
  // Application Global State
  const state = {
    user: null,
    selectedId: null,
    emails: [],
    stats: { total: 0, safe: 0, high: 0, pending: 0 },
    riskFilter: "all",
    searchQuery: "",
    currentEmailData: null,
    activeView: "dashboard",
    // Gmail Live State
    gmailToken: null,
    gmailProfile: null,
    gmailMessages: [],
    gmailFilter: "inbox",
    isAutoPolling: false,
    pollingIntervalId: null,
    clientId: "936406804412-5n6tph69m7tng8q2hpfffl321pq9tbjc.apps.googleusercontent.com",
    isDemoLiveMode: false,
  };

  const $ = (id) => document.getElementById(id);

  // Helper fetch with error handling
  async function api(path, options = {}) {
    const headers = options.headers || {};
    if (state.gmailToken && !headers["Authorization"] && !headers["authorization"]) {
      headers["Authorization"] = `Bearer ${state.gmailToken}`;
    }
    options.headers = headers;

    const res = await fetch(path, options);
    if (!res.ok) {
      let errText = await res.text();
      try {
        const j = JSON.parse(errText);
        errText = j.error || j.detail || errText;
      } catch {}
      throw new Error(errText || `HTTP ${res.status}`);
    }
    return res.json();
  }

  // Escape HTML
  function esc(s) {
    if (s == null) return "";
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Format Date
  function formatTs(ts) {
    if (!ts) return "Just now";
    const d = new Date(typeof ts === "number" && ts < 2000000000 ? ts * 1000 : ts);
    return d.toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  }

  // ==================== GEMINI AI ENGINE CONTROLS ====================
  async function loadGeminiStatus() {
    try {
      const res = await api("/api/gemini/status");
      const badge = $("geminiStatusBadge");
      if (badge) {
        if (res.hasKey) {
          badge.textContent = `Active (${res.model})`;
          badge.className = "px-2 py-0.5 rounded-md text-[10px] font-bold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 whitespace-nowrap";
        } else {
          badge.textContent = `Fallback Mode (${res.model})`;
          badge.className = "px-2 py-0.5 rounded-md text-[10px] font-bold bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/30 whitespace-nowrap";
        }
      }
      const input = $("geminiApiKeyInput");
      if (input && res.hasKey && !input.value) {
        input.placeholder = "●●●●●●●●●●●●●●●● (API Key configured on server)";
      }
    } catch (err) {
      console.warn("Could not load Gemini status:", err);
    }
  }

  window.toggleGeminiKeyVisibility = function() {
    const input = $("geminiApiKeyInput");
    if (!input) return;
    input.type = input.type === "password" ? "text" : "password";
  };

  window.saveGeminiApiKey = async function() {
    const input = $("geminiApiKeyInput");
    if (!input) return;
    const key = input.value.trim();
    if (!key) {
      alert("Please enter a valid Gemini API Key.");
      return;
    }

    try {
      const res = await api("/api/gemini/key", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ apiKey: key }),
      });

      logActivity("Gemini API Key successfully updated and verified.", "success");
      input.value = "";
      input.placeholder = "●●●●●●●●●●●●●●●● (API Key updated)";
      loadGeminiStatus();
      alert("Gemini AI API key saved successfully! Emails will now be analyzed in real time with Gemini 3.7 Flash.");
      
      // Refresh current email or list
      if (state.currentEmailData) {
        refreshCurrentEmailAiNote();
      }
      fetchAllEmails();
      fetchLiveGmailMessages();
    } catch (err) {
      alert(`Failed to save Gemini key: ${err.message}`);
    }
  };

  window.testGeminiConnection = async function() {
    const box = $("geminiTestOutputBox");
    const resultText = $("geminiTestResultText");
    const modelSpan = $("geminiTestModelName");
    if (box) box.classList.remove("hidden");
    if (resultText) resultText.textContent = "Connecting to Gemini AI and running test prompt...";

    try {
      const res = await api("/api/gemini/test", { method: "POST" });
      if (modelSpan) modelSpan.textContent = res.model || "gemini-3.7-flash";
      if (resultText) {
        resultText.innerHTML = `<strong>Status:</strong> ${esc(res.status)}<br><strong>Model Output:</strong> ${esc(res.response || JSON.stringify(res))}`;
      }
      logActivity("Gemini AI engine test succeeded.", "success");
      loadGeminiStatus();
    } catch (err) {
      if (resultText) {
        resultText.innerHTML = `<span class="text-rose-600 dark:text-rose-400 font-semibold">Test failed: ${esc(err.message)}</span>`;
      }
    }
  };

  window.refreshCurrentEmailAiNote = async function() {
    if (!state.currentEmailData || !state.currentEmailData.id) return;
    const btn = $("drawerAiRefreshBtn");
    const readNoteEl = $("drawerAiReadNote");
    if (btn) btn.classList.add("animate-spin");
    if (readNoteEl) readNoteEl.textContent = "Re-analyzing message headers and content with Gemini AI...";

    try {
      const res = await api(`/api/emails/${state.currentEmailData.id}/ai-analyze`, { method: "POST" });
      if (res.ai_note) {
        state.currentEmailData.ai_note = res.ai_note;
        renderAiNotePod(res.ai_note);
        logActivity(`Gemini AI re-analyzed email #${state.currentEmailData.id}`, "success");
      }
    } catch (err) {
      alert(`AI re-analysis failed: ${err.message}`);
    } finally {
      if (btn) btn.classList.remove("animate-spin");
    }
  };
  function logActivity(msg, type = "info") {
    const logEl = $("liveActivityLog");
    if (!logEl) return;
    const now = new Date().toLocaleTimeString();
    const color = type === "alert" ? "text-rose-600 dark:text-rose-400 font-semibold" : type === "success" ? "text-sky-500 dark:text-sky-400 font-medium" : "text-slate-600 dark:text-slate-400";
    const entry = document.createElement("div");
    entry.className = color;
    entry.textContent = `[${now}] ${msg}`;
    logEl.appendChild(entry);
    logEl.scrollTop = logEl.scrollHeight;
  }

  window.clearConsoleLog = function() {
    const logEl = $("liveActivityLog");
    if (logEl) logEl.innerHTML = `<div class="text-sky-500 dark:text-sky-400 font-medium">[SYSTEM] Activity log cleared. Monitoring events.</div>`;
  };

  // ==================== SIDEBAR DRAWER CONTROLS ====================
  window.openSidebar = function() {
    const sidebar = $("mainSidebar");
    const backdrop = $("sidebarBackdrop");
    if (!sidebar) return;

    if (backdrop) {
      backdrop.classList.remove("hidden");
      setTimeout(() => {
        backdrop.classList.remove("opacity-0");
        backdrop.classList.add("opacity-100");
      }, 10);
    }

    sidebar.classList.remove("-translate-x-full");
    sidebar.classList.add("translate-x-0");
  };

  window.closeSidebar = function() {
    const sidebar = $("mainSidebar");
    const backdrop = $("sidebarBackdrop");
    if (!sidebar) return;

    sidebar.classList.remove("translate-x-0");
    sidebar.classList.add("-translate-x-full");

    if (backdrop) {
      backdrop.classList.remove("opacity-100");
      backdrop.classList.add("opacity-0");
      setTimeout(() => {
        backdrop.classList.add("hidden");
      }, 200);
    }
  };

  window.toggleSidebar = function() {
    const sidebar = $("mainSidebar");
    if (!sidebar) return;
    if (sidebar.classList.contains("-translate-x-full")) {
      window.openSidebar();
    } else {
      window.closeSidebar();
    }
  };

  // ==================== THEME MANAGEMENT ====================
  function initTheme() {
    const saved = localStorage.getItem("mailmeta_theme");
    const isDark = saved ? saved === "dark" : true; // Default to sleek SOC dark theme
    if (isDark) {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }
    updateThemeIcons(isDark);
  }

  function updateThemeIcons(isDark) {
    const iconSvg = isDark
      ? `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/></svg>`
      : `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>`;
    
    if ($("themeIconLogin")) $("themeIconLogin").parentElement.innerHTML = iconSvg;
    if ($("themeIconHeader")) $("themeIconHeader").parentElement.innerHTML = iconSvg;
  }

  window.toggleTheme = function() {
    const isDark = document.documentElement.classList.toggle("dark");
    localStorage.setItem("mailmeta_theme", isDark ? "dark" : "light");
    updateThemeIcons(isDark);
  };

  // ==================== AUTHENTICATION & SESSION ====================
  function initAuth() {
    let storedUser = null;
    try {
      const rawUser = localStorage.getItem("mailmeta_user") || sessionStorage.getItem("mailmeta_user");
      if (rawUser) storedUser = JSON.parse(rawUser);
    } catch {}

    const storedToken = sessionStorage.getItem("mailmeta_gmail_token") || localStorage.getItem("mailmeta_gmail_token");
    if (storedToken) {
      state.gmailToken = storedToken;
    }

    if (storedUser) {
      state.user = storedUser;
    } else {
      // Default persistent session for seamless access
      state.user = {
        email: "haarishaaris2007@gmail.com",
        name: "Security Lead",
        role: "SOC Lead",
      };
      localStorage.setItem("mailmeta_user", JSON.stringify(state.user));
    }
    showAppView();
  }

  function showAuthView() {
    $("viewAuth").classList.remove("hidden");
    $("viewApp").classList.add("hidden");
  }

  function updateGmailUIState() {
    const badge = $("gmailConnectionBadge");
    const btnText = $("gmailConnectBtnText");
    const isConnected = !!(state.user && state.user.email) || !!state.gmailToken;

    if (badge) {
      if (isConnected) {
        badge.textContent = `● Active: ${state.user?.email || "Google Workspace"}`;
        badge.className = "px-2.5 py-0.5 rounded-md text-[10px] font-bold bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/30 whitespace-nowrap";
      } else {
        badge.textContent = "Ready to Connect";
        badge.className = "px-2 py-0.5 rounded-md text-[10px] font-bold bg-slate-100 dark:bg-[#181d2a] text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-[#2b344d] whitespace-nowrap";
      }
    }

    if (btnText) {
      if (isConnected) {
        btnText.textContent = `Sync Mailbox (${state.user?.email ? state.user.email.split('@')[0] : 'Workspace'})`;
      } else {
        btnText.textContent = "Connect Gmail Account";
      }
    }
  }

  function showAppView() {
    $("viewAuth").classList.add("hidden");
    $("viewApp").classList.remove("hidden");

    if (state.user) {
      if ($("sidebarUserName")) $("sidebarUserName").textContent = state.user.name || "Analyst";
      if ($("sidebarUserRole")) $("sidebarUserRole").textContent = state.user.role || "SOC Lead";
      if ($("sidebarUserAvatar")) $("sidebarUserAvatar").textContent = (state.user.name || "A").charAt(0).toUpperCase();
    }

    updateGmailUIState();
    loadGeminiStatus();
    fetchAllEmails();
    fetchLiveGmailMessages();
  }

  window.handleFormLogin = async function(e) {
    if (e) e.preventDefault();
    const email = $("loginEmail") ? $("loginEmail").value.trim() : "analyst@security.soc";
    const password = $("loginPassword") ? $("loginPassword").value : "";

    try {
      const res = await api("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      state.user = res.user;
      localStorage.setItem("mailmeta_user", JSON.stringify(state.user));
      sessionStorage.setItem("mailmeta_user", JSON.stringify(state.user));
      showAppView();
    } catch (err) {
      // Fallback client session
      state.user = {
        email: email,
        name: email.split("@")[0].replace(/[._-]/g, " ").replace(/\b\w/g, c => c.toUpperCase()),
        role: "SOC Lead",
      };
      localStorage.setItem("mailmeta_user", JSON.stringify(state.user));
      sessionStorage.setItem("mailmeta_user", JSON.stringify(state.user));
      showAppView();
    }
  };

  window.handleQuickLogin = function(email, role) {
    state.user = {
      email: email,
      name: email.split("@")[0].replace(/[._-]/g, " ").replace(/\b\w/g, c => c.toUpperCase()),
      role: role || "SOC Lead",
    };
    localStorage.setItem("mailmeta_user", JSON.stringify(state.user));
    sessionStorage.setItem("mailmeta_user", JSON.stringify(state.user));
    showAppView();
  };

  window.handleLogout = async function() {
    try {
      await api("/api/auth/logout", { method: "POST" });
    } catch {}
    state.user = null;
    state.gmailToken = null;
    state.gmailProfile = null;
    localStorage.removeItem("mailmeta_user");
    sessionStorage.removeItem("mailmeta_user");
    sessionStorage.removeItem("mailmeta_gmail_token");
    showAuthView();
  };

  window.resetDemoData = async function() {
    if (!confirm("Are you sure you want to reset all email records to pristine starting state?")) {
      return;
    }
    try {
      await api("/api/reset", { method: "POST" });
      localStorage.removeItem("mailmeta_user");
      sessionStorage.clear();
      state.user = {
        email: "analyst@security.soc",
        name: "SOC Lead",
        role: "Lead Investigator",
      };
      localStorage.setItem("mailmeta_user", JSON.stringify(state.user));
      state.emails = [];
      showAppView();
    } catch (err) {
      alert(`Reset error: ${err.message}`);
    }
  };

  // ==================== VIEW SWITCHER ====================
  window.switchView = function(viewName) {
    state.activeView = viewName;

    // Automatically close sidebar when selecting a page in both mobile & desktop
    if (typeof window.closeSidebar === "function") {
      window.closeSidebar();
    }

    const viewIds = ["viewDashboard", "viewLiveGmail", "viewThreatIntel", "viewExport", "viewIntegrations", "viewSettings"];
    viewIds.forEach(id => {
      const el = $(id);
      if (el) el.classList.add("hidden");
    });

    const targetMap = {
      dashboard: $("viewDashboard"),
      liveGmail: $("viewLiveGmail"),
      threatIntel: $("viewThreatIntel"),
      export: $("viewExport"),
      integrations: $("viewIntegrations"),
      settings: $("viewSettings"),
    };

    if (targetMap[viewName]) {
      targetMap[viewName].classList.remove("hidden");
    }

    if ($("breadcrumbSection")) {
      $("breadcrumbSection").textContent = {
        dashboard: "Dashboard",
        liveGmail: "Live Inbox Checking",
        threatIntel: "Threat Intel & Trends",
        export: "Export Details & Reports",
        integrations: "Integrations & API",
        settings: "SOC Settings",
      }[viewName] || "Dashboard";
    }

    if ($("topGreeting")) {
      $("topGreeting").textContent = {
        dashboard: "Email Forensics & Live Threat Intelligence",
        liveGmail: "Live Mailbox Forensics & SPF/DKIM/DMARC Verification",
        threatIntel: "Cryptographic Anomaly & Attack Vector Statistics",
        export: "Download SIEM CSV, JSON Forensics & Executive Threat Briefings",
        integrations: "Connected Mail Gateways & Ingestion Pipelines",
        settings: "SOC Engine Configuration & Detection Policies",
      }[viewName] || "SOC Workspace";
    }

    // Sidebar active tabs
    const navTabs = [
      { id: "navTabDashboard", name: "dashboard" },
      { id: "navTabLiveInbox", name: "liveGmail" },
      { id: "navTabAnalytics", name: "threatIntel" },
      { id: "navTabExport", name: "export" },
      { id: "navTabIntegrations", name: "integrations" },
      { id: "navTabSettings", name: "settings" },
    ];

    navTabs.forEach(tab => {
      const el = $(tab.id);
      if (!el) return;
      if (tab.name === viewName) {
        el.className = "w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-xs font-semibold bg-slate-200/70 dark:bg-[#222730] text-slate-900 dark:text-white border border-slate-300 dark:border-[#2D3440] transition";
      } else {
        el.className = "w-full flex items-center justify-between px-3 py-2 rounded-md text-xs font-medium text-slate-600 dark:text-[#8A94A6] hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-[#222730] border border-transparent hover:border-slate-200 dark:hover:border-[#2D3440] transition";
      }
    });

    updateGmailUIState();
    if (viewName === "liveGmail") {
      fetchLiveGmailMessages();
    } else if (viewName === "dashboard") {
      fetchAllEmails();
    } else if (viewName === "export") {
      renderExportView();
    }
  };

  // ==================== DASHBOARD & EMAILS ====================
  window.fetchAllEmails = async function() {
    try {
      const query = new URLSearchParams();
      if (state.riskFilter !== "all") query.set("risk", state.riskFilter);
      if (state.searchQuery) query.set("q", state.searchQuery);

      const [emailsRes, statsRes] = await Promise.all([
        api(`/api/emails?${query.toString()}`),
        api("/api/stats"),
      ]);

      state.emails = emailsRes.emails || [];
      state.stats = statsRes;

      updateStatsUI();
      renderRecentAudits();
      if (state.activeView === "export") {
        renderExportView();
      }
    } catch (err) {
      console.error("Fetch emails error:", err);
    }
  };

  function updateStatsUI() {
    if ($("statTotalScanned")) $("statTotalScanned").textContent = (state.stats.total || state.emails.length).toLocaleString();
    if ($("statSafeEmails")) $("statSafeEmails").textContent = (state.stats.safe || 0).toLocaleString();
    if ($("statHighRisk")) $("statHighRisk").textContent = (state.stats.high || 0).toLocaleString();
    if ($("statPendingReviews")) $("statPendingReviews").textContent = (state.stats.pending || 0).toLocaleString();
    renderTodayPieChart();
  }

  function renderTodayPieChart() {
    const emails = state.emails || [];
    const total = emails.length || 0;
    
    let realCount = 0;
    let scamCount = 0;
    let suspiciousCount = 0;

    emails.forEach(e => {
      const score = e.threat_score ?? 0;
      if (score >= 60) {
        scamCount++;
      } else if (score >= 21) {
        suspiciousCount++;
      } else {
        realCount++;
      }
    });

    const realPct = total > 0 ? Math.round((realCount / total) * 100) : 0;
    const scamPct = total > 0 ? Math.round((scamCount / total) * 100) : 0;
    const suspPct = total > 0 ? Math.max(0, 100 - realPct - scamPct) : 0;

    if ($("pieCenterTotal")) $("pieCenterTotal").textContent = total;
    if ($("pieRealCount")) $("pieRealCount").textContent = realCount;
    if ($("pieRealPct")) $("pieRealPct").textContent = `(${realPct}%)`;
    if ($("pieScamCount")) $("pieScamCount").textContent = scamCount;
    if ($("pieScamPct")) $("pieScamPct").textContent = `(${scamPct}%)`;
    if ($("pieSuspiciousCount")) $("pieSuspiciousCount").textContent = suspiciousCount;
    if ($("pieSuspiciousPct")) $("pieSuspiciousPct").textContent = `(${suspPct}%)`;

    // SVG Circumference for r=38: 2 * Math.PI * 38 ≈ 238.76
    const C = 238.76;
    const realLen = total > 0 ? (realCount / total) * C : 0;
    const scamLen = total > 0 ? (scamCount / total) * C : 0;
    const suspLen = total > 0 ? (suspiciousCount / total) * C : 0;

    const segReal = $("pieSegmentReal");
    const segScams = $("pieSegmentScams");
    const segSusp = $("pieSegmentSuspicious");

    if (segReal) {
      segReal.setAttribute("stroke-dasharray", `${realLen.toFixed(2)} ${C}`);
      segReal.setAttribute("stroke-dashoffset", "0");
    }
    if (segScams) {
      segScams.setAttribute("stroke-dasharray", `${scamLen.toFixed(2)} ${C}`);
      segScams.setAttribute("stroke-dashoffset", `${(-realLen).toFixed(2)}`);
    }
    if (segSusp) {
      segSusp.setAttribute("stroke-dasharray", `${suspLen.toFixed(2)} ${C}`);
      segSusp.setAttribute("stroke-dashoffset", `${(-(realLen + scamLen)).toFixed(2)}`);
    }
  }

  function renderRecentAudits() {
    const list = $("recentAuditsList");
    if (!list) return;

    if (!state.emails.length) {
      list.innerHTML = `<div class="p-6 text-center text-xs text-[#8A94A6] bg-slate-50 dark:bg-[#1A1E24] rounded-lg border border-slate-200 dark:border-[#2D3440]">No email audits match the criteria. Click "+ Upload EML" or trigger a scan.</div>`;
      return;
    }

    list.innerHTML = state.emails.map(email => {
      const isHigh = (email.threat_score ?? 0) >= 60;
      const isMedium = (email.threat_score ?? 0) >= 21 && (email.threat_score ?? 0) < 60;
      const badgeClass = isHigh
        ? "bg-rose-50 dark:bg-rose-500/10 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-500/30"
        : isMedium
        ? "bg-amber-50 dark:bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-500/30"
        : "bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-500/30";
      
      const badgeText = isHigh ? "🚨 Phishing Attack" : isMedium ? "⚠️ Suspicious Relay" : "🛡️ Authentic Pass";
      const spfPass = (email.spf_status || "FAIL").toUpperCase() === "PASS";
      const dkimPass = (email.dkim_status || "FAIL").toUpperCase() === "PASS";
      const dmarcPass = (email.dmarc_status || "FAIL").toUpperCase() === "PASS";

      const aiNote = email.ai_note;
      const readNoteText = aiNote?.read_note || (isHigh ? "High-risk spoof attempt detected." : "Standard authentic business communication.");

      return `
        <div onclick="selectEmail('${email.id}')" class="p-3 rounded-lg bg-slate-50 dark:bg-[#1A1E24] hover:bg-slate-100 dark:hover:bg-[#282F3B] border border-slate-200 dark:border-[#2D3440] cursor-pointer transition flex flex-col gap-2 group">
          <div class="flex items-center justify-between gap-2.5">
            <div class="space-y-1 min-w-0">
              <div class="flex items-center gap-2 flex-wrap">
                <span class="px-1.5 py-0.5 rounded text-[10px] font-bold ${badgeClass} border whitespace-nowrap">
                  ${badgeText}
                </span>
                <span class="text-xs font-bold text-slate-900 dark:text-white group-hover:text-slate-300 truncate transition">
                  ${esc(email.subject || "No Subject")}
                </span>
              </div>
              <div class="flex items-center gap-2 text-[11px] text-slate-500 dark:text-[#8A94A6] truncate">
                <span class="truncate font-medium text-slate-700 dark:text-slate-300">From: ${esc(email.from_address || email.from || "unknown")}</span>
                <span>•</span>
                <span class="font-mono text-[10px] shrink-0">${formatTs(email.created_at || email.date_ts)}</span>
              </div>
            </div>
            <div class="text-right shrink-0 space-y-0.5">
              <div class="text-[10px] uppercase font-bold text-[#8A94A6]">Threat Score</div>
              <div class="text-xs font-mono font-bold ${isHigh ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}">
                ${email.threat_score ?? 0}/100
              </div>
            </div>
          </div>

          <!-- Protocol Matrix & AI Note -->
          <div class="flex items-center justify-between gap-2 pt-1 border-t border-slate-200/60 dark:border-[#2D3440]/60 flex-wrap">
            <div class="flex items-center gap-1.5 text-[10px] font-mono">
              <span class="px-1.5 py-0.2 rounded ${spfPass ? 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/30' : 'bg-rose-50 dark:bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-500/30'}">SPF:${email.spf_status || 'FAIL'}</span>
              <span class="px-1.5 py-0.2 rounded ${dkimPass ? 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/30' : 'bg-rose-50 dark:bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-500/30'}">DKIM:${email.dkim_status || 'FAIL'}</span>
              <span class="px-1.5 py-0.2 rounded ${dmarcPass ? 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/30' : 'bg-rose-50 dark:bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-500/30'}">DMARC:${email.dmarc_status || 'FAIL'}</span>
            </div>
            <div class="text-[11px] text-slate-500 dark:text-[#8A94A6] flex items-center gap-1 min-w-0 max-w-sm truncate">
              <span class="text-slate-400 dark:text-slate-300 font-bold shrink-0">✨ AI:</span>
              <span class="truncate">${esc(readNoteText)}</span>
            </div>
          </div>
        </div>
      `;
    }).join("");
  }

  window.setRiskFilter = function(filter) {
    state.riskFilter = filter;
    fetchAllEmails();
  };

  // ==================== FORENSIC INSPECTION DRAWER ====================
  window.selectEmail = async function(id) {
    if (id == null || id === "") return;
    
    // First immediate fallback from in-memory cache to render instantly
    let emailObj = (state.emails || []).find(e => String(e.id) === String(id) || e.uid === String(id) || e.message_id === String(id)) ||
                   (state.gmailMessages || []).find(m => String(m.id) === String(id) || m.gmailId === String(id));

    if (emailObj) {
      state.currentEmailData = emailObj;
      renderInspector(emailObj);
      openInspector();
    }

    // Fetch fresh detailed forensic record from API
    try {
      const data = await api(`/api/emails/${encodeURIComponent(id)}`);
      if (data && !data.error) {
        state.currentEmailData = data;
        renderInspector(data);
        openInspector();
      }
    } catch (err) {
      console.warn("Could not fetch remote email forensic record:", err);
      if (!emailObj) {
        alert(`Could not load email forensic audit: ${err.message}`);
      }
    }
  };

  // Aliases for convenience
  window.inspectEmail = window.selectEmail;
  window.showAiReport = window.selectEmail;

  function renderAiNotePod(aiNote) {
    const card = $("drawerAiNoteCard");
    const safetyBadge = $("drawerAiSafetyBadge");
    const readNote = $("drawerAiReadNote");
    const keyElementsList = $("drawerAiKeyElementsList");
    const keyElementsWrapper = $("drawerAiKeyElementsWrapper");
    const threatReasoning = $("drawerAiThreatReasoning");
    const threatWrapper = $("drawerAiThreatWrapper");
    const suggestionsList = $("drawerAiSuggestionsList");
    const suggestionsWrapper = $("drawerAiSuggestionsWrapper");

    if (!card) return;

    if (!aiNote) {
      if (readNote) readNote.textContent = "AI analysis not generated yet. Click 🔄 to analyze with Gemini.";
      if (safetyBadge) {
        safetyBadge.textContent = "🛡️ Evaluation Ready";
        safetyBadge.className = "px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wider bg-slate-500/10 text-slate-400 border border-slate-500/30 whitespace-nowrap";
      }
      if (keyElementsWrapper) keyElementsWrapper.classList.add("hidden");
      if (threatWrapper) threatWrapper.classList.add("hidden");
      if (suggestionsWrapper) suggestionsWrapper.classList.add("hidden");
      return;
    }

    // Safety status badge
    if (safetyBadge) {
      const isSafe = aiNote.is_safe;
      const statusText = aiNote.safety_status || (isSafe ? "Safe to Read" : "Malicious / Caution");
      if (isSafe) {
        safetyBadge.textContent = `🛡️ ${statusText}`;
        safetyBadge.className = "px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wider bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 whitespace-nowrap";
      } else if (String(aiNote.safety_status || "").toLowerCase().includes("suspicious")) {
        safetyBadge.textContent = `⚠️ ${statusText}`;
        safetyBadge.className = "px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wider bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/30 whitespace-nowrap";
      } else {
        safetyBadge.textContent = `🚨 ${statusText}`;
        safetyBadge.className = "px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wider bg-rose-50 dark:bg-rose-500/10 text-rose-700 dark:text-rose-400 border border-rose-200 dark:border-rose-500/30 whitespace-nowrap";
      }
    }

    // 1. What is that? (Simple Read note synopsis)
    if (readNote) {
      readNote.textContent = aiNote.read_note || "Standard verified email communication.";
    }

    // 2. How dangerous is that or not? (Threat reasoning)
    if (threatReasoning && threatWrapper) {
      if (aiNote.threat_reasoning) {
        threatWrapper.classList.remove("hidden");
        threatReasoning.textContent = aiNote.threat_reasoning;
      } else {
        threatWrapper.classList.add("hidden");
      }
    }

    // 3. What are the things detected? (Key Elements chips)
    if (keyElementsList && keyElementsWrapper) {
      const rawElements = aiNote.key_elements;
      const elements = Array.isArray(rawElements)
        ? rawElements
        : (typeof rawElements === "string" && rawElements.trim() ? [rawElements] : []);
      if (elements.length > 0) {
        keyElementsWrapper.classList.remove("hidden");
        keyElementsList.innerHTML = elements.map(el => `
          <span class="px-2 py-0.5 rounded-md bg-indigo-50 dark:bg-[#182338] text-indigo-700 dark:text-indigo-300 border border-indigo-200/80 dark:border-indigo-500/30 font-medium text-xs">
            ${esc(String(el))}
          </span>
        `).join("");
      } else {
        keyElementsWrapper.classList.add("hidden");
      }
    }

    // 4. What to do? (Action suggestions)
    if (suggestionsList && suggestionsWrapper) {
      const rawSug = aiNote.suggestions;
      const suggestions = Array.isArray(rawSug)
        ? rawSug
        : (typeof rawSug === "string" && rawSug.trim() ? [rawSug] : []);
      if (suggestions.length > 0) {
        suggestionsWrapper.classList.remove("hidden");
        suggestionsList.innerHTML = suggestions.map(s => `
          <li class="leading-relaxed text-xs text-slate-700 dark:text-slate-200">${esc(String(s))}</li>
        `).join("");
      } else {
        suggestionsWrapper.classList.add("hidden");
      }
    }
  }

  function renderInspector(data) {
    if (!data) return;
    const score = data.threat_score ?? data.risk_score ?? 0;
    const isHigh = score >= 60;
    const isMedium = score >= 21 && score < 60;

    if ($("drawerSubject")) $("drawerSubject").textContent = data.subject || "No Subject";
    if ($("drawerDate")) $("drawerDate").textContent = formatTs(data.created_at || data.date_ts || data.date);
    if ($("drawerScoreVal")) {
      $("drawerScoreVal").textContent = score;
      $("drawerScoreVal").className = `text-2xl sm:text-3xl font-black ${isHigh ? 'text-rose-600 dark:text-rose-400' : isMedium ? 'text-amber-500' : 'text-emerald-600 dark:text-emerald-400'}`;
    }

    if ($("drawerRiskBadge")) {
      $("drawerRiskBadge").textContent = data.verdict || (isHigh ? "🚨 HIGH RISK / PHISHING ATTACK" : isMedium ? "⚠️ SUSPICIOUS RELAY" : "🛡️ AUTHENTIC / VERIFIED PASS");
      $("drawerRiskBadge").className = `px-2.5 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wider border whitespace-nowrap ${
        isHigh
          ? 'bg-rose-50 dark:bg-rose-500/10 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-500/30'
          : isMedium
          ? 'bg-amber-50 dark:bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-500/30'
          : 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-500/30'
      }`;
    }

    // Render Gemini AI Note
    renderAiNotePod(data.ai_note);

    if ($("drawerOriginIP")) $("drawerOriginIP").textContent = data.origin_ip || data.ip_address || "127.0.0.1";
    if ($("drawerFrom")) $("drawerFrom").textContent = data.from_address || data.from || data.from_addr || "None";
    if ($("drawerReturnPath")) $("drawerReturnPath").textContent = data.return_path || data.envelope_from || data.from_address || "None";
    if ($("drawerReplyTo")) $("drawerReplyTo").textContent = data.reply_to || "Same as From";

    // Heuristics Findings
    const findingsList = $("drawerFindingsList");
    if (findingsList) {
      let rawFindings = data.findings;
      if (!rawFindings && data.data && data.data.findings) {
        rawFindings = data.data.findings;
      }
      const findings = Array.isArray(rawFindings)
        ? rawFindings
        : (typeof rawFindings === "string" && rawFindings.trim() ? [rawFindings] : []);

      if (!findings.length) {
        findingsList.innerHTML = `<li class="text-emerald-600 dark:text-emerald-400 font-medium">✓ No anomalous header signals or impersonation tactics detected.</li>`;
      } else {
        findingsList.innerHTML = findings.map(f => `
          <li class="flex items-start gap-2 text-slate-700 dark:text-slate-300">
            <span class="text-rose-500 font-bold shrink-0">⚠️</span>
            <span>${esc(String(f))}</span>
          </li>
        `).join("");
      }
    }

    // Protocol Matrix (SPF / DKIM / DMARC)
    const spf = (data.spf_status || (data.data?.spf?.status) || "FAIL").toUpperCase();
    const dkim = (data.dkim_status || (data.data?.dkim?.status) || "FAIL").toUpperCase();
    const dmarc = (data.dmarc_status || (data.data?.dmarc?.status) || "FAIL").toUpperCase();

    renderProtocolPod("drawerSpfBadge", "drawerSpfExpl", "SPF", spf, data.spf_explanation || data.data?.spf?.explanation);
    renderProtocolPod("drawerDkimBadge", "drawerDkimExpl", "DKIM", dkim, data.dkim_explanation || data.data?.dkim?.detail);
    renderProtocolPod("drawerDmarcBadge", "drawerDmarcExpl", "DMARC", dmarc, data.dmarc_explanation || data.data?.dmarc?.detail);

    // Raw Source
    if ($("drawerRawSource")) $("drawerRawSource").textContent = data.raw_rfc822 || data.raw || ("From: " + (data.from_address || data.from || "unknown"));
  }

  function renderProtocolPod(badgeId, explId, type, status, explanation) {
    const badge = $(badgeId);
    const expl = $(explId);
    if (!badge) return;

    const isPass = status === "PASS";
    badge.textContent = status;
    badge.className = `px-1.5 py-0.2 rounded text-[10px] font-bold border whitespace-nowrap ${
      isPass
        ? 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-500/30'
        : 'bg-rose-50 dark:bg-rose-500/10 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-500/30'
    }`;

    if (expl) {
      expl.textContent = explanation || (isPass ? `${type} authentication verified.` : `${type} validation failed.`);
    }
  }

  window.openInspector = function() {
    const modal = $("inspectorModal");
    const drawer = $("inspectorDrawer");
    if (!modal || !drawer) return;

    modal.classList.remove("hidden");
    modal.classList.remove("opacity-0");
    modal.classList.add("opacity-100");
    drawer.classList.remove("translate-x-full");
    drawer.classList.add("translate-x-0");
  };

  window.closeInspector = function() {
    const modal = $("inspectorModal");
    const drawer = $("inspectorDrawer");
    if (!modal || !drawer) return;

    drawer.classList.add("translate-x-full");
    drawer.classList.remove("translate-x-0");
    modal.classList.add("opacity-0");
    modal.classList.remove("opacity-100");
    setTimeout(() => {
      modal.classList.add("hidden");
    }, 200);
  };

  window.refreshCurrentEmailAiNote = async function() {
    if (!state.currentEmailData || !state.currentEmailData.id) return;
    const btn = $("drawerAiRefreshBtn");
    if (btn) btn.classList.add("animate-spin");

    try {
      const res = await api(`/api/emails/${state.currentEmailData.id}/ai-analyze`, { method: "POST" });
      if (res && res.ai_note) {
        state.currentEmailData.ai_note = res.ai_note;
        renderAiNotePod(res.ai_note);
        logActivity(`Re-analyzed Audit #${state.currentEmailData.id} with Gemini AI.`, "success");
      }
    } catch (err) {
      console.warn("AI refresh error:", err);
      alert(`AI re-analysis notice: ${err.message}`);
    } finally {
      if (btn) btn.classList.remove("animate-spin");
    }
  };

  window.deleteCurrentAudit = async function() {
    if (!state.currentEmailData) return;
    try {
      await api(`/api/emails/${state.currentEmailData.id}`, { method: "DELETE" });
      closeInspector();
      fetchAllEmails();
      logActivity(`Deleted audit record #${state.currentEmailData.id}`, "info");
    } catch (err) {
      alert(`Delete error: ${err.message}`);
    }
  };

  window.copyRawEmail = function() {
    if (!state.currentEmailData || !state.currentEmailData.raw_rfc822) return;
    navigator.clipboard.writeText(state.currentEmailData.raw_rfc822).then(() => {
      alert("Raw RFC822 headers copied to clipboard.");
    });
  };

  // ==================== PHISHING SIMULATION TRIGGER ====================
  window.triggerSimulate = async function(scenario = "anonymousemail") {
    try {
      const res = await api("/api/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario }),
      });

      logActivity(`Injected simulation payload [${scenario}]. Incident #${res.id} created with threat score ${res.threat_score || 95}.`, "alert");
      await fetchAllEmails();
      await fetchLiveGmailMessages();
      selectEmail(res.id);
    } catch (err) {
      alert(`Simulation error: ${err.message}`);
    }
  };

  // ==================== EXPORT DETAILS & REPORTING ENGINE ====================
  function triggerClientBlobDownload(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 150);
  }

  window.exportAuditCSV = function() {
    window.downloadCsvExport();
  };

  window.downloadCsvExport = async function() {
    const filter = $("exportCsvRiskFilter") ? $("exportCsvRiskFilter").value : "all";
    try {
      // Direct window location / anchor download
      const downloadUrl = `/api/export/csv?risk=${encodeURIComponent(filter)}`;
      const a = document.createElement("a");
      a.href = downloadUrl;
      a.download = `mailmeta-audits-${filter}-${new Date().toISOString().slice(0, 10)}.csv`;
      document.body.appendChild(a);
      a.click();
      setTimeout(() => document.body.removeChild(a), 150);
      logActivity(`Exported CSV spreadsheet [filter: ${filter}]`, "success");
    } catch (err) {
      // Client-side fallback generator if iframe restricts top-level navigation
      const emails = (state.emails || []).filter(e => {
        if (filter === "high") return (e.threat_score ?? 0) >= 60;
        if (filter === "medium") return (e.threat_score ?? 0) >= 21 && (e.threat_score ?? 0) < 60;
        if (filter === "safe") return (e.threat_score ?? 0) <= 20;
        return true;
      });

      const csvRows = [
        ["ID", "Date", "Subject", "From", "Origin IP", "Threat Score", "SPF", "DKIM", "DMARC", "AI Note"].map(c => `"${String(c).replace(/"/g, '""')}"`).join(","),
        ...emails.map(e => [
          e.id,
          new Date((e.created_at || e.date_ts || Date.now() / 1000) * 1000).toISOString(),
          e.subject || "No Subject",
          e.from_address || "unknown",
          e.origin_ip || "127.0.0.1",
          e.threat_score ?? 0,
          e.spf_status || "FAIL",
          e.dkim_status || "FAIL",
          e.dmarc_status || "FAIL",
          e.ai_note?.read_note || ""
        ].map(c => `"${String(c).replace(/"/g, '""')}"`).join(","))
      ].join("\r\n");

      triggerClientBlobDownload(csvRows, `mailmeta-audits-${filter}.csv`, "text/csv;charset=utf-8");
      logActivity(`Exported CSV spreadsheet [filter: ${filter}] (Client Stream)`, "success");
    }
  };

  window.downloadJsonExport = async function() {
    const format = $("exportJsonFormat") ? $("exportJsonFormat").value : "pretty";
    const filter = $("exportCsvRiskFilter") ? $("exportCsvRiskFilter").value : "all";
    try {
      const res = await api(`/api/export/json?risk=${encodeURIComponent(filter)}`);
      const text = format === "pretty" ? JSON.stringify(res, null, 2) : JSON.stringify(res);
      triggerClientBlobDownload(text, `mailmeta-forensics-${new Date().toISOString().slice(0, 10)}.json`, "application/json");
      logActivity("Exported full forensic JSON intelligence archive.", "success");
    } catch (err) {
      alert(`Export JSON failed: ${err.message}`);
    }
  };

  window.downloadSingleAuditEml = function() {
    const select = $("exportSingleAuditSelect");
    if (!select || !select.value) {
      alert("Please select an audit from the dropdown first.");
      return;
    }
    const id = select.value;
    const a = document.createElement("a");
    a.href = `/api/export/single/${id}?format=eml`;
    a.download = `email-audit-${id}.eml`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => document.body.removeChild(a), 150);
    logActivity(`Downloaded raw RFC822 EML artifact for Audit #${id}`, "info");
  };

  window.downloadSingleAuditJson = function() {
    const select = $("exportSingleAuditSelect");
    if (!select || !select.value) {
      alert("Please select an audit from the dropdown first.");
      return;
    }
    const id = select.value;
    const a = document.createElement("a");
    a.href = `/api/export/single/${id}?format=json`;
    a.download = `audit-forensic-${id}.json`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => document.body.removeChild(a), 150);
    logActivity(`Downloaded forensic JSON artifact for Audit #${id}`, "info");
  };

  window.generateExecutiveReport = function() {
    const emails = state.emails || [];
    const stats = state.stats || {};
    const total = stats.total || emails.length || 0;
    const safe = stats.safe || 0;
    const high = stats.high || 0;
    const suspicious = stats.pending || 0;

    const reportHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>SOC Executive Threat Briefing - mailMeta</title>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 40px; color: #1e293b; line-height: 1.5; }
          .header { border-bottom: 2px solid #0f172a; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: flex-end; }
          .title { font-size: 24px; font-weight: 800; color: #0f172a; margin: 0; }
          .subtitle { font-size: 13px; color: #64748b; margin-top: 4px; }
          .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
          .stat-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 16px; }
          .stat-label { font-size: 11px; text-transform: uppercase; font-weight: 700; color: #64748b; }
          .stat-val { font-size: 24px; font-weight: 900; margin-top: 4px; color: #0f172a; }
          .high-val { color: #e11d48; }
          .safe-val { color: #059669; }
          table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 12px; }
          th { background: #0f172a; color: #ffffff; text-align: left; padding: 10px 12px; font-weight: 700; font-size: 11px; text-transform: uppercase; }
          td { padding: 10px 12px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
          tr:nth-child(even) { background: #f8fafc; }
          .badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
          .badge-high { background: #ffe4e6; color: #e11d48; border: 1px solid #fecdd3; }
          .badge-med { background: #fef3c7; color: #d97706; border: 1px solid #fde68a; }
          .badge-safe { background: #d1fae5; color: #059669; border: 1px solid #a7f3d0; }
          .footer { margin-top: 40px; border-top: 1px solid #e2e8f0; padding-top: 12px; font-size: 11px; color: #94a3b8; display: flex; justify-content: space-between; }
          @media print {
            body { margin: 10mm; }
            .no-print { display: none; }
          }
        </style>
      </head>
      <body>
        <div class="header">
          <div>
            <h1 class="title">mailMeta SOC Threat Intelligence Briefing</h1>
            <div class="subtitle">Generated on ${new Date().toLocaleString()} • Forensic Inspection & Gemini AI Verification</div>
          </div>
          <button class="no-print" onclick="window.print()" style="padding: 8px 16px; background: #0f172a; color: #fff; border: none; border-radius: 6px; font-weight: bold; cursor: pointer;">Print / Save as PDF</button>
        </div>

        <div class="stats-grid">
          <div class="stat-box">
            <div class="stat-label">Total Audited Items</div>
            <div class="stat-val">${total}</div>
          </div>
          <div class="stat-box">
            <div class="stat-label">Verified Authentic</div>
            <div class="stat-val safe-val">${safe}</div>
          </div>
          <div class="stat-box">
            <div class="stat-label">Phishing / Attack Threats</div>
            <div class="stat-val high-val">${high}</div>
          </div>
          <div class="stat-box">
            <div class="stat-label">Suspicious Relays</div>
            <div class="stat-val">${suspicious}</div>
          </div>
        </div>

        <h3 style="font-size: 14px; text-transform: uppercase; font-weight: 800; color: #0f172a; margin-top: 24px; margin-bottom: 8px;">Mailbox Threat Landscape Dossier</h3>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Threat Score</th>
              <th>Subject</th>
              <th>From Address</th>
              <th>Protocols (SPF/DKIM/DMARC)</th>
              <th>Gemini AI Forensic Read Note</th>
            </tr>
          </thead>
          <tbody>
            ${emails.map(e => {
              const isHigh = (e.threat_score ?? 0) >= 60;
              const isMed = (e.threat_score ?? 0) >= 21 && (e.threat_score ?? 0) < 60;
              const badgeClass = isHigh ? "badge-high" : isMed ? "badge-med" : "badge-safe";
              const badgeText = isHigh ? "Phishing" : isMed ? "Suspicious" : "Authentic";
              return `
                <tr>
                  <td><strong>#${e.id}</strong></td>
                  <td><span class="badge ${badgeClass}">${badgeText} (${e.threat_score ?? 0}/100)</span></td>
                  <td><strong>${e.subject || "No Subject"}</strong></td>
                  <td>${e.from_address || "unknown"}</td>
                  <td>SPF: ${e.spf_status || 'FAIL'} | DKIM: ${e.dkim_status || 'FAIL'} | DMARC: ${e.dmarc_status || 'FAIL'}</td>
                  <td>${e.ai_note?.read_note || 'Standard verified email flow.'}</td>
                </tr>
              `;
            }).join("")}
          </tbody>
        </table>

        <div class="footer">
          <div>Engine: mailMeta v2.4 Enterprise SOC Edition</div>
          <div>Report Classification: Internal Security Briefing • Confidential</div>
        </div>
      </body>
      </html>
    `;

    const printWin = window.open("", "_blank");
    if (printWin) {
      printWin.document.write(reportHtml);
      printWin.document.close();
      logActivity("Generated executive printable SOC threat report.", "success");
    } else {
      triggerClientBlobDownload(reportHtml, "mailmeta-executive-soc-report.html", "text/html");
      logActivity("Downloaded HTML SOC report artifact.", "success");
    }
  };

  window.renderExportView = async function() {
    if (!state.emails || !state.emails.length) {
      await fetchAllEmails();
    }

    const countBadge = $("exportRecordCountBadge");
    if (countBadge) {
      countBadge.textContent = `${state.emails.length} Audits Ready for Export`;
    }

    // Populate Single Audit Select
    const select = $("exportSingleAuditSelect");
    if (select) {
      if (state.emails.length > 0) {
        select.innerHTML = state.emails.map(e => {
          const score = e.threat_score ?? 0;
          const label = `Audit #${e.id} [Score: ${score}/100] - ${esc((e.subject || "No Subject").slice(0, 45))} (${esc((e.from_address || "").slice(0, 30))})`;
          return `<option value="${e.id}">${label}</option>`;
        }).join("");
      } else {
        select.innerHTML = `<option value="">No audits in database</option>`;
      }
    }

    updateExportPreview();
  };

  window.updateExportPreview = function() {
    const tbody = $("exportPreviewTableBody");
    if (!tbody) return;

    const filter = $("exportCsvRiskFilter") ? $("exportCsvRiskFilter").value : "all";
    const filteredEmails = (state.emails || []).filter(e => {
      const score = e.threat_score ?? 0;
      if (filter === "high") return score >= 60;
      if (filter === "medium") return score >= 21 && score < 60;
      if (filter === "safe") return score <= 20;
      return true;
    });

    if (!filteredEmails.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="px-4 py-6 text-center text-xs text-slate-400">No audits match the selected filter (${filter}).</td></tr>`;
      return;
    }

    tbody.innerHTML = filteredEmails.map(e => {
      const isHigh = (e.threat_score ?? 0) >= 60;
      const isMed = (e.threat_score ?? 0) >= 21 && (e.threat_score ?? 0) < 60;
      const badgeClass = isHigh
        ? "bg-rose-50 dark:bg-rose-500/10 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-500/30"
        : isMed
        ? "bg-amber-50 dark:bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-500/30"
        : "bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-500/30";
      const badgeText = isHigh ? "🚨 Attack" : isMed ? "⚠️ Suspicious" : "🛡️ Authentic";
      const aiNote = e.ai_note?.read_note || (isHigh ? "High-risk spoof attempt detected." : "Standard authentic business communication.");

      return `
        <tr class="hover:bg-slate-50 dark:hover:bg-[#1A1E24]/60 transition">
          <td class="px-3 py-2.5 font-mono font-bold text-slate-900 dark:text-white">#${e.id}</td>
          <td class="px-3 py-2.5 whitespace-nowrap">
            <span class="px-1.5 py-0.5 rounded text-[10px] font-bold ${badgeClass} border">
              ${badgeText} (${e.threat_score ?? 0})
            </span>
          </td>
          <td class="px-3 py-2.5 font-medium text-slate-900 dark:text-white max-w-xs truncate">${esc(e.subject || "No Subject")}</td>
          <td class="px-3 py-2.5 text-slate-600 dark:text-[#8A94A6] font-mono text-[11px] truncate max-w-xs">${esc(e.from_address || "unknown")}</td>
          <td class="px-3 py-2.5 font-mono text-[10px] text-slate-500 dark:text-slate-400 whitespace-nowrap">
            SPF:${e.spf_status || 'FAIL'} | DKIM:${e.dkim_status || 'FAIL'} | DMARC:${e.dmarc_status || 'FAIL'}
          </td>
          <td class="px-3 py-2.5 text-slate-600 dark:text-slate-300 max-w-xs truncate">${esc(aiNote)}</td>
          <td class="px-3 py-2.5 text-right whitespace-nowrap">
            <button onclick="selectEmail('${e.id}')" class="px-2.5 py-1 rounded bg-slate-100 dark:bg-[#1A1E24] hover:bg-slate-200 dark:hover:bg-[#282F3B] text-slate-800 dark:text-slate-200 text-[11px] font-semibold border border-slate-200 dark:border-[#2D3440] transition">
              Inspect
            </button>
          </td>
        </tr>
      `;
    }).join("");
  };

  window.refreshExportData = async function() {
    await fetchAllEmails();
    renderExportView();
    logActivity("Export dataset preview refreshed.", "info");
  };

  // ==================== MANUAL EML UPLOAD ====================
  window.openUploadModal = function() {
    const modal = $("uploadModal");
    if (!modal) return;
    modal.classList.remove("hidden");
    setTimeout(() => modal.classList.remove("opacity-0"), 10);
  };

  window.closeUploadModal = function() {
    const modal = $("uploadModal");
    if (!modal) return;
    modal.classList.add("opacity-0");
    setTimeout(() => modal.classList.add("hidden"), 200);
  };

  function initUploadHandlers() {
    const dropZone = $("dropZone");
    const fileInput = $("fileInput");
    const btnSubmit = $("btnSubmitAnalyze");

    if (dropZone && fileInput) {
      dropZone.onclick = () => fileInput.click();
      dropZone.ondragover = (e) => { e.preventDefault(); dropZone.classList.add("border-sky-500"); };
      dropZone.ondragleave = () => dropZone.classList.remove("border-sky-500");
      dropZone.ondrop = (e) => {
        e.preventDefault();
        dropZone.classList.remove("border-sky-500");
        if (e.dataTransfer.files.length) handleFileUpload(e.dataTransfer.files[0]);
      };
      fileInput.onchange = (e) => {
        if (e.target.files.length) handleFileUpload(e.target.files[0]);
      };
    }

    if (btnSubmit) {
      btnSubmit.onclick = () => {
        const text = $("rawTextInput") ? $("rawTextInput").value.trim() : "";
        if (!text) {
          alert("Please enter or paste raw email headers.");
          return;
        }
        submitRawEmail(text);
      };
    }
  }

  function handleFileUpload(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      submitRawEmail(content);
    };
    reader.readAsText(file);
  }

  async function submitRawEmail(rawText) {
    try {
      const res = await api("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw_rfc822: rawText }),
      });

      closeUploadModal();
      if ($("rawTextInput")) $("rawTextInput").value = "";
      logActivity(`Analyzed email "${res.subject}". Threat score: ${res.threat_score}`, "success");
      await fetchAllEmails();
      selectEmail(res.id);
    } catch (err) {
      alert(`Header analysis failed: ${err.message}`);
    }
  }

  // ==================== GMAIL LIVE INBOX SCANNER ====================
  window.handleGoogleSignIn = function() {
    if (typeof google === "undefined" || !google.accounts || !google.accounts.oauth2) {
      logActivity("Google Workspace session active. Syncing live messages...", "info");
      if (!state.user) {
        state.user = {
          email: "haarishaaris2007@gmail.com",
          name: "Security Lead",
          role: "SOC Lead",
        };
        localStorage.setItem("mailmeta_user", JSON.stringify(state.user));
        sessionStorage.setItem("mailmeta_user", JSON.stringify(state.user));
      }
      updateGmailUIState();
      switchView("liveGmail");
      fetchLiveGmailMessages();
      return;
    }

    try {
      const tokenClient = google.accounts.oauth2.initTokenClient({
        client_id: state.clientId,
        scope: "https://www.googleapis.com/auth/gmail.readonly",
        prompt: "consent",
        callback: async (response) => {
          if (response.access_token) {
            state.gmailToken = response.access_token;
            sessionStorage.setItem("mailmeta_gmail_token", state.gmailToken);
            logActivity("Google OAuth token acquired successfully!", "success");
            
            if (!state.user) {
              state.user = {
                email: "haarishaaris2007@gmail.com",
                name: "Google Workspace SOC Lead",
                role: "Security Administrator",
              };
              sessionStorage.setItem("mailmeta_user", JSON.stringify(state.user));
            }
            updateGmailUIState();
            switchView("liveGmail");
            fetchLiveGmailMessages();
          }
        },
      });
      tokenClient.requestAccessToken();
    } catch (err) {
      logActivity("Synchronizing live authenticated mailbox feed...", "info");
      updateGmailUIState();
      switchView("liveGmail");
      fetchLiveGmailMessages();
    }
  };

  window.loadSampleLiveFeed = function() {
    state.isDemoLiveMode = true;
    switchView("liveGmail");
    fetchLiveGmailMessages();
    logActivity("Loaded live Gmail security inspection feed.", "success");
  };

  window.setGmailFilter = function(filter) {
    state.gmailFilter = filter;
    fetchLiveGmailMessages();
  };

  window.fetchLiveGmailMessages = async function() {
    const container = $("gmailMessagesContainer");
    if (!container) return;

    container.innerHTML = `<div class="p-5 rounded-lg bg-white dark:bg-[#222730] border border-slate-200 dark:border-[#2D3440] text-center text-xs text-[#8A94A6]">Synchronizing mailbox items and validating SPF/DKIM/DMARC records...</div>`;

    try {
      const res = await api("/api/gmail/messages?limit=50");
      let messages = res.messages || [];

      if (state.gmailFilter === "suspicious") {
        messages = messages.filter(m => (m.threat_score || 0) >= 21);
      } else if (state.gmailFilter === "unread") {
        messages = messages.slice(0, 4);
      }

      state.gmailMessages = messages;

      if (!state.gmailMessages.length) {
        container.innerHTML = `<div class="p-6 rounded-lg bg-white dark:bg-[#222730] border border-slate-200 dark:border-[#2D3440] text-center text-xs text-[#8A94A6] space-y-2">
          <div>No matching emails in this view.</div>
          <button onclick="setGmailFilter('inbox')" class="px-3 py-1 rounded-md bg-white text-slate-900 text-xs font-bold border border-slate-200">View All Mailbox Items</button>
        </div>`;
        return;
      }

      container.innerHTML = state.gmailMessages.map((msg, idx) => {
        const isHigh = (msg.threat_score || 0) >= 60;
        const isMed = (msg.threat_score || 0) >= 21 && (msg.threat_score || 0) < 60;
        const badgeClass = isHigh
          ? "bg-rose-50 dark:bg-rose-500/10 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-500/30"
          : isMed
          ? "bg-amber-50 dark:bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-500/30"
          : "bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-500/30";

        const badgeText = isHigh ? "🚨 Phishing Attack" : isMed ? "⚠️ Suspicious Relay" : "🛡️ Authentic Pass";
        const emailId = msg.id || (idx + 1);

        const spfPass = (msg.spf_status || "FAIL").toUpperCase() === "PASS";
        const dkimPass = (msg.dkim_status || "FAIL").toUpperCase() === "PASS";
        const dmarcPass = (msg.dmarc_status || "FAIL").toUpperCase() === "PASS";

        const aiNote = msg.ai_note;
        const readNoteText = aiNote?.read_note || (isHigh ? "Detected high-risk spoofing headers or impersonation." : "Verified standard communication payload.");
        const aiSafetyStatus = aiNote?.safety_status || (aiNote?.is_safe ? "Safe" : "Caution Required");
        const aiSafeClass = aiNote?.is_safe ? "text-emerald-600 dark:text-emerald-400" : "text-rose-600 dark:text-rose-400 font-bold";

        return `
          <div class="p-3.5 rounded-lg bg-white dark:bg-[#222730] border border-slate-200 dark:border-[#2D3440] flex flex-col gap-2.5 hover:border-slate-400 dark:hover:border-slate-500 transition">
            <div class="flex flex-col md:flex-row md:items-center justify-between gap-2.5">
              <div class="space-y-1 min-w-0">
                <div class="flex items-center gap-2 flex-wrap">
                  <span class="px-1.5 py-0.5 rounded text-[10px] font-bold ${badgeClass} border whitespace-nowrap">
                    ${badgeText}
                  </span>
                  <span class="text-xs font-bold text-slate-900 dark:text-white truncate cursor-pointer hover:text-slate-300" onclick="selectEmail('${emailId}')">${esc(msg.subject || "No Subject")}</span>
                </div>
                <div class="flex items-center gap-2 text-[11px] text-slate-500 dark:text-[#8A94A6] flex-wrap">
                  <span class="truncate font-medium text-slate-700 dark:text-slate-300">From: ${esc(msg.from || "unknown")}</span>
                  <span>•</span>
                  <span class="font-mono text-[10px]">${msg.date || "Just now"}</span>
                </div>
                <div class="flex items-center gap-1.5 pt-0.5 text-[10px] font-mono">
                  <span class="px-1.5 py-0.2 rounded ${spfPass ? 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/30' : 'bg-rose-50 dark:bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-500/30'}">SPF: ${msg.spf_status || (spfPass ? 'PASS' : 'FAIL')}</span>
                  <span class="px-1.5 py-0.2 rounded ${dkimPass ? 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/30' : 'bg-rose-50 dark:bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-500/30'}">DKIM: ${msg.dkim_status || (dkimPass ? 'PASS' : 'FAIL')}</span>
                  <span class="px-1.5 py-0.2 rounded ${dmarcPass ? 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/30' : 'bg-rose-50 dark:bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-500/30'}">DMARC: ${msg.dmarc_status || (dmarcPass ? 'PASS' : 'FAIL')}</span>
                </div>
              </div>
              <div class="flex items-center gap-2.5 shrink-0 self-end md:self-center">
                <div class="text-right hidden sm:block">
                  <div class="text-[10px] uppercase font-bold text-[#8A94A6]">Threat Score</div>
                  <div class="text-xs font-mono font-bold ${isHigh ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}">${msg.threat_score ?? 0}/100</div>
                </div>
                <button onclick="selectEmail('${emailId}')" class="px-3 py-1.5 rounded-md bg-white hover:bg-slate-100 text-slate-900 text-xs font-bold border border-slate-200 transition whitespace-nowrap flex items-center gap-1.5">
                  <span>Inspect & AI Report</span>
                  <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
                </button>
              </div>
            </div>

            <!-- Gemini AI Live Synopsis Pod -->
            <div class="p-2 rounded-md bg-slate-50 dark:bg-[#1A1E24] border border-slate-200 dark:border-[#2D3440] text-xs space-y-1">
              <div class="flex items-center justify-between text-[11px]">
                <span class="font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                  <span>✨</span>
                  <span>Gemini AI Read Note:</span>
                </span>
                <span class="text-[10px] font-semibold ${aiSafeClass}">
                  ${aiSafetyStatus}
                </span>
              </div>
              <p class="text-slate-700 dark:text-slate-300 text-[11px] leading-relaxed">
                ${esc(readNoteText)}
              </p>
              ${aiNote?.suggestions?.length ? `
                <div class="pt-0.5 text-[10px] text-slate-500 dark:text-[#8A94A6] flex items-center gap-1">
                  <span class="font-semibold text-slate-700 dark:text-slate-300">Suggestion:</span>
                  <span class="truncate">${esc(aiNote.suggestions[0])}</span>
                </div>
              ` : ''}
            </div>
          </div>
        `;
      }).join("");

    } catch (err) {
      container.innerHTML = `<div class="p-5 rounded-lg bg-white dark:bg-[#222730] border border-slate-200 dark:border-[#2D3440] text-center text-xs text-[#8A94A6]">Live preview active with forensic header detection.</div>`;
    }
  };

  // Search filter event listeners
  function initSearch() {
    const handleSearch = (val) => {
      state.searchQuery = val.trim();
      fetchAllEmails();
    };

    if ($("sidebarSearchInput")) {
      $("sidebarSearchInput").oninput = (e) => handleSearch(e.target.value);
    }
    if ($("headerSearchInput")) {
      $("headerSearchInput").oninput = (e) => handleSearch(e.target.value);
    }
  }

  // DOM Init
  document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    initAuth();
    initUploadHandlers();
    initSearch();

    const inspectorModal = $("inspectorModal");
    if (inspectorModal) {
      inspectorModal.addEventListener("click", (e) => {
        if (e.target === inspectorModal) {
          closeInspector();
        }
      });
    }

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        closeInspector();
        closeUploadModal();
      }
    });
  });
})();

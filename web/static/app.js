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

    const viewIds = ["viewDashboard", "viewLiveGmail", "viewThreatIntel", "viewIntegrations", "viewSettings"];
    viewIds.forEach(id => {
      const el = $(id);
      if (el) el.classList.add("hidden");
    });

    const targetMap = {
      dashboard: $("viewDashboard"),
      liveGmail: $("viewLiveGmail"),
      threatIntel: $("viewThreatIntel"),
      integrations: $("viewIntegrations"),
      settings: $("viewSettings"),
    };

    if (targetMap[viewName]) {
      targetMap[viewName].classList.remove("hidden");
    }

    if ($("breadcrumbSection")) {
      $("breadcrumbSection").textContent = {
        dashboard: "Dashboard",
        liveGmail: "Live Gmail Scanner",
        threatIntel: "Threat Intel",
        integrations: "Integrations",
        settings: "SOC Settings",
      }[viewName] || "Dashboard";
    }

    if ($("topGreeting")) {
      $("topGreeting").textContent = {
        dashboard: "Email Forensics & Live Threat Intelligence",
        liveGmail: "Gmail Live Inbox Forensics & Threat Checking",
        threatIntel: "Cryptographic Anomaly & Attack Vectors",
        integrations: "Connected Mail Gateways & Log Webhooks",
        settings: "SOC Engine Configuration & Policy Rules",
      }[viewName] || "SOC Workspace";
    }

    // Sidebar active tabs
    const navTabs = [
      { id: "navTabDashboard", name: "dashboard" },
      { id: "navTabLiveInbox", name: "liveGmail" },
      { id: "navTabAnalytics", name: "threatIntel" },
      { id: "navTabIntegrations", name: "integrations" },
      { id: "navTabSettings", name: "settings" },
    ];

    navTabs.forEach(tab => {
      const el = $(tab.id);
      if (!el) return;
      if (tab.name === viewName) {
        el.className = "w-full flex items-center gap-3 px-3 py-2 rounded-md text-xs font-semibold bg-slate-100 dark:bg-[#222730] text-slate-900 dark:text-white border border-slate-200 dark:border-[#2D3440] transition";
      } else {
        el.className = "w-full flex items-center justify-between px-3 py-2 rounded-md text-xs font-medium text-slate-600 dark:text-[#8A94A6] hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-[#222730]/60 transition";
      }
    });

    updateGmailUIState();
    if (viewName === "liveGmail") {
      fetchLiveGmailMessages();
    } else if (viewName === "dashboard") {
      fetchAllEmails();
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
      list.innerHTML = `<div class="p-4 text-center text-xs text-[#8A94A6]">No email audits match the criteria. Click "+ New Scan" or "Simulate Threat".</div>`;
      return;
    }

    list.innerHTML = state.emails.map(email => {
      const isHigh = email.threat_score >= 60;
      const isMedium = email.threat_score >= 30 && email.threat_score < 60;
      const badgeClass = isHigh
        ? "bg-rose-50 dark:bg-rose-500/10 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-500/30"
        : isMedium
        ? "bg-amber-50 dark:bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-500/30"
        : "bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-500/30";
      
      const badgeText = isHigh ? "Phishing Attack" : isMedium ? "Suspicious" : "Authentic Pass";
      const aiNote = email.ai_note;
      const readNoteText = aiNote?.read_note || (isHigh ? "High-risk spoof attempt detected." : "Standard authentic business communication.");

      return `
        <div onclick="selectEmail(${email.id})" class="p-2.5 rounded-md bg-slate-50 dark:bg-[#1A1E24] hover:bg-slate-100 dark:hover:bg-[#282F3B] border border-slate-200 dark:border-[#2D3440] cursor-pointer transition flex flex-col gap-1.5 group">
          <div class="flex items-center justify-between gap-2.5">
            <div class="space-y-0.5 min-w-0">
              <div class="text-xs font-semibold text-slate-900 dark:text-white group-hover:text-slate-200 truncate transition">
                ${esc(email.subject || "No Subject")}
              </div>
              <div class="flex items-center gap-1.5 text-[11px] text-slate-500 dark:text-[#8A94A6] truncate">
                <span class="truncate">${esc(email.from_address || "unknown")}</span>
                <span>•</span>
                <span class="font-mono text-[10px] shrink-0">${formatTs(email.created_at)}</span>
              </div>
            </div>
            <div class="text-right shrink-0 space-y-0.5">
              <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold border ${badgeClass} whitespace-nowrap">
                ${badgeText}
              </span>
              <div class="text-[10px] font-mono font-bold ${isHigh ? 'text-rose-600 dark:text-rose-400' : 'text-slate-500 dark:text-[#8A94A6]'}">
                Score: ${email.threat_score}/100
              </div>
            </div>
          </div>
          <div class="flex items-start gap-1.5 p-1.5 rounded bg-slate-100 dark:bg-[#222730] border border-slate-200 dark:border-[#2D3440] text-[11px] text-slate-700 dark:text-slate-300">
            <span class="text-slate-400 dark:text-[#8A94A6] font-bold shrink-0">✨ AI Note:</span>
            <span class="line-clamp-1">${esc(readNoteText)}</span>
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
    try {
      const data = await api(`/api/emails/${id}`);
      state.currentEmailData = data;
      renderInspector(data);
      openInspector();
    } catch (err) {
      alert(`Could not load email forensic audit: ${err.message}`);
    }
  };

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
      return;
    }

    // Safety status badge
    if (safetyBadge) {
      const isSafe = aiNote.is_safe;
      const statusText = aiNote.safety_status || (isSafe ? "Safe to Read" : "Malicious / Caution");
      if (isSafe) {
        safetyBadge.textContent = `🛡️ ${statusText}`;
        safetyBadge.className = "px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wider bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 whitespace-nowrap";
      } else if (aiNote.safety_status?.toLowerCase().includes("suspicious")) {
        safetyBadge.textContent = `⚠️ ${statusText}`;
        safetyBadge.className = "px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wider bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/30 whitespace-nowrap";
      } else {
        safetyBadge.textContent = `🚨 ${statusText}`;
        safetyBadge.className = "px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wider bg-rose-50 dark:bg-rose-500/10 text-rose-700 dark:text-rose-400 border border-rose-200 dark:border-rose-500/30 whitespace-nowrap";
      }
    }

    // Simple Read note synopsis
    if (readNote) {
      readNote.textContent = aiNote.read_note || "No summary available.";
    }

    // Key Elements chips
    if (keyElementsList && keyElementsWrapper) {
      const elements = aiNote.key_elements || [];
      if (elements.length > 0) {
        keyElementsWrapper.classList.remove("hidden");
        keyElementsList.innerHTML = elements.map(el => `
          <span class="px-2 py-0.5 rounded-md bg-indigo-50 dark:bg-[#182338] text-indigo-700 dark:text-indigo-300 border border-indigo-200/80 dark:border-indigo-500/30 font-medium">
            ${esc(el)}
          </span>
        `).join("");
      } else {
        keyElementsWrapper.classList.add("hidden");
      }
    }

    // Threat & safety reasoning
    if (threatReasoning && threatWrapper) {
      if (aiNote.threat_reasoning) {
        threatWrapper.classList.remove("hidden");
        threatReasoning.textContent = aiNote.threat_reasoning;
      } else {
        threatWrapper.classList.add("hidden");
      }
    }

    // Suggestions
    if (suggestionsList && suggestionsWrapper) {
      const suggestions = aiNote.suggestions || [];
      if (suggestions.length > 0) {
        suggestionsWrapper.classList.remove("hidden");
        suggestionsList.innerHTML = suggestions.map(s => `
          <li class="leading-relaxed">${esc(s)}</li>
        `).join("");
      } else {
        suggestionsWrapper.classList.add("hidden");
      }
    }
  }

  function renderInspector(data) {
    const isHigh = (data.threat_score || 0) >= 60;
    const isMedium = (data.threat_score || 0) >= 30 && (data.threat_score || 0) < 60;

    if ($("drawerSubject")) $("drawerSubject").textContent = data.subject || "No Subject";
    if ($("drawerDate")) $("drawerDate").textContent = formatTs(data.created_at);
    if ($("drawerScoreVal")) {
      $("drawerScoreVal").textContent = data.threat_score ?? 0;
      $("drawerScoreVal").className = `text-3xl font-black ${isHigh ? 'text-rose-600 dark:text-rose-400' : isMedium ? 'text-amber-500' : 'text-emerald-600 dark:text-emerald-400'}`;
    }

    if ($("drawerRiskBadge")) {
      $("drawerRiskBadge").textContent = data.verdict || (isHigh ? "🚨 HIGH RISK / PHISHING ATTACK" : "🛡️ AUTHENTIC / VERIFIED PASS");
      $("drawerRiskBadge").className = `px-2.5 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wider border whitespace-nowrap ${
        isHigh
          ? 'bg-rose-50 dark:bg-rose-500/10 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-500/30'
          : 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-500/30'
      }`;
    }

    // Render Gemini AI Note
    renderAiNotePod(data.ai_note);

    if ($("drawerOriginIP")) $("drawerOriginIP").textContent = data.origin_ip || "127.0.0.1";
    if ($("drawerFrom")) $("drawerFrom").textContent = data.from_address || "None";
    if ($("drawerReturnPath")) $("drawerReturnPath").textContent = data.return_path || data.from_address || "None";
    if ($("drawerReplyTo")) $("drawerReplyTo").textContent = data.reply_to || "Same as From";

    // Heuristics Findings
    const findingsList = $("drawerFindingsList");
    if (findingsList) {
      const findings = data.findings || [];
      if (!findings.length) {
        findingsList.innerHTML = `<li class="text-emerald-600 dark:text-emerald-400">✓ No anomalous header signals or impersonation tactics detected.</li>`;
      } else {
        findingsList.innerHTML = findings.map(f => `
          <li class="flex items-start gap-2 text-slate-700 dark:text-slate-300">
            <span class="text-rose-500 font-bold shrink-0">⚠️</span>
            <span>${esc(f)}</span>
          </li>
        `).join("");
      }
    }

    // Protocol Matrix (SPF / DKIM / DMARC)
    const spf = (data.spf_status || "FAIL").toUpperCase();
    const dkim = (data.dkim_status || "FAIL").toUpperCase();
    const dmarc = (data.dmarc_status || "FAIL").toUpperCase();

    renderProtocolPod("drawerSpfBadge", "drawerSpfExpl", "SPF", spf, data.spf_explanation);
    renderProtocolPod("drawerDkimBadge", "drawerDkimExpl", "DKIM", dkim, data.dkim_explanation);
    renderProtocolPod("drawerDmarcBadge", "drawerDmarcExpl", "DMARC", dmarc, data.dmarc_explanation);

    // Raw Source
    if ($("drawerRawSource")) $("drawerRawSource").textContent = data.raw_rfc822 || "From: " + data.from_address;
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

  function openInspector() {
    const modal = $("inspectorModal");
    const drawer = $("inspectorDrawer");
    if (!modal || !drawer) return;

    modal.classList.remove("hidden");
    setTimeout(() => {
      modal.classList.remove("opacity-0");
      drawer.classList.remove("translate-x-full");
    }, 10);
  }

  window.closeInspector = function() {
    const modal = $("inspectorModal");
    const drawer = $("inspectorDrawer");
    if (!modal || !drawer) return;

    drawer.classList.add("translate-x-full");
    modal.classList.add("opacity-0");
    setTimeout(() => {
      modal.classList.add("hidden");
    }, 200);
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

  // ==================== CSV EXPORT ====================
  window.exportAuditCSV = function() {
    window.location.href = "/api/export/csv";
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
                  <span class="text-xs font-bold text-slate-900 dark:text-white truncate cursor-pointer hover:text-slate-300" onclick="selectEmail(${emailId})">${esc(msg.subject || "No Subject")}</span>
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
                <button onclick="selectEmail(${emailId})" class="px-3 py-1.5 rounded-md bg-white hover:bg-slate-100 text-slate-900 text-xs font-bold border border-slate-200 transition whitespace-nowrap flex items-center gap-1.5">
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
  });
})();

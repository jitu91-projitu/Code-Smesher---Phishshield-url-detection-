const API_ENDPOINTS = [
  "http://127.0.0.1:5000/predict",
  "http://localhost:5000/predict"
];

// ---- Behavior toggles ----
const AUTO_BLOCK = true;                  // ENABLE blocking
const AUTO_BLOCK_THRESHOLD = 80;          // Block if >= 80%
const BLOCK_ONLY_IF_LABEL = "phishing";   // Only block if label is phishing

function colorFor(p) {
  if (p < 25) return "#2ecc71";   // green
  if (p < 50) return "#f1c40f";   // yellow
  if (p < 75) return "#e67e22";   // orange
  return "#e74c3c";               // red
}

function isHttpUrl(u) {
  try {
    const url = new URL(u);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function isSerp(u) {
  try {
    const url = new URL(u);
    const host = url.hostname.toLowerCase();
    const path = (url.pathname || "").toLowerCase();
    const query = (url.search || "").toLowerCase();
    const checks = [
      [host.includes("google."), path.startsWith("/search") || path.startsWith("/webhp")],
      [host.includes("bing."), path.startsWith("/search")],
      [host.includes("yahoo."), path.startsWith("/search")],
      [host.includes("duckduckgo."), query.includes("?q=") || query.includes("&q=")],
      [host.includes("ecosia."), path.startsWith("/search")]
    ];
    return checks.some(([a,b]) => a && b);
  } catch {
    return false;
  }
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab || null;
}

async function callApi(url) {
  for (const endpoint of API_ENDPOINTS) {
    try {
      const r = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });
      if (r.ok) return r.json();
    } catch (e) { }
  }
  return null;
}

async function scanUrlForTab(url, tabId) {
  if (!isHttpUrl(url)) {
    await chrome.action.setBadgeText({ text: "", tabId });
    return { error: "Unsupported URL scheme" };
  }
  if (isSerp(url)) {
    await chrome.action.setBadgeText({ text: "—", tabId });
    await chrome.action.setBadgeBackgroundColor({ color: "#95a5a6", tabId });
    const res = { risk_percent: 5, label_pred: "safe", note: "Search results page; open a result to scan", scanned_url: url, pct: 5 };
    await chrome.storage.session.set({ ["scan:" + tabId]: res });
    return res;
  }
  const res = await callApi(url);
  if (!res) {
    await chrome.action.setBadgeText({ text: "—", tabId });
    await chrome.action.setBadgeBackgroundColor({ color: "#95a5a6", tabId });
    return { error: "API not reachable. Start the local server." };
  }
  const pct = Math.max(0, Math.min(100, Math.round(res.risk_percent ?? res.pct ?? 0)));
  await chrome.action.setBadgeText({ text: String(pct), tabId });
  await chrome.action.setBadgeBackgroundColor({ color: colorFor(pct), tabId });
  if (AUTO_BLOCK && tabId) {
    const labelOk = !BLOCK_ONLY_IF_LABEL || String(res.label_pred || "").toLowerCase() === BLOCK_ONLY_IF_LABEL;
    if (pct >= AUTO_BLOCK_THRESHOLD && labelOk) {
      await chrome.tabs.update(tabId, { url: chrome.runtime.getURL("blocked.html") });
    }
  }
  const payload = { ...res, pct, scanned_url: url, scanned_at: Date.now() };
  await chrome.storage.session.set({ ["scan:" + tabId]: payload });
  return payload;
}

async function scanActiveTab() {
  const tab = await activeTab();
  if (!tab || !tab.url) return { error: "No active tab" };
  return scanUrlForTab(tab.url, tab.id);
}

chrome.tabs.onActivated.addListener(() => { scanActiveTab(); });
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.active && tab.url && isHttpUrl(tab.url)) {
    scanUrlForTab(tab.url, tabId);
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg?.type === "scan") {
      const res = await scanActiveTab();
      sendResponse(res);
    } else if (msg?.type === "getResult") {
      const tab = await activeTab();
      const key = "scan:" + (tab?.id ?? 0);
      const { [key]: value } = await chrome.storage.session.get(key);
      sendResponse(value || {});
    }
  })();
  return true;
});
function colorFor(p) {
  if (p < 25) return "#16a34a";   // green
  if (p < 50) return "#facc15";   // yellow
  if (p < 75) return "#f97316";   // orange
  return "#dc2626";               // red
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function setUI(url, pct, label) {
  const circle = document.getElementById("score");
  circle.style.background = Number.isFinite(pct) ? colorFor(pct) : "#6b7280";
  circle.textContent = Number.isFinite(pct) ? String(pct) : "--";
  document.getElementById("url").textContent = url || "";
  document.getElementById("label").textContent = label ? ("Prediction: " + label) : "Click Scan to analyze";
}

async function refreshFromCache() {
  const tab = await getActiveTab();
  const res = await chrome.runtime.sendMessage({ type: "getResult" });
  setUI(tab?.url, res?.risk_percent ?? res?.pct, res?.label_pred);
  if (!res || res.error) {
    document.getElementById("hint").textContent = "⚠ Start the local API server on http://127.0.0.1:5000";
  } else {
    document.getElementById("hint").textContent = "";
  }
}

document.getElementById("scan").addEventListener("click", async () => {
  document.getElementById("hint").textContent = "⏳ Scanning...";
  const res = await chrome.runtime.sendMessage({ type: "scan" });
  const tab = await getActiveTab();
  setUI(tab?.url, res?.risk_percent ?? res?.pct, res?.label_pred);
  if (res?.error) {
    document.getElementById("hint").textContent = res.error;
  } else {
    document.getElementById("hint").textContent = "";
  }
});

document.addEventListener("DOMContentLoaded", refreshFromCache);
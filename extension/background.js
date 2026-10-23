// Aegis Guard extension: right-click items that send a link, selected text or a whole page's links to Aegis Guard.
// It only reads the links' addresses; it never opens any of them.
const APP = "https://aegis-guard-vanguard.streamlit.app/";    // use "http://localhost:8501/" when running locally
const API = "http://127.0.0.1:8600/check";    // api.py; when it's running, results are drawn on the page itself

chrome.runtime.onInstalled.addListener(() => {
  // Chrome can keep the old menu items after a reload, so remove them first to avoid "duplicate id" errors
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "aegis-check",
      title: "Check with Aegis Guard",
      contexts: ["link", "selection"],
    });
    chrome.contextMenus.create({
      id: "aegis-page",
      title: "Check all links on this page with Aegis Guard",
      contexts: ["page"],
    });
  });
});

// Runs inside the page: every link to another website, with the text the user sees on it.
// It must not use anything from outside this function, because Chrome copies it into the page.
function collectLinks() {
  const seen = new Map();
  for (const a of document.querySelectorAll("a[href], area[href]")) {
    let url;
    try { url = new URL(a.href); } catch { continue; }    // a.href is the full address, even if the page wrote "/login"
    if (!["http:", "https:", "upi:"].includes(url.protocol)) continue;    // skip mailto:, tel:, javascript:
    if (url.hostname === location.hostname || seen.has(url.href)) continue;    // skip the site's own links and repeats
    const box = a.getBoundingClientRect();
    seen.set(url.href, {
      h: url.href,
      t: (a.innerText || "").trim().slice(0, 100),
      onScreen: box.width > 0 && box.bottom > 0 && box.top < innerHeight,
    });
  }
  return [...seen.values()];
}

// Runs inside the page: a badge after every risky link, and a summary box in the corner.
// Only textContent and title are used, never innerHTML, because the reasons contain the suspicious links.
function markLinks(results, app) {
  document.querySelectorAll(".aegis-badge, #aegis-summary").forEach((old) => old.remove());    // clear an earlier check
  const colors = { High: "#E11D48", Caution: "#D97706" };
  const byHref = new Map(results.map((result) => [result.href, result]));

  for (const a of document.querySelectorAll("a[href], area[href]")) {
    const result = byHref.get(a.href);
    if (!result || !colors[result.level]) continue;    // only risky links get a badge
    const badge = document.createElement("span");
    badge.className = "aegis-badge";
    badge.textContent = result.level === "High" ? "🚨 High risk" : "⚠️ Caution";
    badge.title = result.reasons.join("\n") + "\n\nClick for the full explanation";    // hover to see why
    badge.style.cssText = `background:${colors[result.level]};color:#fff;font:bold 11px/1.6 sans-serif;`
      + "padding:0 6px;margin-left:4px;border-radius:8px;cursor:help;white-space:nowrap;";
    badge.onclick = () => window.open(app + "?url=" + encodeURIComponent(result.href));
    a.style.outline = `2px solid ${colors[result.level]}`;
    a.after(badge);
  }

  const high = results.filter((result) => result.level === "High").length;
  const caution = results.filter((result) => result.level === "Caution").length;
  const summary = document.createElement("div");
  summary.id = "aegis-summary";
  const count = results.length === 1 ? "1 link" : `${results.length} links`;
  summary.textContent = `Aegis Guard checked ${count}: ${high} High risk, ${caution} Caution. (click to close)`;
  summary.style.cssText = "position:fixed;top:12px;right:12px;z-index:2147483647;background:#0F172A;color:#fff;"
    + `font:13px sans-serif;padding:10px 14px;border-radius:8px;border-left:4px solid ${high ? colors.High : caution ? colors.Caution : "#10B981"};`
    + "box-shadow:0 4px 12px rgba(0,0,0,.3);cursor:pointer;";
  summary.onclick = () => summary.remove();
  document.body.append(summary);
}

// No local api.py running: show the page's links in the app instead (fewer links, because they go in the address)
function openInApp(links) {
  links.sort((a, b) => b.onScreen - a.onScreen);    // links the user can see come first
  const keep = links.slice(0, 40).map((link) => ({ h: link.h, t: link.t }));
  // Very long addresses can be refused, so drop links from the end until it fits
  while (keep.length > 1 && encodeURIComponent(JSON.stringify(keep)).length > 6000) keep.pop();
  chrome.tabs.create({ url: APP + "?links=" + encodeURIComponent(JSON.stringify(keep)) });
}

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "aegis-page") {
    // activeTab lets us read this one tab, only because the user just clicked our menu item
    let links;
    try {
      [{ result: links }] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: collectLinks });
    } catch {
      return;    // Chrome doesn't let extensions read some pages (chrome:// pages, the Web Store, the PDF viewer)
    }
    try {
      const response = await fetch(API, { method: "POST", body: JSON.stringify(links) });
      if (!response.ok) throw new Error("api.py answered " + response.status);
      const results = await response.json();
      await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: markLinks, args: [results, APP] });
    } catch {
      openInApp(links);
    }
    return;
  }
  const query = info.linkUrl
    ? "url=" + encodeURIComponent(info.linkUrl)
    : "text=" + encodeURIComponent(info.selectionText);
  chrome.tabs.create({ url: APP + "?" + query });
});

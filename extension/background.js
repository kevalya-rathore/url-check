// Aegis Guard extension: a right-click item that sends a link or selected text to the Aegis Guard app.
// It only reads the link's address; it never opens the link itself.
const APP = "https://aegis-guard-vanguard.streamlit.app/";    // use "http://localhost:8501/" when running locally

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "aegis-check",
    title: "Check with Aegis Guard",
    contexts: ["link", "selection"],
  });
});

chrome.contextMenus.onClicked.addListener((info) => {
  const query = info.linkUrl
    ? "url=" + encodeURIComponent(info.linkUrl)
    : "text=" + encodeURIComponent(info.selectionText);
  chrome.tabs.create({ url: APP + "?" + query });
});

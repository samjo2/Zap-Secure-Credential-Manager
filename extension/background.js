const ZAP_ORIGIN = 'http://localhost:5000';

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type !== 'getCredentials') return;
  const url = `${ZAP_ORIGIN}/api/fill?domain=${encodeURIComponent(message.domain)}`;
  fetch(url, { credentials: 'include' })
    .then((resp) => {
      if (resp.status === 401) return { error: 'locked' };
      if (!resp.ok) return null;
      return resp.json();
    })
    .then((data) => sendResponse(data))
    .catch(() => sendResponse(null));
  return true; // async sendResponse
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'getCredentials') {
    fetch('http://localhost:5000/get_credentials', { credentials: 'include' })
      .then(response => response.json())
      .then(data => {
        const creds = data[message.domain];
        sendResponse(creds || {});
      })
      .catch(() => sendResponse({}));
    return true; // Keep the message channel open for async response
  }
});

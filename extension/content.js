const domain = window.location.hostname;

function fillForm(creds) {
  const usernameField = document.querySelector('input[type="text"], input[type="email"]');
  const passwordField = document.querySelector('input[type="password"]');
  if (usernameField && passwordField) {
    usernameField.value = creds.username || '';
    passwordField.value = creds.password || '';
  }
}

function requestAndFill() {
  chrome.runtime.sendMessage({ type: 'getCredentials', domain }, response => {
    if (response && response.username) {
      fillForm(response);
    }
  });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'triggerAutofill') {
    requestAndFill();
  }
});

chrome.storage.sync.get(['whitelist'], data => {
  const whitelist = data.whitelist || [];
  if (whitelist.includes(domain)) {
    requestAndFill();
  }
});

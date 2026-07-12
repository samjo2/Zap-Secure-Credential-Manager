// Top frame only: never hand credentials to embedded third-party iframes.
if (window.top === window.self) {
  const domain = window.location.hostname;

  function setValue(field, value) {
    field.value = value;
    field.dispatchEvent(new Event('input', { bubbles: true }));
    field.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function fillForm(creds) {
    const passwordField = document.querySelector('input[type="password"]');
    if (!passwordField) return false;
    const scope = passwordField.closest('form') || document;
    const usernameField = scope.querySelector(
      'input[autocomplete="username"], input[type="email"], input[type="text"]'
    );
    if (usernameField) setValue(usernameField, creds.username || '');
    setValue(passwordField, creds.password || '');
    return true;
  }

  function requestAndFill(sendResult) {
    chrome.runtime.sendMessage({ type: 'getCredentials', domain }, (response) => {
      let status;
      if (response && response.error === 'locked') {
        status = 'locked';
      } else if (response && response.password) {
        status = fillForm(response) ? 'filled' : 'no-form';
      } else {
        status = 'no-credential';
      }
      if (sendResult) sendResult(status);
    });
  }

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'triggerAutofill') {
      requestAndFill(sendResponse);
      return true;
    }
  });

  chrome.storage.sync.get(['whitelist'], (data) => {
    const whitelist = data.whitelist || [];
    if (whitelist.includes(domain)) {
      requestAndFill();
    }
  });
}

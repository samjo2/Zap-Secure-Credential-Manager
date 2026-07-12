const statusEl = document.getElementById('status');
const checkbox = document.getElementById('whitelist');

const MESSAGES = {
  filled: 'Credentials filled.',
  locked: 'Vault is locked. Log in to Zap first.',
  'no-credential': 'No credential saved for this site.',
  'no-form': 'No login form found on this page.',
};

document.getElementById('autofill').addEventListener('click', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    chrome.tabs.sendMessage(tabs[0].id, { type: 'triggerAutofill' }, (result) => {
      if (chrome.runtime.lastError) {
        statusEl.textContent = 'Cannot autofill on this page.';
        return;
      }
      statusEl.textContent = MESSAGES[result] || '';
    });
  });
});

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  let domain;
  try {
    domain = new URL(tabs[0].url).hostname;
  } catch {
    checkbox.disabled = true;
    return;
  }
  chrome.storage.sync.get(['whitelist'], (data) => {
    const list = data.whitelist || [];
    checkbox.checked = list.includes(domain);
    checkbox.addEventListener('change', () => {
      const updated = new Set(list);
      if (checkbox.checked) {
        updated.add(domain);
      } else {
        updated.delete(domain);
      }
      chrome.storage.sync.set({ whitelist: Array.from(updated) });
    });
  });
});

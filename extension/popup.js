document.getElementById('autofill').addEventListener('click', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    chrome.tabs.sendMessage(tabs[0].id, { type: 'triggerAutofill' });
  });
});

const checkbox = document.getElementById('whitelist');

chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
  const domain = new URL(tabs[0].url).hostname;
  chrome.storage.sync.get(['whitelist'], data => {
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

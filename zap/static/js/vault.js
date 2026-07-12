'use strict';

const CSRF = document.querySelector('meta[name="csrf-token"]').content;

const els = {
  list: document.getElementById('credentials'),
  empty: document.getElementById('empty-state'),
  search: document.getElementById('search'),
  form: document.getElementById('credential-form'),
  formTitle: document.getElementById('form-title'),
  showAdd: document.getElementById('show-add'),
  cancel: document.getElementById('cancel-form'),
  credId: document.getElementById('cred-id'),
  service: document.getElementById('service'),
  site: document.getElementById('site'),
  username: document.getElementById('username'),
  password: document.getElementById('password'),
  togglePassword: document.getElementById('toggle-form-password'),
  generate: document.getElementById('generate'),
  genLength: document.getElementById('gen-length'),
  genSymbols: document.getElementById('gen-symbols'),
  notes: document.getElementById('notes'),
};

let items = [];

async function api(path, options = {}) {
  options.headers = Object.assign(
    { 'X-CSRF-Token': CSRF, 'Content-Type': 'application/json' },
    options.headers || {}
  );
  const resp = await fetch(path, options);
  if (resp.status === 401) {
    window.location = '/login';
    throw new Error('vault locked');
  }
  const body = await resp.json();
  if (!resp.ok) throw new Error(body.error || 'request failed');
  return body;
}

async function refresh() {
  items = await api('/api/credentials');
  render();
}

function render() {
  const query = els.search.value.trim().toLowerCase();
  const visible = items.filter(
    (it) =>
      !query ||
      it.service.toLowerCase().includes(query) ||
      (it.site || '').includes(query) ||
      it.username.toLowerCase().includes(query)
  );
  els.list.replaceChildren(...visible.map(card));
  els.empty.classList.toggle('hidden', items.length > 0);
}

function card(item) {
  const root = el('div', 'credential-card');
  const head = el('div', 'cred-head');
  head.append(el('strong', '', item.service));
  if (item.site) head.append(el('span', 'cred-site', item.site));
  root.append(head);

  const body = el('div', 'cred-body');
  body.append(field('Username', item.username, () => copyText(item.username)));

  const secretRow = el('div', 'cred-field');
  secretRow.append(el('span', 'cred-label', 'Password'));
  const secretValue = el('code', 'cred-value', '••••••••••');
  secretRow.append(secretValue);
  let revealed = false;
  secretRow.append(
    action('Show', async (btn) => {
      if (!revealed) {
        const data = await api(`/api/credentials/${item.id}/reveal`);
        secretValue.textContent = data.password;
        btn.textContent = 'Hide';
      } else {
        secretValue.textContent = '••••••••••';
        btn.textContent = 'Show';
      }
      revealed = !revealed;
    }),
    action('Copy', async () => {
      const data = await api(`/api/credentials/${item.id}/reveal`);
      copyText(data.password);
    })
  );
  body.append(secretRow);

  if (item.has_notes) {
    const notesRow = el('div', 'cred-field');
    notesRow.append(el('span', 'cred-label', 'Notes'));
    const notesValue = el('span', 'cred-value cred-notes', '');
    notesRow.append(
      notesValue,
      action('Show', async (btn) => {
        if (!notesValue.textContent) {
          const data = await api(`/api/credentials/${item.id}/reveal`);
          notesValue.textContent = data.notes;
          btn.textContent = 'Hide';
        } else {
          notesValue.textContent = '';
          btn.textContent = 'Show';
        }
      })
    );
    body.append(notesRow);
  }
  root.append(body);

  const actions = el('div', 'cred-actions');
  actions.append(
    action('Edit', async () => {
      const data = await api(`/api/credentials/${item.id}/reveal`);
      openForm({
        id: item.id,
        service: item.service,
        site: item.site || '',
        username: data.username,
        password: data.password,
        notes: data.notes,
      });
    }),
    action('Delete', async () => {
      if (!confirm(`Delete the credential for "${item.service}"?`)) return;
      await api(`/api/credentials/${item.id}`, { method: 'DELETE' });
      await refresh();
    })
  );
  root.append(actions);
  return root;
}

function field(label, value, onCopy) {
  const row = el('div', 'cred-field');
  row.append(el('span', 'cred-label', label));
  row.append(el('span', 'cred-value', value || '-'));
  if (value && onCopy) row.append(action('Copy', onCopy));
  return row;
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function action(label, handler) {
  const btn = el('button', 'small', label);
  btn.type = 'button';
  btn.addEventListener('click', () => handler(btn).catch(showError));
  return btn;
}

function copyText(text) {
  navigator.clipboard.writeText(text).catch(showError);
}

function showError(err) {
  alert(err.message || String(err));
}

function openForm(data) {
  els.credId.value = data ? data.id : '';
  els.formTitle.textContent = data ? 'Edit credential' : 'Add credential';
  els.service.value = data ? data.service : '';
  els.site.value = data ? data.site : '';
  els.username.value = data ? data.username : '';
  els.password.value = data ? data.password : '';
  els.notes.value = data ? data.notes : '';
  els.form.classList.remove('hidden');
  els.service.focus();
}

function closeForm() {
  els.form.reset();
  els.credId.value = '';
  els.form.classList.add('hidden');
}

els.showAdd.addEventListener('click', () => openForm(null));
els.cancel.addEventListener('click', closeForm);
els.search.addEventListener('input', render);

els.togglePassword.addEventListener('click', () => {
  const hidden = els.password.type === 'password';
  els.password.type = hidden ? 'text' : 'password';
  els.togglePassword.textContent = hidden ? 'Hide' : 'Show';
});

els.generate.addEventListener('click', async () => {
  const length = parseInt(els.genLength.value, 10) || 20;
  const symbols = els.genSymbols.checked ? '1' : '0';
  const data = await api(`/api/generate-password?length=${length}&symbols=${symbols}`);
  els.password.value = data.password;
  els.password.type = 'text';
  els.togglePassword.textContent = 'Hide';
});

els.form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const payload = {
    service: els.service.value,
    site: els.site.value,
    username: els.username.value,
    password: els.password.value,
    notes: els.notes.value,
  };
  const id = els.credId.value;
  try {
    if (id) {
      await api(`/api/credentials/${id}`, { method: 'PUT', body: JSON.stringify(payload) });
    } else {
      await api('/api/credentials', { method: 'POST', body: JSON.stringify(payload) });
    }
    closeForm();
    await refresh();
  } catch (err) {
    showError(err);
  }
});

refresh().catch(showError);

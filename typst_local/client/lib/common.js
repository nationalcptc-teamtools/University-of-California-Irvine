// Shared helpers for the dashboard and the editor.

const USER_KEY = 'typst-local-user';

export const USER_COLORS = [
  '#e5484d', '#f76b15', '#d6a100', '#30a46c', '#12a594', '#0090ff', '#3e63dd', '#8e4ec6', '#d6409f', '#ad7f58',
];

export function getUser() {
  let user = null;
  try {
    user = JSON.parse(localStorage.getItem(USER_KEY));
  } catch {}
  if (!user || typeof user.name !== 'string') {
    user = { name: '', color: USER_COLORS[Math.floor(Math.random() * USER_COLORS.length)] };
  }
  return user;
}

export function saveUser(user) {
  try {
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  } catch {}
}

export async function api(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : {},
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) {
    location.href = '/login?next=' + encodeURIComponent(location.pathname);
    throw new Error('unauthorized');
  }
  if (!res.ok) {
    let msg = res.statusText;
    try {
      msg = (await res.json()).error || msg;
    } catch {}
    throw new Error(msg);
  }
  return res.json();
}

/** Tiny DOM builder: h('div.a.b', {onclick}, children...) */
export function h(tag, props, ...children) {
  const [name, ...classes] = tag.split('.');
  const el = document.createElement(name || 'div');
  if (classes.length) el.className = classes.join(' ');
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else if (k === 'html') el.innerHTML = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

export function timeAgo(ts) {
  const s = Math.round((Date.now() - ts) / 1000);
  if (s < 60) return 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const hrs = Math.round(m / 60);
  if (hrs < 24) return `${hrs} h ago`;
  const d = Math.round(hrs / 24);
  if (d < 30) return `${d} d ago`;
  return new Date(ts).toLocaleDateString();
}

export function initials(name) {
  return (name || '?')
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0].toUpperCase())
    .join('');
}

let toastTimer;
let toastId = 0;
/**
 * Shows a short message. With `duration: null` it stays until the returned
 * function is called (or another message replaces it).
 */
export function toast(text, kind = 'info', { duration = 2600 } = {}) {
  let el = document.getElementById('toast');
  if (!el) {
    el = h('div');
    el.id = 'toast';
    document.body.append(el);
  }
  el.textContent = text;
  el.className = 'show ' + kind;
  clearTimeout(toastTimer);
  const id = ++toastId;
  const hide = () => {
    if (id === toastId) el.className = '';
  };
  if (duration !== null) toastTimer = setTimeout(hide, duration);
  return hide;
}

/**
 * Promise-based modal dialog. fields: [{name, label, value, placeholder, type, options}];
 * list: items (text or nodes) shown in a scrollable box under the message.
 */
export function dialog({ title, message, list, fields = [], confirm = 'OK', danger = false, cancel = 'Cancel' }) {
  return new Promise((resolve) => {
    const inputs = {};
    const close = (value) => {
      overlay.remove();
      document.removeEventListener('keydown', onKey, true);
      resolve(value);
    };
    const submit = () => {
      const values = {};
      for (const [k, el] of Object.entries(inputs)) values[k] = el.value;
      close(fields.length ? values : true);
    };
    const onKey = (e) => {
      if (e.key === 'Escape') close(null);
    };
    const form = h(
      'form.dialog',
      {
        onsubmit: (e) => {
          e.preventDefault();
          submit();
        },
      },
      h('h2', null, title),
      message && h('p.dialog-message', null, message),
      list?.length ? h('ul.dialog-list', null, list.map((item) => h('li', null, item))) : null,
      fields.map((f) => {
        let input;
        if (f.options) {
          input = h('div.choice-row', null);
          const hidden = h('input', { type: 'hidden', value: f.value ?? f.options[0].value });
          for (const o of f.options) {
            const btn = h(
              'button.choice' + ((f.value ?? f.options[0].value) === o.value ? '.selected' : ''),
              {
                type: 'button',
                onclick: () => {
                  hidden.value = o.value;
                  input.querySelectorAll('.choice').forEach((b) => b.classList.toggle('selected', b === btn));
                },
              },
              o.label,
            );
            input.append(btn);
          }
          input.append(hidden);
          inputs[f.name] = hidden;
        } else {
          input = inputs[f.name] = h('input.text-input', {
            type: f.type || 'text',
            value: f.value ?? '',
            placeholder: f.placeholder,
            autocomplete: 'off',
            spellcheck: 'false',
          });
        }
        return h('label.field', null, f.label && h('span', null, f.label), input);
      }),
      h(
        'div.dialog-actions',
        null,
        cancel && h('button.btn', { type: 'button', onclick: () => close(null) }, cancel),
        h('button.btn' + (danger ? '.danger' : '.primary'), { type: 'submit' }, confirm),
      ),
    );
    const overlay = h('div.overlay', { onmousedown: (e) => e.target === overlay && close(null) }, form);
    document.body.append(overlay);
    document.addEventListener('keydown', onKey, true);
    const first = form.querySelector('input.text-input');
    if (first) {
      first.focus();
      const dot = first.value.lastIndexOf('.');
      first.setSelectionRange(0, dot > 0 ? dot : first.value.length);
    } else form.querySelector('button[type=submit]').focus();
  });
}

/** Simple popup menu anchored to an element or point. items: [{label, onclick, danger}] | 'sep' */
export function popupMenu(anchor, items) {
  document.querySelectorAll('.menu').forEach((m) => m.remove());
  const menu = h(
    'div.menu',
    null,
    items.map((it) =>
      it === 'sep'
        ? h('div.menu-sep')
        : h(
            'button.menu-item' + (it.danger ? '.danger' : ''),
            {
              onclick: () => {
                menu.remove();
                it.onclick();
              },
            },
            it.label,
          ),
    ),
  );
  document.body.append(menu);
  let x, y;
  if (anchor instanceof MouseEvent) {
    x = anchor.clientX;
    y = anchor.clientY;
  } else {
    const r = anchor.getBoundingClientRect();
    x = r.right - menu.offsetWidth;
    y = r.bottom + 4;
  }
  x = Math.max(8, Math.min(x, innerWidth - menu.offsetWidth - 8));
  y = Math.max(8, Math.min(y, innerHeight - menu.offsetHeight - 8));
  menu.style.left = x + 'px';
  menu.style.top = y + 'px';
  setTimeout(() => {
    const off = (e) => {
      if (!menu.contains(e.target)) {
        menu.remove();
        document.removeEventListener('mousedown', off, true);
      }
    };
    document.addEventListener('mousedown', off, true);
  });
}

export async function ensureUserName() {
  const user = getUser();
  if (user.name) return user;
  const res = await dialog({
    title: 'Welcome!',
    message: 'Pick a display name so collaborators know who you are.',
    fields: [{ name: 'name', label: 'Your name', placeholder: 'e.g. Ada Lovelace' }],
    confirm: 'Continue',
    cancel: null,
  });
  user.name = (res?.name || '').trim().slice(0, 40) || 'Anonymous';
  saveUser(user);
  return user;
}

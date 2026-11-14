// The share viewer: one static page served at /p/:id. It reads the link key from the URL fragment
// (never sent to the relay), asks for the PIN, derives `auth` and the AES key from both, fetches
// the ciphertext, and shows the decrypted page in a sandboxed srcdoc frame. An answer the page
// submits is encrypted with the same key and posted back.
//
// Crypto contract (must match the OpenChamber host, packages/web/server/lib/share-pages):
//   linkKey  = 32 random bytes, base64url in the fragment
//   auth     = HKDF-SHA-256(ikm = linkKey, salt = UTF-8(PIN), info = "openchamber-share-v1 auth"), 32 bytes
//   encKey   = HKDF-SHA-256(ikm = linkKey, salt = UTF-8(PIN), info = "openchamber-share-v1 enc"), AES-256-GCM
//   blob     = 0x01 || iv(12) || AES-GCM(encKey, iv, plaintext, aad)
//   document = blob of UTF-8 JSON { v: 1, title, html, source? }, aad "openchamber-share-v1 document"
//              (`source` is the page as the agent wrote it, for a recipient's own agent to read
//              in OpenChamber; this viewer ignores it)
//   answer   = base64url(blob of UTF-8 JSON { v: 1, data, summary, submittedAt }), aad "openchamber-share-v1 answer"
//
// Frame protocol (postMessage, the frame is an opaque origin):
//   page -> viewer  { source: "openchamber-share-document", type: "submit", data, summary }
//   viewer -> page  { source: "openchamber-share-viewer", type: "init", wantsAnswer, locale, answer? }
//                   (`answer` is sent by OpenChamber when it reopens an answered page; never here)
//                   { source: "openchamber-share-viewer", type: "submit-result", ok, error? }
//
// Colors are the app's default themes (openchamber-light / openchamber-dark), icons the app's
// Remix paths. The script avoids template literals so it can live in this string.

import { VIEWER_STRINGS } from './viewer-strings';

const ICONS = {
  lock: '<path d="M19 10H20C20.5523 10 21 10.4477 21 11V21C21 21.5523 20.5523 22 20 22H4C3.44772 22 3 21.5523 3 21V11C3 10.4477 3.44772 10 4 10H5V9C5 5.13401 8.13401 2 12 2C15.866 2 19 5.13401 19 9V10ZM5 12V20H19V12H5ZM11 14H13V18H11V14ZM17 10V9C17 6.23858 14.7614 4 12 4C9.23858 4 7 6.23858 7 9V10H17Z" fill="currentColor"/>',
  time: '<path d="M12 22C6.47715 22 2 17.5228 2 12C2 6.47715 6.47715 2 12 2C17.5228 2 22 6.47715 22 12C22 17.5228 17.5228 22 12 22ZM12 20C16.4183 20 20 16.4183 20 12C20 7.58172 16.4183 4 12 4C7.58172 4 4 7.58172 4 12C4 16.4183 7.58172 20 12 20ZM13 12H17V14H11V7H13V12Z" fill="currentColor"/>',
  check: '<path d="M4 12C4 7.58172 7.58172 4 12 4C16.4183 4 20 7.58172 20 12C20 16.4183 16.4183 20 12 20C7.58172 20 4 16.4183 4 12ZM12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2ZM17.4571 9.45711L16.0429 8.04289L11 13.0858L8.20711 10.2929L6.79289 11.7071L11 15.9142L17.4571 9.45711Z" fill="currentColor"/>',
  close: '<path d="M12 22C6.47715 22 2 17.5228 2 12C2 6.47715 6.47715 2 12 2C17.5228 2 22 6.47715 22 12C22 17.5228 17.5228 22 12 22ZM12 20C16.4183 20 20 16.4183 20 12C20 7.58172 16.4183 4 12 4C7.58172 4 4 7.58172 4 12C4 16.4183 7.58172 20 12 20ZM12 10.5858L14.8284 7.75736L16.2426 9.17157L13.4142 12L16.2426 14.8284L14.8284 16.2426L12 13.4142L9.17157 16.2426L7.75736 14.8284L10.5858 12L7.75736 9.17157L9.17157 7.75736L12 10.5858Z" fill="currentColor"/>',
  warning: '<path d="M12 22C6.47715 22 2 17.5228 2 12C2 6.47715 6.47715 2 12 2C17.5228 2 22 6.47715 22 12C22 17.5228 17.5228 22 12 22ZM12 20C16.4183 20 20 16.4183 20 12C20 7.58172 16.4183 4 12 4C7.58172 4 4 7.58172 4 12C4 16.4183 7.58172 20 12 20ZM11 15H13V17H11V15ZM11 7H13V13H11V7Z" fill="currentColor"/>',
  key: '<path d="M12 1L20.2169 2.82598C20.6745 2.92766 21 3.33347 21 3.80217V13.7889C21 15.795 19.9974 17.6684 18.3282 18.7812L12 23L5.6718 18.7812C4.00261 17.6684 3 15.795 3 13.7889V3.80217C3 3.33347 3.32553 2.92766 3.78307 2.82598L12 1ZM12 3.04879L5 4.60434V13.7889C5 15.1263 5.6684 16.3752 6.7812 17.1171L12 20.5963L17.2188 17.1171C18.3316 16.3752 19 15.1263 19 13.7889V4.60434L12 3.04879ZM12 7C13.1046 7 14 7.89543 14 9C14 9.73984 13.5983 10.3858 13.0011 10.7318L13 15H11L10.9999 10.7324C10.4022 10.3866 10 9.74025 10 9C10 7.89543 10.8954 7 12 7Z" fill="currentColor"/>',
  shield: '<path d="M12 1L20.2169 2.82598C20.6745 2.92766 21 3.33347 21 3.80217V13.7889C21 15.795 19.9974 17.6684 18.3282 18.7812L12 23L5.6718 18.7812C4.00261 17.6684 3 15.795 3 13.7889V3.80217C3 3.33347 3.32553 2.92766 3.78307 2.82598L12 1ZM12 3.04879L5 4.60434V13.7889C5 15.1263 5.6684 16.3752 6.7812 17.1171L12 20.5963L17.2188 17.1171C18.3316 16.3752 19 15.1263 19 13.7889V4.60434L12 3.04879ZM16.4524 8.22183L17.8666 9.63604L11.5026 16L7.25999 11.7574L8.67421 10.3431L11.5019 13.1709L16.4524 8.22183Z" fill="currentColor"/>',
};

const STYLE = `
:root {
  color-scheme: light dark;
  --bg: #fdfcfa; --fg: #262521; --muted-fg: #696960; --surface: #f3f2f0; --surface-2: #ecebe7;
  --border: #e5e1debf; --border-hover: #cbc7c2; --primary: #b35017; --focus: #b3501755; --error: #b7493f;
  --inset: color-mix(in srgb, var(--fg) 6%, transparent);
  --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  --font-mono: ui-monospace, "SFMono-Regular", "Menlo", "Cascadia Mono", "Segoe UI Mono", monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #120f0e; --fg: #dbd7cc; --muted-fg: #9a978d; --surface: #1b1918; --surface-2: #242221;
    --border: #242323bf; --border-hover: #504e4c; --primary: #da7c47; --focus: #da7c4755; --error: #da5b4a;
    --inset: color-mix(in srgb, var(--fg) 4.5%, transparent);
  }
}
* { box-sizing: border-box; }
html, body { margin: 0; height: 100%; }
body {
  background: var(--bg); color: var(--fg); font-family: var(--font-sans); font-size: 15px; line-height: 1.45;
  display: flex; flex-direction: column; min-height: 100dvh; -webkit-font-smoothing: antialiased;
}
.screen { flex: 1; display: flex; align-items: center; justify-content: center; padding: 24px 16px; }
.card { width: min(320px, 100%); text-align: center; display: flex; flex-direction: column; align-items: center; }
.icon {
  width: 40px; height: 40px; border-radius: 10px; background: var(--inset); color: var(--muted-fg);
  display: flex; align-items: center; justify-content: center; margin-bottom: 14px;
}
.icon svg { width: 22px; height: 22px; display: block; }
.icon.is-success { color: var(--primary); }
h1 { font-size: 15px; line-height: 1.3; font-weight: 600; margin: 0 0 4px; }
p { margin: 0; color: var(--muted-fg); font-size: 13px; }
.summary { margin-top: 14px; padding: 10px 12px; border-radius: 9px; background: var(--inset); color: var(--fg); font-size: 13px; text-align: start; overflow-wrap: anywhere; align-self: stretch; }
/* The PIN cells are the app's text fields (oc-raised oc-field): a hairline edge that brightens
   on focus, no ring; pressed in on light themes, lit from above on dark ones. */
.pins { display: flex; gap: 6px; justify-content: center; margin: 18px 0 10px; direction: ltr; }
.pins input {
  width: 36px; height: 42px; border-radius: 8px; border: 0; color: var(--fg); padding: 0; outline: none;
  text-align: center; font: 600 17px var(--font-mono); caret-color: var(--fg);
  --edge: color-mix(in srgb, var(--fg) 16%, transparent); --edge-w: 0.5px;
  background: var(--bg);
  box-shadow: inset 0 0 0 var(--edge-w) var(--edge), inset 0 1px 2px 0 rgb(0 0 0 / 0.04);
}
.pins input:nth-child(3) { margin-inline-end: 6px; }
.pins input:focus { --edge: color-mix(in srgb, var(--fg) 26%, transparent); --edge-w: 1px; }
.pins.is-error input { --edge: var(--error); --edge-w: 1px; }
@media (prefers-color-scheme: dark) {
  .pins input {
    --edge: color-mix(in srgb, var(--fg) 14%, transparent);
    background-image: linear-gradient(color-mix(in srgb, var(--fg) 4%, transparent), color-mix(in srgb, var(--fg) 4%, transparent));
    box-shadow: inset 0 0.5px 0 0 color-mix(in srgb, var(--fg) 8%, transparent), inset 0 0 0 var(--edge-w) var(--edge), 0 1px 2px 0 rgb(0 0 0 / 0.4);
  }
}
/* One reserved line under the PIN: expiry at rest, then progress or the error. */
.status { height: 18px; font-size: 12px; color: var(--muted-fg); display: inline-flex; align-items: center; gap: 5px; }
.status svg { width: 13px; height: 13px; }
.status.is-error { color: var(--error); }
/* The app's tinted button at its default size: it hugs its label. */
.button {
  height: 32px; padding: 0 14px; border-radius: 7px; font: 500 13px var(--font-sans); cursor: pointer;
  color: var(--primary); background: color-mix(in srgb, var(--primary) 10%, var(--bg));
  border: 1px solid color-mix(in srgb, var(--primary) 12%, transparent);
  box-shadow: inset 0 1px 0 rgb(255 255 255 / 0.2), 0 1px 1.5px rgb(0 0 0 / 0.1);
}
.button:hover:not(:disabled) { background: color-mix(in srgb, var(--primary) 16%, var(--bg)); }
@media (prefers-color-scheme: dark) {
  .button {
    background: color-mix(in srgb, var(--primary) 16%, transparent); border-color: color-mix(in srgb, var(--primary) 20%, transparent);
    box-shadow: inset 0 1px 0 color-mix(in srgb, var(--fg) 1.5%, transparent), 0 1px 1px rgb(0 0 0 / 0.28);
  }
  .button:hover:not(:disabled) { background: color-mix(in srgb, var(--primary) 22%, transparent); }
}
.button:focus-visible { outline: none; box-shadow: 0 0 0 3px var(--focus); }
.button:disabled { opacity: 0.5; cursor: default; }
.doc { flex: 1; width: 100%; border: 0; display: block; background: var(--bg); }
.foot {
  display: flex; align-items: center; justify-content: center; gap: 6px; flex-wrap: wrap;
  padding: 8px 12px; font-size: 0.75rem; color: var(--muted-fg);
}
.foot > span { display: inline-flex; align-items: center; }
.foot svg { width: 13px; height: 13px; display: block; }
.foot .sep { opacity: 0.5; }
.confirm {
  position: fixed; inset-inline: 12px; bottom: 44px; margin: 0 auto; max-width: 420px; padding: 16px;
  border-radius: 14px; background: var(--surface); box-shadow: 0 8px 32px rgba(0, 0, 0, 0.25);
}
.confirm-title { font-weight: 600; }
.confirm .summary { margin-top: 8px; }
.confirm-row { display: flex; gap: 8px; margin-top: 12px; }
.confirm-row { justify-content: flex-end; }
.button-secondary { color: var(--fg); background: var(--inset); border-color: transparent; box-shadow: none; }
[hidden] { display: none !important; }
`;

const SCRIPT = String.raw`
(function () {
  'use strict';
  var STRINGS = __STRINGS__;
  var ICONS = __ICONS__;
  var RTL = { ar: true, he: true };
  var DOC_AAD = 'openchamber-share-v1 document';
  // The page inherits the viewer's policy, which allows requests to this relay for the viewer's
  // own API. A second, stricter policy inside the page takes the network away from it entirely;
  // both apply, so the page can reach nothing.
  var DOC_CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:; font-src data:; media-src data: blob:; connect-src 'none'; form-action 'none'; base-uri 'none'";
  var ANSWER_AAD = 'openchamber-share-v1 answer';
  var enc = new TextEncoder();
  var dec = new TextDecoder();

  function pickLocale() {
    var wanted = (navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language || 'en']);
    for (var i = 0; i < wanted.length; i++) {
      var tag = String(wanted[i] || '');
      if (STRINGS[tag]) return tag;
      var lower = tag.toLowerCase();
      if (lower.indexOf('zh') === 0) return /(tw|hk|mo|hant)/.test(lower) ? 'zh-TW' : 'zh-CN';
      if (lower.indexOf('pt') === 0) return 'pt-BR';
      var base = lower.split('-')[0];
      if (STRINGS[base]) return base;
    }
    return 'en';
  }

  var locale = pickLocale();
  document.documentElement.lang = locale;
  document.documentElement.dir = RTL[locale] ? 'rtl' : 'ltr';

  function t(key, vars) {
    var text = (STRINGS[locale] && STRINGS[locale][key]) || STRINGS.en[key] || key;
    if (vars) Object.keys(vars).forEach(function (name) { text = text.split('{' + name + '}').join(String(vars[name])); });
    return text;
  }

  function formatDate(ms) {
    try {
      return new Intl.DateTimeFormat(locale, { weekday: 'short', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(new Date(ms));
    } catch (e) {
      return new Date(ms).toLocaleString();
    }
  }

  function b64uToBytes(value) {
    if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
    var normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    while (normalized.length % 4) normalized += '=';
    try {
      var binary = atob(normalized);
      var bytes = new Uint8Array(binary.length);
      for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes;
    } catch (e) {
      return null;
    }
  }

  function bytesToB64u(bytes) {
    var binary = '';
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  async function deriveKeys(linkKey, pin) {
    var base = await crypto.subtle.importKey('raw', linkKey, 'HKDF', false, ['deriveBits', 'deriveKey']);
    var salt = enc.encode(pin);
    var auth = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: salt, info: enc.encode('openchamber-share-v1 auth') }, base, 256);
    var key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: salt, info: enc.encode('openchamber-share-v1 enc') }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    return { auth: bytesToB64u(new Uint8Array(auth)), key: key };
  }

  async function openBlob(key, buffer, aad) {
    var bytes = new Uint8Array(buffer);
    if (bytes.length < 13 + 16 || bytes[0] !== 1) throw new Error('format');
    var plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(1, 13), additionalData: enc.encode(aad) }, key, bytes.slice(13));
    return JSON.parse(dec.decode(plain));
  }

  async function sealBlob(key, value, aad) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: enc.encode(aad) }, key, enc.encode(JSON.stringify(value))));
    var out = new Uint8Array(1 + iv.length + cipher.length);
    out[0] = 1;
    out.set(iv, 1);
    out.set(cipher, 13);
    return bytesToB64u(out);
  }

  var screen = document.getElementById('screen');
  var card = document.getElementById('card');
  var frame = document.getElementById('doc');
  var foot = document.getElementById('foot');

  function icon(name) {
    return '<svg viewBox="0 0 24 24" aria-hidden="true">' + ICONS[name] + '</svg>';
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function renderFoot() {
    foot.innerHTML = '';
    var shield = el('span');
    shield.innerHTML = icon('shield');
    foot.appendChild(shield);
    foot.appendChild(el('span', '', t('encrypted')));
    foot.appendChild(el('span', 'sep', '·'));
    foot.appendChild(el('span', '', 'OpenChamber'));
  }

  function showCard(iconName, title, body, extra, success) {
    frame.hidden = true;
    screen.hidden = false;
    card.innerHTML = '';
    var badge = el('div', success ? 'icon is-success' : 'icon');
    badge.innerHTML = icon(iconName);
    card.appendChild(badge);
    card.appendChild(el('h1', '', title));
    if (body) card.appendChild(el('p', '', body));
    if (extra) card.appendChild(extra);
    document.title = title;
  }

  function showStatus(status) {
    var s = status || {};
    if (s.status === 'locked') return showCard('lock', t('lockedTitle'), t('lockedBody'));
    if (s.status === 'expired') return showCard('time', t('expiredTitle'), t('expiredBody'));
    if (s.status === 'answered') return showCard('check', t('answeredTitle'), s.answeredAt ? t('answeredBody', { date: formatDate(s.answeredAt) }) : '');
    if (s.status === 'cancelled') return showCard('close', t('cancelledTitle'), t('cancelledBody'));
    return showCard('warning', t('missingTitle'), t('missingBody'));
  }

  var parts = location.pathname.split('/');
  var shareId = parts[2] || '';
  var linkKey = b64uToBytes(location.hash.slice(1));
  var opened = null;
  var shareInfo = null;
  var sending = false;

  async function post(path, body) {
    return fetch('/p/' + encodeURIComponent(shareId) + path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      cache: 'no-store',
    });
  }

  function showPin(info) {
    var wrap = el('div');
    var pins = el('div', 'pins');
    var inputs = [];
    for (var i = 0; i < 6; i++) {
      var input = document.createElement('input');
      input.inputMode = 'numeric';
      input.maxLength = 1;
      input.autocomplete = i === 0 ? 'one-time-code' : 'off';
      input.setAttribute('aria-label', t('pinDigit', { n: i + 1 }));
      pins.appendChild(input);
      inputs.push(input);
    }
    // No Open button: the page opens as soon as the sixth digit is in. One line under the PIN
    // carries the expiry at rest, then progress or the error.
    var status = el('div', 'status');
    status.setAttribute('role', 'status');
    status.setAttribute('aria-live', 'polite');
    function setStatus(kind, text) {
      status.className = kind === 'error' ? 'status is-error' : 'status';
      status.innerHTML = kind === 'rest' ? icon('time') : '';
      status.appendChild(document.createTextNode(text));
    }
    var expires = t('expires', { date: formatDate(info.expiresAt) });
    setStatus('rest', expires);
    wrap.appendChild(pins);
    wrap.appendChild(status);
    showCard('key', info.kind === 'questionnaire' ? t('titleQuestionnaire') : t('titlePage'), t('pinHint'), wrap);
    var busy = false;

    function pin() { return inputs.map(function (x) { return x.value; }).join(''); }
    function fill(digits, from) {
      for (var j = 0; j < digits.length && from + j < 6; j++) inputs[from + j].value = digits[j];
      var next = Math.min(from + digits.length, 5);
      inputs[next].focus();
      if (pins.classList.contains('is-error')) {
        pins.classList.remove('is-error');
        setStatus('rest', expires);
      }
      if (pin().length === 6) submit();
    }
    inputs.forEach(function (input, index) {
      input.addEventListener('input', function () {
        var digits = input.value.replace(/\D/g, '');
        input.value = '';
        if (digits) fill(digits.split(''), index);
      });
      input.addEventListener('keydown', function (event) {
        if (event.key === 'Backspace' && !input.value && index > 0) { inputs[index - 1].value = ''; inputs[index - 1].focus(); event.preventDefault(); }
        if (event.key === 'Enter') submit();
      });
      input.addEventListener('paste', function (event) {
        var digits = ((event.clipboardData && event.clipboardData.getData('text')) || '').replace(/\D/g, '');
        if (!digits) return;
        event.preventDefault();
        fill(digits.split(''), index);
      });
    });
    inputs[0].focus();

    async function submit() {
      if (busy) return;
      var code = pin();
      if (code.length !== 6) return;
      busy = true;
      setStatus('progress', t('opening'));
      try {
        var keys = await deriveKeys(linkKey, code);
        var response = await post('/open', { auth: keys.auth });
        if (response.ok) {
          var documentValue = await openBlob(keys.key, await response.arrayBuffer(), DOC_AAD);
          opened = keys;
          showDocument(documentValue);
          return;
        }
        var body = await response.json().catch(function () { return {}; });
        if (body.error === 'wrong-pin' && response.status === 403) {
          inputs.forEach(function (x) { x.value = ''; });
          pins.classList.add('is-error');
          setStatus('error', t('wrongPin', { n: body.attemptsLeft }));
          inputs[0].focus();
        } else {
          showStatus(body);
          return;
        }
      } catch (error) {
        setStatus('error', error instanceof TypeError ? t('network') : t('openFailed'));
      }
      busy = false;
    }
  }

  function lockDown(html) {
    var parsed = new DOMParser().parseFromString(html, 'text/html');
    var meta = parsed.createElement('meta');
    meta.httpEquiv = 'Content-Security-Policy';
    meta.content = DOC_CSP;
    parsed.head.insertBefore(meta, parsed.head.firstChild);
    return '<!doctype html>' + parsed.documentElement.outerHTML;
  }

  var armed = false;
  var armTimer = null;
  function armAfterActivationLapses() {
    armed = false;
    if (armTimer) clearInterval(armTimer);
    if (!navigator.userActivation) return;
    armTimer = setInterval(function () {
      if (!navigator.userActivation.isActive) {
        armed = true;
        clearInterval(armTimer);
        armTimer = null;
      }
    }, 200);
  }

  function showDocument(value) {
    armAfterActivationLapses();
    screen.hidden = true;
    frame.hidden = false;
    document.title = typeof value.title === 'string' && value.title ? value.title : t('titlePage');
    frame.title = document.title;
    frame.srcdoc = lockDown(typeof value.html === 'string' ? value.html : '');
  }

  frame.addEventListener('load', function () {
    if (!opened || !frame.contentWindow) return;
    frame.contentWindow.postMessage({ source: 'openchamber-share-viewer', type: 'init', wantsAnswer: !!(shareInfo && shareInfo.wantsAnswer), locale: locale }, '*');
  });

  function replyToFrame(message) {
    if (frame.contentWindow) frame.contentWindow.postMessage(Object.assign({ source: 'openchamber-share-viewer' }, message), '*');
  }

  function confirmAnswer(summary) {
    return new Promise(function (resolve) {
      var bar = el('div', 'confirm');
      bar.setAttribute('role', 'dialog');
      bar.appendChild(el('div', 'confirm-title', t('confirmTitle')));
      if (summary) bar.appendChild(el('div', 'summary', summary));
      var row = el('div', 'confirm-row');
      var cancel = el('button', 'button button-secondary', t('cancel'));
      var send = el('button', 'button', t('confirmSend'));
      cancel.type = 'button';
      send.type = 'button';
      row.appendChild(cancel);
      row.appendChild(send);
      bar.appendChild(row);
      document.body.appendChild(bar);
      function done(value) { bar.remove(); resolve(value); }
      cancel.addEventListener('click', function () { done(false); });
      send.addEventListener('click', function () { done(true); });
      send.focus();
    });
  }

  window.addEventListener('message', async function (event) {
    if (event.source !== frame.contentWindow || !opened) return;
    var data = event.data;
    if (!data || data.source !== 'openchamber-share-document' || data.type !== 'submit') return;
    if (!shareInfo || !shareInfo.wantsAnswer || sending) return;
    // The page is someone else's code: a script could post a submit on load. Only an answer the
    // reader just clicked counts; a gesture inside the frame activates this window too. The PIN
    // typing that opened the page keeps the window active for a few seconds, so a submit counts
    // only once that activation has lapsed (armed) and a new one is live.
    // Browsers without the activation API (Safari before 16.4) can't tell a click from a script:
    // there the reader confirms the answer in the viewer's own bar before it leaves.
    var confirmFirst = !navigator.userActivation;
    if (!confirmFirst && !(armed && navigator.userActivation.isActive)) {
      replyToFrame({ type: 'submit-result', ok: false, error: t('sendFailed') });
      return;
    }
    var summary = typeof data.summary === 'string' ? data.summary.slice(0, 500) : '';
    var payload = data.data === undefined ? null : data.data;
    var encoded;
    try {
      encoded = JSON.stringify(payload);
    } catch (e) {
      replyToFrame({ type: 'submit-result', ok: false, error: t('sendFailed') });
      return;
    }
    if (encoded && encoded.length > 16000) {
      replyToFrame({ type: 'submit-result', ok: false, error: t('sendFailed') });
      return;
    }
    sending = true;
    if (confirmFirst && !(await confirmAnswer(summary))) {
      sending = false;
      replyToFrame({ type: 'submit-result', ok: false, error: t('sendCancelled') });
      return;
    }
    try {
      var answer = await sealBlob(opened.key, { v: 1, data: payload, summary: summary, submittedAt: Date.now() }, ANSWER_AAD);
      var response = await post('/answer', { auth: opened.auth, answer: answer });
      if (response.ok) {
        replyToFrame({ type: 'submit-result', ok: true });
        var extra = summary ? el('div', 'summary', summary) : null;
        showCard('check', t('sentTitle'), t('sentBody'), extra, true);
        return;
      }
      var body = await response.json().catch(function () { return {}; });
      if (response.status === 409 || response.status === 410 || response.status === 423) {
        showStatus(body);
        return;
      }
      replyToFrame({ type: 'submit-result', ok: false, error: t('sendFailed') });
    } catch (error) {
      replyToFrame({ type: 'submit-result', ok: false, error: error instanceof TypeError ? t('network') : t('sendFailed') });
    } finally {
      sending = false;
    }
  });

  async function start() {
    renderFoot();
    if (!/^[A-Za-z0-9_-]{22}$/.test(shareId)) return showStatus({ status: 'missing' });
    if (!linkKey || linkKey.length !== 32) return showCard('warning', t('brokenTitle'), t('brokenBody'));
    try {
      var response = await fetch('/p/' + encodeURIComponent(shareId) + '/status', { cache: 'no-store' });
      var info = await response.json().catch(function () { return { status: 'missing' }; });
      shareInfo = info;
      if (info.status === 'open') return showPin(info);
      showStatus(info);
    } catch (error) {
      showCard('warning', t('missingTitle'), t('network'));
    }
  }

  start();
})();
`;

const safeJson = (value: unknown): string => JSON.stringify(value).replace(/</g, '\\u003c');

export const VIEWER_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="color-scheme" content="light dark">
<title>OpenChamber</title>
<style>${STYLE}</style>
</head>
<body>
<main class="screen" id="screen"><div class="card" id="card"></div></main>
<iframe class="doc" id="doc" hidden sandbox="allow-scripts allow-forms" referrerpolicy="no-referrer"></iframe>
<footer class="foot" id="foot"></footer>
<script>${SCRIPT.replace('__STRINGS__', () => safeJson(VIEWER_STRINGS)).replace('__ICONS__', () => safeJson(ICONS))}</script>
</body>
</html>`;

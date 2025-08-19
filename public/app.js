// public/app.js
import * as Stronghold from '/src/stronghold.js';
import * as Passkeys   from '/src/passkeys.js';

(function () {
  console.log('[init] app.js starting');
  const $ = (id) => {
    const el = document.getElementById(id);
    if (!el) throw new Error(`missing #${id}`);
    return el;
  };

  // Optional elements (so file works on smaller pages too)
  const out = document.getElementById('out');
  const safeLog = (...a) => {
    console.log(...a);
    if (!out) return;
    out.textContent += a.map(x => typeof x === 'string' ? x : JSON.stringify(x, null, 2)).join(' ') + '\n';
  };
  const log = (...a) => safeLog(...a);

  // ---------- Status ----------
  async function reportStatus(note = '') {
    try {
      const bind = (await Stronghold.get('bind'))?.value || null;
      if (bind) log('[status] session: continuing (bind present)');
      else log('[status] session: none (no bind)');
      if (note) log('[status-note]', note);
    } catch (e) {
      log('[err] status', e.message || String(e));
    }
  }

  // ---------- Buttons ----------
  const swRegBtn = document.getElementById('btn-sw-register');
  if (swRegBtn) {
    swRegBtn.onclick = async () => {
      try {
        if (!('serviceWorker' in navigator)) return log('[err] Service Worker not supported');
        const reg = await navigator.serviceWorker.register('/stronghold-sw.js', { type: 'module' });
        log('[ok] SW registered', { scope: reg.scope });
        await navigator.serviceWorker.ready;
        if (navigator.serviceWorker.controller) log('[ok] SW is controlling this page');
        else log('[note] SW installed but no controller yet. Reload once to allow takeover.');
      } catch (e) {
        log('[err] SW register', e.message);
      }
      await reportStatus('after sw-register');
    };
  }

  const swUnregBtn = document.getElementById('btn-sw-unregister');
  if (swUnregBtn) {
    swUnregBtn.onclick = async () => {
      try {
        if (!('serviceWorker' in navigator)) return log('[err] SW unsupported');
        const regs = await navigator.serviceWorker.getRegistrations();
        let count = 0;
        for (const r of regs) { if (await r.unregister()) count++; }
        log('[ok] SW unregistered', { count });
        if (navigator.serviceWorker.controller) log('[note] this tab remains controlled until reload/navigation.');
      } catch (e) {
        log('[err] SW unregister', e.message);
      }
      await reportStatus('after sw-unregister');
    };
  }

  const initBtn = document.getElementById('btn-init');
  if (initBtn) {
    initBtn.onclick = async () => {
      try {
        const res = await Stronghold.sessionInit({ sessionInitUrl: '/session/init' });
        log('[ok] session/init', res);
      } catch (e) {
        log('[err] init', e.message);
      }
      await reportStatus('after init');
    };
  }

  const bikBtn = document.getElementById('btn-bik');
  if (bikBtn) {
    bikBtn.onclick = async () => {
      try {
        const res = await Stronghold.bikRegisterStep({ bikRegisterUrl: '/browser/register' });
        log('[ok] bik/register', res);
      } catch (e) {
        log('[err] BIK', e.message);
      }
      await reportStatus('after bik');
    };
  }

  const bindBtn = document.getElementById('btn-bind');
  if (bindBtn) {
    bindBtn.onclick = async () => {
      try {
        const state = await Stronghold.dpopBindStep({ dpopBindUrl: '/dpop/bind' });
        log('[ok] dpop/bind', state);
        if (navigator.serviceWorker?.controller) {
          navigator.serviceWorker.controller.postMessage({
            type: 'stronghold/bind',
            bind: state.bind,
            dpopKeyId: state.dpopKeyId,
            nonce: state.nonce
          });
        } else {
          log('[note] no SW controller – requests via fetch() won’t be auto-signed by SW.');
        }
      } catch (e) {
        log('[err] bind', e.message);
      }
      await reportStatus('after bind');
    };
  }

  const echoSWBtn = document.getElementById('btn-echo-sw');
  if (echoSWBtn) {
    echoSWBtn.onclick = async () => {
      try {
        const r = await fetch('/api/echo', {
          method: 'POST',
          body: JSON.stringify({ hello: 'world' }),
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include'
        });
        const j = await r.json().catch(() => ({}));
        log(r.ok ? '[ok] echo(sw)' : '[err] echo(sw)', j, 'nonce:', r.headers.get('DPoP-Nonce'));
      } catch (e) {
        log('[err] echo(sw)', e.message);
      }
      await reportStatus('after echo-sw');
    };
  }

  const echoDirectBtn = document.getElementById('btn-echo-direct');
  if (echoDirectBtn) {
    echoDirectBtn.onclick = async () => {
      try {
        const j = await Stronghold.strongholdFetch('/api/echo', { method: 'POST', body: { hello: 'direct' } });
        log('[ok] echo(direct)', j);
      } catch (e) {
        log('[err] echo(direct)', e.message);
      }
      await reportStatus('after echo-direct');
    };
  }

  const flushBtn = document.getElementById('btn-flush');
  if (flushBtn) {
    flushBtn.onclick = async () => {
      try {
        const r = await fetch('/_admin/flush', { method: 'POST' });
        log('[ok] admin/flush', await r.json());
        clearQr();
      } catch (e) {
        log('[err] admin/flush', e.message);
      }
      await reportStatus('after admin-flush');
    };
  }

  const clientFlushBtn = document.getElementById('btn-client-flush');
  if (clientFlushBtn) {
    clientFlushBtn.onclick = async () => {
      try {
        const r = await Stronghold.clientFlush({ unregisterSW: false });
        log('[ok] client/flush', r);
        clearQr();
      } catch (e) {
        log('[err] client-flush', e.message);
      }
      await reportStatus('after client-flush');
    };
  }

  // ---------- PASSKEYS ----------
  const pkCheckBtn = document.getElementById('btn-passkey-check');
  if (pkCheckBtn) {
    pkCheckBtn.onclick = async () => {
      try {
        const sup = await Passkeys.checkSupport();
        log('[ok] passkey/check', sup);
        if (!sup.hasAPI || !sup.uvp) {
          const regBtn = document.getElementById('btn-passkey-register');
          const authBtn = document.getElementById('btn-passkey-login');
          if (regBtn) regBtn.disabled = true;
          if (authBtn) authBtn.disabled = true;
          if (location.protocol !== 'https:' && location.hostname !== 'localhost') {
            log('[note] WebAuthn requires HTTPS (or localhost).');
          }
        }
      } catch (e) {
        log('[err] passkey/check', e.message);
      }
    };
  }

  const pkRegBtn = document.getElementById('btn-passkey-register');
  if (pkRegBtn) {
    pkRegBtn.onclick = async () => {
      try {
        // preflight to see if one already exists
        let pre = null;
        try { pre = await Passkeys.getAuthOptions(); } catch {}
        const existing = pre?.allowCredentials?.length || 0;
        if (existing > 0) {
          const proceed = confirm(`You already have ${existing} passkey(s) for this account on this device.\nCreate another?`);
          if (!proceed) return;
        }
    
        const res = await Passkeys.registerPasskey();
        // optional: auto-authenticate after registration
        try { await Passkeys.authenticatePasskey(); } catch {}
        log('[ok] passkey/register ✓', res);
      } catch (e) {
        log('[err] passkey/register', e.message || String(e));
      }
      await reportStatus('after passkey-register');
    };
  }

  const pkLoginBtn = document.getElementById('btn-passkey-login');
  if (pkLoginBtn) {
    pkLoginBtn.onclick = async () => {
      try {
        const pre = await Passkeys.getAuthOptions();
        const count = pre?.allowCredentials?.length || 0;
    
        if (count === 0) {
          const go = confirm(
            "No passkey is registered for this account on this device.\nWould you like to create one now?"
          );
          if (!go) return;
          await Passkeys.registerPasskey();
          // After registering, try login again with fresh options
          const pre2 = await Passkeys.getAuthOptions();
          const res2 = await Passkeys.authenticatePasskey(pre2);
          log('[ok] passkey/auth (post-register)', res2);
        } else {
          const res = await Passkeys.authenticatePasskey(pre);
          log('[ok] passkey/auth', res);
        }
      } catch (e) {
        log('[err] passkey/auth', e.message || String(e));
      }
      await reportStatus('after passkey-auth');
    };
  }

  // =========================
  // LINKING (SSE + polling fallback)
  // =========================

  // QR helpers
  function clearQr() {
    const host = document.getElementById('link-qr');
    if (host) host.innerHTML = '';
    const urlEl = document.getElementById('link-url');
    if (urlEl) urlEl.textContent = '';
    const statusEl = document.getElementById('link-status');
    if (statusEl) statusEl.textContent = 'pending';
  }

  function renderQr(text) {
    const host = document.getElementById('link-qr');
    if (!host) {
      log('[note] add <div id="link-qr"></div> to display the QR.');
      log('[note] link URI:', text);
      return;
    }
    host.innerHTML = '';
    if (!('QRCode' in window)) {
      log('[note] QR lib not loaded. Add <script src="/public/qrcode.min.js"></script>.');
      log('[note] link URI:', text);
      return;
    }
    // eslint-disable-next-line no-undef
    new QRCode(host, { text, width: 192, height: 192, correctLevel: QRCode.CorrectLevel.M });
  }

  // Polling
  let _pollAbort = { on: false };
  async function pollLinkStatus(linkId) {
    _pollAbort.on = true;
    try {
      while (_pollAbort.on) {
        await new Promise(r => setTimeout(r, 2000));
        let j;
        try {
          j = await Stronghold.strongholdFetch(`/link/status/${encodeURIComponent(linkId)}`, { method: 'GET' });
          log('[link] status', j);
          updateLinkUI(j);
          if ((j.status === 'linked' && j.applied) || j.status === 'expired') {
            _pollAbort.on = false;
            return;
          }
        } catch (e) {
          log('[err] link/status', e.message);
          _pollAbort.on = false; // stop polling on hard error
        }
      }
    } finally {
      _pollAbort.on = false;
    }
  }

  function updateLinkUI(j) {
    const statusEl = document.getElementById('link-status');
    if (statusEl) statusEl.textContent = `${j.status}${j.applied ? ' (applied)' : ''}`;
  }

  function openSSE(linkId) {
    const url = `/link/events/${encodeURIComponent(linkId)}`;
    let es;
    try {
      es = new EventSource(url, { withCredentials: true });
    } catch (e) {
      log('[link][sse] failed to open', e.message || String(e));
      return null;
    }
    es.addEventListener('status', (ev) => {
      try {
        const data = JSON.parse(ev.data);
        log('[link][sse] status', data);
        updateLinkUI(data);
        if ((data.status === 'linked' && data.applied) || data.status === 'expired') {
          es.close();
          _pollAbort.on = false;
        }
      } catch {}
    });
    es.onerror = (ev) => {
      log('[link][sse] error; falling back to polling', ev);
      es.close();
      // Do not keep retrying SSE; fallback to polling
      if (!_pollAbort.on) pollLinkStatus(linkId);
    };
    return es;
  }

  const linkArea = document.getElementById('link-area');
  const linkBtn = document.getElementById('btn-link-start');
  if (linkBtn) {
    linkBtn.onclick = async () => {
      clearQr();
      try {
        const r = await Stronghold.strongholdFetch('/link/start', { method: 'POST' });
        const linkId = r.linkId || r.rid || r.id;
        const url = r.qr_url || r.url;
        if (!linkId || !url) throw new Error('link/start returned unexpected payload');

        if (linkArea) linkArea.style.display = 'flex';
        renderQr(url);
        const urlEl = document.getElementById('link-url');
        if (urlEl) urlEl.textContent = url;

        // Prefer SSE; fallback to polling on error
        const es = openSSE(linkId);
        if (!es) pollLinkStatus(linkId);

        log('[ok] link/start', { linkId, exp: r.exp, url });
      } catch (e) {
        log('[err] link/start', e.message || String(e));
      }
    };
  }

  // initial status after handlers bound
  reportStatus('on load').catch(err => log('[err] status', err.message));
  console.log('[init] handlers bound');
})();

// global traps
window.addEventListener('error', e => console.error('[global-error]', e.message));
window.addEventListener('unhandledrejection', e => console.error('[unhandled]', e.reason?.message || e.reason));

// public/app.js
import * as Stronghold from '/src/stronghold.js';
import * as Passkeys   from '/src/passkeys.js';

(function () {
  console.log('[init] app.js starting');
  console.log('[init] Stronghold exports:', Object.keys(Stronghold));
  console.log('[init] Passkeys exports:', Object.keys(Passkeys));

  // --------------------------
  // DOM helpers + logger
  // --------------------------
  function $(id) {
    const el = document.getElementById(id);
    if (!el) throw new Error(`missing #${id}`);
    return el;
  }
  const out = $('out');
  const log = (...a) => {
    console.log(...a);
    out.textContent += a.map(x => typeof x === 'string' ? x : JSON.stringify(x, null, 2)).join(' ') + '\n';
  };

  // --------------------------
  // Status (session + SW)
  // --------------------------
  async function reportStatus(note = '') {
    const bind = (await Stronghold.get('bind'))?.value || null;

    const sw = { supported: 'serviceWorker' in navigator, registered: false, controlled: false, scope: null };
    if (sw.supported) {
      const reg = await navigator.serviceWorker.getRegistration();
      sw.registered = !!reg;
      sw.scope = reg?.scope || null;
      sw.controlled = !!navigator.serviceWorker.controller;
    }

    if (bind) log('[status] session: continuing (bind present)');
    else log('[status] session: none (no bind)');

    if (sw.supported && sw.registered && !sw.controlled) {
      log('[note] SW installed but not controlling this page yet. Reload once to allow takeover.');
    }
    if (note) log('[status-note]', note);
  }

  // ---- SW controller diagnostics
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      log('[sw] controllerchange → now controlled');
      reportStatus('after controllerchange').catch(() => {});
    });
  }

  // --------------------------
  // SW buttons
  // --------------------------
  $('btn-sw-register').onclick = async () => {
    try {
      if (!('serviceWorker' in navigator)) return log('[err] Service Worker not supported');

      const reg = await navigator.serviceWorker.register('/stronghold-sw.js', { type: 'module' });
      log('[ok] SW registered (module)', { scope: reg.scope });

      await navigator.serviceWorker.ready;
      if (navigator.serviceWorker.controller) {
        log('[ok] SW is controlling this page');
      } else {
        log('[note] SW installed but no controller yet. Reload once to allow takeover.');
      }
    } catch (e) {
      log('[err] SW register', e.message);
    }
    await reportStatus('after sw-register');
  };

  const unregBtn = document.getElementById('btn-sw-unregister');
  if (unregBtn) {
    unregBtn.onclick = async () => {
      try {
        if (!('serviceWorker' in navigator)) return log('[err] SW unsupported');
        const regs = await navigator.serviceWorker.getRegistrations();
        let count = 0;
        for (const r of regs) { if (await r.unregister()) count++; }
        log('[ok] SW unregistered', { count });
        if (navigator.serviceWorker.controller) {
          log('[note] this tab remains controlled until reload/navigation.');
        }
      } catch (e) {
        log('[err] SW unregister', e.message);
      }
      await reportStatus('after sw-unregister');
    };
  }

  // --------------------------
  // Session buttons
  // --------------------------
  $('btn-init').onclick = async () => {
    try {
      log('[ok] session/init', await Stronghold.sessionInit({ sessionInitUrl: '/session/init' }));
    } catch (e) {
      log('[err] init', e.message);
    }
    await reportStatus('after init');
  };

  $('btn-bik').onclick = async () => {
    try {
      log('[ok] bik/register', await Stronghold.bikRegisterStep({ bikRegisterUrl: '/browser/register' }));
    } catch (e) {
      log('[err] BIK', e.message);
    }
    await reportStatus('after bik');
  };

  $('btn-bind').onclick = async () => {
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
        log('[note] no SW controller (piecemeal mode) – requests via fetch() won’t be auto-signed by SW.');
      }
    } catch (e) {
      log('[err] bind', e.message);
    }
    await reportStatus('after bind');
  };

  $('btn-echo-sw').onclick = async () => {
    try {
      if (!navigator.serviceWorker?.controller) {
        log('[note] SW not controlling; /api/* fetches won’t be SW-signed (expect 428 first call).');
      }
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

  $('btn-echo-direct').onclick = async () => {
    try {
      log('[ok] echo(direct)', await Stronghold.strongholdFetch('/api/echo', { method: 'POST', body: { hello: 'direct' } }));
    } catch (e) {
      log('[err] echo(direct)', e.message);
    }
    await reportStatus('after echo-direct');
  };

  $('btn-flush').onclick = async () => {
    try {
      const r = await fetch('/_admin/flush', { method: 'POST' });
      log('[ok] admin/flush', await r.json());
      clearLinkUI(true);
    } catch (e) {
      log('[err] admin/flush', e.message);
    }
    await reportStatus('after admin-flush');
  };

  $('btn-client-flush').onclick = async () => {
    try {
      const r = await Stronghold.clientFlush({ unregisterSW: false });
      log('[ok] client/flush', r);
      clearLinkUI(true);
    } catch (e) {
      log('[err] client-flush', e.message);
    }
    await reportStatus('after client-flush');
  };

  // --------------------------
  // PASSKEYS (check / register / authenticate)
  // --------------------------
  $('btn-passkey-check').onclick = async () => {
    try {
      const sup = await Passkeys.checkSupport();
      log('[ok] passkey/check', sup);
      if (!sup.hasAPI || !sup.uvp) {
        $('btn-passkey-register').disabled = true;
        $('btn-passkey-login').disabled = true;
        if (location.protocol !== 'https:' && location.hostname !== 'localhost') {
          log('[note] WebAuthn requires HTTPS (or localhost).');
        }
      }
    } catch (e) {
      log('[err] passkey/check', e.message);
    }
  };

  $('btn-passkey-register').onclick = async () => {
    try {
      const res = await Passkeys.registerPasskey();
      log('[ok] passkey/register', res);
    } catch (e) {
      log('[err] passkey/register', e.message || String(e));
    }
    await reportStatus('after passkey-register');
  };

  $('btn-passkey-login').onclick = async () => {
    try {
      const res = await Passkeys.authenticatePasskey();
      log('[ok] passkey/auth', res);
    } catch (e) {
      log('[err] passkey/auth', e.message || String(e));
    }
    await reportStatus('after passkey-auth');
  };

  // =========================
  // LINKING (client-side QR)
  // =========================

  // --- Link UI helpers
  function setLinkStatus(text) {
    const el = document.getElementById('link-status');
    if (el) el.textContent = text;
  }
  function showLinkArea(urlText) {
    const area = document.getElementById('link-area');
    const urlEl = document.getElementById('link-url');
    if (area) area.style.display = 'flex';
    if (urlEl) urlEl.textContent = urlText || '';
    setLinkStatus('pending');
  }
  function drawQrIntoLinkArea(text) {
    const host = document.getElementById('link-qr');
    if (!host) return;
    host.innerHTML = '';
    if (!('QRCode' in window)) {
      // Fallback: just print the URL if QR library isn't loaded
      const a = document.createElement('a');
      a.href = text; a.textContent = text; a.rel = 'noopener noreferrer';
      host.appendChild(a);
      return;
    }
    // eslint-disable-next-line no-undef
    new QRCode(host, { text, width: 192, height: 192, correctLevel: QRCode.CorrectLevel.M });
  }
  function clearLinkUI(hide = false) {
    const host = document.getElementById('link-qr');
    if (host) host.innerHTML = '';
    if (hide) {
      const area = document.getElementById('link-area');
      if (area) area.style.display = 'none';
    } else {
      setLinkStatus('pending');
    }
    if (linkPollStop) { linkPollStop(); linkPollStop = null; }
    linkActiveId = null;
    const btn = document.getElementById('btn-link-start');
    if (btn) btn.disabled = false;
  }
  // Keep your old name for compatibility with previous calls
  function clearQr() { clearLinkUI(); }

  // --- JWS payload decode (base64url)
  function decodeJwsPayload(token) {
    try {
      const parts = token.split('.');
      if (parts.length < 2) return null;
      const p = parts[1];
      const pad = '='.repeat((4 - (p.length % 4)) % 4);
      const json = atob(p.replace(/-/g, '+').replace(/_/g, '/') + pad);
      return JSON.parse(json);
    } catch {
      return null;
    }
  }

  // --- Polling
  let linkPollStop = null;
  let linkActiveId = null;

  async function pollLinkStatus(linkId) {
    linkActiveId = linkId;
    let stopped = false;
    linkPollStop = () => { stopped = true; };

    const INTERVAL = 2000; // ms
    const MAX_TRIES = 120; // ~4 minutes total
    let tries = 0;

    async function tick() {
      if (stopped) return;
      if (++tries > MAX_TRIES) {
        log('[err] link/status timeout');
        setLinkStatus('timeout');
        clearLinkUI(false);
        return;
      }

      try {
        const j = await Stronghold.strongholdFetch(`/link/status/${encodeURIComponent(linkId)}`, { method: 'GET' });
        log('[link] status', j);
        if (j?.status) setLinkStatus(j.status);

        if (j.status === 'linked' && j.applied) {
          log('[ok] link complete — desktop session is now authenticated.');
          setLinkStatus('linked');
          clearLinkUI(true);
          await reportStatus('after link-complete');
          return;
        }
        if (j.status === 'expired') {
          log('[err] link expired');
          setLinkStatus('expired');
          clearLinkUI(false);
          return;
        }
      } catch (e) {
        // Stop polling on any error (401/404/etc.) as requested
        log('[err] link/status request failed:', e.message || String(e));
        setLinkStatus('error');
        clearLinkUI(false);
        return;
      }

      setTimeout(tick, INTERVAL);
    }

    setTimeout(tick, INTERVAL);
  }

  // --- Start link flow
  const linkBtn = document.getElementById('btn-link-start');
  if (linkBtn) {
    linkBtn.onclick = async () => {
      if (linkActiveId) {
        log('[note] a link is already active; wait or flush.');
        return;
      }
      try {
        const r = await Stronghold.strongholdFetch('/link/start', { method: 'POST' });
        // r may contain { rid/id, token, qr_url }; be tolerant to shape
        let id = r.rid || r.id || r.link_id || r.linkId || null;
        let url = r.qr_url || r.url || null;

        if (!url) {
          const token = r.token;
          if (!token) throw new Error('link/start did not return token or qr_url');
          url = `${location.origin}/public/link.html?token=${encodeURIComponent(token)}`;
          if (!id) {
            const claims = decodeJwsPayload(token);
            id = claims?.lid || claims?.rid || null;
          }
        }
        if (!id) throw new Error('link/start did not provide a link id');

        // Show panel + draw QR + start polling
        showLinkArea(url);
        drawQrIntoLinkArea(url);

        log('[ok] link/start', { id, url });
        linkBtn.disabled = true;
        await pollLinkStatus(id);
      } catch (e) {
        log('[err] link/start', e.message || String(e));
        setLinkStatus('error');
        clearLinkUI(false);
      }
    };
  }

  // --------------------------
  // Initial status after handlers bound
  // --------------------------
  reportStatus('on load').catch(err => log('[err] status', err.message));
  console.log('[init] handlers bound');
})();

// global traps
window.addEventListener('error', e => console.error('[global-error]', e.message));
window.addEventListener('unhandledrejection', e => console.error('[unhandled]', e.reason?.message || e.reason));

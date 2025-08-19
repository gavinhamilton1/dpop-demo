// public/app.js
import * as Stronghold from '/src/stronghold.js';
import * as Passkeys   from '/src/passkeys.js';

(function () {
  console.log('[init] app.js starting');
  console.log('[init] Stronghold exports:', Object.keys(Stronghold));
  console.log('[init] Passkeys exports:', Object.keys(Passkeys));

  // ------- helpers -------
  function $(id) {
    const el = document.getElementById(id);
    if (!el) throw new Error(`missing #${id}`);
    return el;
  }

  const out = (() => {
    try { return $('out'); } catch { return null; }
  })();

  const log = (...a) => {
    console.log(...a);
    if (!out) return;
    out.textContent += a.map(x => typeof x === 'string' ? x : JSON.stringify(x, null, 2)).join(' ') + '\n';
  };

  // ---- status (session + SW)
  async function reportStatus(note = '') {
    const bind = (await Stronghold.get('bind'))?.value || null;

    let sw = { supported: 'serviceWorker' in navigator, registered: false, controlled: false, scope: null };
    if (sw.supported) {
      const reg = await navigator.serviceWorker.getRegistration();
      sw.registered = !!reg;
      sw.scope = reg?.scope || null;
      sw.controlled = !!navigator.serviceWorker.controller;
    }

    if (bind) {
      log('[status] session: continuing (bind present)');
    } else {
      log('[status] session: none (no bind)');
    }
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

  // ---- buttons
  const swRegBtn = document.getElementById('btn-sw-register');
  if (swRegBtn) {
    swRegBtn.onclick = async () => {
      try {
        if (!('serviceWorker' in navigator)) return log('[err] Service Worker not supported');

        const reg = await navigator.serviceWorker.register('/stronghold-sw.js', { type: 'module' });
        log('[ok] SW registered (module)', { scope: reg.scope });

        // Wait for activation; some browsers still need a reload to get a controller
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
  }

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

  const initBtn = document.getElementById('btn-init');
  if (initBtn) {
    initBtn.onclick = async () => {
      try {
        log('[ok] session/init', await Stronghold.sessionInit({ sessionInitUrl: '/session/init' }));
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
        log('[ok] bik/register', await Stronghold.bikRegisterStep({ bikRegisterUrl: '/browser/register' }));
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
          log('[note] no SW controller (piecemeal mode) – requests via fetch() won’t be auto-signed by SW.');
        }
      } catch (e) {
        log('[err] bind', e.message);
      }
      await reportStatus('after bind');
    };
  }

  const echoSwBtn = document.getElementById('btn-echo-sw');
  if (echoSwBtn) {
    echoSwBtn.onclick = async () => {
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
  }

  const echoDirectBtn = document.getElementById('btn-echo-direct');
  if (echoDirectBtn) {
    echoDirectBtn.onclick = async () => {
      try {
        log('[ok] echo(direct)', await Stronghold.strongholdFetch('/api/echo', { method: 'POST', body: { hello: 'direct' } }));
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
        // also clear any linking UI
        stopLinkWatch(); clearQr(); setLinkUIVisible(false);
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
        const r = await Stronghold.clientFlush({ unregisterSW: false }); // set true to also unregister SW
        log('[ok] client/flush', r);
        stopLinkWatch(); clearQr(); setLinkUIVisible(false);
      } catch (e) {
        log('[err] client/flush', e.message);
      }
      await reportStatus('after client-flush');
    };
  }

  // ---- PASSKEYS (check / register / authenticate)
  const pkCheckBtn = document.getElementById('btn-passkey-check');
  if (pkCheckBtn) {
    pkCheckBtn.onclick = async () => {
      try {
        const sup = await Passkeys.checkSupport();
        log('[ok] passkey/check', sup);
        if (!sup.hasAPI || !sup.uvp) {
          const regBtn = document.getElementById('btn-passkey-register');
          const loginBtn = document.getElementById('btn-passkey-login');
          if (regBtn) regBtn.disabled = true;
          if (loginBtn) loginBtn.disabled = true;
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
        const res = await Passkeys.registerPasskey();
        log('[ok] passkey/register', res);
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
        const res = await Passkeys.authenticatePasskey();
        log('[ok] passkey/auth', res);
      } catch (e) {
        log('[err] passkey/auth', e.message || String(e));
      }
      await reportStatus('after passkey-auth');
    };
  }

  // =========================
  // LINKING (client-side QR) with SSE + polling fallback
  // =========================

  let currentSSE = null;
  let currentPollTimer = null;

  function stopLinkWatch() {
    if (currentSSE) {
      try { currentSSE.close(); } catch {}
      currentSSE = null;
    }
    if (currentPollTimer) {
      clearTimeout(currentPollTimer);
      currentPollTimer = null;
    }
  }

  function clearQr() {
    const host = document.getElementById('link-qr');
    if (host) host.innerHTML = '';
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

  function setLinkUIVisible(v) {
    const area = document.getElementById('link-area');
    if (area) area.style.display = v ? 'flex' : 'none';
  }

  function setLinkStatus(text) {
    const el = document.getElementById('link-status');
    if (el) el.textContent = text;
  }

  async function pollLinkStatus(linkId) {
    const tick = async () => {
      try {
        const j = await Stronghold.strongholdFetch(`/link/status/${encodeURIComponent(linkId)}`, { method: 'GET' });
        log('[link] status', j);
        setLinkStatus(j.status + (j.applied ? ' (applied)' : ''));

        if (j.status === 'linked' && j.applied) {
          log('[ok] link complete — desktop session is now authenticated.');
          stopLinkWatch(); clearQr(); setLinkUIVisible(false);
          await reportStatus('after link-complete');
          return;
        }
        if (j.status === 'expired') {
          stopLinkWatch(); clearQr(); setLinkUIVisible(false);
          log('[err] link expired');
          return;
        }
      } catch (e) {
        log('[err] link/status', e.message);
        // Stop on terminal auth/session errors
        if (/\b(401|403|404)\b/.test(String(e))) {
          stopLinkWatch(); setLinkUIVisible(false); return;
        }
      }
      currentPollTimer = setTimeout(tick, 2000);
    };
    stopLinkWatch();
    currentPollTimer = setTimeout(tick, 0);
  }

  function startSSE(linkId) {
    stopLinkWatch();
    if (!('EventSource' in window)) {
      log('[note] SSE unsupported; falling back to polling');
      pollLinkStatus(linkId);
      return;
    }

    try {
      const es = new EventSource(`/link/events/${encodeURIComponent(linkId)}`, { withCredentials: true });
      currentSSE = es;

      es.onmessage = async (ev) => {
        try {
          const j = JSON.parse(ev.data || '{}');
          log('[link][sse]', j);
          setLinkStatus(j.status + (j.applied ? ' (applied)' : ''));

          if (j.status === 'linked' && j.applied) {
            stopLinkWatch(); clearQr(); setLinkUIVisible(false);
            await reportStatus('after link-complete');
          } else if (j.status === 'expired' || j.status === 'gone') {
            stopLinkWatch(); clearQr(); setLinkUIVisible(false);
          }
        } catch (e) {
          log('[link][sse] bad data', e.message || String(e));
        }
      };

      es.onerror = (e) => {
        log('[link][sse] error; falling back to polling', e?.message || JSON.stringify(e));
        stopLinkWatch();
        pollLinkStatus(linkId);
      };
    } catch (e) {
      log('[link][sse] setup failed; falling back to polling', e.message || String(e));
      pollLinkStatus(linkId);
    }
  }

  // Hook up the Start Link button
  const linkBtn = document.getElementById('btn-link-start');
  if (linkBtn) {
    linkBtn.onclick = async () => {
      stopLinkWatch();
      clearQr();
      try {
        const r = await Stronghold.strongholdFetch('/link/start', { method: 'POST' });
        const linkId = r.link_id || r.rid || r.id;
        const url = r.qr_url;

        if (!linkId || !url) {
          log('[err] link/start missing fields', r);
          return;
        }

        // UI
        setLinkUIVisible(true);
        renderQr(url);
        const urlEl = document.getElementById('link-url'); if (urlEl) urlEl.textContent = url;
        setLinkStatus('pending');

        // Live updates: SSE first, then polling
        startSSE(linkId);

        log('[ok] link/start', { linkId, exp: r.exp, url });
      } catch (e) {
        log('[err] link/start', e.message || String(e));
        setLinkUIVisible(false);
      }
    };
  }

  // Clean up on unload just in case
  window.addEventListener('beforeunload', () => stopLinkWatch());

  // initial status after handlers bound
  reportStatus('on load').catch(err => log('[err] status', err.message));
  console.log('[init] handlers bound');
})();

// global traps
window.addEventListener('error', e => console.error('[global-error]', e.message));
window.addEventListener('unhandledrejection', e => console.error('[unhandled]', e.reason?.message || e.reason));

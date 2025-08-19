// public/app.js
import * as Stronghold from '/src/stronghold.js';
import * as Passkeys   from '/src/passkeys.js';

(function () {
  console.log('[init] app.js starting');
  console.log('[init] Stronghold exports:', Object.keys(Stronghold));
  console.log('[init] Passkeys exports:', Object.keys(Passkeys));

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

  // ------------ helpers: button guard & WebAuthn single-op guard ------------
  function guardBtn(btnId, fn) {
    const btn = $(btnId);
    btn.onclick = async () => {
      if (btn.dataset.busy === '1') return;
      btn.dataset.busy = '1';
      btn.disabled = true;
      try { await fn(btn); } finally { btn.dataset.busy = '0'; btn.disabled = false; }
    };
  }

  // One WebAuthn operation at a time (prevents “A request is already pending.”)
  let webauthnBusy = false;
  async function withWebAuthnGuard(btn, fn) {
    if (webauthnBusy) {
      log('[note] webauthn busy; ignoring click');
      return;
    }
    webauthnBusy = true;
    if (btn) btn.disabled = true;
    try {
      await fn();
    } finally {
      webauthnBusy = false;
      if (btn) btn.disabled = false;
    }
  }

  // Best effort: cancel an in-flight native sheet if we navigate/blur
  function cancelWebAuthnIfSupported() {
    if (typeof Passkeys.cancelWebAuthn === 'function') {
      try { Passkeys.cancelWebAuthn(); } catch {}
    }
    webauthnBusy = false;
  }
  window.addEventListener('visibilitychange', () => {
    if (document.hidden) cancelWebAuthnIfSupported();
  });
  window.addEventListener('beforeunload', () => cancelWebAuthnIfSupported());

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

  // optional button with id="btn-sw-unregister"
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
    } catch (e) {
      log('[err] admin/flush', e.message);
    }
    await reportStatus('after admin-flush');
  };

  $('btn-client-flush').onclick = async () => {
    try {
      const r = await Stronghold.clientFlush({ unregisterSW: false }); // set true to also unregister SW
      log('[ok] client/flush', r);
    } catch (e) {
      log('[err] client-flush', e.message);
    }
    await reportStatus('after client-flush');
  };

  // ---- PASSKEYS (check / register / authenticate)
  guardBtn('btn-passkey-check', async () => {
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
      log('[err] passkey/check', e.message || String(e));
    }
  });

  guardBtn('btn-passkey-register', async (btn) => {
    await withWebAuthnGuard(btn, async () => {
      try {
        const res = await Passkeys.registerPasskey();
        log('[ok] passkey/register', res);
      } catch (e) {
        log('[err] passkey/register', e.message || String(e));
      } finally {
        await reportStatus('after passkey-register');
      }
    });
  });

  guardBtn('btn-passkey-login', async (btn) => {
    await withWebAuthnGuard(btn, async () => {
      try {
        const res = await Passkeys.authenticatePasskey();
        log('[ok] passkey/auth', res);
      } catch (e) {
        log('[err] passkey/auth', e.message || String(e));
      } finally {
        await reportStatus('after passkey-auth');
      }
    });
  });

  // initial status after handlers bound
  reportStatus('on load').catch(err => log('[err] status', err.message));
  console.log('[init] handlers bound');
})();

// global traps
window.addEventListener('error', e => console.error('[global-error]', e.message));
window.addEventListener('unhandledrejection', e => console.error('[unhandled]', e.reason?.message || e.reason));

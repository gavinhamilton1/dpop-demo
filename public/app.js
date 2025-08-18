// public/app.js
import * as Stronghold from '/src/stronghold.js';

(function () {
  console.log('[init] app.js starting');
  console.log('[init] Stronghold exports:', Object.keys(Stronghold));

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

  // ---- status (session + SW)
  async function reportStatus(note = '') {
    const bind = (await Stronghold.get('bind'))?.value || null;
    const nonce = (await Stronghold.get('dpop_nonce'))?.value || null;

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
      // After takeover, show fresh status
      reportStatus('after controllerchange').catch(() => {});
    });
  }

  // ---- buttons
  $('btn-sw-register').onclick = async () => {
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
      log('[err] client/flush', e.message);
    }
    await reportStatus('after client-flush');
  };

  // initial status after handlers bound
  reportStatus('on load').catch(err => log('[err] status', err.message));
  console.log('[init] handlers bound');
})();

// global traps
window.addEventListener('error', e => console.error('[global-error]', e.message));
window.addEventListener('unhandledrejection', e => console.error('[unhandled]', e.reason?.message || e.reason));

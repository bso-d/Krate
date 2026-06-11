(function () {
  var btn = document.createElement('a');
  btn.href = '/visualizer';
  btn.title = 'Stream Visualizer';
  btn.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:9999;display:none;align-items:center;gap:8px;background:#6750A4;color:#fff;padding:12px 20px;border-radius:24px;text-decoration:none;font-family:Roboto,sans-serif;font-size:13px;font-weight:500;letter-spacing:.04em;box-shadow:0 4px 14px rgba(0,0,0,.45)';
  btn.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 17 9 11 13 15 21 7"/><polyline points="17 7 21 7 21 11"/></svg> Stream Visualizer';
  document.body.appendChild(btn);

  function update() {
    btn.style.display = window.location.pathname === '/login' ? 'none' : 'inline-flex';
  }

  update();

  // Track React router navigation
  var orig = history.pushState;
  history.pushState = function () { orig.apply(this, arguments); update(); };
  window.addEventListener('popstate', update);

  // Catch the moment the login form mounts/unmounts (SPA navigation)
  new MutationObserver(update).observe(document.body, { childList: true, subtree: true });
})();

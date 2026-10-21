/* Local appearance preference only: never access credentials or protected data. */
(() => {
  'use strict';

  const root = document.documentElement;
  const button = document.getElementById('theme-switch');
  const icon = button?.querySelector('.theme-switch-icon');
  const label = button?.querySelector('.theme-switch-label');
  const themeColor = document.querySelector('meta[name="theme-color"]');
  const storageKey = 'netwatch-ui-theme-v1';

  function readTheme() {
    try {
      return window.localStorage.getItem(storageKey) === 'dark' ? 'dark' : 'light';
    } catch (_) {
      return 'light';
    }
  }

  function applyTheme(theme) {
    const light = theme === 'light';
    root.dataset.theme = light ? 'light' : 'dark';
    if (button) {
      button.setAttribute('aria-label', light ? 'Switch to dark theme' : 'Switch to light theme');
      button.setAttribute('aria-pressed', String(light));
      button.title = light ? 'Switch to dark theme' : 'Switch to light theme';
    }
    if (label) label.textContent = light ? 'Light' : 'Dark';
    if (icon) icon.textContent = light ? '☀' : '☾';
    if (themeColor) themeColor.setAttribute('content', light ? '#f4fbf7' : '#07131e');
  }

  applyTheme(readTheme());
  if (!button) return;
  button.addEventListener('click', () => {
    const next = root.dataset.theme === 'light' ? 'dark' : 'light';
    applyTheme(next);
    try {
      window.localStorage.setItem(storageKey, next);
    } catch (_) {
      // Browsers may disable optional appearance storage.
    }
  });
})();

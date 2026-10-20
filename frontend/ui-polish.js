/* Visual preferences only. This module intentionally never reads API keys or backend state. */
(() => {
  'use strict';

  const accents = ['cyan', 'violet', 'emerald'];
  const names = { cyan: 'Cyan', violet: 'Violet', emerald: 'Emerald' };
  const storageKey = 'netwatch-ui-accent-v2';
  const root = document.documentElement;
  const button = document.getElementById('accent-switch');
  const label = document.getElementById('accent-label');

  function readPreference() {
    try {
      const saved = window.localStorage.getItem(storageKey);
      return accents.includes(saved) ? saved : 'emerald';
    } catch (_) {
      return 'emerald';
    }
  }

  function setAccent(accent) {
    root.dataset.accent = accent;
    if (!button) return;
    const next = accents[(accents.indexOf(accent) + 1) % accents.length];
    if (label) label.textContent = names[accent];
    button.setAttribute('aria-label', `Interface accent: ${names[accent]}. Switch to ${names[next]}`);
    button.title = `Accent: ${names[accent]} — click for ${names[next]}`;
  }

  setAccent(readPreference());
  if (button) {
    button.addEventListener('click', () => {
      const current = root.dataset.accent;
      const next = accents[(accents.indexOf(current) + 1) % accents.length];
      setAccent(next);
      try {
        window.localStorage.setItem(storageKey, next);
      } catch (_) {
        // A private or restricted browser may deny appearance storage.
      }
    });
  }

  // Preserve semantic navigation state for keyboard and assistive-tech users,
  // including navigation initiated through NetWatch's command palette.
  const nav = document.getElementById('nav');
  if (!nav) return;
  const syncNavigation = () => {
    nav.querySelectorAll('button[data-view]').forEach((item) => {
      if (item.classList.contains('active')) item.setAttribute('aria-current', 'page');
      else item.removeAttribute('aria-current');
    });
  };
  const observer = new MutationObserver(syncNavigation);
  observer.observe(nav, { subtree: true, attributes: true, attributeFilter: ['class'] });
  syncNavigation();
})();

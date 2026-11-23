# Browser API-key storage

NetWatch keeps local role API keys in browser session storage when the browser
allows it. The dashboard and TLS Investigator do not use localStorage, cookies,
URL parameters, or a persistent browser store for these keys.

Some private-browsing, embedded, hardened, or storage-restricted contexts can
throw when the browser exposes sessionStorage. This must not prevent the
dashboard from loading or using a key entered for the current page:

- Reads fail closed to an empty in-memory key.
- A key entered by the operator remains in the page JavaScript memory and is
  still used for same-origin authenticated requests.
- If session storage cannot be written, the UI warns that the key will be lost
  when the page reloads.
- Disconnect and clear operations attempt to remove the session value but do
  not claim secure erasure if the browser denies storage access.
- There is deliberately no fallback to localStorage or another persistent
  browser store.

If storage is unavailable, re-enter the key after a reload. Prefer the approved
company SSO gateway for managed deployments. Never put an API key in a
shareable URL, screenshot, browser console, or support bundle.

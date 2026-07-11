const queryApi = new URLSearchParams(window.location.search).get('api');
const API_BASE = window.NETWATCH_API_BASE || queryApi || 'http://127.0.0.1:8000';

function setApiKey(value) {
  const key = String(value || '').trim();
  if (key) {
    sessionStorage.setItem('netwatchApiKey', key);
  } else {
    sessionStorage.removeItem('netwatchApiKey');
  }
}

async function apiFetch(path, options = {}) {
  const key = sessionStorage.getItem('netwatchApiKey');
  const headers = new Headers(options.headers || {});
  if (key) {
    headers.set('X-NetWatch-Key', key);
  }
  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (!response.ok) {
    let detail = `Request failed with status ${response.status}`;
    try {
      const payload = await response.json();
      detail = payload.detail || detail;
    } catch (_) {
      // Keep the status-based message for non-JSON errors.
    }
    throw new Error(detail);
  }
  return response;
}

async function checkApi() {
  try {
    const response = await apiFetch('/api/health');
    const data = await response.json();
    console.log('NetWatch API:', data);
  } catch (error) {
    console.warn('NetWatch API is unavailable:', error.message);
  }
}

window.NetWatchApi = { API_BASE, apiFetch, setApiKey };
checkApi();

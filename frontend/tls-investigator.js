const keyInput = document.querySelector('#api-key');
const statusNode = document.querySelector('#status');
const savedKey = sessionStorage.getItem('netwatchApiKey') || '';
keyInput.value = savedKey;

function setStatus(message, kind = '') {
  statusNode.textContent = message;
  statusNode.className = `status ${kind}`.trim();
}

function valueOf(selector) {
  return String(document.querySelector(selector).value || '').trim();
}

const shareableScope = [
  ['#filter-ip', 'ip_address'],
  ['#filter-port', 'port'],
  ['#filter-protocol', 'protocol'],
  ['#filter-change', 'change_type'],
  ['#filter-severity', 'severity'],
  ['#filter-limit', 'limit'],
];

function setScopeValue(selector, value) {
  const node = document.querySelector(selector);
  if (!node || !value) return;
  if (node.tagName === 'SELECT' && !Array.from(node.options).some((option) => option.value === value)) {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = labelize(value);
    node.appendChild(option);
  }
  node.value = value;
}

function loadScopeFromUrl() {
  const params = new URLSearchParams(window.location.search);
  for (const [selector, name] of shareableScope) {
    const value = String(params.get(name) || '').trim();
    if (value) setScopeValue(selector, value);
  }
  document.querySelector('#alerts-only').checked = params.get('alerts_only') === 'true';
}

function syncScopeToUrl() {
  const params = new URLSearchParams();
  for (const [selector, name] of shareableScope) {
    const value = valueOf(selector);
    if (value && !(name === 'limit' && value === '100')) params.set(name, value);
  }
  if (document.querySelector('#alerts-only').checked) params.set('alerts_only', 'true');
  const query = params.toString();
  const nextUrl = `${window.location.pathname}${query ? `?${query}` : ''}${window.location.hash}`;
  window.history.replaceState(null, '', nextUrl);
}

function investigatorUrl() {
  const params = new URLSearchParams({
    history_limit: '400',
    limit: valueOf('#filter-limit') || '100',
    expiry_warning_days: '30',
    alert_min_severity: 'medium',
  });
  for (const [selector, name] of [
    ['#filter-ip', 'ip_address'], ['#filter-port', 'port'], ['#filter-protocol', 'protocol'],
    ['#filter-change', 'change_type'], ['#filter-severity', 'severity'],
  ]) {
    const value = valueOf(selector);
    if (value) params.set(name, value);
  }
  if (document.querySelector('#alerts-only').checked) params.set('alerts_only', 'true');
  return `/api/tls/investigator?${params.toString()}`;
}

function labelize(value) {
  return String(value || '—').replaceAll('_', ' ');
}

function setMetric(selector, value) {
  document.querySelector(selector).textContent = String(Number(value || 0));
}

function syncChangeOptions(entries) {
  const select = document.querySelector('#filter-change');
  const selected = select.value;
  while (select.options.length > 1) select.remove(1);
  Object.keys(entries || {}).sort().forEach((name) => {
    const option = document.createElement('option');
    option.value = name;
    option.textContent = labelize(name);
    select.appendChild(option);
  });
  if (Array.from(select.options).some((option) => option.value === selected)) select.value = selected;
}

function renderFacets(container, entries, filterSelector) {
  container.replaceChildren();
  const selected = valueOf(filterSelector).toLowerCase();
  Object.entries(entries || {}).forEach(([name, count]) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `facet${selected === name.toLowerCase() ? ' active' : ''}`;
    button.textContent = `${labelize(name)} · ${Number(count || 0)}`;
    button.addEventListener('click', () => {
      const select = document.querySelector(filterSelector);
      if (!Array.from(select.options).some((option) => option.value === name)) {
        const option = document.createElement('option');
        option.value = name;
        option.textContent = labelize(name);
        select.appendChild(option);
      }
      select.value = selected === name.toLowerCase() ? '' : name;
      loadEvidence();
    });
    container.appendChild(button);
  });
}

function renderTimeline(points) {
  const container = document.querySelector('#timeline');
  container.replaceChildren();
  if (!Array.isArray(points) || !points.length) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = 'No dated TLS changes matched this scope.';
    container.appendChild(empty);
    return;
  }
  const maxCount = Math.max(1, ...points.map((point) => Number(point.change_count || 0)));
  points.slice(-60).forEach((point) => {
    const day = document.createElement('div');
    day.className = 'day';
    const bars = document.createElement('div');
    bars.className = 'bar-wrap';
    for (const [count, className, title] of [
      [Number(point.change_count || 0), 'bar', 'changes'],
      [Number(point.alert_recommended_count || 0), 'bar alert', 'recommended alerts'],
    ]) {
      const bar = document.createElement('div');
      bar.className = className;
      bar.style.transform = `scaleY(${Math.max(0.02, count / maxCount)})`;
      bar.title = `${point.day}: ${count} ${title}`;
      bars.appendChild(bar);
    }
    const date = document.createElement('small');
    date.textContent = String(point.day || '').slice(5);
    const count = document.createElement('strong');
    count.textContent = String(Number(point.change_count || 0));
    day.append(bars, date, count);
    container.appendChild(day);
  });
}

function renderChanges(items) {
  const container = document.querySelector('#changes');
  container.replaceChildren();
  const rows = Array.isArray(items) ? items.slice(0, 1000) : [];
  document.querySelector('#row-count').textContent = `${rows.length} row${rows.length === 1 ? '' : 's'}`;
  if (!rows.length) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = 'No TLS changes matched the selected retained-evidence pivots.';
    container.appendChild(empty);
    return;
  }
  const table = document.createElement('table');
  const head = document.createElement('thead');
  const headerRow = document.createElement('tr');
  for (const label of ['Observed', 'Service', 'Change', 'Severity', 'Before', 'After', 'Alert', 'Evidence']) {
    const th = document.createElement('th');
    th.textContent = label;
    headerRow.appendChild(th);
  }
  head.appendChild(headerRow);
  const body = document.createElement('tbody');
  rows.forEach((item) => {
    const row = document.createElement('tr');
    const values = [
      item.observed_at || '—',
      `${item.ip_address || '—'}:${Number(item.port || 0) || '—'} / ${item.protocol || 'TCP'}`,
      labelize(item.change_type), item.severity || '—', item.previous_value ?? item.before ?? '—',
      item.current_value ?? item.after ?? '—', item.alert_recommended === true ? 'recommended' : 'no',
      item.explanation || item.reason || 'retained TLS metadata transition',
    ];
    values.forEach((value, index) => {
      const td = document.createElement('td');
      if (index === 3 || index === 6) {
        const pill = document.createElement('span');
        pill.className = `pill ${index === 6 && value === 'recommended' ? 'alert' : String(value).toLowerCase()}`;
        pill.textContent = String(value);
        td.appendChild(pill);
      } else {
        td.textContent = typeof value === 'object' ? JSON.stringify(value) : String(value);
      }
      row.appendChild(td);
    });
    body.appendChild(row);
  });
  table.append(head, body);
  container.appendChild(table);
}

function renderSnapshot(payload) {
  setMetric('#history-count', payload.history_count);
  setMetric('#service-count', payload.service_count);
  setMetric('#change-count', payload.change_count);
  setMetric('#alert-count', payload.alert_recommended_count);
  const changeTypes = payload.facets?.change_types || {};
  const severities = payload.facets?.severities || {};
  syncChangeOptions(changeTypes);
  renderFacets(document.querySelector('#change-facets'), changeTypes, '#filter-change');
  renderFacets(document.querySelector('#severity-facets'), severities, '#filter-severity');
  document.querySelector('#facet-summary').textContent = `${Object.keys(changeTypes).length} change types · ${Object.keys(severities).length} severities`;
  renderTimeline(payload.timeline || []);
  renderChanges(payload.items || []);
}

async function loadEvidence() {
  const key = String(keyInput.value || '').trim();
  if (!key) return setStatus('A Viewer, Operator, or Admin API key is required.', 'error');
  const limit = Number(valueOf('#filter-limit') || 100);
  if (!Number.isInteger(limit) || limit < 1 || limit > 1000) return setStatus('Result limit must be between 1 and 1,000.', 'error');
  const port = valueOf('#filter-port');
  if (port && (!Number.isInteger(Number(port)) || Number(port) < 1 || Number(port) > 65535)) return setStatus('Port must be between 1 and 65,535.', 'error');
  syncScopeToUrl();
  setStatus('Loading bounded retained TLS evidence…');
  try {
    const response = await fetch(investigatorUrl(), {
      headers: { 'X-NetWatch-Key': key, Accept: 'application/json' },
      cache: 'no-store', credentials: 'same-origin',
    });
    if (!response.ok) {
      let detail = `Request failed (${response.status}).`;
      try { const error = await response.json(); detail = String(error.detail || detail); } catch (_) { /* non-JSON error */ }
      throw new Error(detail);
    }
    const payload = await response.json();
    renderSnapshot(payload);
    setStatus(`Loaded ${Number(payload.change_count || 0)} retained TLS change record(s).`, 'success');
  } catch (error) {
    setStatus(error.message || 'TLS investigator request failed.', 'error');
  }
}

document.querySelector('#save-key').addEventListener('click', () => {
  const key = String(keyInput.value || '').trim();
  if (key) sessionStorage.setItem('netwatchApiKey', key);
  else sessionStorage.removeItem('netwatchApiKey');
  loadEvidence();
});
document.querySelector('#apply').addEventListener('click', loadEvidence);
document.querySelector('#clear').addEventListener('click', () => {
  ['#filter-ip', '#filter-port', '#filter-change', '#filter-severity'].forEach((selector) => { document.querySelector(selector).value = ''; });
  document.querySelector('#filter-protocol').value = '';
  document.querySelector('#filter-limit').value = '100';
  document.querySelector('#alerts-only').checked = false;
  loadEvidence();
});
for (const selector of ['#filter-protocol', '#filter-change', '#filter-severity', '#alerts-only']) {
  document.querySelector(selector).addEventListener('change', () => { if (keyInput.value.trim()) loadEvidence(); });
}
loadScopeFromUrl();
if (savedKey) loadEvidence();

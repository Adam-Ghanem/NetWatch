const queryApi = new URLSearchParams(window.location.search).get('api');
const API_BASE = window.NETWATCH_API_BASE || queryApi || window.location.origin;

const state = {
  key: sessionStorage.getItem('netwatchApiKey') || '',
  view: 'overview',
  health: null,
};

const titles = {
  overview: 'Overview',
  network: 'Network scan',
  host: 'Host check',
  ports: 'Port audit',
  inventory: 'Inventory',
  advisor: 'Risk advisor',
  reports: 'Reports',
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

function setApiKey(value) {
  state.key = String(value || '').trim();
  if (state.key) sessionStorage.setItem('netwatchApiKey', state.key);
  else sessionStorage.removeItem('netwatchApiKey');
}

async function apiFetch(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (state.key) headers.set('X-NetWatch-Key', state.key);
  if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');

  const response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (!response.ok) {
    let detail = `Request failed with status ${response.status}`;
    try {
      const payload = await response.json();
      detail = payload.detail || detail;
    } catch (_) {
      // Non-JSON response; retain status message.
    }
    const error = new Error(detail);
    error.status = response.status;
    throw error;
  }
  return response;
}

async function apiJson(path, options = {}) {
  return (await apiFetch(path, options)).json();
}

function showToast(message, kind = 'success') {
  const toast = $('#toast');
  toast.textContent = message;
  toast.className = `toast show ${kind === 'error' ? 'error' : ''}`;
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => { toast.className = 'toast'; }, 3200);
}

function setFormStatus(id, message = '', kind = '') {
  const node = $(`#${id}`);
  if (!node) return;
  node.textContent = message;
  node.className = `form-status ${kind}`;
}

function setBusy(button, busy, busyLabel = 'Working…') {
  if (!button) return;
  if (busy) {
    button.dataset.originalText = button.textContent;
    button.textContent = busyLabel;
    button.disabled = true;
  } else {
    button.textContent = button.dataset.originalText || button.textContent;
    button.disabled = false;
  }
}

function text(value) {
  if (value === null || value === undefined || value === '') return '—';
  return String(value);
}

function statusClass(value) {
  const normalized = String(value || '').toLowerCase();
  if (normalized.includes('filtered') || normalized.includes('not observed')) return 'filtered';
  if (normalized.includes('new asset') || normalized.includes('returned')) return 'online';
  if (normalized.includes('open')) return 'open';
  if (normalized.includes('online')) return 'online';
  if (normalized.includes('complete')) return 'completed';
  if (normalized.includes('high')) return 'high';
  if (normalized.includes('medium')) return 'medium';
  if (normalized.includes('block')) return 'blocked';
  if (normalized.includes('error') || normalized.includes('offline')) return 'error';
  return '';
}

function renderTable(container, rows, columns, emptyMessage = 'No data available.') {
  container.replaceChildren();
  container.classList.remove('empty-state');
  if (!Array.isArray(rows) || rows.length === 0) {
    container.classList.add('empty-state');
    container.textContent = emptyMessage;
    return;
  }

  const table = document.createElement('table');
  const thead = document.createElement('thead');
  const headRow = document.createElement('tr');
  columns.forEach(({ label }) => {
    const th = document.createElement('th');
    th.textContent = label;
    headRow.appendChild(th);
  });
  thead.appendChild(headRow);

  const tbody = document.createElement('tbody');
  rows.forEach((row) => {
    const tr = document.createElement('tr');
    columns.forEach(({ key, chip = false, format = null }) => {
      const td = document.createElement('td');
      const raw = row[key];
      const display = format ? format(raw, row) : text(raw);
      if (chip) {
        const span = document.createElement('span');
        span.className = `status-chip ${statusClass(display)}`;
        span.textContent = display;
        td.appendChild(span);
      } else {
        td.textContent = display;
        td.title = display;
      }
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });

  table.append(thead, tbody);
  container.appendChild(table);
}

function renderMiniMetrics(container, metrics) {
  container.replaceChildren();
  metrics.forEach(({ label, value, note = '' }) => {
    const card = document.createElement('div');
    card.className = 'mini-metric';
    const labelNode = document.createElement('span');
    labelNode.textContent = label;
    const valueNode = document.createElement('strong');
    valueNode.textContent = text(value);
    valueNode.title = text(value);
    const noteNode = document.createElement('small');
    noteNode.textContent = note;
    card.append(labelNode, valueNode, noteNode);
    container.appendChild(card);
  });
}

function renderDetails(container, entries) {
  container.replaceChildren();
  container.classList.remove('empty-state');
  entries.forEach(([label, value]) => {
    const row = document.createElement('div');
    row.className = 'detail-row';
    const key = document.createElement('span');
    key.textContent = label;
    const val = document.createElement('strong');
    val.textContent = text(value);
    row.append(key, val);
    container.appendChild(row);
  });
}

function applyRiskBadge(node, level) {
  const value = text(level);
  node.textContent = value;
  node.className = `risk-badge ${String(level || 'neutral').toLowerCase()}`;
}

async function checkHealth() {
  const dot = $('#health-dot');
  const label = $('#health-label');
  try {
    const health = await (await fetch(`${API_BASE}/api/health`)).json();
    state.health = health;
    dot.className = 'health-dot online';
    label.textContent = health.scanning_enabled ? 'API online' : 'API needs setup';
    $('#version-label').textContent = `v${health.version}`;
    return health;
  } catch (error) {
    dot.className = 'health-dot offline';
    label.textContent = 'API offline';
    $('#version-label').textContent = 'Check local service';
    throw error;
  }
}

function setConnected(connected) {
  $('#connect-overlay').classList.toggle('hidden', connected);
  if (connected) $('#api-key').value = '';
}

async function connectWithKey(key) {
  setApiKey(key);
  await apiJson('/api/inventory');
  setConnected(true);
  showToast('Connected to NetWatch securely.');
  await loadOverview();
}

async function loadOverview() {
  const advisorBox = $('#overview-advisor');
  advisorBox.classList.add('skeleton-block');
  try {
    const [inventoryPayload, historyPayload, changesPayload, advice] = await Promise.all([
      apiJson('/api/inventory'),
      apiJson('/api/history?limit=8'),
      apiJson('/api/changes?limit=8'),
      apiJson('/api/advisor'),
    ]);
    const assets = inventoryPayload.assets || [];
    const history = historyPayload.items || [];
    const openCount = assets.reduce((sum, asset) => sum + Number(asset.open_port_count || 0), 0);
    const priorityCount = assets.filter((asset) => Number(asset.exposure_score || 0) > 0).length;

    $('#metric-assets').textContent = assets.length;
    $('#metric-open').textContent = openCount;
    $('#metric-risk').textContent = priorityCount;
    $('#metric-runs').textContent = history.length;

    renderTable($('#overview-history'), history.slice(0, 6), [
      { key: 'created_at', label: 'Time' },
      { key: 'scan_type', label: 'Type' },
      { key: 'target', label: 'Target' },
      { key: 'status', label: 'Status', chip: true },
    ], 'No checks recorded yet.');

    renderTable($('#overview-changes'), changesPayload.items || [], [
      { key: 'created_at', label: 'Time' },
      { key: 'ip_address', label: 'IP address' },
      { key: 'event_label', label: 'Change', chip: true },
      { key: 'details', label: 'Evidence' },
    ], 'No changes recorded yet. Run a network scan to establish a baseline.');

    advisorBox.replaceChildren();
    advisorBox.classList.remove('skeleton-block');
    const heading = document.createElement('strong');
    heading.textContent = `${advice.risk_level} priority · ${advice.confidence} confidence`;
    const copy = document.createElement('p');
    copy.textContent = advice.summary;
    advisorBox.append(heading, copy);
  } catch (error) {
    advisorBox.classList.remove('skeleton-block');
    advisorBox.textContent = error.message;
    if (error.status === 401 || error.status === 503) setConnected(false);
    throw error;
  }
}

async function loadInventory() {
  const [inventoryPayload, historyPayload, changesPayload] = await Promise.all([
    apiJson('/api/inventory'),
    apiJson('/api/history?limit=50'),
    apiJson('/api/changes?limit=50'),
  ]);
  renderTable($('#inventory-results'), inventoryPayload.assets || [], [
    { key: 'ip_address', label: 'IP address' },
    { key: 'status', label: 'Status', chip: true },
    { key: 'last_seen', label: 'Last seen' },
    { key: 'open_ports', label: 'Open ports' },
    { key: 'exposure_score', label: 'Score' },
    { key: 'exposure_level', label: 'Priority', chip: true },
  ], 'Inventory is empty. Run a network scan or port audit.');
  renderTable($('#changes-results'), changesPayload.items || [], [
    { key: 'created_at', label: 'Time' },
    { key: 'ip_address', label: 'IP address' },
    { key: 'event_label', label: 'Change', chip: true },
    { key: 'details', label: 'Evidence' },
  ], 'No changes recorded yet. Run a network scan to establish a baseline.');
  renderTable($('#history-results'), historyPayload.items || [], [
    { key: 'created_at', label: 'Time' },
    { key: 'scan_type', label: 'Type' },
    { key: 'target', label: 'Target' },
    { key: 'summary', label: 'Summary' },
    { key: 'status', label: 'Status', chip: true },
  ], 'No history recorded yet.');
}

async function loadAdvisor() {
  const advice = await apiJson('/api/advisor');
  applyRiskBadge($('#advisor-level'), advice.risk_level);
  $('#advisor-summary').textContent = advice.summary;
  $('#advisor-confidence').textContent = advice.confidence;

  const priorities = $('#advisor-priorities');
  const steps = $('#advisor-steps');
  priorities.replaceChildren();
  steps.replaceChildren();
  (advice.priorities || []).forEach((item) => {
    const li = document.createElement('li');
    li.textContent = item;
    priorities.appendChild(li);
  });
  (advice.next_steps || []).forEach((item) => {
    const li = document.createElement('li');
    li.textContent = item;
    steps.appendChild(li);
  });
}

async function refreshCurrentView() {
  if (state.view === 'overview') return loadOverview();
  if (state.view === 'inventory') return loadInventory();
  if (state.view === 'advisor') return loadAdvisor();
  return checkHealth();
}

function navigate(view) {
  if (!titles[view]) return;
  state.view = view;
  $$('.view').forEach((node) => node.classList.toggle('active', node.id === `view-${view}`));
  $$('.nav-item').forEach((node) => node.classList.toggle('active', node.dataset.view === view));
  $('#page-title').textContent = titles[view];
  window.scrollTo({ top: 0, behavior: 'smooth' });
  if (view === 'inventory') loadInventory().catch((error) => showToast(error.message, 'error'));
  if (view === 'advisor') loadAdvisor().catch((error) => showToast(error.message, 'error'));
}

async function downloadReport(type, button) {
  setBusy(button, true, 'Preparing…');
  try {
    const extension = type === 'html' ? 'html' : 'md';
    const response = await apiFetch(`/api/reports/${type}`);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `netwatch-report.${extension}`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    showToast(`${type.toUpperCase()} report downloaded.`);
  } catch (error) {
    showToast(error.message, 'error');
  } finally {
    setBusy(button, false);
  }
}

$('#connect-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.submitter;
  setBusy(button, true, 'Connecting…');
  setFormStatus('connect-status');
  try {
    await connectWithKey($('#api-key').value);
  } catch (error) {
    setApiKey('');
    setFormStatus('connect-status', error.message, 'error');
  } finally {
    setBusy(button, false);
  }
});

$('#toggle-key').addEventListener('click', () => {
  const input = $('#api-key');
  const visible = input.type === 'text';
  input.type = visible ? 'password' : 'text';
  $('#toggle-key').textContent = visible ? 'Show' : 'Hide';
});

$('#disconnect').addEventListener('click', () => {
  setApiKey('');
  setConnected(false);
  showToast('Disconnected. API key cleared from this tab.');
});

$('#nav').addEventListener('click', (event) => {
  const button = event.target.closest('[data-view]');
  if (button) navigate(button.dataset.view);
});

$$('[data-go]').forEach((button) => button.addEventListener('click', () => navigate(button.dataset.go)));
$('#refresh').addEventListener('click', async (event) => {
  setBusy(event.currentTarget, true, 'Refreshing…');
  try {
    await refreshCurrentView();
    showToast('View refreshed.');
  } catch (error) {
    showToast(error.message, 'error');
  } finally {
    setBusy(event.currentTarget, false);
  }
});

$('#network-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.submitter;
  setBusy(button, true, 'Scanning…');
  setFormStatus('network-status', 'Checking authorized local hosts…');
  try {
    const payload = await apiJson('/api/scan/network', {
      method: 'POST',
      body: JSON.stringify({
        cidr: $('#network-cidr').value.trim(),
        authorized: $('#network-authorized').checked,
      }),
    });
    $('#network-result-title').textContent = payload.target;
    $('#network-count').textContent = `${payload.online_hosts} host${payload.online_hosts === 1 ? '' : 's'}`;
    const changes = payload.changes || {};
    renderMiniMetrics($('#network-changes'), [
      { label: 'Observed', value: (changes.observed_assets || []).length, note: 'Latest snapshot' },
      { label: 'New', value: (changes.new_assets || []).length, note: 'First observed' },
      { label: 'Returned', value: (changes.returned_assets || []).length, note: 'Observed again' },
      { label: 'Not observed', value: (changes.not_observed_assets || []).length, note: 'Verify manually' },
    ]);
    renderTable($('#network-results'), payload.hosts || [], [
      { key: 'IP Address', label: 'IP address' },
      { key: 'Status', label: 'Status', chip: true },
      { key: 'Details', label: 'Detection details' },
    ], 'No hosts replied. Active hosts may be blocking ICMP.');
    setFormStatus('network-status', payload.summary, 'success');
    showToast(payload.summary);
  } catch (error) {
    setFormStatus('network-status', error.message, 'error');
  } finally {
    setBusy(button, false);
  }
});

$('#host-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.submitter;
  setBusy(button, true, 'Checking…');
  setFormStatus('host-status', 'Profiling the approved host…');
  try {
    const result = await apiJson('/api/scan/host', {
      method: 'POST',
      body: JSON.stringify({ ip: $('#host-ip').value.trim(), authorized: $('#host-authorized').checked }),
    });
    $('#host-result-title').textContent = result.ip_address;
    renderMiniMetrics($('#host-metrics'), [
      { label: 'Status', value: result.online ? 'Online' : 'No reply', note: 'ICMP result' },
      { label: 'Latency', value: result.latency_ms === null ? '—' : `${result.latency_ms} ms`, note: 'Round trip' },
      { label: 'TTL', value: result.ttl, note: 'Observed value' },
      { label: 'Hostname', value: result.hostname, note: 'Reverse DNS' },
    ]);
    renderDetails($('#host-details'), [
      ['Operating-system hint', result.os_hint],
      ['Observation', result.notes],
      ['Target', result.ip_address],
    ]);
    setFormStatus('host-status', result.notes, result.online ? 'success' : 'error');
  } catch (error) {
    setFormStatus('host-status', error.message, 'error');
  } finally {
    setBusy(button, false);
  }
});

$('#ports-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.submitter;
  setBusy(button, true, 'Auditing…');
  setFormStatus('ports-status', 'Reviewing the configured common-service list…');
  try {
    const result = await apiJson('/api/audit/ports', {
      method: 'POST',
      body: JSON.stringify({ ip: $('#ports-ip').value.trim(), authorized: $('#ports-authorized').checked }),
    });
    const exposure = result.exposure || {};
    $('#ports-result-title').textContent = result.target;
    applyRiskBadge($('#ports-risk'), exposure.level);
    renderMiniMetrics($('#ports-summary'), [
      { label: 'Checked', value: exposure.checked, note: 'Configured ports' },
      { label: 'Open', value: exposure.open_ports, note: 'Observed services' },
      { label: 'High priority', value: exposure.high, note: 'Review first' },
      { label: 'Score', value: exposure.score, note: 'Exposure priority' },
    ]);
    renderTable($('#ports-results'), result.ports || [], [
      { key: 'Port', label: 'Port' },
      { key: 'Service', label: 'Service' },
      { key: 'Status', label: 'Status', chip: true },
      { key: 'Response Time (ms)', label: 'Response ms' },
      { key: 'Risk', label: 'Priority', chip: true },
      { key: 'Recommendation', label: 'Recommendation' },
    ]);
    setFormStatus('ports-status', `${exposure.open_ports} open service(s), ${exposure.level} priority.`, 'success');
  } catch (error) {
    setFormStatus('ports-status', error.message, 'error');
  } finally {
    setBusy(button, false);
  }
});

$('#inventory-refresh').addEventListener('click', async (event) => {
  setBusy(event.currentTarget, true, 'Refreshing…');
  try { await loadInventory(); showToast('Inventory refreshed.'); }
  catch (error) { showToast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
});

$('#advisor-refresh').addEventListener('click', async (event) => {
  setBusy(event.currentTarget, true, 'Rebuilding…');
  try { await loadAdvisor(); showToast('Advisor rebuilt from saved evidence.'); }
  catch (error) { showToast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
});

$$('[data-report]').forEach((button) => button.addEventListener('click', () => downloadReport(button.dataset.report, button)));

function updateClock() {
  $('#clock').textContent = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date());
}
setInterval(updateClock, 1000);
updateClock();

async function init() {
  try {
    await checkHealth();
  } catch (_) {
    setFormStatus('connect-status', 'NetWatch API is not reachable. Start the local service first.', 'error');
    return;
  }

  if (state.key) {
    try {
      await connectWithKey(state.key);
      return;
    } catch (error) {
      setApiKey('');
      setFormStatus('connect-status', error.message, 'error');
    }
  }
  setConnected(false);
}

window.NetWatchApi = { API_BASE, apiFetch, setApiKey };
init();

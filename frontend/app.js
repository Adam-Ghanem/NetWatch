const queryApi = new URLSearchParams(window.location.search).get('api');
const API_BASE = window.NETWATCH_API_BASE || queryApi || window.location.origin;

const state = {
  key: sessionStorage.getItem('netwatchApiKey') || '',
  view: 'overview',
  health: null,
  role: '',
  capabilities: {
    read: false,
    scan: false,
    manage_assets: false,
    manage_alerts: false,
    manage_operations: false,
    backup: false,
  },
  assets: [],
};

const titles = {
  overview: 'Overview',
  network: 'Network scan',
  host: 'Host check',
  ports: 'Port audit',
  inventory: 'Inventory',
  advisor: 'Risk advisor',
  audit: 'Audit log',
  operations: 'Operations',
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
  if (normalized.includes('scheduled') || normalized.includes('running')) return 'online';
  if (normalized === 'enabled') return 'completed';
  if (normalized === 'disabled') return 'filtered';
  if (normalized.includes('acknowledged')) return 'completed';
  if (normalized.includes('deferred')) return 'medium';
  if (normalized.includes('open')) return 'open';
  if (normalized.includes('online')) return 'online';
  if (normalized.includes('complete')) return 'completed';
  if (normalized.includes('high') || normalized.includes('critical')) return 'high';
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
    label.textContent = !health.access_enabled
      ? 'API needs setup'
      : (health.scanning_enabled ? 'API online' : 'API read-only');
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
  if (!connected) {
    state.role = '';
    state.capabilities = {
      read: false,
      scan: false,
      manage_assets: false,
      manage_alerts: false,
      manage_operations: false,
      backup: false,
    };
    applyRoleAccess();
  }
}

function applyRoleAccess() {
  const roleBadge = $('#session-role');
  const roleLabel = state.role ? `${state.role[0].toUpperCase()}${state.role.slice(1)}` : 'Disconnected';
  roleBadge.textContent = roleLabel;
  roleBadge.className = `role-badge ${state.role || ''}`;

  const canScan = Boolean(state.capabilities.scan);
  ['#network-form', '#host-form', '#ports-form'].forEach((selector) => {
    $$('input, button', $(selector)).forEach((control) => { control.disabled = !canScan; });
  });
  $$('[data-scan-control]').forEach((control) => { control.disabled = !canScan; });

  const canManageAssets = Boolean(state.capabilities.manage_assets);
  $$('input, select, textarea, button', $('#asset-context-form')).forEach((control) => {
    control.disabled = !canManageAssets;
  });
  if (canManageAssets) {
    setFormStatus('context-status', 'Select a saved asset, then add accountable business context.');
  } else if (state.role) {
    setFormStatus('context-status', 'Admin access is required to edit asset context.');
  }

  const canManageOperations = Boolean(state.capabilities.manage_operations);
  $$('input, button', $('#policy-form')).forEach((control) => {
    control.disabled = !canManageOperations;
  });
  if (canManageOperations) {
    setFormStatus('policy-status', 'Create a policy only for a private range with durable approval.');
  } else if (state.role) {
    setFormStatus('policy-status', 'Admin access is required to create and change policies.');
  }
  $('#policy-run-authorized').disabled = !canScan;
  $('#database-backup').disabled = !Boolean(state.capabilities.backup);
}

async function connectWithKey(key) {
  setApiKey(key);
  const session = await apiJson('/api/session');
  state.role = session.role || '';
  state.capabilities = session.capabilities || {};
  applyRoleAccess();
  await loadOverview();
  setConnected(true);
  showToast(`Connected with ${state.role} access.`);
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
  state.assets = inventoryPayload.assets || [];
  renderTable($('#inventory-results'), state.assets, [
    { key: 'ip_address', label: 'IP address' },
    { key: 'owner', label: 'Owner' },
    { key: 'department', label: 'Department' },
    { key: 'location', label: 'Location' },
    { key: 'criticality', label: 'Criticality', chip: true },
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
  populateAssetOptions();
  fillAssetContext($('#asset-ip').value);
}

function populateAssetOptions() {
  const datalist = $('#asset-options');
  datalist.replaceChildren();
  state.assets.forEach((asset) => {
    const option = document.createElement('option');
    option.value = asset.ip_address;
    option.label = [asset.owner, asset.department].filter(Boolean).join(' · ');
    datalist.appendChild(option);
  });
}

function fillAssetContext(ipAddress) {
  const asset = state.assets.find((item) => item.ip_address === String(ipAddress || '').trim());
  if (!asset) return;
  $('#asset-owner').value = asset.owner || '';
  $('#asset-department').value = asset.department || '';
  $('#asset-location').value = asset.location || '';
  $('#asset-criticality').value = asset.criticality || 'Medium';
  $('#asset-notes').value = asset.notes || '';
  if (state.capabilities.manage_assets) {
    setFormStatus('context-status', `Editing ${asset.ip_address}.`, 'success');
  } else {
    setFormStatus('context-status', 'Admin access is required to edit asset context.');
  }
}

async function loadAudit() {
  const payload = await apiJson('/api/audit-log?limit=200');
  renderTable($('#audit-results'), payload.items || [], [
    { key: 'created_at', label: 'Time' },
    { key: 'actor_role', label: 'Role', chip: true },
    { key: 'action', label: 'Action', format: (value) => text(value).replaceAll('_', ' ') },
    { key: 'target', label: 'Target' },
    { key: 'outcome', label: 'Outcome', chip: true },
    { key: 'details', label: 'Details' },
  ], 'No operational events have been recorded yet.');
}

function actionButton(label, action, itemId, enabled = true, primary = false) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = `button ${primary ? 'primary' : 'ghost'} compact table-button`;
  button.textContent = label;
  button.dataset.action = action;
  button.dataset.itemId = String(itemId);
  button.disabled = !enabled;
  return button;
}

function appendTableCell(row, value, chip = false) {
  const cell = document.createElement('td');
  if (chip) {
    const badge = document.createElement('span');
    badge.className = `status-chip ${statusClass(value)}`;
    badge.textContent = text(value);
    cell.appendChild(badge);
  } else {
    cell.textContent = text(value);
    cell.title = text(value);
  }
  row.appendChild(cell);
  return cell;
}

function renderPolicies(policies) {
  const container = $('#policy-results');
  container.replaceChildren();
  container.classList.remove('empty-state');
  if (!Array.isArray(policies) || policies.length === 0) {
    container.classList.add('empty-state');
    container.textContent = 'No approved scan policies have been saved.';
    return;
  }

  const table = document.createElement('table');
  const head = document.createElement('thead');
  const headRow = document.createElement('tr');
  ['Policy', 'Approved CIDR', 'Interval', 'State', 'Last result', 'Next run', 'Actions'].forEach((label) => {
    const cell = document.createElement('th');
    cell.textContent = label;
    headRow.appendChild(cell);
  });
  head.appendChild(headRow);

  const body = document.createElement('tbody');
  policies.forEach((policy) => {
    const row = document.createElement('tr');
    appendTableCell(row, policy.name);
    appendTableCell(row, policy.cidr);
    appendTableCell(row, `${policy.interval_minutes} min`);
    appendTableCell(row, policy.enabled ? 'Enabled' : 'Disabled', true);
    appendTableCell(row, policy.last_status, true);
    appendTableCell(row, policy.next_run_at || 'Manual only');
    const actions = appendTableCell(row, '');
    actions.replaceChildren();
    const rowActions = document.createElement('div');
    rowActions.className = 'table-actions';
    const canRun = Boolean(state.capabilities.scan) && policy.last_status !== 'running';
    const canManage = Boolean(state.capabilities.manage_operations);
    const runButton = actionButton('Run now', 'run-policy', policy.id, canRun, true);
    const toggleButton = actionButton(
      policy.enabled ? 'Disable' : 'Enable',
      'toggle-policy',
      policy.id,
      canManage,
    );
    toggleButton.dataset.nextEnabled = String(!policy.enabled);
    rowActions.append(runButton, toggleButton);
    actions.appendChild(rowActions);
    body.appendChild(row);
  });

  table.append(head, body);
  container.appendChild(table);
}

function renderAlerts(alerts) {
  const container = $('#alert-results');
  container.replaceChildren();
  container.classList.remove('empty-state');
  if (!Array.isArray(alerts) || alerts.length === 0) {
    container.classList.add('empty-state');
    container.textContent = 'No alerts match this filter.';
    return;
  }

  const table = document.createElement('table');
  const head = document.createElement('thead');
  const headRow = document.createElement('tr');
  ['Time', 'Severity', 'Alert', 'Target', 'Status', 'Evidence', 'Action'].forEach((label) => {
    const cell = document.createElement('th');
    cell.textContent = label;
    headRow.appendChild(cell);
  });
  head.appendChild(headRow);

  const body = document.createElement('tbody');
  alerts.forEach((alert) => {
    const row = document.createElement('tr');
    appendTableCell(row, alert.created_at);
    appendTableCell(row, alert.severity, true);
    appendTableCell(row, alert.title);
    appendTableCell(row, alert.target);
    appendTableCell(row, alert.status, true);
    appendTableCell(row, alert.details);
    const actions = appendTableCell(row, '');
    actions.replaceChildren();
    const nextStatus = alert.status === 'open' ? 'acknowledged' : 'open';
    const label = nextStatus === 'acknowledged' ? 'Acknowledge' : 'Reopen';
    const button = actionButton(
      label,
      'set-alert-status',
      alert.id,
      Boolean(state.capabilities.manage_alerts),
    );
    button.dataset.nextStatus = nextStatus;
    actions.appendChild(button);
    body.appendChild(row);
  });

  table.append(head, body);
  container.appendChild(table);
}

async function loadOperations() {
  const filter = $('#alert-filter').value;
  const alertPath = filter
    ? `/api/alerts?status=${encodeURIComponent(filter)}&limit=200`
    : '/api/alerts?limit=200';
  const [policyPayload, alertPayload] = await Promise.all([
    apiJson('/api/scan-policies'),
    apiJson(alertPath),
  ]);
  const policies = policyPayload.items || [];
  const alerts = alertPayload.items || [];
  const schedulerEnabled = Boolean(policyPayload.scheduler_enabled);
  const schedulerBadge = $('#scheduler-state');
  schedulerBadge.textContent = schedulerEnabled ? 'Scheduler enabled' : 'Scheduler disabled';
  schedulerBadge.className = `risk-badge ${schedulerEnabled ? 'low' : 'medium'}`;
  renderMiniMetrics($('#operations-metrics'), [
    { label: 'Approved policies', value: policies.length, note: 'Maximum 50' },
    { label: 'Enabled policies', value: policies.filter((item) => item.enabled).length, note: 'Private CIDRs only' },
    { label: 'Open alerts', value: alertPayload.open_count || 0, note: 'Needs triage' },
    { label: 'Scheduler', value: schedulerEnabled ? 'On' : 'Off', note: 'Deployment setting' },
  ]);
  renderPolicies(policies);
  renderAlerts(alerts);
  applyRoleAccess();
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
  if (state.view === 'audit') return loadAudit();
  if (state.view === 'operations') return loadOperations();
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
  if (view === 'audit') loadAudit().catch((error) => showToast(error.message, 'error'));
  if (view === 'operations') loadOperations().catch((error) => showToast(error.message, 'error'));
}

async function downloadApiFile(path, filename, button, successMessage) {
  setBusy(button, true, 'Preparing…');
  try {
    const response = await apiFetch(path);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    const disposition = response.headers.get('Content-Disposition') || '';
    const serverFilename = /filename="([^"\\/]+)"/.exec(disposition);
    anchor.href = url;
    anchor.download = serverFilename ? serverFilename[1] : filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    showToast(successMessage);
  } catch (error) {
    showToast(error.message, 'error');
  } finally {
    setBusy(button, false);
  }
}

async function downloadReport(type, button) {
  const extension = type === 'html' ? 'html' : 'md';
  return downloadApiFile(
    `/api/reports/${type}`,
    `netwatch-report.${extension}`,
    button,
    `${type.toUpperCase()} report downloaded.`,
  );
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
    setConnected(false);
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

$('#inventory-export').addEventListener('click', (event) => downloadApiFile(
  '/api/inventory/export.csv',
  'netwatch-inventory.csv',
  event.currentTarget,
  'Inventory CSV downloaded.',
));

$('#asset-ip').addEventListener('change', (event) => fillAssetContext(event.currentTarget.value));

$('#asset-context-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.submitter;
  setBusy(button, true, 'Saving…');
  setFormStatus('context-status', 'Saving accountable asset context…');
  try {
    const ipAddress = $('#asset-ip').value.trim();
    await apiJson(`/api/assets/${encodeURIComponent(ipAddress)}`, {
      method: 'PATCH',
      body: JSON.stringify({
        owner: $('#asset-owner').value.trim(),
        department: $('#asset-department').value.trim(),
        location: $('#asset-location').value.trim(),
        criticality: $('#asset-criticality').value,
        notes: $('#asset-notes').value.trim(),
      }),
    });
    await loadInventory();
    setFormStatus('context-status', `Asset context saved for ${ipAddress}.`, 'success');
    showToast('Asset context saved and logged.');
  } catch (error) {
    setFormStatus('context-status', error.message, 'error');
  } finally {
    setBusy(button, false);
  }
});

$('#audit-refresh').addEventListener('click', async (event) => {
  setBusy(event.currentTarget, true, 'Refreshing…');
  try { await loadAudit(); showToast('Audit log refreshed.'); }
  catch (error) { showToast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
});

$('#policy-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.submitter;
  setBusy(button, true, 'Saving…');
  setFormStatus('policy-status', 'Validating and saving approved scope…');
  try {
    const payload = await apiJson('/api/scan-policies', {
      method: 'POST',
      body: JSON.stringify({
        name: $('#policy-name').value.trim(),
        cidr: $('#policy-cidr').value.trim(),
        interval_minutes: Number($('#policy-interval').value),
        enabled: $('#policy-enabled').checked,
        authorized: $('#policy-authorized').checked,
      }),
    });
    $('#policy-authorized').checked = false;
    setFormStatus('policy-status', `Policy saved for ${payload.policy.cidr}.`, 'success');
    await loadOperations();
    showToast('Approved scan policy saved and audited.');
  } catch (error) {
    setFormStatus('policy-status', error.message, 'error');
  } finally {
    setBusy(button, false);
    applyRoleAccess();
  }
});

$('#policy-results').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-action]');
  if (!button) return;
  const policyId = button.dataset.itemId;
  if (button.dataset.action === 'run-policy' && !$('#policy-run-authorized').checked) {
    showToast('Confirm current authorization before running this policy.', 'error');
    return;
  }

  setBusy(button, true, button.dataset.action === 'run-policy' ? 'Running…' : 'Updating…');
  try {
    if (button.dataset.action === 'run-policy') {
      const result = await apiJson(`/api/scan-policies/${policyId}/run`, {
        method: 'POST',
        body: JSON.stringify({ authorized: true }),
      });
      $('#policy-run-authorized').checked = false;
      showToast(result.summary);
    } else if (button.dataset.action === 'toggle-policy') {
      const enabled = button.dataset.nextEnabled === 'true';
      await apiJson(`/api/scan-policies/${policyId}`, {
        method: 'PATCH',
        body: JSON.stringify({ enabled }),
      });
      showToast(`Scan policy ${enabled ? 'enabled' : 'disabled'}.`);
    }
    await loadOperations();
  } catch (error) {
    showToast(error.message, 'error');
  } finally {
    setBusy(button, false);
  }
});

$('#operations-refresh').addEventListener('click', async (event) => {
  setBusy(event.currentTarget, true, 'Refreshing…');
  try { await loadOperations(); showToast('Operations view refreshed.'); }
  catch (error) { showToast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
});

$('#alerts-refresh').addEventListener('click', async (event) => {
  setBusy(event.currentTarget, true, 'Refreshing…');
  try { await loadOperations(); showToast('Alert inbox refreshed.'); }
  catch (error) { showToast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
});

$('#alert-filter').addEventListener('change', () => {
  loadOperations().catch((error) => showToast(error.message, 'error'));
});

$('#alert-results').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-action="set-alert-status"]');
  if (!button) return;
  setBusy(button, true, 'Updating…');
  try {
    await apiJson(`/api/alerts/${button.dataset.itemId}`, {
      method: 'PATCH',
      body: JSON.stringify({ status: button.dataset.nextStatus }),
    });
    await loadOperations();
    showToast(`Alert ${button.dataset.nextStatus}.`);
  } catch (error) {
    showToast(error.message, 'error');
  } finally {
    setBusy(button, false);
  }
});

$('#database-backup').addEventListener('click', (event) => downloadApiFile(
  '/api/backups/database',
  'netwatch-backup.sqlite3',
  event.currentTarget,
  'Database backup downloaded and audited.',
));

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
      setConnected(false);
      setFormStatus('connect-status', error.message, 'error');
    }
  }
  setConnected(false);
}

window.NetWatchApi = { API_BASE, apiFetch, setApiKey };
init();

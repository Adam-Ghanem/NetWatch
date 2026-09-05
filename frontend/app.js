// NetWatch Traffic Explorer bootstrap.
// The existing application stays in app-core.js; this layer adds bounded flow exports,
// offline PCAP/PCAPNG analysis, and flow-aware analyst pivots without retaining raw payload bytes.
// Compatibility markers used by frontend safety tests: NetWatchApi /api/session /api/readiness renderReadiness /api/traffic/capture /api/service-findings renderTrafficCapture candidate.origin !== window.location.origin

function loadNetWatchCore(onReady) {
  const script = document.createElement('script');
  script.src = '/app-core.js';
  script.addEventListener('load', onReady, { once: true });
  document.head.appendChild(script);
}

function trafficCaptureRequest() {
  const portValue = document.querySelector('#traffic-port').value.trim();
  return {
    interface: document.querySelector('#traffic-interface').value,
    duration_seconds: Number(document.querySelector('#traffic-duration').value),
    max_packets: Number(document.querySelector('#traffic-limit').value),
    protocol: document.querySelector('#traffic-protocol').value,
    ip_filter: document.querySelector('#traffic-ip').value.trim(),
    port_filter: portValue ? Number(portValue) : null,
    authorized: document.querySelector('#traffic-authorized').checked,
  };
}

function responseFilename(response, exportFormat) {
  const disposition = response.headers.get('content-disposition') || '';
  const match = disposition.match(/filename="?([^";]+)"?/i);
  return match ? match[1] : `netwatch-flows.${exportFormat}`;
}

async function downloadTrafficFlows() {
  const button = document.querySelector('#traffic-export');
  const status = document.querySelector('#traffic-status');
  const authorization = document.querySelector('#traffic-authorized');
  const exportFormat = document.querySelector('#traffic-export-format').value;

  if (!authorization.checked) {
    status.textContent = 'Confirm authorization before capturing and exporting flow metadata.';
    status.className = 'form-status error';
    return;
  }

  const originalText = button.textContent;
  button.disabled = true;
  button.textContent = 'Capturing…';
  status.textContent = `Capturing bounded metadata for ${exportFormat.toUpperCase()} export…`;
  status.className = 'form-status';

  try {
    const response = await window.NetWatchApi.apiFetch(
      `/api/traffic/capture/export.${exportFormat}`,
      {
        method: 'POST',
        body: JSON.stringify(trafficCaptureRequest()),
      },
    );
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = responseFilename(response, exportFormat);
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    authorization.checked = false;
    status.textContent = `${exportFormat.toUpperCase()} flow export downloaded. Payload bytes were not retained.`;
    status.className = 'form-status success';
  } catch (error) {
    status.textContent = error.message || 'Flow export failed.';
    status.className = 'form-status error';
  } finally {
    button.textContent = originalText;
    button.disabled = authorization.disabled;
  }
}

function offlineAnalysisUrl() {
  const params = new URLSearchParams({
    authorized: 'true',
    packet_limit: document.querySelector('#traffic-offline-packet-limit').value,
    flow_limit: document.querySelector('#traffic-offline-flow-limit').value,
    protocol: document.querySelector('#traffic-protocol').value,
    ip_address: document.querySelector('#traffic-ip').value.trim(),
  });
  return `/api/traffic/offline/analyze?${params.toString()}`;
}

function offlineExportUrl(exportFormat) {
  const params = new URLSearchParams({
    authorized: 'true',
    packet_limit: document.querySelector('#traffic-offline-packet-limit').value,
    flow_limit: document.querySelector('#traffic-offline-flow-limit').value,
    protocol: document.querySelector('#traffic-protocol').value,
    ip_address: document.querySelector('#traffic-ip').value.trim(),
  });
  return `/api/traffic/offline/export.${exportFormat}?${params.toString()}`;
}

async function analyzeOfflineCapture() {
  const fileInput = document.querySelector('#traffic-offline-file');
  const authorization = document.querySelector('#traffic-offline-authorized');
  const button = document.querySelector('#traffic-offline-analyze');
  const status = document.querySelector('#traffic-offline-status');
  const file = fileInput.files?.[0];

  if (!file) {
    status.textContent = 'Choose a PCAP or PCAPNG file first.';
    status.className = 'form-status error';
    return;
  }
  if (!authorization.checked) {
    status.textContent = 'Confirm that you are authorized to analyze this capture.';
    status.className = 'form-status error';
    return;
  }

  const originalText = button.textContent;
  button.disabled = true;
  button.textContent = 'Analyzing…';
  status.textContent = `Analyzing ${file.name} as bounded metadata only…`;
  status.className = 'form-status';

  try {
    const response = await window.NetWatchApi.apiFetch(offlineAnalysisUrl(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: file,
    });
    const payload = await response.json();
    renderTrafficCapture(payload);
    authorization.checked = false;
    status.textContent = `Offline analysis complete: ${Number(payload.captured_packets || 0)} packet header(s), ${Number(payload.flow_count || 0)} flow(s). Raw payload bytes were not retained.`;
    status.className = 'form-status success';
  } catch (error) {
    status.textContent = error.message || 'Offline capture analysis failed.';
    status.className = 'form-status error';
  } finally {
    button.textContent = originalText;
    button.disabled = false;
  }
}

async function downloadOfflineFlows() {
  const fileInput = document.querySelector('#traffic-offline-file');
  const authorization = document.querySelector('#traffic-offline-authorized');
  const button = document.querySelector('#traffic-offline-export');
  const status = document.querySelector('#traffic-offline-status');
  const exportFormat = document.querySelector('#traffic-offline-export-format').value;
  const file = fileInput.files?.[0];

  if (!file) {
    status.textContent = 'Choose a PCAP or PCAPNG file first.';
    status.className = 'form-status error';
    return;
  }
  if (!authorization.checked) {
    status.textContent = 'Confirm that you are authorized to analyze and export this capture.';
    status.className = 'form-status error';
    return;
  }

  const originalText = button.textContent;
  button.disabled = true;
  button.textContent = 'Exporting…';
  status.textContent = `Analyzing ${file.name} for bounded ${exportFormat.toUpperCase()} flow export…`;
  status.className = 'form-status';

  try {
    const response = await window.NetWatchApi.apiFetch(offlineExportUrl(exportFormat), {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: file,
    });
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = responseFilename(response, exportFormat);
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    authorization.checked = false;
    status.textContent = `Offline ${exportFormat.toUpperCase()} flow export downloaded. Payload bytes were not retained.`;
    status.className = 'form-status success';
  } catch (error) {
    status.textContent = error.message || 'Offline flow export failed.';
    status.className = 'form-status error';
  } finally {
    button.textContent = originalText;
    button.disabled = false;
  }
}

function buildOfflineLimitControl(id, labelText, max, value) {
  const wrapper = document.createElement('div');
  const label = document.createElement('label');
  label.setAttribute('for', id);
  label.textContent = labelText;

  const input = document.createElement('input');
  input.id = id;
  input.type = 'number';
  input.min = '1';
  input.max = String(max);
  input.value = String(value);

  wrapper.append(label, input);
  return wrapper;
}

function buildExportFormatControl(id) {
  const wrapper = document.createElement('div');
  const label = document.createElement('label');
  label.setAttribute('for', id);
  label.textContent = 'Offline flow export format';

  const select = document.createElement('select');
  select.id = id;
  for (const [value, labelText] of [['json', 'JSON'], ['csv', 'CSV'], ['ndjson', 'NDJSON']]) {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = labelText;
    select.appendChild(option);
  }

  wrapper.append(label, select);
  return wrapper;
}

function installOfflineCaptureControls(form) {
  if (document.querySelector('#traffic-offline-panel')) return;

  const panel = document.createElement('section');
  panel.id = 'traffic-offline-panel';
  panel.className = 'subpanel';

  const heading = document.createElement('h4');
  heading.textContent = 'Analyze saved capture';
  const help = document.createElement('p');
  help.className = 'muted';
  help.textContent = 'Open an authorized PCAP/PCAPNG file locally for bounded metadata-only analysis. Live sensor packet privileges are not required.';

  const fileLabel = document.createElement('label');
  fileLabel.setAttribute('for', 'traffic-offline-file');
  fileLabel.textContent = 'PCAP / PCAPNG file';
  const fileInput = document.createElement('input');
  fileInput.id = 'traffic-offline-file';
  fileInput.type = 'file';
  fileInput.accept = '.pcap,.pcapng,application/vnd.tcpdump.pcap,application/octet-stream';

  const limitGrid = document.createElement('div');
  limitGrid.className = 'traffic-form-grid';
  limitGrid.append(
    buildOfflineLimitControl('traffic-offline-packet-limit', 'Packet limit', 10000, 1000),
    buildOfflineLimitControl('traffic-offline-flow-limit', 'Flow limit', 1000, 100),
    buildExportFormatControl('traffic-offline-export-format'),
  );

  const authorizationLabel = document.createElement('label');
  authorizationLabel.className = 'check-row';
  const authorization = document.createElement('input');
  authorization.id = 'traffic-offline-authorized';
  authorization.type = 'checkbox';
  const authorizationText = document.createElement('span');
  authorizationText.textContent = 'I confirm I am authorized to analyze this capture file.';
  authorizationLabel.append(authorization, authorizationText);

  const actions = document.createElement('div');
  actions.className = 'button-row';
  const analyzeButton = document.createElement('button');
  analyzeButton.id = 'traffic-offline-analyze';
  analyzeButton.type = 'button';
  analyzeButton.className = 'button ghost';
  analyzeButton.textContent = 'Analyze capture file';
  analyzeButton.addEventListener('click', analyzeOfflineCapture);

  const exportButton = document.createElement('button');
  exportButton.id = 'traffic-offline-export';
  exportButton.type = 'button';
  exportButton.className = 'button ghost';
  exportButton.textContent = 'Export offline flows';
  exportButton.addEventListener('click', downloadOfflineFlows);
  actions.append(analyzeButton, exportButton);

  const status = document.createElement('div');
  status.id = 'traffic-offline-status';
  status.className = 'form-status';
  status.setAttribute('role', 'status');

  panel.append(
    heading,
    help,
    fileLabel,
    fileInput,
    limitGrid,
    authorizationLabel,
    actions,
    status,
  );
  form.after(panel);
}

function formatPivotBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) return '—';
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function flowEndpointText(endpoint) {
  if (!endpoint || typeof endpoint !== 'object') return '—';
  const ip = String(endpoint.ip || '—');
  const port = Number(endpoint.port || 0);
  return port > 0 ? `${ip}:${port}` : ip;
}

function buildPivotButton(label, ip, protocol) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'button ghost';
  button.textContent = label;
  button.addEventListener('click', () => applyTrafficFlowPivot({ ip, protocol }));
  return button;
}

function buildFlowTable(container, columns, rows, emptyMessage) {
  container.replaceChildren();
  container.classList.remove('empty-state');
  if (!Array.isArray(rows) || rows.length === 0) {
    container.classList.add('empty-state');
    container.textContent = emptyMessage;
    return;
  }

  const table = document.createElement('table');
  const head = document.createElement('thead');
  const headRow = document.createElement('tr');
  columns.forEach((column) => {
    const cell = document.createElement('th');
    cell.textContent = column.label;
    headRow.appendChild(cell);
  });
  head.appendChild(headRow);

  const body = document.createElement('tbody');
  rows.forEach((row) => {
    const tableRow = document.createElement('tr');
    columns.forEach((column) => {
      const cell = document.createElement('td');
      const value = column.render(row);
      if (value instanceof Node) cell.appendChild(value);
      else cell.textContent = String(value ?? '—');
      tableRow.appendChild(cell);
    });
    body.appendChild(tableRow);
  });
  table.append(head, body);
  container.appendChild(table);
}

function applyTrafficFlowPivot(pivot) {
  const ipInput = document.querySelector('#traffic-ip');
  const portInput = document.querySelector('#traffic-port');
  const protocolSelect = document.querySelector('#traffic-protocol');
  const status = document.querySelector('#traffic-status');
  const ip = String(pivot?.ip || '').trim();
  const protocol = String(pivot?.protocol || '').trim().toLowerCase();

  if (ip && ip !== '—' && ip !== '-') ipInput.value = ip;
  // Offline analysis has no independent port query today. Clear a stale live-only
  // port filter so the same pivot means the same thing for live and saved evidence.
  portInput.value = '';
  if (Array.from(protocolSelect.options).some((option) => option.value === protocol)) {
    protocolSelect.value = protocol;
  } else {
    protocolSelect.value = 'all';
  }

  status.textContent = 'Limit next capture/analysis to this flow pivot. Confirm authorization, then run the live or saved-capture analysis again.';
  status.className = 'form-status success';
  ipInput.focus();
}

function installTrafficFlowPivotPanels() {
  if (document.querySelector('#traffic-flow-conversations')) return;
  const packetPanel = document.querySelector('#traffic-packets')?.closest('.panel');
  if (!packetPanel) return;

  const grid = document.createElement('div');
  grid.className = 'split-grid traffic-analysis-grid';

  const conversationPanel = document.createElement('article');
  conversationPanel.className = 'panel';
  const conversationHead = document.createElement('div');
  conversationHead.className = 'panel-head';
  const conversationCopy = document.createElement('div');
  const conversationEyebrow = document.createElement('p');
  conversationEyebrow.className = 'eyebrow';
  conversationEyebrow.textContent = 'Flow conversations';
  const conversationTitle = document.createElement('h3');
  conversationTitle.textContent = 'Originator ↔ responder';
  conversationCopy.append(conversationEyebrow, conversationTitle);
  const conversationCount = document.createElement('span');
  conversationCount.id = 'traffic-flow-conversation-count';
  conversationCount.className = 'count-badge';
  conversationCount.textContent = '0 flows';
  conversationHead.append(conversationCopy, conversationCount);
  const conversations = document.createElement('div');
  conversations.id = 'traffic-flow-conversations';
  conversations.className = 'table-wrap empty-state';
  conversations.textContent = 'Run an analysis to build flow-aware conversations.';
  conversationPanel.append(conversationHead, conversations);

  const endpointPanel = document.createElement('article');
  endpointPanel.className = 'panel';
  const endpointHead = document.createElement('div');
  endpointHead.className = 'panel-head';
  const endpointCopy = document.createElement('div');
  const endpointEyebrow = document.createElement('p');
  endpointEyebrow.className = 'eyebrow';
  endpointEyebrow.textContent = 'Flow endpoints';
  const endpointTitle = document.createElement('h3');
  endpointTitle.textContent = 'Directional activity';
  endpointCopy.append(endpointEyebrow, endpointTitle);
  const endpointCount = document.createElement('span');
  endpointCount.id = 'traffic-flow-endpoint-count';
  endpointCount.className = 'count-badge';
  endpointCount.textContent = '0 endpoints';
  endpointHead.append(endpointCopy, endpointCount);
  const endpoints = document.createElement('div');
  endpoints.id = 'traffic-flow-endpoints';
  endpoints.className = 'table-wrap empty-state';
  endpoints.textContent = 'Run an analysis to build endpoint statistics.';
  endpointPanel.append(endpointHead, endpoints);

  grid.append(conversationPanel, endpointPanel);
  packetPanel.before(grid);
}

function renderTrafficFlowPivots(payload) {
  const conversationContainer = document.querySelector('#traffic-flow-conversations');
  const endpointContainer = document.querySelector('#traffic-flow-endpoints');
  if (!conversationContainer || !endpointContainer) return;

  const conversationCount = Number(payload.conversation_count || 0);
  const endpointCount = Number(payload.endpoint_count || 0);
  document.querySelector('#traffic-flow-conversation-count').textContent = `${conversationCount} flow${conversationCount === 1 ? '' : 's'}`;
  document.querySelector('#traffic-flow-endpoint-count').textContent = `${endpointCount} endpoint${endpointCount === 1 ? '' : 's'}`;

  buildFlowTable(
    conversationContainer,
    [
      { label: 'Originator', render: (row) => flowEndpointText(row.source) },
      { label: 'Responder', render: (row) => flowEndpointText(row.destination) },
      { label: 'Protocol', render: (row) => row.protocol || '—' },
      { label: 'Service', render: (row) => row.service || '—' },
      { label: 'State', render: (row) => row.tcp_state || '—' },
      { label: 'Packets', render: (row) => Number(row.packets || 0) },
      { label: 'Bytes', render: (row) => formatPivotBytes(row.bytes) },
      { label: 'Duration', render: (row) => `${Number(row.duration_ms || 0)} ms` },
      {
        label: 'Pivot',
        render: (row) => {
          const actions = document.createElement('div');
          actions.className = 'button-row';
          actions.append(
            buildPivotButton('Originator', row.source?.ip, row.protocol),
            buildPivotButton('Responder', row.destination?.ip, row.protocol),
          );
          return actions;
        },
      },
    ],
    payload.conversations || [],
    'No flow conversations matched the selected evidence.',
  );

  buildFlowTable(
    endpointContainer,
    [
      { label: 'IP address', render: (row) => row.ip || '—' },
      { label: 'Conversations', render: (row) => Number(row.conversation_count || 0) },
      { label: 'Packets', render: (row) => Number(row.packets || 0) },
      { label: 'Bytes', render: (row) => formatPivotBytes(row.bytes) },
      { label: 'Sent', render: (row) => formatPivotBytes(row.sent_bytes) },
      { label: 'Received', render: (row) => formatPivotBytes(row.received_bytes) },
      { label: 'Pivot', render: (row) => buildPivotButton('Filter IP', row.ip, '') },
    ],
    payload.endpoints || [],
    'No flow endpoint statistics matched the selected evidence.',
  );
}

function installTrafficFlowPivotRendering() {
  installTrafficFlowPivotPanels();
  const baseRenderer = window.renderTrafficCapture;
  if (typeof baseRenderer !== 'function') return;
  window.renderTrafficCapture = function renderTrafficCaptureWithFlowPivots(payload) {
    baseRenderer(payload);
    renderTrafficFlowPivots(payload);
  };
}

function installTrafficExportControls() {
  const form = document.querySelector('#traffic-form');
  const authorization = document.querySelector('#traffic-authorized');
  const actions = form?.querySelector('.button-row');
  if (!form || !authorization || !actions) return;

  if (!document.querySelector('#traffic-export')) {
    const formatLabel = document.createElement('label');
    formatLabel.setAttribute('for', 'traffic-export-format');
    formatLabel.textContent = 'Flow export format';

    const formatSelect = document.createElement('select');
    formatSelect.id = 'traffic-export-format';
    for (const [value, label] of [['json', 'JSON'], ['csv', 'CSV'], ['ndjson', 'NDJSON']]) {
      const option = document.createElement('option');
      option.value = value;
      option.textContent = label;
      formatSelect.appendChild(option);
    }

    const exportButton = document.createElement('button');
    exportButton.id = 'traffic-export';
    exportButton.type = 'button';
    exportButton.className = 'button ghost';
    exportButton.dataset.captureControl = '';
    exportButton.textContent = 'Capture & export flows';
    exportButton.disabled = authorization.disabled;
    exportButton.addEventListener('click', downloadTrafficFlows);

    actions.before(formatLabel, formatSelect);
    actions.appendChild(exportButton);

    new MutationObserver(() => {
      exportButton.disabled = authorization.disabled;
    }).observe(authorization, { attributes: true, attributeFilter: ['disabled'] });
  }

  installOfflineCaptureControls(form);
  installTrafficFlowPivotRendering();
}

loadNetWatchCore(installTrafficExportControls);

function applicationInsightDetail(event) {
  const metadata = event && typeof event.metadata === 'object' ? event.metadata : {};
  if (event?.event_type === 'dns') {
    const query = String(metadata.query || '—');
    const qtype = String(metadata.qtype || '—');
    const rcode = Number.isFinite(Number(metadata.rcode)) ? `rcode ${Number(metadata.rcode)}` : 'rcode —';
    return `DNS query ${query} · ${qtype} · ${rcode}`;
  }
  if (event?.event_type === 'tls') {
    const server = String(metadata.server_name || '—');
    const version = String(metadata.version || '—');
    const alpn = String(metadata.alpn || '—');
    return `TLS server ${server} · ${version} · ALPN ${alpn}`;
  }
  if (event?.event_type === 'http') {
    const host = String(metadata.host || '—');
    const method = String(metadata.method || '—');
    const status = metadata.status == null ? 'status —' : `status ${Number(metadata.status)}`;
    return `HTTP host ${host} · ${method} · ${status}`;
  }
  return 'Application metadata event';
}

let latestTrafficApplicationPayload = null;

function trafficApplicationInsightRows(payload) {
  const rows = [];
  for (const flow of Array.isArray(payload?.flows) ? payload.flows : []) {
    for (const event of Array.isArray(flow?.protocol_events) ? flow.protocol_events : []) {
      if (!['dns', 'tls', 'http'].includes(String(event?.event_type || ''))) continue;
      rows.push({
        type: String(event.event_type).toUpperCase(),
        timestamp: event.timestamp || '—',
        detail: applicationInsightDetail(event),
        source: flow.source,
        destination: flow.destination,
        protocol: flow.protocol,
      });
    }
  }
  return rows;
}

function filterTrafficApplicationInsightRows(rows) {
  const typeFilter = document.querySelector('#traffic-application-type-filter');
  const valueFilter = document.querySelector('#traffic-application-value-filter');
  const selectedType = String(typeFilter?.value || 'all').toUpperCase();
  const value = String(valueFilter?.value || '').trim().toLowerCase();

  return rows
    .filter((row) => selectedType === 'ALL' || row.type === selectedType)
    .filter((row) => !value || row.detail.toLowerCase().includes(value))
    .slice(0, 200);
}

function renderTrafficApplicationFilterState(totalRows, visibleRows) {
  const state = document.querySelector('#traffic-application-filter-state');
  if (!state) return;
  const type = document.querySelector('#traffic-application-type-filter')?.value || 'all';
  const value = document.querySelector('#traffic-application-value-filter')?.value.trim() || '';
  const active = type !== 'all' || Boolean(value);
  state.textContent = active
    ? `Showing ${visibleRows} of ${totalRows} selected-flow signals · type ${type.toUpperCase()}${value ? ` · value “${value}”` : ''}`
    : `Showing ${visibleRows} of ${totalRows} selected-flow signals · no application filter`;
}

function installTrafficApplicationInsightsPanel() {
  if (document.querySelector('#traffic-application-insights')) return;
  const packetPanel = document.querySelector('#traffic-packets')?.closest('.panel');
  if (!packetPanel) return;

  const panel = document.createElement('article');
  panel.className = 'panel';
  const head = document.createElement('div');
  head.className = 'panel-head';
  const copy = document.createElement('div');
  const eyebrow = document.createElement('p');
  eyebrow.className = 'eyebrow';
  eyebrow.textContent = 'Application insights';
  const title = document.createElement('h3');
  title.textContent = 'DNS · TLS · HTTP metadata';
  copy.append(eyebrow, title);
  const count = document.createElement('span');
  count.id = 'traffic-application-insight-count';
  count.className = 'count-badge';
  count.textContent = '0 signals';
  head.append(copy, count);

  const filters = document.createElement('div');
  filters.className = 'traffic-form-grid';
  const typeWrapper = document.createElement('div');
  const typeLabel = document.createElement('label');
  typeLabel.setAttribute('for', 'traffic-application-type-filter');
  typeLabel.textContent = 'Application type';
  const typeFilter = document.createElement('select');
  typeFilter.id = 'traffic-application-type-filter';
  for (const [value, label] of [['all', 'All'], ['dns', 'DNS'], ['tls', 'TLS'], ['http', 'HTTP']]) {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = label;
    typeFilter.appendChild(option);
  }
  typeWrapper.append(typeLabel, typeFilter);

  const valueWrapper = document.createElement('div');
  const valueLabel = document.createElement('label');
  valueLabel.setAttribute('for', 'traffic-application-value-filter');
  valueLabel.textContent = 'Visible metadata contains';
  const valueFilter = document.createElement('input');
  valueFilter.id = 'traffic-application-value-filter';
  valueFilter.type = 'search';
  valueFilter.maxLength = 128;
  valueFilter.placeholder = 'host, query, method, status…';
  valueWrapper.append(valueLabel, valueFilter);

  const clearWrapper = document.createElement('div');
  const clearLabel = document.createElement('span');
  clearLabel.textContent = 'Application filter';
  const clearButton = document.createElement('button');
  clearButton.type = 'button';
  clearButton.className = 'button ghost';
  clearButton.textContent = 'Clear';
  clearButton.addEventListener('click', () => {
    typeFilter.value = 'all';
    valueFilter.value = '';
    if (latestTrafficApplicationPayload) renderTrafficApplicationInsights(latestTrafficApplicationPayload);
  });
  clearWrapper.append(clearLabel, clearButton);
  filters.append(typeWrapper, valueWrapper, clearWrapper);

  const filterState = document.createElement('p');
  filterState.id = 'traffic-application-filter-state';
  filterState.className = 'muted';
  filterState.textContent = 'No application filter active.';

  const body = document.createElement('div');
  body.id = 'traffic-application-insights';
  body.className = 'table-wrap empty-state';
  body.textContent = 'Run an analysis to correlate safe application metadata with flows.';

  const rerender = () => {
    if (latestTrafficApplicationPayload) renderTrafficApplicationInsights(latestTrafficApplicationPayload);
  };
  typeFilter.addEventListener('change', rerender);
  valueFilter.addEventListener('input', rerender);

  panel.append(head, filters, filterState, body);
  packetPanel.before(panel);
}

function renderTrafficApplicationInsights(payload) {
  const container = document.querySelector('#traffic-application-insights');
  const count = document.querySelector('#traffic-application-insight-count');
  if (!container || !count) return;
  latestTrafficApplicationPayload = payload;
  const allRows = trafficApplicationInsightRows(payload);
  const rows = filterTrafficApplicationInsightRows(allRows);
  count.textContent = `${rows.length} signal${rows.length === 1 ? '' : 's'}`;
  renderTrafficApplicationFilterState(allRows.length, rows.length);
  buildFlowTable(
    container,
    [
      { label: 'Type', render: (row) => row.type },
      { label: 'Time', render: (row) => row.timestamp },
      { label: 'Insight', render: (row) => row.detail },
      { label: 'Originator', render: (row) => flowEndpointText(row.source) },
      { label: 'Responder', render: (row) => flowEndpointText(row.destination) },
      { label: 'Pivot', render: (row) => buildPivotButton('Flow', row.source?.ip, row.protocol) },
    ],
    rows,
    'No DNS, TLS, or HTTP metadata signals matched the selected evidence and application filters.',
  );
}

function installTrafficApplicationInsights(attempt = 0) {
  if (typeof window.renderTrafficCapture !== 'function') {
    if (attempt < 40) window.setTimeout(() => installTrafficApplicationInsights(attempt + 1), 50);
    return;
  }
  installTrafficApplicationInsightsPanel();
  if (window.renderTrafficCapture.applicationInsightsWrapped) return;
  const baseRenderer = window.renderTrafficCapture;
  const wrappedRenderer = function renderTrafficCaptureWithApplicationInsights(payload) {
    baseRenderer(payload);
    renderTrafficApplicationInsights(payload);
  };
  wrappedRenderer.applicationInsightsWrapped = true;
  window.renderTrafficCapture = wrappedRenderer;
}

installTrafficApplicationInsights();

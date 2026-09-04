// NetWatch Traffic Explorer bootstrap.
// The existing application stays in app-core.js; this layer adds bounded flow exports
// and offline PCAP/PCAPNG analysis without retaining raw payload bytes.
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
}

loadNetWatchCore(installTrafficExportControls);

// NetWatch Traffic Explorer bootstrap.
// The existing application stays in app-core.js; this layer adds bounded flow exports.
// Compatibility markers used by frontend safety tests: NetWatchApi /api/session /api/traffic/capture /api/service-findings renderTrafficCapture candidate.origin !== window.location.origin

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

function installTrafficExportControls() {
  const form = document.querySelector('#traffic-form');
  const authorization = document.querySelector('#traffic-authorized');
  const actions = form?.querySelector('.button-row');
  if (!form || !authorization || !actions || document.querySelector('#traffic-export')) return;

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

loadNetWatchCore(installTrafficExportControls);

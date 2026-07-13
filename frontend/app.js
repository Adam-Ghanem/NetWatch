const API_BASE = window.NETWATCH_API_BASE || 'http://127.0.0.1:8000';
const statusElement = document.querySelector('[data-api-status]');

function setStatus(status, message){
  if (!statusElement) return;
  statusElement.textContent = status;
  statusElement.dataset.state = status.toLowerCase();
  statusElement.title = message;
}

async function checkApi(){
  try{
    const res = await fetch(`${API_BASE}/api/health`);
    if (!res.ok) throw new Error(`API returned HTTP ${res.status}`);
    const data = await res.json();
    setStatus('ONLINE', `${data.app} ${data.version}`);
    console.log('NetWatch API:', data);
  }catch(error){
    setStatus('OFFLINE', 'Start the local FastAPI service on port 8000.');
    console.warn('API is not running yet:', error);
  }
}

checkApi();

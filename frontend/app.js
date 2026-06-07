const API_BASE = 'http://127.0.0.1:8000';

async function checkApi(){
  try{
    const res = await fetch(`${API_BASE}/api/health`);
    const data = await res.json();
    console.log('NetWatch API:', data);
  }catch(error){
    console.warn('API is not running yet:', error);
  }
}

checkApi();

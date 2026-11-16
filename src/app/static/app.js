'use strict';
const $ = (id) => document.getElementById(id);
let hosts = [], detected = [], statuses = new Map(), sessions = [];
let selectedHost = null, editingHostId = null, terminalSocket = null;
let refreshHandle = null, toastHandle = null;

function notice(message, failed = false) {
  const node = $('notice'); node.textContent = message;
  node.className = 'notice' + (failed ? ' error' : ''); node.hidden = false;
  clearTimeout(toastHandle); toastHandle = setTimeout(() => { node.hidden = true; }, 6500);
}
async function api(path, options = {}) {
  const method = options.method || 'GET';
  const config = { credentials: 'same-origin', ...options, headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) } };
  if (method !== 'GET') config.headers['X-ZeoDev-Request'] = '1';
  let response;
  try { response = await fetch(path, config); }
  catch { throw new Error('Brak połączenia z panelem. Sprawdź sieć i Umbrel.'); }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401) showLogin();
    throw new Error(data.error || `Błąd serwera (${response.status})`);
  }
  return data;
}
function showLogin() {
  $('setup-screen').hidden = true; $('app-shell').hidden = true; $('login-screen').hidden = false;
  if (refreshHandle) clearInterval(refreshHandle);
  if (terminalSocket) terminalSocket.close();
}
function showSetup() {
  $('app-shell').hidden = true;
  $('login-screen').hidden = true;
  $('setup-screen').hidden = false;
  if (refreshHandle) clearInterval(refreshHandle);
}
function showApp() {
  $('setup-screen').hidden = true; $('login-screen').hidden = true; $('app-shell').hidden = false;
  if (refreshHandle) clearInterval(refreshHandle);
  refreshHandle = setInterval(() => refreshAll().catch(e => notice(e.message, true)), 25000);
  switchPage('devices');
}
function switchPage(id) {
  document.querySelectorAll('[data-page]').forEach(node => { node.hidden = node.dataset.page !== id; });
  document.querySelectorAll('[data-view]').forEach(node => node.classList.toggle('active', node.dataset.view === id));
  $('breadcrumb').textContent = ({ devices:'Urządzenia', discovery:'Wykryte SSH', settings:'Ustawienia' })[id];
}
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function pill(ok, yes = 'SSH dostępne', no = 'Niedostępne') {
  return el('span', `pill ${ok ? 'good' : 'bad'}`, ok ? yes : no);
}
function empty(title, caption) {
  const wrap = el('div','empty-state');
  wrap.append(el('div','empty-symbol','⌁'), el('strong','',title),el('p','',caption));
  return wrap;
}
function button(label, style, action) {
  const b = el('button', `btn ${style} small`, label); b.type='button'; b.addEventListener('click', action);return b;
}
function renderHosts() {
  $('stat-hosts').textContent = String(hosts.length);
  $('stat-online').textContent = String(hosts.filter(h => statuses.get(h.id) === true).length);
  $('stat-sessions').textContent = String(sessions.length);
  const container = $('host-list'); container.replaceChildren();
  if (!hosts.length) { container.append(empty('Nie masz jeszcze żadnego urządzenia', 'Wybierz „Dodaj SSH” lub znajdź serwer automatycznie w zakładce Wykryte SSH.')); return; }
  for (const h of hosts) {
    const row = el('div','device');
    const info = el('div','device-body');
    info.append(el('div','device-title',h.name),el('div','device-sub',`${h.username}@${h.address}:${h.port}`));
    const tags = el('div','device-badges');
    const status = statuses.get(h.id);
    tags.append(status === undefined ? el('span','pill','Sprawdzanie…') : pill(status));
    const active = sessions.filter(s => s.hostId === h.id).length;
    if (active) tags.append(el('span','pill good',`${active} ${active === 1 ? 'sesja' : 'sesje'}`));
    const actions = el('div','device-actions');
    actions.append(button('Połącz', 'secondary', () => openTerminal(h)), button('Edytuj', 'ghost', () => openHostForm(h)), button('Usuń', 'ghost', () => deleteHost(h)));
    row.append(el('div','device-icon','▣'), info,tags,actions); container.append(row);
  }
  const area = $('sessions-list');area.replaceChildren();
  if (!sessions.length) { area.textContent = 'Brak aktywnych sesji SSH.';return; }
  for (const s of sessions) {
    const row = el('div','session-row');
    row.append(el('span','',`${s.name} · aktywne`),el('span','',`Od ${new Date(s.startedAt * 1000).toLocaleTimeString('pl-PL')}`)); area.append(row);
  }
}
function renderDiscovery() {
  const container = $('discovered-list');container.replaceChildren();
  $('discovery-count').textContent = String(detected.filter(d => d.reachable).length);
  if (!detected.length) {container.append(empty('Nic jeszcze nie wykryto','Sprawdź ustawienia sieci oraz czy serwery SSH mają włączoną usługę na porcie 22.'));return;}
  for (const d of detected) {
    const matchingHost = hosts.find(h => h.address === d.address && h.port === 22);
    const row = el('div','device');
    const info = el('div','device-body');
    info.append(el('div','device-title',d.address),el('div','device-sub', d.banner || 'Ostatnio widziano: '+new Date(d.lastSeen*1000).toLocaleString('pl-PL')));
    const tags = el('div','device-badges');tags.append(pill(d.reachable, 'SSH dostępne', 'Nie wykryto teraz'));
    const actions = el('div','device-actions');
    if (matchingHost) actions.append(el('span','pill good','Zapisano'));
    else actions.append(button('Dodaj SSH','secondary',()=>openHostForm(null,d.address)));
    row.append(el('div','device-icon','⌘'),info,tags,actions);container.append(row);
  }
}
async function refreshAll() {
  const [h,d,s] = await Promise.all([api('/api/hosts'),api('/api/discovery'),api('/api/status')]);
  hosts = h.hosts; detected = d.devices;
  statuses = new Map(s.hosts.map(x => [x.id,x.reachable]));sessions = s.sessions;
  renderHosts(); renderDiscovery();
  $('scan-cidrs').value = d.settings.cidrs;
  $('last-scan').textContent = d.scanning ? 'Skanowanie w toku…' : d.settings.lastScan ? `Ostatni skan: ${new Date(d.settings.lastScan*1000).toLocaleString('pl-PL')}` : 'Brak wykonanego skanu';
  $('scan-btn').disabled = Boolean(d.scanning);
  $('scan-btn').textContent = d.scanning ? 'Skanowanie…' : '◎ Skanuj sieć';
}
function openHostForm(host = null, ip = '') {
  editingHostId = host?.id || null;
  $('host-dialog-title').textContent = host ? 'Edytuj urządzenie' : 'Dodaj urządzenie';
  $('host-name').value = host?.name || '';
  $('host-address').value = host?.address || ip;
  $('host-port').value = String(host?.port || 22);
  $('host-user').value = host?.username || '';
  $('host-dialog').showModal();
  if (ip) $('host-name').focus();
}
async function saveHost(event) {
  event.preventDefault();
  const body = {name:$('host-name').value.trim(), address:$('host-address').value.trim(),port:Number($('host-port').value),username:$('host-user').value.trim()};
  try {
    await api(editingHostId ? `/api/hosts/${editingHostId}` : '/api/hosts', {method:editingHostId ? 'PUT' : 'POST',body:JSON.stringify(body)});
    $('host-dialog').close();notice('Urządzenie zapisane.');await refreshAll();
  } catch(e) {notice(e.message,true);}
}
async function deleteHost(host) {
  if (!confirm(`Usunąć „${host.name}” z listy urządzeń?`))return;
  try {await api(`/api/hosts/${host.id}`,{method:'DELETE'});notice('Usunięto urządzenie.');await refreshAll();}
  catch(e) {notice(e.message,true);}
}
async function scanNow() {
  $('scan-btn').disabled = true;$('scan-btn').textContent = 'Skanowanie…';
  try {
    const result = await api('/api/discovery/scan',{method:'POST'});
    if (result.message) notice(result.message);
    else notice(result.running ? 'Skanowanie już trwa.' : `Skan zakończony: znaleziono ${result.found} serwerów SSH.`);
    await refreshAll();
  } catch(e) {notice(e.message,true);}
  finally {$('scan-btn').disabled=false;$('scan-btn').textContent='◎ Skanuj sieć';}
}
function clearTerminalCredentials() {
  $('ssh-password').value=''; $('ssh-private-key').value=''; $('ssh-passphrase').value='';
}
function openTerminal(host) {
  selectedHost = host; clearTerminalCredentials();
  $('terminal-title').textContent = host.name;
  $('terminal-auth').hidden = false;$('terminal-workspace').hidden = true;
  $('terminal-output').textContent = '';
  $('terminal-dialog').showModal();
}
function appendTerminal(text) {
  // Minimal text console for bootstrap releases; full ANSI terminal emulator comes later.
  const output = $('terminal-output');
  const filtered = text.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'').replace(/\x1b\][^\x07]*(\x07|\x1b\\)/g,'');
  output.textContent = (output.textContent + filtered).slice(-120000);
  output.scrollTop = output.scrollHeight;
}
function connectTerminal() {
  if (!selectedHost || terminalSocket && terminalSocket.readyState === WebSocket.OPEN) return;
  const authType = $('ssh-auth-type').value;
  const credentials = {hostId:selectedHost.id, authType,password:$('ssh-password').value,privateKey:$('ssh-private-key').value,passphrase:$('ssh-passphrase').value};
  if (authType === 'password' && !credentials.password) return notice('Wpisz hasło SSH.',true);
  if (authType === 'privateKey' && !credentials.privateKey) return notice('Wklej klucz prywatny.',true);
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${scheme}//${location.host}/ws/terminal`);terminalSocket=ws;
  $('terminal-auth').hidden=true;$('terminal-workspace').hidden=false;
  $('terminal-connection-status').textContent='Nawiązywanie połączenia…';
  ws.binaryType='arraybuffer';
  ws.onopen=()=>{ws.send(JSON.stringify(credentials));clearTerminalCredentials();};
  const decoder=new TextDecoder();
  ws.onmessage=async event=>{
    if (typeof event.data !== 'string') {appendTerminal(decoder.decode(event.data,{stream:true}));return;}
    let msg;
    try {msg=JSON.parse(event.data);}catch{return;}
    if (msg.type==='trust_required') {
      const approved=confirm(`NOWY KLUCZ HOSTA\n\n${selectedHost.name}\n${msg.fingerprint}\n\nPorównaj fingerprint z kluczem pokazanym bezpośrednio na serwerze. Czy potwierdzasz, że jest poprawny?`);
      ws.send(JSON.stringify({type:approved?'trust':'cancel',fingerprint:msg.fingerprint}));
    } else if (msg.type==='connected') {
      $('terminal-connection-status').textContent='● Połączono przez SSH';$('terminal-input').focus();refreshAll().catch(()=>{});
    } else if (msg.type==='error') {
      appendTerminal(`\n[Błąd] ${msg.message}\n`);$('terminal-connection-status').textContent='Błąd połączenia';notice(msg.message,true);
    }
  };
  ws.onerror=()=>{$('terminal-connection-status').textContent='Błąd komunikacji WebSocket';};
  ws.onclose=()=>{$('terminal-connection-status').textContent='● Rozłączono';appendTerminal('\n[Połączenie zamknięte]\n');refreshAll().catch(()=>{});};
}
function closeTerminal() {if (terminalSocket) {terminalSocket.close();terminalSocket=null;} clearTerminalCredentials();}
async function init() {
  document.querySelectorAll('[data-view]').forEach(b=>b.addEventListener('click',()=>switchPage(b.dataset.view)));
  document.querySelectorAll('[data-close]').forEach(b=>b.addEventListener('click',()=>$(b.dataset.close).close()));
  $('terminal-dialog').addEventListener('close',closeTerminal);
  $('add-host-btn').addEventListener('click',()=>openHostForm());$('host-form').addEventListener('submit',saveHost);
  $('scan-btn').addEventListener('click',scanNow);
  $('refresh-btn').addEventListener('click',()=>refreshAll().catch(e=>notice(e.message,true)));
  $('logout-btn').addEventListener('click',async()=>{try{await api('/api/logout',{method:'POST'});}catch{}showLogin();});
  $('setup-form').addEventListener('submit',async e=>{e.preventDefault();const pwd=$('setup-password').value;if(pwd!==$('setup-password-confirm').value) return notice('Hasła nie są identyczne.',true);try{await api('/api/initialize',{method:'POST',body:JSON.stringify({password:pwd})});$('setup-form').reset();showApp();await refreshAll();}catch(err){notice(err.message,true);}});
  $('login-form').addEventListener('submit',async e=>{e.preventDefault();try{await api('/api/login',{method:'POST',body:JSON.stringify({password:$('login-password').value})});$('login-password').value='';showApp();await refreshAll();}catch(err){notice(err.message,true);}});
  $('network-form').addEventListener('submit',async e=>{e.preventDefault();try{await api('/api/discovery/settings',{method:'PUT',body:JSON.stringify({cidrs:$('scan-cidrs').value})});notice('Zakres sieci zapisany. Rozpocznij nowe skanowanie.');await refreshAll();}catch(err){notice(err.message,true);}});
  $('password-form').addEventListener('submit',async e=>{e.preventDefault();try{await api('/api/change-password',{method:'POST',body:JSON.stringify({currentPassword:$('current-password').value,newPassword:$('new-password').value})});$('password-form').reset();notice('Hasło administratora zmienione.');}catch(err){notice(err.message,true);}});
  $('ssh-auth-type').addEventListener('change',()=>{$('password-auth').hidden=$('ssh-auth-type').value!=='password';$('key-auth').hidden=$('ssh-auth-type').value!=='privateKey';});
  $('terminal-connect-btn').addEventListener('click',connectTerminal);
  $('terminal-input').addEventListener('keydown',event=>{
    if(!terminalSocket || terminalSocket.readyState!==WebSocket.OPEN)return;
    if(event.key==='Enter') {event.preventDefault();terminalSocket.send(new TextEncoder().encode($('terminal-input').value+'\r'));$('terminal-input').value='';}
    else if(event.key==='c' && event.ctrlKey){event.preventDefault();terminalSocket.send(new Uint8Array([3]));}
  });
  $('terminal-ctrl-c').addEventListener('click',()=>{if(terminalSocket?.readyState===WebSocket.OPEN) terminalSocket.send(new Uint8Array([3]));});
  try {
    const state=await api('/api/setup');
    if (state.authenticated) {showApp();await refreshAll();}
    else if (state.needsSetup) showSetup();
    else showLogin();
  } catch(error) {showLogin();notice(error.message,true);}
}
window.addEventListener('DOMContentLoaded',init);

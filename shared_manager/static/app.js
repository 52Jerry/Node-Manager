'use strict';
const $ = (id) => document.getElementById(id);
const labels = {vless:'VLESS',vmess:'VMess',socks:'SOCKS5'};
const pageLabels = {connections:'我的连接',import:'批量导入',subscription:'账号订阅',admin:'用户管理'};
let account = null, csrf = '', epoch = 0, selectionEpoch = 0, site = null;
let profiles = [], selectedId = null, connectionData = null, upstream = null;
let listSequence = 0, authMode = 'login', createMode = 'create', renameTarget = null;
let createRequest = null, createBusy = false, selectedBusy = false;
let importRequest = null, importPreview = null, importBusy = false, subscriptionBusy = false;
let quotaBusy = false, quotaDirty = false;
let renameBusy = false, manageLauncher = null;
let adminSequence = 0, adminPage = 1, adminTotalPages = 1, adminSearch = '', adminBusy = false;
let authBusy = false;
const GiB = 1024 ** 3;

function clearAuthErrors(field = null) {
  for (const id of field ? [field] : ['username','password','confirm-password']) {
    $(id).setAttribute('aria-invalid','false');
    $(id + '-error').textContent = ''; $(id + '-error').hidden = true;
  }
  $('auth-error').textContent = ''; $('auth-error').hidden = true;
}
function authFieldError(id, message) {
  $(id).setAttribute('aria-invalid','true');
  $(id + '-error').textContent = message; $(id + '-error').hidden = false;
}
function authError(message) {
  $('auth-error').textContent = message; $('auth-error').hidden = !message;
}
function focusAuthField(id) {
  $(id).focus();
  $(id).scrollIntoView?.({block:'center',behavior:'smooth'});
}
function setAuthBusy(value) {
  authBusy = value;
  $('auth-form').setAttribute('aria-busy',String(value));
  for (const id of ['auth-submit','login-tab','register-tab','switch-register']) $(id).disabled = value;
  for (const id of ['username','password','confirm-password']) $(id).readOnly = value;
}
function validateAuth() {
  clearAuthErrors();
  const username = $('username').value.trim();
  $('username').value = username;
  let firstInvalid = null;
  const invalid = (id,message) => { authFieldError(id,message); firstInvalid ||= id; };
  if (!username) invalid('username','请输入账号。');
  if (!$('password').value) invalid('password','请输入密码。');
  if (authMode === 'register') {
    if (!$('confirm-password').value) invalid('confirm-password','请再次输入密码。');
    else if ($('password').value !== $('confirm-password').value) invalid('confirm-password','两次输入的密码不一致。');
  }
  if (firstInvalid) { focusAuthField(firstInvalid); return false; }
  return true;
}
function notify(message = '', error = false) {
  $('notice').textContent = message;
  $('notice').className = 'notice' + (error ? ' error' : '');
  $('notice').hidden = !message;
  if ($('manage-dialog').open) {
    $('manage-notice').textContent = message;
    $('manage-notice').className = 'notice' + (error ? ' error' : '');
    $('manage-notice').hidden = !message;
  }
}
function active(version) { return !!account && epoch === version; }
function selectedActive(version, sequence, id) { return active(version) && selectionEpoch === sequence && selectedId === id; }
function humanBytes(value) {
  if (!Number.isFinite(Number(value))) return '—';
  const number = Math.max(0, Number(value));
  if (number < 1024) return Math.round(number) + ' B';
  const units = ['KiB','MiB','GiB','TiB'];
  let amount = number / 1024, index = 0;
  while (amount >= 1024 && index < units.length - 1) { amount /= 1024; index++; }
  return amount.toLocaleString('zh-CN',{maximumFractionDigits:2}) + ' ' + units[index];
}
function dateLabel(value) {
  const date = value ? new Date(value) : null;
  return date && Number.isFinite(date.getTime()) ? date.toLocaleDateString('zh-CN') : '—';
}
function quotaBytes(value) {
  const amount = Number(value);
  const bytes = Math.round(amount * GiB);
  if (!String(value).trim() || !Number.isFinite(amount) || amount <= 0 || !Number.isSafeInteger(bytes) || bytes <= 0) throw new Error('请输入有效的正数流量额度，可使用小数。');
  return bytes;
}
function showQuota(bytes, populate = true) {
  $('traffic-limit').textContent = '当前连接额度 ' + humanBytes(bytes);
  if (populate) $('quota-limit').value = String(Number(bytes) / GiB);
  $('quota-fields').disabled = !connectionData || quotaBusy;
}
function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function actionButton(text, action, id) {
  const node = element('button',text,'text-button');
  node.type = 'button'; node.dataset.profileAction = action; node.dataset.profileId = id;
  return node;
}
function clearDetail() {
  if ($('connection-dialog').open) $('connection-dialog').close();
  $('detail-link').value = ''; $('detail-socks-password').value = '';
  for (const id of ['detail-socks-host','detail-socks-port','detail-socks-user']) $(id).textContent = '—';
  $('detail-socks-password').type = 'password'; $('toggle-socks-password').textContent = '显示';
}
function clearSelected() {
  selectionEpoch++;
  connectionData = null; upstream = null;
  clearDetail();
  $('connection-panel').hidden = true;
  $('connections-pending').hidden = true;
  $('traffic-used').textContent = '—'; $('traffic-limit').textContent = '当前连接额度待查询';
  $('expiry').textContent = '—'; $('current-egress').textContent = '—'; $('egress-summary').textContent = '';
  $('upstream-form').reset(); $('upstream-password').value = ''; $('upstream-password').type = 'password';
  $('upstream-fields').disabled = true; $('restore-direct').disabled = true;
  $('upstream-password-note').hidden = true; configureAuth();
  quotaBusy = false; quotaDirty = false; $('quota-limit').value = ''; $('quota-fields').disabled = true;
  renameBusy = false; $('manage-name').value = ''; $('manage-name').disabled = true;
  $('rename-profile').disabled = true; $('manage-loading').hidden = true;
}
function clearManager() {
  const previousId = selectedId;
  selectedId = null;
  clearSelected();
  $('selected-panel').hidden = true;
  $('manage-notice').textContent = ''; $('manage-notice').hidden = true;
  renderProfiles();
  const replacement = [...document.querySelectorAll('#profiles-body [data-profile-id]')]
    .find((button) => button.dataset.profileId === previousId && button.dataset.profileAction === 'select');
  const launcher = manageLauncher?.isConnected ? manageLauncher : replacement || $('create-profile');
  manageLauncher = null;
  if (account) launcher.focus();
}
function closeManager() {
  clearDetail();
  if ($('manage-dialog').open) $('manage-dialog').close();
  else clearManager();
}
async function openManager(id, launcher = null) {
  if (!account || !profiles.some((item) => item.id === id)) return;
  manageLauncher = launcher;
  notify();
  if (!$('manage-dialog').open) $('manage-dialog').showModal();
  const loading = selectProfile(id);
  ($('manage-name').disabled ? $('close-manage-dialog') : $('manage-name')).focus();
  await loading;
}
function clearImport() {
  $('import-text').value = ''; $('import-file').value = '';
  $('import-preview-panel').hidden = true; $('import-results-body').replaceChildren();
  importRequest = null; importPreview = null; $('run-import').disabled = true;
}
function setAdminBusy(value) {
  adminBusy = value;
  for (const id of ['admin-refresh','admin-search-submit','admin-search-clear']) $(id).disabled = value;
  $('admin-search').readOnly = value;
  $('admin-prev').disabled = value || adminPage <= 1;
  $('admin-next').disabled = value || adminPage >= adminTotalPages;
  $('admin-users-table').setAttribute('aria-busy',String(value));
  $('admin-loading').hidden = !value;
}
function clearAdmin() {
  adminSequence++; adminPage = 1; adminTotalPages = 1; adminSearch = '';
  $('admin-nav').hidden = true; $('admin-page').hidden = true;
  $('admin-users-body').replaceChildren(); $('admin-search').value = '';
  for (const id of ['admin-registered-users','admin-enabled-users','admin-total-connections','admin-ready-connections','admin-pending-connections','admin-deleting-connections','admin-user-total','admin-page-info']) $(id).textContent = '—';
  $('admin-empty').hidden = true; $('admin-error').hidden = true; $('admin-error').textContent = '';
  setAdminBusy(false);
}
function renderAdmin(result) {
  const summary = result.summary;
  $('admin-registered-users').textContent = String(summary.registeredUsers);
  $('admin-enabled-users').textContent = summary.enabledUsers + ' 个账号可用';
  $('admin-total-connections').textContent = String(summary.totalConnections);
  $('admin-ready-connections').textContent = String(summary.readyConnections);
  $('admin-pending-connections').textContent = String(summary.pendingConnections);
  $('admin-deleting-connections').textContent = summary.deletingConnections + ' 条删除待确认';
  $('admin-users-body').replaceChildren();
  for (const user of result.items || []) {
    const row = document.createElement('tr');
    const name = document.createElement('td'); name.append(element('strong',user.username,'admin-username'));
    if (user.isAdmin) name.append(element('span','管理员','badge admin-role'));
    const status = document.createElement('td'); status.append(element('span',user.enabled ? '可用' : '已停用','badge ' + (user.enabled ? 'green' : 'neutral')));
    row.append(name,element('td',dateLabel(user.createdAt)),status,
      element('td',String(user.totalConnections),'admin-count'),element('td',String(user.readyConnections),'admin-count ready'),
      element('td',String(user.pendingConnections),'admin-count'),element('td',String(user.deletingConnections),'admin-count'));
    $('admin-users-body').append(row);
  }
  adminPage = result.page; adminTotalPages = Math.max(1,result.totalPages);
  $('admin-user-total').textContent = adminSearch ? '匹配 ' + result.total + ' 个用户' : result.total + ' 个用户';
  $('admin-page-info').textContent = '第 ' + adminPage + ' / ' + adminTotalPages + ' 页 · 共 ' + result.total + ' 个用户';
  $('admin-empty').hidden = (result.items || []).length !== 0;
}
async function loadAdmin(page = adminPage) {
  if (!account?.isAdmin || $('admin-page').hidden) return;
  const version = epoch, sequence = ++adminSequence;
  setAdminBusy(true); $('admin-error').hidden = true; $('admin-error').textContent = '';
  try {
    const query = new URLSearchParams({search:adminSearch,page:String(page),pageSize:'20'});
    const result = await api('/api/admin/users?' + query);
    if (!active(version) || sequence !== adminSequence || !account.isAdmin || $('admin-page').hidden) return;
    renderAdmin(result);
  } catch (error) {
    if (!active(version) || sequence !== adminSequence) return;
    if (error.status === 403) {
      account.isAdmin = false; clearAdmin(); setPage('connections'); notify('当前账号没有管理员权限。',true);
      return;
    }
    $('admin-error').textContent = error.message; $('admin-error').hidden = false;
  } finally { if (active(version) && sequence === adminSequence) setAdminBusy(false); }
}
function showGuest() {
  epoch++; listSequence++;
  account = null; csrf = ''; profiles = []; selectedId = null;
  createRequest = null; createBusy = false; selectedBusy = false; subscriptionBusy = false; importBusy = false;
  clearSelected(); clearImport(); clearAdmin(); clearAuthErrors(); setAuthBusy(false);
  closeManager();
  if ($('profile-dialog').open) $('profile-dialog').close();
  $('profiles-body').replaceChildren(); $('profile-name').value = '';
  $('subscription-url').value = ''; $('copy-subscription').disabled = true; $('rotate-subscription').disabled = true;
  $('auth-view').hidden = false; $('dashboard-view').hidden = true; $('panel-nav').hidden = true;
  $('guest-sidebar').hidden = false; $('account-menu').hidden = true; $('guest-label').hidden = false;
  $('selected-panel').hidden = true; $('page-label').textContent = '账号登录';
  $('auth-form').reset(); $('auth-submit').disabled = false;
}
async function api(path, method = 'GET', body) {
  const requestEpoch = epoch;
  const headers = {Accept:'application/json'};
  if (method !== 'GET') { headers['Content-Type'] = 'application/json'; if (csrf) headers['X-CSRF-Token'] = csrf; }
  let response;
  try { response = await fetch(path,{method,headers,credentials:'same-origin',cache:'no-store',body:method === 'GET' ? undefined : JSON.stringify(body ?? {})}); }
  catch { const error = new Error('网络连接暂时中断，请按原操作重试。'); error.status = 0; throw error; }
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && account && epoch === requestEpoch) showGuest();
    const error = new Error(typeof result.detail === 'string' ? result.detail : '暂时无法完成，请检查输入后重试。');
    error.status = response.status;
    if (['username','password'].includes(result.field)) error.field = result.field;
    throw error;
  }
  return result;
}
function profilePath(id, suffix = '') { return '/api/me/profiles/' + encodeURIComponent(id) + suffix; }
function currentProfile() { return profiles.find((item) => item.id === selectedId); }
function setPage(page, updateHash = true) {
  const selected = Object.hasOwn(pageLabels,page) && (page !== 'admin' || account?.isAdmin) ? page : 'connections';
  if (selected !== 'connections' && $('manage-dialog').open) closeManager();
  if (selected !== 'admin' && !$('admin-page').hidden) { adminSequence++; setAdminBusy(false); }
  for (const name of Object.keys(pageLabels)) $(name + '-page').hidden = name !== selected;
  for (const button of document.querySelectorAll('#panel-nav [data-page]')) button.classList.toggle('active',button.dataset.page === selected);
  $('page-label').textContent = pageLabels[selected];
  if ((updateHash || page === 'admin' && selected !== 'admin') && location.hash !== '#' + selected) history.replaceState(null,'','#' + selected);
  if (selected === 'subscription' && account) void loadSubscription(false);
  if (selected === 'admin') void loadAdmin();
}
function showSession(data) {
  epoch++; account = data.user; csrf = data.csrfToken;
  profiles = []; selectedId = null; clearSelected(); clearAdmin();
  $('admin-nav').hidden = !account.isAdmin;
  $('account-name').textContent = account.username;
  $('account-avatar').textContent = [...account.username][0]?.toUpperCase() || 'U';
  $('account-menu').hidden = false; $('guest-label').hidden = true; $('guest-sidebar').hidden = true;
  $('panel-nav').hidden = false; $('auth-view').hidden = true; $('dashboard-view').hidden = false;
  $('auth-form').reset(); clearAuthErrors(); setAuthBusy(false); setPage(location.hash.slice(1));
}
function switchAuthMode(next) {
  if (authBusy) return;
  if (next === 'register' && site && !site.registrationEnabled) return authError('当前暂停注册，已有账号可登录。');
  authMode = next;
  const registering = next === 'register';
  $('login-tab').classList.toggle('active',!registering); $('register-tab').classList.toggle('active',registering);
  $('login-tab').setAttribute('aria-selected',String(!registering)); $('register-tab').setAttribute('aria-selected',String(registering));
  $('confirm-label').hidden = !registering; $('confirm-password').hidden = !registering;
  $('confirm-password').required = registering; $('confirm-password').value = ''; $('register-hint').hidden = !registering;
  $('password').value = ''; $('password').type = 'password'; $('toggle-password').textContent = '显示';
  $('password').autocomplete = registering ? 'new-password' : 'current-password';
  $('auth-submit').textContent = registering ? '注册并进入面板 →' : '登录用户面板 →';
  $('switch-register').textContent = registering ? '已有账号，去登录' : '立即注册'; clearAuthErrors(); notify();
}
function renderProfiles() {
  $('profiles-body').replaceChildren();
  $('profiles-empty').hidden = profiles.length !== 0;
  $('profile-count').textContent = String(profiles.length);
  $('nav-connection-count').textContent = String(profiles.length);
  $('ready-count').textContent = String(profiles.filter((item) => item.state === 'READY').length);
  $('residential-count').textContent = String(profiles.filter((item) => item.upstream?.mode === 'socks5' && item.upstream.state === 'APPLIED').length);
  $('subscription-count').textContent = profiles.filter((item) => item.state === 'READY').length + ' 条连接';
  for (const item of profiles) {
    const row = document.createElement('tr'); row.classList.toggle('selected-row',item.id === selectedId);
    const name = document.createElement('td'); const select = actionButton(item.name,'select',item.id); select.classList.add('profile-name-button'); name.append(select);
    const proxy = document.createElement('td'); proxy.append(element('span',item.upstream?.mode === 'socks5' ? item.upstream.server + ':' + item.upstream.port : '默认出口','profile-proxy'));
    if (item.upstream?.state === 'PENDING') proxy.append(element('small','代理变更待确认','profile-pending-note'));
    const status = document.createElement('td'); status.append(element('span',item.state === 'READY' ? '已生成' : item.state === 'DELETING' ? '删除待确认' : '待生成', 'badge ' + (item.state === 'READY' ? 'green' : 'pending')));
    const date = element('td',dateLabel(item.expiresAt));
    const actions = document.createElement('td'); const group = element('div',undefined,'row-actions');
    group.append(actionButton('管理连接','select',item.id),actionButton('重命名','rename',item.id),actionButton(item.state === 'DELETING' ? '重试删除' : '删除','delete',item.id)); actions.append(group);
    row.append(name,proxy,status,date,actions); $('profiles-body').append(row);
  }
}
async function refreshProfiles(selectId = null, details = true) {
  const version = epoch, request = ++listSequence;
  const result = await api('/api/me/profiles');
  if (!active(version) || request !== listSequence) return;
  profiles = result.items || [];
  if (!$('manage-dialog').open) selectedId = null;
  else if (!profiles.some((item) => item.id === selectedId)) closeManager();
  renderProfiles();
  $('selected-panel').hidden = !$('manage-dialog').open || !selectedId;
  if ($('manage-dialog').open && selectedId && details) await selectProfile(selectedId);
  if (!selectedId) { clearSelected(); $('subscription-url').value = ''; $('copy-subscription').disabled = true; $('rotate-subscription').disabled = true; }
}
function renderUpstream(value, populate = true) {
  upstream = value;
  const residential = value.mode === 'socks5', pending = value.state === 'PENDING';
  const label = pending ? '变更待确认' : residential ? '住宅代理' : '默认出口';
  $('current-egress').textContent = label;
  $('egress-summary').textContent = residential ? value.server + ':' + value.port : '未绑定住宅代理';
  $('upstream-state').textContent = label; $('upstream-state').className = 'badge ' + (pending ? 'pending' : residential ? 'green' : 'neutral');
  $('upstream-fields').disabled = !connectionData || selectedBusy;
  $('restore-direct').disabled = !connectionData || selectedBusy || (!residential && !pending) || (residential && pending);
  if (populate) {
    $('upstream-server').value = value.server || ''; $('upstream-port').value = String(value.port || 1080);
    $('upstream-username').value = value.username || ''; $('upstream-password').value = '';
    $('upstream-password').type = 'password'; $('toggle-upstream-password').textContent = '显示';
    $('upstream-use-auth').checked = !!(value.username || value.passwordConfigured);
    $('upstream-password-note').hidden = !value.passwordConfigured;
    configureAuth();
  }
}
function renderConnections(value) {
  connectionData = value;
  $('connection-panel').hidden = false; $('connections-pending').hidden = true;
  $('expiry').textContent = dateLabel(value.expiresAt);
  const item = currentProfile();
  if (item) { item.state = 'READY'; item.expiresAt = value.expiresAt; renderProfiles(); }
  if (upstream) renderUpstream(upstream,false);
  $('quota-fields').disabled = quotaBusy;
}
async function selectProfile(id) {
  if (!$('manage-dialog').open) return;
  const item = profiles.find((entry) => entry.id === id);
  if (!item) return;
  selectedId = id; selectedBusy = false; clearSelected();
  const version = epoch, sequence = selectionEpoch;
  $('selected-panel').hidden = false; $('selected-name').textContent = item.name;
  $('manage-name').value = item.name; $('manage-name').disabled = item.state === 'DELETING';
  $('rename-profile').disabled = item.state === 'DELETING';
  $('manage-loading').hidden = false;
  $('expiry').textContent = dateLabel(item.expiresAt);
  showQuota(item.trafficLimitBytes ?? site?.trafficLimitBytes ?? 300 * GiB);
  $('connections-pending').hidden = item.state === 'DELETING';
  $('generate-selected').disabled = item.state === 'DELETING';
  $('generate-selected').textContent = item.state === 'PENDING' ? '检查并生成三协议' : '重新检查连接';
  renderProfiles(); renderUpstream(item.upstream || {mode:'direct',state:'APPLIED'});
  if (item.state === 'DELETING') { $('manage-loading').hidden = true; return; }
  const tasks = [
    api(profilePath(id,'/connections')).then((value) => { if (selectedActive(version,sequence,id)) renderConnections(value); }).catch((error) => {
      if (selectedActive(version,sequence,id)) { $('connections-pending').hidden = false; if (item.state === 'READY') notify(error.message,true); }
    }),
    api(profilePath(id,'/traffic')).then((value) => {
      if (!selectedActive(version,sequence,id)) return;
      $('traffic-used').textContent = value.available ? humanBytes(value.total) : '暂未采样';
      item.trafficLimitBytes = value.trafficLimitBytes;
      showQuota(value.trafficLimitBytes,!quotaDirty && !quotaBusy);
    }).catch(() => {})
  ];
  if (item.state === 'READY') tasks.push(api(profilePath(id,'/upstream')).then((value) => { if (selectedActive(version,sequence,id)) renderUpstream(value); }).catch((error) => { if (selectedActive(version,sequence,id)) notify(error.message,true); }));
  await Promise.allSettled(tasks);
  if (selectedActive(version,sequence,id)) $('manage-loading').hidden = true;
}
function openProfileDialog(mode = 'create', item = null) {
  createMode = mode; renameTarget = item?.id || null;
  $('profile-dialog-title').textContent = mode === 'rename' ? '重命名连接' : '创建连接';
  $('profile-name').value = mode === 'rename' ? item.name : createRequest?.name || '';
  $('profile-name').readOnly = mode === 'create' && !!createRequest;
  $('create-quota-row').hidden = mode !== 'create';
  $('create-quota').required = mode === 'create';
  $('create-quota').value = String((createRequest?.trafficLimitBytes ?? site?.trafficLimitBytes ?? 300 * GiB) / GiB);
  $('create-quota').readOnly = mode === 'create' && !!createRequest;
  $('profile-dialog-note').textContent = mode === 'rename' ? '仅修改名称，认证信息和住宅代理不变。' : createRequest ? '上一笔创建尚未确认，请按原名称重试。' : '创建后可为该连接单独配置住宅代理。';
  $('save-profile').textContent = mode === 'rename' ? '保存名称' : createRequest ? '重试创建' : '创建并生成三协议';
  $('save-profile').disabled = createBusy;
  $('profile-dialog').showModal(); $('profile-name').focus();
}
async function removeProfile(item) {
  if (!window.confirm('删除“' + item.name + '”？该连接的三协议和住宅代理绑定将一并移除。')) return;
  const version = epoch;
  try {
    await api(profilePath(item.id),'DELETE');
    if (!active(version)) return;
    if (selectedId === item.id) closeManager();
    await refreshProfiles(null,false); notify('“' + item.name + '”已删除。');
  } catch (error) { if (active(version)) { notify(error.message,true); await refreshProfiles().catch(() => {}); } }
}
function configureAuth() {
  const use = $('upstream-use-auth').checked;
  $('upstream-auth-fields').hidden = !use;
  $('upstream-username').disabled = !use || $('upstream-fields').disabled;
  $('upstream-password').disabled = !use || $('upstream-fields').disabled;
  $('upstream-username').required = use; $('upstream-password').required = use;
  if (!use) { $('upstream-username').value = ''; $('upstream-password').value = ''; }
}
async function mutateUpstream(direct = false) {
  if (!selectedId || !connectionData || selectedBusy) return;
  const id = selectedId, version = epoch, sequence = selectionEpoch;
  const name = currentProfile()?.name || '该连接';
  const useAuth = $('upstream-use-auth').checked;
  const body = direct ? {} : {server:$('upstream-server').value.trim(),port:Number($('upstream-port').value),username:useAuth ? $('upstream-username').value : '',password:useAuth ? $('upstream-password').value : ''};
  selectedBusy = true; $('upstream-fields').disabled = true; $('restore-direct').disabled = true;
  notify(direct ? '正在将“' + name + '”恢复默认出口…' : '正在保存“' + name + '”的住宅代理…');
  try {
    const value = await api(profilePath(id,'/upstream'),direct ? 'DELETE' : 'PUT',body);
    if (!active(version)) return;
    const item = profiles.find((entry) => entry.id === id); if (item) item.upstream = value;
    renderProfiles();
    if (selectedActive(version,sequence,id)) { selectedBusy = false; renderUpstream(value); }
    notify(value.state === 'PENDING' ? '“' + name + '”的变更尚未确认，请用原配置重试。' : direct ? '“' + name + '”已恢复默认出口。' : '“' + name + '”的住宅代理已保存。');
  } catch (error) { if (active(version)) notify('“' + name + '”：' + error.message,true); }
  finally { if (selectedActive(version,sequence,id)) { selectedBusy = false; $('upstream-fields').disabled = !connectionData; if (upstream) renderUpstream(upstream,false); configureAuth(); } }
}
function importText() {
  const text = $('import-text').value;
  if (!text.trim()) throw new Error('请先粘贴代理内容，或读取文件。');
  if (new TextEncoder().encode(text).length > 65536) throw new Error('导入内容不能超过 64 KiB。');
  return text;
}
function setImportBusy(value) {
  importBusy = value;
  for (const id of ['preview-import','clear-import','import-file']) $(id).disabled = value;
  $('import-text').readOnly = value;
  $('run-import').disabled = value || !importPreview || importPreview.failedCount > 0;
  $('run-import').textContent = value ? '正在导入…' : '开始导入';
}
function renderImport(result, complete) {
  $('import-preview-panel').hidden = false; $('import-results-body').replaceChildren();
  $('import-results-title').textContent = complete ? '导入结果' : '导入预览';
  const items = result.items || [];
  if (complete) {
    const ready = items.filter((item) => item.state === 'READY').length;
    const pending = items.filter((item) => item.state === 'PENDING').length;
    $('import-summary').textContent = '已完成 ' + ready + ' 条，待确认 ' + pending + ' 条，失败 ' + (result.failedCount || 0) + ' 条。';
  } else $('import-summary').textContent = '检查通过 ' + result.validCount + ' 条，需修正 ' + result.failedCount + ' 条。';
  for (const item of items) {
    const row = document.createElement('tr');
    const state = complete ? item.state : item.valid ? 'VALID' : 'FAILED';
    const title = {READY:'已完成',PENDING:'待确认',FAILED:'失败',VALID:'可导入'}[state] || '待检查';
    row.append(element('td',String(item.line)),element('td',item.name || '—'),element('td',item.server ? item.server + ':' + item.port : '—'));
    const status = document.createElement('td'); status.append(element('span',title,'badge ' + (['READY','VALID'].includes(state) ? 'green' : 'pending'))); row.append(status);
    const explanation = element('td',item.error || (state === 'PENDING' ? '使用原批次重试，或前往连接列表检查' : '—'),'import-explanation');
    if (complete && item.profileId) { const button = actionButton('查看连接','select',item.profileId); explanation.append(document.createTextNode(' '),button); }
    row.append(explanation); $('import-results-body').append(row);
  }
}
async function previewImport() {
  if (importBusy) return;
  const version = epoch;
  let text;
  try { text = importText(); } catch (error) { return notify(error.message,true); }
  $('preview-import').disabled = true;
  try {
    const result = await api('/api/me/profiles/import/preview','POST',{text});
    if (!active(version) || $('import-text').value !== text) return;
    importPreview = {...result,text}; renderImport(result,false);
    $('run-import').disabled = result.failedCount > 0 || !result.validCount;
    notify(result.failedCount ? '请先修正未通过的行，再重新预览。' : '预览通过，可以开始导入。',!!result.failedCount);
  } catch (error) { if (active(version)) { importPreview = null; $('run-import').disabled = true; notify(error.message,true); } }
  finally { if (active(version)) $('preview-import').disabled = false; }
}
async function runImport() {
  if (importBusy || !importPreview || importPreview.failedCount) return;
  let text;
  try { text = importText(); } catch (error) { return notify(error.message,true); }
  if (text !== importPreview.text) return notify('内容已修改，请先重新预览。',true);
  if (!importRequest || importRequest.text !== text) importRequest = {text,idempotencyKey:crypto.randomUUID()};
  const version = epoch, request = importRequest;
  setImportBusy(true); notify('正在逐条创建连接并绑定住宅代理，请保持页面打开。');
  try {
    const result = await api('/api/me/profiles/import','POST',request);
    if (!active(version)) return;
    renderImport(result,true);
    await refreshProfiles(null,false);
    const pending = (result.items || []).some((item) => item.state !== 'READY');
    notify(pending ? '批次已处理，部分连接仍待确认。可按原批次重试，不会重复创建。' : '住宅代理已导入，每条连接已生成三协议。',pending);
    if (!pending) { $('import-text').value = ''; $('import-file').value = ''; importRequest = null; importPreview = null; }
  } catch (error) { if (active(version)) { notify(error.message + ' 请保留原内容重试。',true); await refreshProfiles(null,false).catch(() => {}); } }
  finally { if (active(version)) setImportBusy(false); }
}
async function loadSubscription(rotate = false) {
  if (!account || subscriptionBusy) return;
  const ready = profiles.filter((item) => item.state === 'READY').length;
  if (!ready) { $('subscription-note').textContent = '请先创建并生成至少一条连接。'; return; }
  const version = epoch;
  subscriptionBusy = true; $('copy-subscription').disabled = true; $('rotate-subscription').disabled = true;
  try {
    let value;
    if (rotate) value = await api('/api/me/subscription','POST',{rotate:true});
    else {
      try { value = await api('/api/me/subscription'); }
      catch (error) { if (error.status !== 404) throw error; value = await api('/api/me/subscription','POST',{rotate:false}); }
    }
    if (!active(version)) return;
    $('subscription-url').value = value.url;
    $('subscription-note').textContent = rotate ? '订阅地址已重置，旧地址已失效。请更新客户端中的地址。' : '创建、删除连接后，在客户端更新订阅即可同步。';
    $('copy-subscription').disabled = false; $('rotate-subscription').disabled = false;
  } catch (error) { if (active(version)) { $('subscription-note').textContent = error.message; $('rotate-subscription').disabled = false; } }
  finally { if (active(version)) subscriptionBusy = false; }
}
async function copyText(text, field) {
  if (!text) return;
  try { await navigator.clipboard.writeText(text); notify('已复制到剪贴板。'); }
  catch { if (field) { field.focus(); field.select(); } notify('请按 Ctrl+C 或长按复制已选中的内容。'); }
}
function openDetail(protocol) {
  if (!connectionData) return;
  const link = connectionData.links.find((item) => item.protocol === protocol); if (!link) return;
  $('dialog-title').textContent = currentProfile().name + ' · ' + labels[protocol];
  $('dialog-description').textContent = '复制连接链接，导入支持该协议的客户端。';
  $('detail-link').value = link.uri; $('socks-details').hidden = protocol !== 'socks';
  $('detail-socks-host').textContent = connectionData.socks.host; $('detail-socks-port').textContent = String(connectionData.socks.port);
  $('detail-socks-user').textContent = connectionData.socks.username; $('detail-socks-password').value = connectionData.socks.password;
  $('detail-socks-password').type = 'password'; $('toggle-socks-password').textContent = '显示'; $('connection-dialog').showModal();
}

for (const button of document.querySelectorAll('[data-page]')) button.addEventListener('click',() => { if (account) { notify(); setPage(button.dataset.page); } });
window.addEventListener('hashchange',() => { if (account) setPage(location.hash.slice(1),false); });
$('admin-refresh').addEventListener('click',() => { if (!adminBusy) void loadAdmin(); });
$('admin-search-form').addEventListener('submit',(event) => {
  event.preventDefault();
  if (!account?.isAdmin || adminBusy) return;
  adminSearch = $('admin-search').value.trim(); void loadAdmin(1);
});
$('admin-search-clear').addEventListener('click',() => {
  if (!account?.isAdmin || adminBusy) return;
  adminSearch = ''; $('admin-search').value = ''; void loadAdmin(1);
});
$('admin-prev').addEventListener('click',() => { if (!adminBusy && adminPage > 1) void loadAdmin(adminPage - 1); });
$('admin-next').addEventListener('click',() => { if (!adminBusy && adminPage < adminTotalPages) void loadAdmin(adminPage + 1); });
$('login-tab').addEventListener('click',() => switchAuthMode('login'));
$('register-tab').addEventListener('click',() => switchAuthMode('register'));
$('switch-register').addEventListener('click',() => switchAuthMode(authMode === 'login' ? 'register' : 'login'));
for (const id of ['username','password','confirm-password']) $(id).addEventListener('input',() => {
  clearAuthErrors(id);
  if (id === 'password') clearAuthErrors('confirm-password');
});
for (const pair of [['toggle-password','password'],['toggle-upstream-password','upstream-password'],['toggle-socks-password','detail-socks-password']]) $(pair[0]).addEventListener('click',() => { const show = $(pair[1]).type === 'password'; $(pair[1]).type = show ? 'text' : 'password'; $(pair[0]).textContent = show ? '隐藏' : '显示'; });
$('auth-form').addEventListener('submit',async (event) => {
  event.preventDefault();
  if (authBusy) return;
  notify();
  if (!validateAuth()) return;
  const version = epoch; setAuthBusy(true);
  try { const result = await api('/api/auth/' + authMode,'POST',{username:$('username').value.trim(),password:$('password').value}); if (epoch !== version) return; showSession(result); await refreshProfiles(); }
  catch (error) {
    if (epoch === version) {
      if (error.field) { authFieldError(error.field,error.message); focusAuthField(error.field); }
      else authError(error.message);
    } else if (account) notify(error.message,true);
  }
  finally { setAuthBusy(false); }
});
for (const id of ['create-profile','empty-create-profile']) $(id).addEventListener('click',() => openProfileDialog());
$('close-profile-dialog').addEventListener('click',() => { if (!createBusy) $('profile-dialog').close(); });
$('profile-dialog').addEventListener('cancel',(event) => { if (createBusy) event.preventDefault(); });
$('profile-form').addEventListener('submit',async (event) => {
  event.preventDefault(); if (createBusy) return;
  const name = $('profile-name').value.trim(); if (!name) return;
  const version = epoch, mode = createMode, target = renameTarget;
  if (mode === 'create' && !createRequest) {
    let bytes;
    try { bytes = quotaBytes($('create-quota').value); } catch (error) { return notify(error.message,true); }
    createRequest = {name,trafficLimitBytes:bytes,idempotencyKey:crypto.randomUUID()};
  }
  createBusy = true; $('save-profile').disabled = true; $('close-profile-dialog').disabled = true; notify();
  try {
    const result = await api(mode === 'rename' ? profilePath(target) : '/api/me/profiles',mode === 'rename' ? 'PATCH' : 'POST',mode === 'rename' ? {name} : createRequest);
    if (!active(version)) return;
    createRequest = null; $('profile-dialog').close(); await refreshProfiles(result.id || target); setPage('connections');
    notify(mode === 'rename' ? '连接名称已更新。' : '连接已创建，三协议可分别复制使用。');
  } catch (error) {
    if (!active(version)) return;
    // Admission can succeed before node generation returns 409 or times out.
    // Retain its identity until the same request is confirmed by the server.
    if (mode === 'create' && error.status === 422) createRequest = null;
    $('profile-name').readOnly = mode === 'create' && !!createRequest;
    $('create-quota').readOnly = mode === 'create' && !!createRequest;
    $('profile-dialog-note').textContent = createRequest ? '创建结果尚未确认，请保留原名称重试，不会重复创建。' : error.message;
    $('save-profile').textContent = createRequest ? '重试创建' : mode === 'rename' ? '保存名称' : '创建并生成三协议';
    notify(error.message,true); await refreshProfiles(null,false).catch(() => {});
  } finally { if (active(version)) { createBusy = false; $('save-profile').disabled = false; $('close-profile-dialog').disabled = false; } }
});
for (const id of ['profiles-body','import-results-body']) $(id).addEventListener('click',async (event) => {
  const button = event.target.closest('[data-profile-action]'); if (!button) return;
  const item = profiles.find((entry) => entry.id === button.dataset.profileId); if (!item) return;
  if (button.dataset.profileAction === 'select') { setPage('connections'); await openManager(item.id,button); }
  else if (button.dataset.profileAction === 'rename') openProfileDialog('rename',item);
  else await removeProfile(item);
});
$('manage-name-form').addEventListener('submit',async (event) => {
  event.preventDefault();
  if (!selectedId || renameBusy || currentProfile()?.state === 'DELETING') return;
  const name = $('manage-name').value.trim();
  if (!name) return;
  const id = selectedId, version = epoch, sequence = selectionEpoch;
  renameBusy = true; $('rename-profile').disabled = true;
  try {
    const result = await api(profilePath(id),'PATCH',{name});
    if (!active(version)) return;
    const item = profiles.find((entry) => entry.id === id);
    if (item) item.name = result.name;
    renderProfiles();
    if (selectedActive(version,sequence,id)) {
      $('selected-name').textContent = result.name; $('manage-name').value = result.name;
    }
    notify('连接名称已更新。');
  } catch (error) { if (active(version)) notify(error.message,true); }
  finally { if (selectedActive(version,sequence,id)) { renameBusy = false; $('rename-profile').disabled = currentProfile()?.state === 'DELETING'; } }
});
for (const id of ['close-manage-dialog','close-manage-footer']) $(id).addEventListener('click',closeManager);
$('manage-dialog').addEventListener('close',clearManager);
$('delete-profile').addEventListener('click',() => { if (currentProfile()) void removeProfile(currentProfile()); });
$('refresh-profiles').addEventListener('click',async () => { $('refresh-profiles').disabled = true; try { await refreshProfiles(); notify('连接列表已刷新。'); } catch (error) { notify(error.message,true); } finally { $('refresh-profiles').disabled = false; } });
$('generate-selected').addEventListener('click',async () => {
  if (!selectedId || selectedBusy) return;
  const version = epoch, sequence = selectionEpoch, id = selectedId;
  selectedBusy = true; $('generate-selected').disabled = true;
  try {
    await api(profilePath(id,'/connections'),'POST');
    if (!active(version)) return;
    if (selectedActive(version,sequence,id)) { await refreshProfiles(id); notify('三协议连接已生成。'); }
    else await refreshProfiles(null,false);
  }
  catch (error) { if (selectedActive(version,sequence,id)) notify(error.message,true); }
  finally { if (selectedActive(version,sequence,id)) { selectedBusy = false; $('generate-selected').disabled = currentProfile()?.state === 'DELETING'; } }
});
$('upstream-use-auth').addEventListener('change',configureAuth);
$('quota-limit').addEventListener('input',() => { quotaDirty = true; });
$('quota-form').addEventListener('submit',async (event) => {
  event.preventDefault();
  if (!selectedId || !connectionData || quotaBusy) return;
  let bytes;
  try { bytes = quotaBytes($('quota-limit').value); } catch (error) { return notify(error.message,true); }
  const id = selectedId, version = epoch, sequence = selectionEpoch, name = currentProfile()?.name || '该连接';
  quotaBusy = true; $('quota-fields').disabled = true;
  try {
    const result = await api(profilePath(id,'/policy'),'PATCH',{trafficLimitBytes:bytes});
    if (!active(version)) return;
    const item = profiles.find((profile) => profile.id === id);
    if (item) item.trafficLimitBytes = result.trafficLimitBytes;
    if (selectedActive(version,sequence,id)) { quotaBusy = false; quotaDirty = false; showQuota(result.trafficLimitBytes); }
    notify('“' + name + '”的额度已更新，已用流量保持不变。');
  } catch (error) { if (active(version)) notify('“' + name + '”：' + error.message,true); }
  finally { if (selectedActive(version,sequence,id)) { quotaBusy = false; $('quota-fields').disabled = !connectionData; } }
});
$('upstream-form').addEventListener('submit',(event) => { event.preventDefault(); void mutateUpstream(); });
$('restore-direct').addEventListener('click',() => void mutateUpstream(true));
$('preview-import').addEventListener('click',() => void previewImport());
$('run-import').addEventListener('click',() => void runImport());
$('clear-import').addEventListener('click',() => { if (!importBusy) { clearImport(); notify(); } });
$('import-text').addEventListener('input',() => { importPreview = null; $('run-import').disabled = true; });
$('import-file').addEventListener('change',async () => {
  const file = $('import-file').files[0]; if (!file) return;
  if (file.size > 65536) { $('import-file').value = ''; return notify('文件不能超过 64 KiB。',true); }
  const version = epoch;
  try { const text = await file.text(); if (!active(version)) return; $('import-text').value = text; importPreview = null; $('run-import').disabled = true; notify('文件已读取，请先预览检查。'); }
  catch { if (active(version)) notify('文件无法读取，请确认使用 UTF-8 编码。',true); }
});
for (const button of document.querySelectorAll('[data-detail]')) button.addEventListener('click',() => openDetail(button.dataset.detail));
for (const button of document.querySelectorAll('[data-copy]')) button.addEventListener('click',async () => { const value = connectionData?.links.find((item) => item.protocol === button.dataset.copy); if (!value) return; try { await navigator.clipboard.writeText(value.uri); notify('连接链接已复制。'); } catch { openDetail(button.dataset.copy); await copyText(value.uri,$('detail-link')); } });
$('close-dialog').addEventListener('click',clearDetail);
$('connection-dialog').addEventListener('close',() => { $('detail-link').value = ''; $('detail-socks-password').value = ''; });
$('copy-detail-link').addEventListener('click',() => copyText($('detail-link').value,$('detail-link')));
$('copy-subscription').addEventListener('click',() => copyText($('subscription-url').value,$('subscription-url')));
$('rotate-subscription').addEventListener('click',() => { if (window.confirm('重置后旧订阅地址立即失效，是否继续？')) void loadSubscription(true); });
$('refresh-subscription').addEventListener('click',async () => { try { await refreshProfiles(null,false); await loadSubscription(); } catch (error) { notify(error.message,true); } });
$('logout').addEventListener('click',async () => { const version = epoch; $('logout').disabled = true; try { await api('/api/auth/logout','POST'); if (active(version)) { showGuest(); notify('已退出登录。'); } } catch (error) { if (active(version)) notify(error.message,true); } finally { $('logout').disabled = false; } });
window.addEventListener('pagehide',() => { closeManager(); clearAdmin(); connectionData = null; clearDetail(); $('subscription-url').value = ''; $('upstream-password').value = ''; $('import-text').value = ''; importRequest = null; });
window.addEventListener('pageshow',(event) => { if (event.persisted) location.reload(); });

(async () => {
  showGuest();
  try {
    site = await api('/api/site'); document.title = site.siteName + ' · 用户面板';
    for (const node of document.querySelectorAll('[data-site-name]')) node.textContent = site.siteName;
    $('register-tab').hidden = !site.registrationEnabled; $('auth-footnote').hidden = !site.registrationEnabled;
    $('registration-status').hidden = !!site.registrationEnabled;
    const session = await api('/api/me'); showSession(session); await refreshProfiles();
    if (location.hash === '#subscription') await loadSubscription();
  } catch (error) { if (error.status !== 401) notify(error.message,true); }
  finally { $('auth-submit').disabled = authBusy; }
})();

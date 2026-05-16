
/* ============================================================
   SECURITY LAB
   ============================================================ */

function _mdToHtml(text) {
  if (!text) return '';
  const lines = text.split('\n');
  const out = [];
  let inUl = false, inOl = false;

  const closeList = () => {
    if (inUl) { out.push('</ul>'); inUl = false; }
    if (inOl) { out.push('</ol>'); inOl = false; }
  };

  const inline = s => s
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>')
    .replace(/\*(.+?)\*/g,'<em>$1</em>')
    .replace(/`([^`]+)`/g,'<code style="background:#1a1a2e;padding:1px 5px;border-radius:3px;font-size:.9em">$1</code>');

  for (const raw of lines) {
    const line = raw.trimEnd();

    if (/^#{4,}\s/.test(line)) {
      closeList();
      out.push(`<h5 style="color:#00e5ff;margin:12px 0 4px">${inline(line.replace(/^#+\s*/,''))}</h5>`);
    } else if (/^###\s/.test(line)) {
      closeList();
      out.push(`<h4 style="color:#00e5ff;margin:14px 0 6px">${inline(line.replace(/^#+\s*/,''))}</h4>`);
    } else if (/^##\s/.test(line)) {
      closeList();
      out.push(`<h3 style="color:#00e5ff;margin:16px 0 8px">${inline(line.replace(/^#+\s*/,''))}</h3>`);
    } else if (/^-\s/.test(line)) {
      if (!inUl) { closeList(); out.push('<ul style="padding-left:20px;margin:6px 0">'); inUl = true; }
      out.push(`<li style="margin-bottom:4px">${inline(line.replace(/^-\s*/,''))}</li>`);
    } else if (/^\d+\.\s/.test(line)) {
      if (!inOl) { closeList(); out.push('<ol style="padding-left:20px;margin:6px 0">'); inOl = true; }
      out.push(`<li style="margin-bottom:4px">${inline(line.replace(/^\d+\.\s*/,''))}</li>`);
    } else if (line.trim() === '') {
      closeList();
      out.push('<br>');
    } else {
      closeList();
      out.push(`<p style="margin:4px 0;line-height:1.6">${inline(line)}</p>`);
    }
  }
  closeList();
  return out.join('\n');
}

let _seclabWslCheckedOnce = false;
let _seclabRunPollers = {};
let _seclabRunSequence = {};

async function _seclabApi(url, options = {}) {
  const r = await fetch(url, options);
  const text = await r.text();
  let data = {};
  if (text) {
    try { data = JSON.parse(text); }
    catch { data = { detail: text }; }
  }
  if (!r.ok) {
    const msg = data.detail || data.error || `${r.status} ${r.statusText}`;
    throw new Error(msg);
  }
  return data;
}

function _seclabJson(body) {
  return {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body || {}),
  };
}

function loadSecurityLabSection() {
  loadSecurityLabHistory();
  _seclabPopulateShodanDevices();
  if (!_seclabWslCheckedOnce) {
    _seclabWslCheckedOnce = true;
    _seclabCheckWSL().catch(() => {});
  }
}

async function _seclabCheckWSL() {
  const el = document.querySelector('#seclab-wsl-status');
  const btn = document.querySelector('#seclab-wsl-check-btn');
  if (el) el.textContent = 'Checking…';
  if (btn) { btn.disabled = true; btn.textContent = 'Checking…'; }
  try {
    const d = await _seclabApi('/api/security/wsl/check', _seclabJson({}));
    const lines = [];
    if (!d.wsl_installed) {
      lines.push('✗ WSL not found — run this in an admin PowerShell:');
      lines.push('    wsl --install -d kali-linux');
      lines.push('Then reboot and come back.');
    } else if (!d.kali_present) {
      lines.push('✓ WSL is installed');
      lines.push('✗ Kali Linux distro not found — run this in an admin PowerShell:');
      lines.push('    wsl --install -d kali-linux');
      lines.push('Then reboot, open the Kali terminal once to finish setup, and click Check Tools again.');
      if (d.distro_list) lines.push('\nInstalled distros:\n' + d.distro_list.trim());
    } else {
      lines.push('✓ WSL installed');
      lines.push('✓ Kali Linux present' + (d.default_distro ? ' (default: ' + d.default_distro + ')' : ''));
      const tools = d.tools || {};
      Object.keys(tools).forEach(name => {
        const t = tools[name];
        lines.push((t.installed ? '✓' : '✗') + ' ' + name + (t.version ? '  ' + t.version.split('\n')[0] : ''));
      });
      if (d.missing_tools && d.missing_tools.length)
        lines.push('\nMissing: ' + d.missing_tools.join(', ') + '\nClick "Install Missing" to install them in Kali.');
      else if (Object.keys(tools).length)
        lines.push('\nAll tools present.');
    }
    if (el) el.textContent = lines.join('\n');
  } catch(e) {
    if (el) el.textContent = 'Check failed: ' + e.message;
    if (typeof showToast === 'function') showToast('Security tool check failed: ' + e.message, 'warning');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Check Tools'; }
  }
}

function _seclabInstallTools() {
  _seclabShowConfirm('Install security tools in Kali WSL? This may take several minutes.', async () => {
    const btn = document.querySelector('#seclab-wsl-install-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Starting…'; }
    try {
      const d = await _seclabApi('/api/security/wsl/install/start', _seclabJson({authorization_confirmed:true}));
      if (d.run_id) _seclabStartRun(d.run_id);
      else throw new Error(d.detail || 'No run id returned');
    } catch (e) {
      if (typeof showToast === 'function') showToast('Install failed to start: ' + e.message, 'warning');
      _seclabAppendProgress('\nInstall failed to start: ' + e.message + '\n');
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Install Missing'; }
    }
  });
}

function _seclabStartRun(runId) {
  const prog = document.querySelector('#seclab-progress');
  if (prog) prog.textContent = '';
  _seclabRunSequence[runId] = 0;
  if (_seclabRunPollers[runId]) clearInterval(_seclabRunPollers[runId]);

  // Auto-refresh history immediately so user sees the new running entry
  loadSecurityLabHistory();

  // Elapsed timer shown in the AI panel while scan runs
  const aiEl = document.querySelector('#seclab-ai-output');
  const startTs = Date.now();
  let timerInterval = null;
  if (aiEl) {
    aiEl.innerHTML = '<p class="muted" id="seclab-scan-timer">⏱ Scanning… 0s elapsed</p>';
    timerInterval = setInterval(() => {
      const t = document.getElementById('seclab-scan-timer');
      if (t) t.textContent = '⏱ Scanning… ' + Math.floor((Date.now() - startTs) / 1000) + 's elapsed';
    }, 1000);
  }

  async function poll() {
    try {
      const d = await _seclabApi('/api/security/run/stream', _seclabJson({run_id:runId, after_sequence:_seclabRunSequence[runId]||0}));
      (d.chunks || []).forEach(c => {
        _seclabRunSequence[runId] = Math.max(_seclabRunSequence[runId]||0, c.sequence);
        if (c.stream !== 'ai') _seclabAppendProgress(c.content);
      });
      if (['succeeded','failed','cancelled'].includes(d.status)) {
        clearInterval(_seclabRunPollers[runId]);
        clearInterval(timerInterval);
        delete _seclabRunPollers[runId];
        _seclabAppendProgress('\n── ' + d.status.toUpperCase() + ' ──\n');
        _seclabLoadRunAIWithRetry(runId);
        loadSecurityLabHistory();
      }
    } catch(e) { _seclabAppendProgress('\nPoll error: ' + e.message + '\n'); }
  }
  poll();
  _seclabRunPollers[runId] = setInterval(poll, 1000);
}

// ── Autonomous fix map & buttons ──────────────────────────────────────────────
const SECLAB_FIX_MAP = {
  router_security_settings: { label:'Fix Security Headers',  keywords:['x-content-type-options','strict-transport-security','content-security-policy','permissions-policy'] },
  router_change_password:   { label:'Change Admin Password', keywords:['default account','password 0000','netgear cbr750'] },
  router_remote_mgmt:       { label:'Disable Remote Admin',  keywords:['remote management','remote admin'] },
  router_firmware:          { label:'Update Firmware',        keywords:['currentsetting.htm','userdata.json','login.json','master.json'] },
  info_bash_history:        { label:'ℹ Shell History Info',  keywords:['.bash_history','.sh_history'] },
};

function _seclabRenderFixButtons(runId, rawOutput) {
  const div = document.getElementById('seclab-fix-buttons');
  if (!div) return;
  div.innerHTML = '';
  const lines = (rawOutput || '').split('\n');
  const seen = new Set();
  for (const [actionKey, fix] of Object.entries(SECLAB_FIX_MAP)) {
    if (seen.has(actionKey)) continue;
    let matchedLine = null;
    for (const kw of fix.keywords) {
      matchedLine = lines.find(l => l.toLowerCase().includes(kw.toLowerCase()));
      if (matchedLine) break;
    }
    if (!matchedLine) continue;
    seen.add(actionKey);
    const btn = document.createElement('button');
    btn.textContent = fix.label;
    btn.dataset.action = actionKey;
    btn.dataset.finding = matchedLine.trim();
    Object.assign(btn.style, {
      background:'transparent', border:'1px solid #00e5ff', color:'#00e5ff',
      borderRadius:'20px', padding:'4px 14px', cursor:'pointer',
      fontSize:'.82em', margin:'3px',
    });
    btn.onclick = function() { _seclabRunFix.call(this, runId, matchedLine.trim(), actionKey); };
    div.appendChild(btn);
  }
  div.style.display = div.children.length ? '' : 'none';
}

async function _seclabRunFix(runId, findingText, actionKey) {
  const btn = this;
  const orig = btn.innerHTML;
  btn.innerHTML = '⏳ Fixing…'; btn.disabled = true;
  try {
    const d = await _seclabApi('/api/security/fix/run', _seclabJson({run_id:runId, finding_text:findingText, action_key:actionKey}));
    if (d.open_in_browser && d.url) window.open(d.url, '_blank');
    if (d.info_text) {
      const p = document.createElement('p');
      p.textContent = d.info_text;
      Object.assign(p.style, {color:'#888', fontSize:'.75em', margin:'4px 4px 2px'});
      btn.parentNode.insertBefore(p, btn.nextSibling);
    }
    btn.innerHTML = '✓ Done'; btn.style.borderColor = '#00c853'; btn.style.color = '#00c853';
  } catch(e) {
    btn.innerHTML = '✗ Failed'; btn.style.borderColor = '#f44'; btn.style.color = '#f44';
    btn.disabled = false;
  }
}

function _seclabLoadRunAIWithRetry(runId, maxWaitSeconds = 120) {
  let waited = 0;
  let timer = null;

  async function attempt() {
    await _seclabLoadRunAI(runId);
    const el = document.getElementById('seclab-ai-output');
    if (!el) return;
    if (el.innerHTML.includes('No AI explanation available')) {
      if (waited < maxWaitSeconds) {
        el.innerHTML = '<p class="muted">⏳ AI analysis generating… checking again in 30s</p>';
        waited += 30;
        timer = setTimeout(attempt, 30000);
      } else {
        el.innerHTML = '<p class="muted">AI analysis timed out. Click the run in history to reload later.</p>';
      }
    } else {
      clearTimeout(timer);
    }
  }

  attempt();
}

// ── Chat state ────────────────────────────────────────────────────────────────
let _seclabChatHistory = [];
let _seclabChatRunId   = null;

async function sendSecLabChat(runId, message) {
  message = (message || '').trim();
  if (!message) return;
  const input  = document.getElementById('seclab-chat-input');
  const sendBtn = document.getElementById('seclab-chat-send');
  if (input)  { input.disabled = true; input.value = ''; }
  if (sendBtn) sendBtn.disabled = true;

  _seclabChatHistory.push({role:'user', content:message});
  _seclabAppendChatMsg('user', message);

  // Show thinking indicator
  const thinkEl = document.createElement('div');
  thinkEl.id = 'seclab-chat-thinking';
  thinkEl.style.cssText = 'padding:8px 12px;border-radius:12px;background:#2a2a3e;color:#aaa;margin-bottom:8px;font-style:italic';
  thinkEl.textContent = '⏳ Thinking…';
  const msgBox = document.getElementById('seclab-chat-messages');
  if (msgBox) { msgBox.appendChild(thinkEl); msgBox.scrollTop = msgBox.scrollHeight; }

  try {
    const d = await _seclabApi('/api/security/chat', _seclabJson({run_id:runId, message, history:_seclabChatHistory}));
    document.getElementById('seclab-chat-thinking')?.remove();
    const reply = d.reply || 'No response.';
    _seclabChatHistory.push({role:'assistant', content:reply});
    _seclabAppendChatMsg('assistant', reply);
  } catch(e) {
    document.getElementById('seclab-chat-thinking')?.remove();
    _seclabAppendChatMsg('assistant', 'Error: ' + e.message);
  } finally {
    if (input)  input.disabled = false;
    if (sendBtn) sendBtn.disabled = false;
    if (input)  input.focus();
  }
}

function _seclabAppendChatMsg(role, content) {
  const box = document.getElementById('seclab-chat-messages');
  if (!box) return;
  const d = document.createElement('div');
  d.style.cssText = 'padding:8px 12px;border-radius:12px;margin-bottom:8px;max-width:85%;white-space:pre-wrap;word-break:break-word;' +
    (role === 'user'
      ? 'background:#0e4f7a;color:#00e5ff;margin-left:auto;text-align:right;'
      : 'background:#2a2a3e;color:#fff;margin-right:auto;');
  d.textContent = content;
  box.appendChild(d);
  box.scrollTop = box.scrollHeight;
}

async function _seclabLoadRunAI(runId) {
  const el = document.querySelector('#seclab-ai-output');
  if (!el) return;
  el.innerHTML = '<p class="muted">Loading explanation…</p>';
  _seclabChatHistory = [];
  _seclabChatRunId   = runId;

  try {
    const d  = await _seclabApi('/api/security/run', _seclabJson({run_id:runId}));
    const ai = d.ai;
    // Render autonomous fix buttons from raw scan output
    const rawOut = (d.chunks || []).filter(c=>c.stream==='stdout').map(c=>c.content).join('');
    _seclabRenderFixButtons(runId, rawOut);
    if (!ai) { el.innerHTML = '<p class="muted">No AI explanation available.</p>'; return; }

    const findings = Array.isArray(ai.findings_json) ? ai.findings_json : [];
    const recs     = Array.isArray(ai.recommendations_json) ? ai.recommendations_json : [];

    let html = '<div style="line-height:1.6">' + _mdToHtml(ai.summary_text || '') + '</div>';

    if (findings.length)
      html += '<h4 style="margin:14px 0 6px;color:#00e5ff">Findings</h4><ul style="padding-left:18px">' +
        findings.map(f => '<li style="margin-bottom:4px">' + escapeHtml(String(f)) + '</li>').join('') + '</ul>';

    if (recs.length) {
      html += '<h4 style="margin:14px 0 8px;color:#00e5ff">Recommended Fixes</h4>' +
        '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px">' +
        recs.map(r =>
          '<button class="seclab-fix-btn" data-rec="' + escapeHtml(r) + '" ' +
          'style="background:#0e4f7a;color:#00e5ff;border:1px solid #00e5ff;padding:6px 12px;border-radius:6px;cursor:pointer;font-size:.85em">' +
          '🔧 ' + escapeHtml(r.length > 60 ? r.slice(0, 60) + '…' : r) + '</button>'
        ).join('') + '</div>';
    }

    // Chat panel
    html += `
      <div style="background:#1a1a2e;border-radius:8px;padding:14px;margin-top:8px">
        <div style="font-size:.85em;color:#aaa;margin-bottom:8px">💬 Ask the AI how to fix anything, or click a button above</div>
        <div id="seclab-chat-messages" style="height:240px;overflow-y:auto;margin-bottom:10px;display:flex;flex-direction:column;gap:4px"></div>
        <div style="display:flex;gap:8px">
          <input id="seclab-chat-input" type="text" placeholder="Ask about a finding or fix…"
            style="flex:1;padding:8px 10px;border-radius:6px;border:1px solid #444;background:#2a2a3e;color:#fff;font-size:.9em">
          <button id="seclab-chat-send"
            style="background:#00897b;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-weight:600">Send</button>
        </div>
      </div>`;

    el.innerHTML = html;

    // Wire fix buttons
    el.querySelectorAll('.seclab-fix-btn').forEach(btn =>
      btn.addEventListener('click', () => sendSecLabChat(runId, btn.dataset.rec))
    );

    // Wire chat send
    const chatInput = document.getElementById('seclab-chat-input');
    document.getElementById('seclab-chat-send').addEventListener('click', () => sendSecLabChat(runId, chatInput.value));
    chatInput.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); sendSecLabChat(runId, chatInput.value); } });

  } catch(e) { el.innerHTML = '<p style="color:#f44">Error: ' + escapeHtml(e.message) + '</p>'; }
}

// ── Run detail modal ──────────────────────────────────────────────────────────
async function _seclabShowRunModal(runId) {
  const overlay = document.getElementById('seclab-run-modal');
  if (!overlay) return;
  overlay.style.display = 'flex';
  overlay.innerHTML = '<div style="color:#aaa;margin:auto">Loading…</div>';

  try {
    const d   = await _seclabApi('/api/security/run', _seclabJson({run_id:runId}));
    const run = d.run || {};
    const ai  = d.ai;
    const findings = ai && Array.isArray(ai.findings_json) ? ai.findings_json : [];
    const recs     = ai && Array.isArray(ai.recommendations_json) ? ai.recommendations_json : [];

    overlay.innerHTML = `
      <div style="background:#1a1a2e;color:#fff;border-radius:10px;max-width:700px;width:100%;padding:28px 28px 24px;position:relative;box-shadow:0 8px 40px rgba(0,0,0,.6)">
        <button onclick="document.getElementById('seclab-run-modal').style.display='none'"
          style="position:absolute;top:12px;right:14px;background:none;border:none;color:#aaa;font-size:1.6em;cursor:pointer;line-height:1">&times;</button>
        <h3 style="margin:0 0 16px;color:#00e5ff">${escapeHtml(run.tool||'Run')} — ${escapeHtml(run.target||'')}</h3>
        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px">
          ${_seclabStatusBadge(run.status)} ${_seclabRiskBadge(run.risk_level)}
          <span style="color:#888;font-size:.85em">${run.created_at ? new Date(run.created_at).toLocaleString() : ''}</span>
        </div>
        ${ai ? `
          <h4 style="color:#00e5ff;margin:0 0 8px">AI Summary</h4>
          <div style="line-height:1.65;margin:0 0 14px">${_mdToHtml(ai.summary_text||'')}</div>
          ${findings.length ? '<h4 style="color:#00e5ff;margin:0 0 6px">Findings</h4><ul style="padding-left:18px;margin:0 0 14px">' + findings.map(f=>'<li style="margin-bottom:4px">'+escapeHtml(String(f))+'</li>').join('') + '</ul>' : ''}
          ${recs.length ? '<h4 style="color:#00e5ff;margin:0 0 6px">Recommendations</h4><ul style="padding-left:18px;margin:0">' + recs.map(r=>'<li style="margin-bottom:4px">'+escapeHtml(String(r))+'</li>').join('') + '</ul>' : ''}
        ` : '<p class="muted">No AI explanation saved for this run.</p>'}
      </div>`;
  } catch(e) {
    overlay.innerHTML = '<div style="color:#f44;margin:auto">Error: ' + escapeHtml(e.message) + '</div>';
  }

  overlay.onclick = e => { if (e.target === overlay) overlay.style.display = 'none'; };
}

async function loadSecurityLabHistory() {
  const el = document.querySelector('#seclab-history');
  if (!el) return;
  try {
    const d = await _seclabApi('/api/security/runs', _seclabJson({limit:20}));
    const runs = d.runs || [];
    if (!runs.length) { el.innerHTML = '<p class="muted">No runs yet.</p>'; return; }
    let html = '<table class="seclab-history-table"><thead><tr><th>Tool</th><th>Target</th><th>Status</th><th>Risk</th><th>Time</th></tr></thead><tbody>';
    runs.forEach(run => {
      const toolLink = '<a href="#" onclick="event.preventDefault();_seclabShowRunModal(' + run.id + ')" style="color:#00e5ff;text-decoration:underline;cursor:pointer">' + escapeHtml(run.tool||'-') + '</a>';
      html += '<tr><td>' + toolLink + '</td><td>' + escapeHtml(run.target||'-') + '</td><td>' + _seclabStatusBadge(run.status) + '</td><td>' + _seclabRiskBadge(run.risk_level) + '</td><td>' + escapeHtml(_seclabFmtTime(run.created_at)) + '</td></tr>';
    });
    html += '</tbody></table>';
    el.innerHTML = html;
  } catch(e) { el.innerHTML = '<p>Error: ' + escapeHtml(e.message) + '</p>'; }
}

async function _seclabUploadFile(inputEl, fileType) {
  if (!inputEl || !inputEl.files || !inputEl.files.length) return null;
  const fd = new FormData();
  fd.append('file', inputEl.files[0]);
  fd.append('file_type', fileType);
  const d = await _seclabApi('/api/security/upload', {method:'POST', body:fd});
  return d.file_id || null;
}

async function _seclabNiktoStart() {
  const target = document.querySelector('#seclab-nikto-target')?.value.trim();
  if (!target) { showToast('Enter a target IP', 'warning'); return; }
  try {
    const d = await _seclabApi('/api/security/nikto/start', _seclabJson({target, port:parseInt(document.querySelector('#seclab-nikto-port')?.value||'80'), use_ssl:!!document.querySelector('#seclab-nikto-ssl')?.checked, authorization_confirmed:true}));
    if (d.run_id) _seclabStartRun(d.run_id); else throw new Error('No run id returned');
  } catch (e) { showToast(e.message, 'warning'); }
}

function _seclabHydraStart() {
  _seclabShowConfirm('Run Hydra password test on this authorized target?', async () => {
    const target = document.querySelector('#seclab-hydra-target')?.value.trim();
    if (!target) { showToast('Enter a target IP', 'warning'); return; }
    const pwFileId = await _seclabUploadFile(document.querySelector('#seclab-hydra-pw-file'), 'wordlist');
    if (!pwFileId) { showToast('Select a password list file', 'warning'); return; }
    try {
      const d = await _seclabApi('/api/security/hydra/start', _seclabJson({target, service:document.querySelector('#seclab-hydra-service')?.value, username:document.querySelector('#seclab-hydra-username')?.value.trim(), password_file_id:pwFileId, port:parseInt(document.querySelector('#seclab-hydra-port')?.value||'0')||null, authorization_confirmed:true}));
      if (d.run_id) _seclabStartRun(d.run_id); else throw new Error('No run id returned');
    } catch (e) { showToast(e.message, 'warning'); }
  });
}

function _seclabJohnStart() {
  _seclabShowConfirm('Run John the Ripper on this hash file?', async () => {
    const hashFileId = await _seclabUploadFile(document.querySelector('#seclab-john-hash-file'), 'hash_file');
    if (!hashFileId) { showToast('Select a hash file', 'warning'); return; }
    const wordlistFileId = await _seclabUploadFile(document.querySelector('#seclab-john-wordlist-file'), 'wordlist');
    try {
      const d = await _seclabApi('/api/security/john/start', _seclabJson({hash_file_id:hashFileId, wordlist_file_id:wordlistFileId, format_name:document.querySelector('#seclab-john-format')?.value||'auto', authorization_confirmed:true}));
      if (d.run_id) _seclabStartRun(d.run_id); else throw new Error('No run id returned');
    } catch (e) { showToast(e.message, 'warning'); }
  });
}

function _seclabMsfStart() {
  _seclabShowConfirm('Run this Metasploit module on the authorized target?', async () => {
    const target = document.querySelector('#seclab-msf-target')?.value.trim();
    const module_name = document.querySelector('#seclab-msf-module')?.value.trim();
    if (!target || !module_name) { showToast('Target and module name required', 'warning'); return; }
    let options = {};
    const raw = document.querySelector('#seclab-msf-options')?.value.trim();
    if (raw) { try { options = JSON.parse(raw); } catch { showToast('Options must be valid JSON', 'error'); return; } }
    try {
      const d = await _seclabApi('/api/security/metasploit/start', _seclabJson({target, module_name, options, authorization_confirmed:true}));
      if (d.run_id) _seclabStartRun(d.run_id); else throw new Error('No run id returned');
    } catch (e) { showToast(e.message, 'warning'); }
  });
}

function _seclabWifiCaptureStart() {
  _seclabShowConfirm('Start WiFi capture on this authorized network?', async () => {
    const iface = document.querySelector('#seclab-wifi-interface')?.value.trim();
    if (!iface) { showToast('Enter interface name', 'warning'); return; }
    try {
      const d = await _seclabApi('/api/security/wifi/capture/start', _seclabJson({interface:iface, bssid:document.querySelector('#seclab-wifi-bssid')?.value.trim()||null, channel:document.querySelector('#seclab-wifi-channel')?.value.trim()||null, duration_seconds:parseInt(document.querySelector('#seclab-wifi-duration')?.value||'60'), authorization_confirmed:true}));
      if (d.run_id) _seclabStartRun(d.run_id); else throw new Error('No run id returned');
    } catch (e) { showToast(e.message, 'warning'); }
  });
}

function _seclabAircrackStart() {
  _seclabShowConfirm('Test this capture file with Aircrack-ng?', async () => {
    const capId = await _seclabUploadFile(document.querySelector('#seclab-aircrack-cap-file'), 'pcap');
    const wlId  = await _seclabUploadFile(document.querySelector('#seclab-aircrack-wl-file'), 'wordlist');
    if (!capId || !wlId) { showToast('Select both a capture file and wordlist', 'warning'); return; }
    try {
      const d = await _seclabApi('/api/security/wifi/aircrack/start', _seclabJson({capture_file_id:capId, wordlist_file_id:wlId, bssid:document.querySelector('#seclab-aircrack-bssid')?.value.trim()||null, authorization_confirmed:true}));
      if (d.run_id) _seclabStartRun(d.run_id); else throw new Error('No run id returned');
    } catch (e) { showToast(e.message, 'warning'); }
  });
}

async function _seclabShodanSave() {
  const key = document.querySelector('#seclab-shodan-key')?.value.trim();
  try {
    await _seclabApi('/api/security/shodan/settings', _seclabJson({api_key:key}));
    showToast('Shodan API key saved', 'info');
  } catch (e) { showToast(e.message, 'warning'); }
}

async function _seclabShodanCheck() {
  const target_ip = document.querySelector('#seclab-shodan-device-select')?.value || null;
  const query_ip  = document.querySelector('#seclab-shodan-ip')?.value.trim() || null;
  try {
    const d = await _seclabApi('/api/security/shodan/check', _seclabJson({target_ip, query_ip}));
    if (d.run_id) _seclabStartRun(d.run_id); else throw new Error('No run id returned');
  } catch (e) { showToast(e.message, 'warning'); }
}

async function _seclabPopulateShodanDevices() {
  const sel = document.querySelector('#seclab-shodan-device-select');
  if (!sel) return;
  try {
    const r = await fetch('/api/devices');
    const data = await r.json();
    sel.innerHTML = '<option value="">— Auto WAN IP —</option>';
    (data.devices || data || []).forEach(dev => {
      const ip = dev.ip || '';
      const label = (dev.label || dev.hostname || dev.vendor || 'Unknown') + (ip ? ' (' + ip + ')' : '');
      if (ip) sel.innerHTML += '<option value="' + escapeHtml(ip) + '">' + escapeHtml(label) + '</option>';
    });
  } catch {}
}

function _seclabShowConfirm(msg, onYes) {
  const modal  = document.querySelector('#seclab-confirm-modal');
  const yesBtn = document.querySelector('#seclab-confirm-yes-btn');
  const canBtn = document.querySelector('#seclab-confirm-cancel-btn');
  const msgEl  = document.querySelector('#seclab-confirm-msg');
  if (!modal) { if (confirm(msg)) onYes(); return; }
  if (msgEl) msgEl.textContent = msg;
  yesBtn.onclick = () => { modal.style.display = 'none'; onYes(); };
  canBtn.onclick = () => { modal.style.display = 'none'; };
  modal.style.display = 'flex';
}

function initSecurityLab() {
  const bind = (sel, fn) => { const el = document.querySelector(sel); if (el) el.onclick = fn; };
  bind('#seclab-wsl-check-btn',       _seclabCheckWSL);
  bind('#seclab-wsl-install-btn',     _seclabInstallTools);
  bind('#seclab-nikto-start-btn',     _seclabNiktoStart);
  bind('#seclab-hydra-start-btn',     _seclabHydraStart);
  bind('#seclab-john-start-btn',      _seclabJohnStart);
  bind('#seclab-msf-start-btn',       _seclabMsfStart);
  bind('#seclab-wifi-capture-btn',    _seclabWifiCaptureStart);
  bind('#seclab-aircrack-start-btn',  _seclabAircrackStart);
  bind('#seclab-shodan-save-btn',     _seclabShodanSave);
  bind('#seclab-shodan-check-btn',    _seclabShodanCheck);
  bind('#seclab-history-refresh-btn', loadSecurityLabHistory);

  document.querySelectorAll('[data-seclab-tab]').forEach(btn => {
    btn.onclick = () => {
      const tab = btn.getAttribute('data-seclab-tab');
      document.querySelectorAll('[data-seclab-tab]').forEach(b => b.classList.toggle('active', b === btn));
      ['vulnerability','password','exploit','wifi','exposure'].forEach(name => {
        const p = document.querySelector('#seclab-tab-' + name);
        if (p) p.style.display = name === tab ? '' : 'none';
      });
    };
  });
}

function _seclabAppendProgress(text) {
  const el = document.querySelector('#seclab-progress');
  if (!el || text == null) return;
  el.textContent += String(text);
  el.scrollTop = el.scrollHeight;
}

function _seclabStatusBadge(s) {
  const c = {running:'#2563eb',succeeded:'#16a34a',failed:'#dc2626',cancelled:'#6b7280'}[s] || '#6b7280';
  return '<span class="seclab-badge" style="background:' + c + '">' + escapeHtml(s||'-') + '</span>';
}

function _seclabRiskBadge(r) {
  const map = {critical:['#dc2626','#fff'],high:['#f97316','#fff'],medium:['#d97706','#fff'],low:['#16a34a','#fff'],info:['#6b7280','#fff']};
  const pair = map[(r||'info').toLowerCase()] || map.info;
  return '<span class="seclab-badge" style="background:' + pair[0] + ';color:' + pair[1] + '">' + escapeHtml(r||'info') + '</span>';
}

function _seclabFmtTime(v) {
  if (!v) return '-';
  const d = new Date(v);
  return isNaN(d.getTime()) ? String(v) : d.toLocaleString();
}

initSecurityLab();

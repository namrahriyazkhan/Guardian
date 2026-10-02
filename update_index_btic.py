with open('templates/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Replace HTML section for BTIC
html_start = content.find('<div class="btic-card" id="bticPanel">')
html_end = content.find('<!-- TAB 8 — SYSTEM HEALTH -->')
if html_start == -1 or html_end == -1:
    print('Error finding BTIC HTML markers')
    exit(1)

NEW_BTIC_HTML = '''<div class="btic-card" id="bticPanel">
      <div class="btic-stats-row">
        <div class="btic-stat"><span class="btic-stat-val" id="bticThreats" style="color:var(--danger)">0</span><span class="btic-stat-lbl">Threats Detected</span></div>
        <div class="btic-stat"><span class="btic-stat-val" id="bticBlocked" style="color:var(--warn)">0</span><span class="btic-stat-lbl">Blocked Sites</span></div>
        <div class="btic-stat"><span class="btic-stat-val" id="bticFlagged" style="color:var(--accent)">0</span><span class="btic-stat-lbl">Downloads Flagged</span></div>
        <div class="btic-stat"><span class="btic-stat-val" id="bticScore" style="color:var(--ok)">100</span><span class="btic-stat-lbl">Security Score /100</span></div>
      </div>
      <div class="btic-tabs">
        <button class="btic-tab active" onclick="bticTab('overview')">Overview</button>
        <button class="btic-tab" onclick="bticTab('web')">Web Activity</button>
        <button class="btic-tab" onclick="bticTab('downloads')">Downloads</button>
        <button class="btic-tab" onclick="bticTab('permissions')">Permissions</button>
        <button class="btic-tab" onclick="bticTab('redirects')">Redirects</button>
        <button class="btic-tab" onclick="bticTab('timeline')">Threat Timeline</button>
      </div>

      <!-- OVERVIEW PANEL -->
      <div class="btic-panel active" id="bticPanelOverview">
        <div id="bticOverviewContent">
          <!-- Dynamically populated in real-time -->
        </div>
      </div>

      <!-- WEB ACTIVITY PANEL -->
      <div class="btic-panel" id="bticPanelWeb">
        <table class="btic-table">
          <thead><tr><th>Time</th><th>Website</th><th>Browser</th><th>Status</th><th>Risk %</th><th>Reason</th></tr></thead>
          <tbody id="bticWebBody">
            <tr><td colspan="6" style="text-align:center;color:var(--muted);padding:1.2rem;font-family:var(--mono);font-size:10px;">No websites visited in this session yet — browse any website and it will appear here live</td></tr>
          </tbody>
        </table>
      </div>

      <!-- DOWNLOADS PANEL -->
      <div class="btic-panel" id="bticPanelDownloads">
        <table class="btic-table">
          <thead><tr><th>Time</th><th>File</th><th>Size</th><th>Status</th><th>Reason</th></tr></thead>
          <tbody id="bticDlBody">
            <tr><td colspan="5" style="text-align:center;color:var(--muted);padding:1.2rem;font-family:var(--mono);font-size:10px;">No files downloaded in this session yet</td></tr>
          </tbody>
        </table>
      </div>

      <!-- PERMISSIONS PANEL -->
      <div class="btic-panel" id="bticPanelPermissions">
        <table class="btic-table">
          <thead><tr><th>Time</th><th>Application / Browser</th><th>Permission Requested</th><th>Status</th></tr></thead>
          <tbody id="bticPermBody">
            <tr><td colspan="4" style="text-align:center;color:var(--muted);padding:1.2rem;font-family:var(--mono);font-size:10px;">No hardware permission access detected</td></tr>
          </tbody>
        </table>
      </div>

      <!-- REDIRECTS PANEL -->
      <div class="btic-panel" id="bticPanelRedirects">
        <table class="btic-table">
          <thead><tr><th>Time</th><th>Redirect Chain</th><th>Status</th><th>Reason</th></tr></thead>
          <tbody id="bticRedirectBody">
            <tr><td colspan="4" style="text-align:center;color:var(--muted);padding:1.2rem;font-family:var(--mono);font-size:10px;">No cross-domain redirect chains detected</td></tr>
          </tbody>
        </table>
      </div>

      <!-- THREAT TIMELINE PANEL -->
      <div class="btic-panel" id="bticPanelTimeline">
        <div class="btic-timeline-list" id="bticTimelineList">
          <div class="btic-empty">No threat events recorded in this session yet</div>
        </div>
      </div>

      <!-- SIMULATION CONTROLS -->
      <div class="btic-sim-section">
        <div class="btic-sim-label">🎭 SIMULATE BROWSER ATTACK</div>
        <div class="btic-sim-types">
          <div class="btic-sim-type" onclick="bticSelectSim(this,'phishing')">○ Phishing</div>
          <div class="btic-sim-type" onclick="bticSelectSim(this,'malicious_download')">○ Malicious Download</div>
          <div class="btic-sim-type" onclick="bticSelectSim(this,'permission_abuse')">○ Permission Abuse</div>
          <div class="btic-sim-type" onclick="bticSelectSim(this,'redirect_attack')">○ Redirect Attack</div>
          <div class="btic-sim-type selected" onclick="bticSelectSim(this,'full')">● Full Attack Chain</div>
        </div>
        <div style="display:flex;align-items:center;">
          <button class="btic-sim-btn" onclick="bticRunSim()">🚨 Start Simulation</button>
          <button class="btic-reset-btn" onclick="bticReset()">↺ Reset</button>
          <button class="btic-reset-btn" onclick="bticExportCSV()" style="border-color:rgba(79,70,229,.25);color:var(--accent);">↓ Export CSV</button>
        </div>
      </div>
    </div>
  </div>
</div>
'''

# 2. Replace JS section for BTIC
js_start = content.find('/* ═══════════════════════════════════════════════════════════════════\n   BROWSER THREAT INTELLIGENCE CENTER')
js_end = content.find('/* ═══════════════════════════════════════════════════════════════════\n   SYSTEM HEALTH CHARTS')
if js_start == -1 or js_end == -1:
    print('Error finding BTIC JS markers')
    exit(1)

NEW_BTIC_JS = '''/* ═══════════════════════════════════════════════════════════════════
   BROWSER THREAT INTELLIGENCE CENTER (Real-Time Engine)
═══════════════════════════════════════════════════════════════════ */
var _bticSelectedSim = 'full';
var _bticData = {websites:[],downloads:[],permissions:[],redirects:[],timeline:[],active_browsers:[],threats_detected:0,blocked_sites:0,downloads_flagged:0,security_score:100};

function bticTab(tab){
  document.querySelectorAll('.btic-tab').forEach(function(t){t.classList.remove('active');});
  document.querySelectorAll('.btic-panel').forEach(function(p){p.classList.remove('active');});
  var tabMap={overview:'bticPanelOverview',web:'bticPanelWeb',downloads:'bticPanelDownloads',permissions:'bticPanelPermissions',redirects:'bticPanelRedirects',timeline:'bticPanelTimeline'};
  var tabs=document.querySelectorAll('.btic-tab');
  var tabNames=['overview','web','downloads','permissions','redirects','timeline'];
  tabNames.forEach(function(name,i){if(name===tab&&tabs[i])tabs[i].classList.add('active');});
  var panel=document.getElementById(tabMap[tab]);if(panel)panel.classList.add('active');
}

function bticSelectSim(el, type){
  document.querySelectorAll('.btic-sim-type').forEach(function(t){t.classList.remove('selected');t.textContent=t.textContent.replace('●','○');});
  el.classList.add('selected');
  el.textContent=el.textContent.replace('○','●');
  _bticSelectedSim=type;
}

function bticRunSim(){
  fetch('/api/browser_simulate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:_bticSelectedSim})})
  .then(function(r){return r.json();})
  .then(function(data){
    _bticData=data.data||_bticData;
    bticRenderAll();
    showToast('🌐 Browser simulation: '+_bticSelectedSim.replace('_',' '),'var(--danger)');
    bticTab_noEvent('timeline');
  }).catch(function(e){console.error('[BTIC]',e);showToast('⚠ Simulation failed','var(--warn)');});
}

function bticTab_noEvent(tab){
  document.querySelectorAll('.btic-tab').forEach(function(t,i){t.classList.remove('active');if(['overview','web','downloads','permissions','redirects','timeline'][i]===tab)t.classList.add('active');});
  document.querySelectorAll('.btic-panel').forEach(function(p){p.classList.remove('active');});
  var tabMap={overview:'bticPanelOverview',web:'bticPanelWeb',downloads:'bticPanelDownloads',permissions:'bticPanelPermissions',redirects:'bticPanelRedirects',timeline:'bticPanelTimeline'};
  var panel=document.getElementById(tabMap[tab]);if(panel)panel.classList.add('active');
}

function bticReset(){
  fetch('/api/browser_reset',{method:'POST'}).then(function(){
    _bticData={websites:[],downloads:[],permissions:[],redirects:[],timeline:[],active_browsers:[],threats_detected:0,blocked_sites:0,downloads_flagged:0,security_score:100};
    bticRenderAll();showToast('↺ Browser data reset','var(--ok)');
  }).catch(function(){});
}

function bticRenderAll(){
  // Stats
  document.getElementById('bticThreats').textContent=_bticData.threats_detected||0;
  document.getElementById('bticBlocked').textContent=_bticData.blocked_sites||0;
  document.getElementById('bticFlagged').textContent=_bticData.downloads_flagged||0;
  var sc=_bticData.security_score||100;
  var scoreEl=document.getElementById('bticScore');
  if(scoreEl){
    scoreEl.textContent=sc;
    scoreEl.style.color=sc<50?'var(--danger)':sc<75?'var(--warn)':'var(--ok)';
  }
  var badge=document.getElementById('bticStatusBadge'),txt=document.getElementById('bticStatusText');
  if(badge&&txt){
    if(_bticData.threats_detected>0){badge.className='btic-status-badge threat';txt.textContent='THREATS DETECTED';}
    else{badge.className='btic-status-badge';txt.textContent='MONITORING';}
  }

  // 1. OVERVIEW PANEL (Real-Time Insight Dashboard)
  var ov=document.getElementById('bticOverviewContent');
  if(ov){
    var browsers = (_bticData.active_browsers && _bticData.active_browsers.length > 0) ? _bticData.active_browsers.join(', ') : 'None Active';
    var sitesCount = (_bticData.websites||[]).length;
    var dlsCount = (_bticData.downloads||[]).length;
    var permsCount = (_bticData.permissions||[]).length;
    
    var recentSites = (_bticData.websites||[]).slice(0, 4);
    var recentDls = (_bticData.downloads||[]).slice(0, 4);

    var html = '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:12px;">'
      + '<div style="background:rgba(255,255,255,.55);border:1px solid rgba(79,70,229,.15);border-radius:8px;padding:10px;text-align:center;">'
      + '<span style="font-family:var(--mono);font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:700;">Active Browsers</span>'
      + '<div style="font-family:var(--mono);font-size:12px;font-weight:700;color:var(--text);margin-top:4px;"><span style="color:#22c55e;">●</span> '+browsers+'</div>'
      + '</div>'
      + '<div style="background:rgba(255,255,255,.55);border:1px solid rgba(79,70,229,.15);border-radius:8px;padding:10px;text-align:center;">'
      + '<span style="font-family:var(--mono);font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:700;">Sites Monitored</span>'
      + '<div style="font-family:var(--mono);font-size:18px;font-weight:800;color:var(--accent);margin-top:2px;">'+sitesCount+'</div>'
      + '</div>'
      + '<div style="background:rgba(255,255,255,.55);border:1px solid rgba(79,70,229,.15);border-radius:8px;padding:10px;text-align:center;">'
      + '<span style="font-family:var(--mono);font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:700;">Session Downloads</span>'
      + '<div style="font-family:var(--mono);font-size:18px;font-weight:800;color:var(--text);margin-top:2px;">'+dlsCount+'</div>'
      + '</div>'
      + '<div style="background:rgba(255,255,255,.55);border:1px solid rgba(79,70,229,.15);border-radius:8px;padding:10px;text-align:center;">'
      + '<span style="font-family:var(--mono);font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:700;">App Permissions</span>'
      + '<div style="font-family:var(--mono);font-size:18px;font-weight:800;color:var(--ok);margin-top:2px;">'+permsCount+'</div>'
      + '</div>'
      + '</div>';

    html += '<div style="display:flex;align-items:center;justify-content:space-between;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.25);border-radius:8px;padding:8px 14px;margin-bottom:12px;font-family:var(--mono);font-size:11px;color:#15803d;font-weight:700;">'
      + '<span>🛡️ Real-Time Protection Status: ACTIVE</span>'
      + '<span style="color:var(--muted);font-weight:500;">Web Shield · Download Guard · Hardware Consent · Redirect Interception</span>'
      + '</div>';

    html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">'
      + '<div style="background:rgba(255,255,255,.45);border:1px solid rgba(79,70,229,.12);border-radius:8px;padding:10px;">'
      + '<div style="font-family:var(--mono);font-size:11px;font-weight:700;color:var(--accent);margin-bottom:8px;">🌐 Recent Web Activity</div>'
      + (recentSites.length ? recentSites.map(function(s){return '<div style="display:flex;align-items:center;justify-content:space-between;padding:4px 0;border-bottom:1px solid rgba(0,0,0,.05);font-family:var(--mono);font-size:11px;"><span style="color:var(--text);font-weight:600;">'+s.url+'</span><span class="btic-badge '+(s.status==='Safe'?'safe':'risk')+'">'+s.status+'</span></div>';}).join('') : '<div style="font-family:var(--mono);font-size:10px;color:var(--muted);padding:8px 0;">No websites visited yet.</div>')
      + '</div>'
      + '<div style="background:rgba(255,255,255,.45);border:1px solid rgba(79,70,229,.12);border-radius:8px;padding:10px;">'
      + '<div style="font-family:var(--mono);font-size:11px;font-weight:700;color:var(--accent);margin-bottom:8px;">📥 Recent Downloads</div>'
      + (recentDls.length ? recentDls.map(function(d){return '<div style="display:flex;align-items:center;justify-content:space-between;padding:4px 0;border-bottom:1px solid rgba(0,0,0,.05);font-family:var(--mono);font-size:11px;"><span style="color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:180px;">'+d.file+'</span><span class="btic-badge '+(d.status==='Allowed'?'safe':'blocked')+'">'+d.status+'</span></div>';}).join('') : '<div style="font-family:var(--mono);font-size:10px;color:var(--muted);padding:8px 0;">No session downloads detected.</div>')
      + '</div>'
      + '</div>';

    ov.innerHTML = html;
  }

  // 2. Web Activity
  var wb=document.getElementById('bticWebBody'),sites=_bticData.websites||[];
  if(!sites.length){wb.innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:1.2rem;font-family:var(--mono);font-size:10px;">No websites visited in this session yet — browse any website and it will appear here live</td></tr>';}
  else{wb.innerHTML=sites.map(function(s){var cls=s.status==='Safe'?'safe':s.status==='High Risk'?'risk':'suspicious';return'<tr><td style="color:var(--muted);font-size:10px;">'+(s.time||'--')+'</td><td style="color:var(--accent);font-weight:600;">'+s.url+'</td><td style="color:var(--text);font-size:10px;">'+(s.browser||'Google Chrome')+'</td><td><span class="btic-badge '+cls+'">'+s.status+'</span></td><td style="color:'+(s.risk>70?'var(--danger)':s.risk>30?'var(--warn)':'var(--ok)')+';font-weight:700;">'+s.risk+'%</td><td style="color:var(--muted)">'+s.reason+'</td></tr>';}).join('');}

  // 3. Downloads
  var db=document.getElementById('bticDlBody'),dls=_bticData.downloads||[];
  if(!dls.length){db.innerHTML='<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:1.2rem;font-family:var(--mono);font-size:10px;">No files downloaded in this session yet</td></tr>';}
  else{db.innerHTML=dls.map(function(d){var cls=d.status==='Blocked'?'blocked':d.status==='Suspicious'?'suspicious':'allowed';return'<tr><td style="color:var(--muted);font-size:10px;">'+(d.time||'--')+'</td><td style="color:var(--text);font-weight:600;">'+d.file+'</td><td style="color:var(--muted);font-size:10px;">'+(d.size||'--')+'</td><td><span class="btic-badge '+cls+'">'+d.status+'</span></td><td style="color:var(--muted)">'+d.reason+'</td></tr>';}).join('');}

  // 4. Permissions
  var pb=document.getElementById('bticPermBody'),perms=_bticData.permissions||[];
  if(!perms.length){pb.innerHTML='<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:1.2rem;font-family:var(--mono);font-size:10px;">No hardware permission access detected</td></tr>';}
  else{pb.innerHTML=perms.map(function(p){var cls=p.status==='Blocked'?'blocked':'allowed';return'<tr><td style="color:var(--muted);font-size:10px;">'+(p.time||'Active')+'</td><td style="color:var(--accent);font-weight:600;">'+p.site+'</td><td style="color:var(--text)">'+p.request+'</td><td><span class="btic-badge '+cls+'">'+p.status+'</span></td></tr>';}).join('');}

  // 5. Redirects
  var rb=document.getElementById('bticRedirectBody'),reds=_bticData.redirects||[];
  if(!reds.length){rb.innerHTML='<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:1.2rem;font-family:var(--mono);font-size:10px;">No cross-domain redirect chains detected</td></tr>';}
  else{rb.innerHTML=reds.map(function(r){var chain=(r.chain||[]).map(function(hop,i){return'<div class="btic-redirect-hop">'+hop+'</div>'+(i<r.chain.length-1?'<div class="btic-redirect-arrow">↓</div>':'');}).join('');return'<tr><td style="color:var(--muted);font-size:10px;">'+(r.time||'--')+'</td><td><div class="btic-redirect-chain">'+chain+'</div></td><td><span class="btic-badge risk">'+r.status+'</span></td><td style="color:var(--muted)">'+r.reason+'</td></tr>';}).join('');}

  // 6. Threat Timeline
  var tl=document.getElementById('bticTimelineList'),events=_bticData.timeline||[];
  if(!events.length){tl.innerHTML='<div class="btic-empty">No threat events recorded in this session yet</div>';}
  else{tl.innerHTML=events.map(function(e){var ic=e.event.indexOf('Block')>-1||e.event.indexOf('Threat')>-1?'🔴':e.event.indexOf('Detect')>-1||e.event.indexOf('Redirect')>-1||e.event.indexOf('🟡')>-1?'🟡':'🟢';return'<div class="btic-tl-item"><div class="btic-tl-time">'+e.time+'</div><div>'+ic+'</div><div class="btic-tl-event">'+e.event+'</div><div class="btic-tl-detail">'+e.detail+'</div></div>';}).join('');}
}

function bticExportCSV(){
  var d = _bticData;
  var now = new Date().toLocaleString('en-IN');
  var sc = d.security_score || 100;
  var scCol = sc < 50 ? '#D63355' : sc < 75 ? '#C47A0F' : '#0F8A5C';

  var websiteRows = (d.websites || []).map(function(s, i){
    var statusCol = s.status === 'High Risk' ? '#D63355' : s.status === 'Suspicious' ? '#C47A0F' : '#0F8A5C';
    var riskCol   = s.risk > 70 ? '#D63355' : s.risk > 30 ? '#C47A0F' : '#0F8A5C';
    return '<tr style="background:'+(i%2===0?'#f8fafc':'#ffffff')+';">'
      +'<td style="color:#64748b;font-size:9px;">'+( s.time||'--')+'</td>'
      +'<td style="color:#0284c7;font-weight:700;">'+s.url+'</td>'
      +'<td><span style="background:'+statusCol+'22;color:'+statusCol+';border:1px solid '+statusCol+'55;padding:2px 10px;border-radius:4px;font-size:10px;font-weight:700;">'+s.status+'</span></td>'
      +'<td style="color:'+riskCol+';font-weight:700;">'+s.risk+'%</td>'
      +'<td style="color:#0f172a;">'+s.reason+'</td>'
      +'</tr>';
  }).join('') || '<tr><td colspan="5" style="text-align:center;color:#64748b;padding:1rem;">No website data</td></tr>';

  var dlRows = (d.downloads || []).map(function(dl, i){
    var cls = dl.status === 'Blocked' ? '#D63355' : dl.status === 'Suspicious' ? '#C47A0F' : '#0F8A5C';
    return '<tr style="background:'+(i%2===0?'#f8fafc':'#ffffff')+';">'
      +'<td style="color:#0f172a;font-weight:700;">'+dl.file+'</td>'
      +'<td><span style="background:'+cls+'22;color:'+cls+';border:1px solid '+cls+'55;padding:2px 10px;border-radius:4px;font-size:10px;font-weight:700;">'+dl.status+'</span></td>'
      +'<td style="color:#64748b;">'+dl.reason+'</td>'
      +'</tr>';
  }).join('') || '<tr><td colspan="3" style="text-align:center;color:#64748b;padding:1rem;">No download data</td></tr>';

  var permRows = (d.permissions || []).map(function(p, i){
    var cls = p.status === 'Blocked' ? '#D63355' : '#0F8A5C';
    return '<tr style="background:'+(i%2===0?'#f8fafc':'#ffffff')+';">'
      +'<td style="color:#0284c7;">'+p.site+'</td>'
      +'<td style="color:#0f172a;">'+p.request+'</td>'
      +'<td><span style="background:'+cls+'22;color:'+cls+';border:1px solid '+cls+'55;padding:2px 10px;border-radius:4px;font-size:10px;font-weight:700;">'+p.status+'</span></td>'
      +'</tr>';
  }).join('') || '<tr><td colspan="3" style="text-align:center;color:#64748b;padding:1rem;">No permission data</td></tr>';

  var redRows = (d.redirects || []).map(function(r, i){
    var chain = (r.chain || []).join(' → ');
    return '<tr style="background:'+(i%2===0?'#f8fafc':'#ffffff')+';">'
      +'<td style="color:#0f172a;font-weight:700;">'+chain+'</td>'
      +'<td><span style="background:#D6335522;color:#D63355;border:1px solid #D6335555;padding:2px 10px;border-radius:4px;font-size:10px;font-weight:700;">'+r.status+'</span></td>'
      +'<td style="color:#64748b;">'+r.reason+'</td>'
      +'</tr>';
  }).join('') || '<tr><td colspan="3" style="text-align:center;color:#64748b;padding:1rem;">No redirect data</td></tr>';

  var tlRows = (d.timeline || []).map(function(e, i){
    return '<tr style="background:'+(i%2===0?'#f8fafc':'#ffffff')+';">'
      +'<td style="color:#64748b;font-size:9px;white-space:nowrap;">'+e.time+'</td>'
      +'<td style="color:#0f172a;font-weight:700;">'+e.event+'</td>'
      +'<td style="color:#64748b;">'+e.detail+'</td>'
      +'</tr>';
  }).join('') || '<tr><td colspan="3" style="text-align:center;color:#64748b;padding:1rem;">No timeline events</td></tr>';

  var reportHTML = '<!DOCTYPE html><html><head><meta charset="utf-8">'
    +'<title>Guardian Browser Threat Intelligence Report</title>'
    +'<style>'
    +'body{font-family:monospace,sans-serif;background:#ffffff;color:#0f172a;padding:2rem;margin:0;}'
    +'h1{color:#4F46E5;margin-bottom:4px;font-size:20px;}'
    +'.meta{color:#64748b;font-size:11px;margin-bottom:1.5rem;border-bottom:2px solid #e2e8f0;padding-bottom:10px;}'
    +'.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:1.5rem;}'
    +'.stat-box{border:1px solid #e2e8f0;padding:10px;border-radius:8px;text-align:center;}'
    +'.stat-val{font-size:20px;font-weight:800;}'
    +'.stat-lbl{font-size:10px;color:#64748b;text-transform:uppercase;}'
    +'table{width:100%;border-collapse:collapse;margin-bottom:1.5rem;font-size:12px;}'
    +'th{background:#4F46E5;color:#ffffff;padding:6px 8px;text-align:left;font-size:11px;}'
    +'td{padding:6px 8px;border-bottom:1px solid #e2e8f0;}'
    +'</style></head><body>'
    +'<h1>🛡️ Guardian Browser Threat Intelligence Report</h1>'
    +'<div class="meta">Generated: '+now+' | Real-time security telemetry</div>'
    +'<div class="stats-grid">'
    +'<div class="stat-box"><div class="stat-val" style="color:#dc2626;">'+(d.threats_detected||0)+'</div><div class="stat-lbl">Threats Detected</div></div>'
    +'<div class="stat-box"><div class="stat-val" style="color:#ea580c;">'+(d.blocked_sites||0)+'</div><div class="stat-lbl">Blocked Sites</div></div>'
    +'<div class="stat-box"><div class="stat-val" style="color:#4F46E5;">'+(d.downloads_flagged||0)+'</div><div class="stat-lbl">Downloads Flagged</div></div>'
    +'<div class="stat-box"><div class="stat-val" style="color:'+scCol+';">'+sc+'</div><div class="stat-lbl">Security Score</div></div>'
    +'</div>'
    +'<h3>Web Activity</h3><table><thead><tr><th>Time</th><th>Website</th><th>Status</th><th>Risk</th><th>Reason</th></tr></thead><tbody>'+websiteRows+'</tbody></table>'
    +'<h3>Downloads</h3><table><thead><tr><th>File</th><th>Status</th><th>Reason</th></tr></thead><tbody>'+dlRows+'</tbody></table>'
    +'<h3>Permissions</h3><table><thead><tr><th>Application</th><th>Requested</th><th>Status</th></tr></thead><tbody>'+permRows+'</tbody></table>'
    +'<h3>Redirects</h3><table><thead><tr><th>Redirect Chain</th><th>Status</th><th>Reason</th></tr></thead><tbody>'+redRows+'</tbody></table>'
    +'<h3>Threat Timeline</h3><table><thead><tr><th>Time</th><th>Event</th><th>Detail</th></tr></thead><tbody>'+tlRows+'</tbody></table>'
    +'</body></html>';

  var blob = new Blob([reportHTML], {type: 'text/html;charset=utf-8'});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'guardian_browser_report_' + Date.now() + '.html';
  a.click();
  showToast('Browser report exported successfully', 'var(--accent)');
}

function bticFetchAndRender(){
  fetch('/api/browser_data').then(function(r){return r.json();}).then(function(data){
    _bticData=data;
    bticRenderAll();
  }).catch(function(e){console.warn('[BTIC] fetch error',e);});
}

setInterval(bticFetchAndRender, 3000);
setTimeout(bticFetchAndRender, 1000);
'''

# Apply JS replacement first
content = content[:js_start] + NEW_BTIC_JS + '\n' + content[js_end:]

# Re-locate HTML markers
html_start = content.find('<div class="btic-card" id="bticPanel">')
html_end = content.find('<!-- TAB 8 — SYSTEM HEALTH -->')
content = content[:html_start] + NEW_BTIC_HTML + '\n' + content[html_end:]

with open('templates/index.html', 'w', encoding='utf-8') as f:
    f.write(content)

print('Updated templates/index.html BTIC sections successfully!')

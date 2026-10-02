/* ════ GUARDIAN WELCOME TOUR — JS ════ */
(function(){

var WT_STEPS = [
  {
    panel: null,
    caption: "⚡ Every second, your system is a battlefield.",
    text: "Right now, as you hear this, thousands of malicious programs are actively searching for unprotected systems. Most users never know they have been compromised — until it is already too late. Files encrypted. Data stolen. Privacy gone. The attack had been running silently for weeks. Guardian was built so that never happens to you."
  },
  {
    panel: null,
    caption: "😴 The Silent Killer — Alert Fatigue.",
    text: "Imagine receiving hundreds of security alerts every single day. At first, you check every one. Then you start skipping a few. Then most. Then all. This is called Alert Fatigue — and it is the number one reason security systems fail. Not because the threat was invisible. But because the user stopped paying attention. Guardian was designed specifically to solve this."
  },
  {
    panel: "dashboardOverviewPanel",
    caption: "📊 One screen. Everything that matters.",
    text: "Guardian brings your entire security picture into a single intelligent dashboard. No jumping between tools. No complex logs to decode. Every threat, every application, every suspicious event — visible, explained, and actionable. Right here."
  },
  {
    panel: "bticPanel",
    caption: "🌐 Your browser is the most attacked surface on your device.",
    text: "Phishing sites, malicious downloads, silent redirects — most attacks begin the moment you open a browser tab. Guardian watches every connection your browser makes, flags dangerous domains instantly, and gives you the evidence before the damage begins."
  },
  {
    panel: "runningAppsPanel",
    caption: "⚙ Traditional antivirus only checks files. Guardian watches behavior.",
    text: "A file can look completely clean and still destroy your system. Guardian does not just scan files. It continuously observes how every application behaves — CPU usage, memory patterns, process activity — and flags anything that acts suspiciously, even if no one has ever seen it before."
  },
  {
    panel: "securityAlertsPanel",
    caption: "🚨 Not just alerts — explanations.",
    text: "Most security tools scream an alert and leave you confused. Guardian is different. Every detection comes with clear evidence, plain language reasoning, and specific guidance. You always know exactly what happened, why it was flagged, and what to do next."
  },
  {
    panel: "tvcFab",
    caption: "🧠 Verify first. React with confidence.",
    text: "When unusual activity appears, Guardian does not panic. It calculates a precise suspicion level using multiple indicators — browser activity, running processes, system changes, and attack patterns — then presents all evidence clearly, letting you decide whether to verify, monitor, or escalate. You stay in control."
  },
  {
    panel: "kcPanel",
    caption: "⛓ See the full story of an attack, not just the ending.",
    text: "Attackers rarely strike in one move. They move slowly, quietly, across multiple stages. Guardian reconstructs every step of that journey into a clear visual timeline — so you can see exactly how an incident began, how it evolved, and where it stands right now."
  },
  {
    panel: "reportsPanel",
    caption: "📄 Professional reports. Zero extra effort.",
    text: "Every event Guardian detects is automatically documented — threats found, applications monitored, browser activity recorded, actions taken. A complete security report is always one click away. Perfect for review, investigation, or documentation."
  },
  {
    panel: "guardianFab",
    caption: "🔔 Your personal security analyst. Always watching.",
    text: "Guardian does not just display data. It thinks alongside you. Ask it anything about your current security situation and it responds instantly with context-aware answers. It also proactively alerts you the moment something suspicious appears — so you never have to constantly watch the dashboard yourself."
  },
  {
    panel: null,
    caption: "🛡 This is Guardian. Built different. Built for you.",
    text: "Other security tools protect systems. Guardian protects people. It understands that the biggest vulnerability is not always in the software — it is in the human managing it. Guardian fights alert fatigue, explains every threat in plain language, and keeps you informed without overwhelming you. Your system is now being monitored. Welcome to Guardian. Stay aware. Stay protected."
  }
];

var STORAGE_KEY = "guardianWelcomeTourDisabled";
var wtCurrentStep = 0;
var wtActiveGlowEl = null;
var wtPaused = false;
var wtDone = false;

var overlayEl, skipBtn, stepEl, captionEl, launchBtn, dontShowChk, initSeqEl;



var WT_TELEMETRY_LINES = [
  'Initializing Guardian...',
  'Watching processes...',
  'Monitoring browser...',
  'Scanning registry...',
  'Correlating events...',
  'Threat intelligence active...',
  'Guardian operational...'
];
var WT_STEP_TELEMETRY = {
  0: 'Threat feed online — global scan active...',
  1: 'Suppressing redundant alerts...',
  2: 'Rendering dashboard blueprint...',
  3: 'Browser watch engaged...',
  4: 'Process behavior analysis running...',
  5: 'Correlating alert evidence...',
  6: 'Threat verification scan running...',
  7: 'Reconstructing kill chain...',
  8: 'Compiling security report...',
  9: 'Guardian assistant online...',
  10: 'All systems operational — Guardian ready.'
};

var WT_STEP_TRUST_LABEL = {
  0:'Vulnerable', 1:'Vulnerable', 2:'Assessing', 3:'Aware', 4:'Aware',
  5:'Monitored', 6:'Monitored', 7:'Monitored', 8:'Secured', 9:'Secured', 10:'Protected'
};

var WT_CC_MODULES = [
  {key:'threat',   name:'Threat Feed'},
  {key:'browser',  name:'Browser Watch'},
  {key:'apps',     name:'Running Applications'},
  {key:'tvc',      name:'Threat Verification'},
  {key:'kc',       name:'Kill Chain'},
  {key:'reports',  name:'Reports'},
  {key:'guardian', name:'Guardian Assistant'}
];
var WT_STEP_MODULE_MAP = {0:'threat',3:'browser',4:'apps',6:'tvc',7:'kc',8:'reports',9:'guardian'};


var wtModuleStepMap = {};
Object.keys(WT_STEP_MODULE_MAP).forEach(function(stepIdx){
  var key = WT_STEP_MODULE_MAP[stepIdx];
  if(wtModuleStepMap[key] === undefined) wtModuleStepMap[key] = parseInt(stepIdx, 10);
});

var WT_FAKE_ALERTS = ['Malware','Trojan','Browser Threat','High CPU','Unknown Process','Registry Changed','Risk Detected','Unknown DLL','Browser Redirect'];

var WT_RING_R = 26;

var wtHoloCanvasA, wtHoloCanvasB, wtHoloCtxA, wtHoloCtxB;
var wtHoloActive = 'A';
var wtHoloRAF = null;
var wtHoloStartTime = 0;
var wtHoloCurrentStep = 0;
var wtPreviewStep = null; // 🆕 non-null while hovering a Command Center row

var WT_HOLO_MIN_WIDTH = 860;

// 🆕 live stats state
var wtMouseMoveCount = 0;
var wtThreatCount = 0;
var wtLiveStatsInterval = null;
var wtMouseListenerAttached = false;

function wtShouldShow(){
  return localStorage.getItem(STORAGE_KEY) !== "true";
}

function wtInit(){
  overlayEl     = document.getElementById('welcomeTourOverlay');
  skipBtn       = document.getElementById('wtSkipBtn');
  stepEl        = document.getElementById('wtStepIndicator');
  captionEl     = document.getElementById('wtCaption');
  launchBtn     = document.getElementById('wtLaunchBtn');
  dontShowChk   = document.getElementById('wtDontShowAgain');
  initSeqEl     = document.getElementById('wtInitSequence');

  if(!overlayEl) return;

  if(!wtShouldShow()){
    overlayEl.style.display = 'none';
    return;
  }

  overlayEl.classList.add('active');

  wtBuildHolograms();
  wtBuildGridFlashLayer();
  wtBuildCommandCenter();
  wtBuildTelemetry();
  wtBuildProgressRing();
  wtBuildLiveStats();     // 🆕
  wtStartLiveStats();     // 🆕
  wtAttachMouseTracking(); // 🆕

  skipBtn.addEventListener('click', wtSkip);
  launchBtn.addEventListener('click', wtLaunchClick);
  document.addEventListener('keydown', wtKeydown);

  setTimeout(wtStart, 700);
}

function wtSetCaption(text){
  captionEl.classList.add('fading');
  var t = text;
  setTimeout(function(){ captionEl.textContent = t; captionEl.classList.remove('fading'); }, 220);
}


function wtGlow(panelId){
  wtClearScanArtifacts();
  if(wtActiveGlowEl){ wtActiveGlowEl.classList.remove('wt-panel-glow'); wtActiveGlowEl = null; }
  if(!panelId) return;
  var el = document.getElementById(panelId);
  if(el){
    el.classList.add('wt-panel-glow');
    wtActiveGlowEl = el;
    wtRunPanelScan(el);
  }
}

function wtRunPanelScan(el){
  if(getComputedStyle(el).position === 'static') el.style.position = 'relative';
  var scan = document.createElement('div');
  scan.className = 'wt-scan-line';
  scan.setAttribute('data-wt-scan', '1');
  el.appendChild(scan);
  setTimeout(function(){
    if(scan.parentNode) scan.parentNode.removeChild(scan);
    var badge = document.createElement('div');
    badge.className = 'wt-scan-badge';
    badge.setAttribute('data-wt-scan', '1');
    badge.textContent = '✓ Verified';
    el.appendChild(badge);
    setTimeout(function(){
      if(badge.parentNode) badge.parentNode.removeChild(badge);
    }, 1200);
  }, 700);
}
function wtClearScanArtifacts(){
  var nodes = document.querySelectorAll('[data-wt-scan="1"]');
  nodes.forEach(function(n){ if(n.parentNode) n.parentNode.removeChild(n); });
}

function wtOnStepEnter(i){
  var step = WT_STEPS[i];
  wtSetCaption(step.caption);
  wtGlow(step.panel);
  wtUpdateProgressRing(i);
  wtSwapHologram(i);
  wtUpdateCommandCenter(i);
  wtReactToKeywords(step.caption + ' ' + step.text);
  wtPushTelemetry(WT_STEP_TELEMETRY[i]);

 
  if(i === 0){
    wtPushTelemetry(wtGetSystemInfoLine());
  }
}

function wtStart(){
  if(!('speechSynthesis' in window)){ wtFallback(); return; }
  wtSpeakStep(0);
}

function wtSpeakStep(i){
  if(i >= WT_STEPS.length){ wtDone = true; wtComplete(); return; }
  wtCurrentStep = i;
  var step = WT_STEPS[i];
  wtOnStepEnter(i);

  window.speechSynthesis.cancel();
  var u = new SpeechSynthesisUtterance(step.text);
  u.rate = 1.25;
  u.pitch = 1.0;
  u.volume = 1.0;
  u.onend = function(){ if(!wtPaused) wtSpeakStep(i + 1); };
  u.onerror = function(){ if(!wtPaused) wtSpeakStep(i + 1); };
  window.speechSynthesis.speak(u);
}

function wtFallback(){
  function next(i){
    if(i >= WT_STEPS.length){ wtDone = true; wtComplete(); return; }
    wtCurrentStep = i;
    wtOnStepEnter(i);
    setTimeout(function(){ next(i+1); }, 3000);
  }
  next(0);
}

function wtComplete(){
  wtGlow(null);
  wtSetCaption("🛡 Guardian is ready. Stay aware. Stay protected.");
  wtUpdateCommandCenter(WT_STEPS.length - 1);
  wtUpdateProgressRing(WT_STEPS.length - 1);
  launchBtn.disabled = false;
  launchBtn.classList.add('ready');
  launchBtn.textContent = "🛡 Launch Guardian Dashboard";
}

function wtSkip(){
  window.speechSynthesis && window.speechSynthesis.cancel();
  wtGlow(null);
  wtSavePref();
  wtClose();
}

function wtClose(){
  wtStopHolograms();
  wtStopLiveStats(); // 🆕
  overlayEl.classList.add('fading-out');
  overlayEl.classList.remove('active');
  setTimeout(function(){ overlayEl.style.display = 'none'; }, 520);
}

function wtLaunchClick(){
  if(launchBtn.disabled) return;
  window.speechSynthesis && window.speechSynthesis.cancel();
  wtGlow(null);
  wtSavePref();
  wtShowInit();
}

function wtShowInit(){
  var card = overlayEl.querySelector('.wt-glass-card');
  if(card) card.style.display = 'none';
  if(skipBtn) skipBtn.style.display = 'none';
  initSeqEl.classList.add('active');
  var lines = initSeqEl.querySelectorAll('.wt-init-line');
  lines.forEach(function(line, idx){
    setTimeout(function(){ line.classList.add('show'); }, idx * 300);
  });
  setTimeout(wtClose, lines.length * 300 + 700);
}

function wtSavePref(){
  if(dontShowChk && dontShowChk.checked) localStorage.setItem(STORAGE_KEY, "true");
}

function wtKeydown(e){
  if(!overlayEl.classList.contains('active')) return;
  if(e.key === 'Escape'){ wtSkip(); return; }
  if(e.code === 'Space' || e.key === ' '){
    e.preventDefault();
    if(!('speechSynthesis' in window)) return;
    if(window.speechSynthesis.speaking && !wtPaused){
      window.speechSynthesis.pause(); wtPaused = true;
      wtSetCaption("⏸ Paused — press Space to resume");
    } else if(wtPaused){
      window.speechSynthesis.resume(); wtPaused = false;
      wtSetCaption(WT_STEPS[wtCurrentStep].caption);
    }
  }
}

window.openGuardianWelcomeTour = function(){
  localStorage.removeItem(STORAGE_KEY); location.reload();
};

if(document.readyState === 'loading'){
  document.addEventListener('DOMContentLoaded', wtInit);
} else { wtInit(); }


function wtBuildProgressRing(){
  var wrap = document.createElement('div');
  wrap.className = 'wt-progress-ring-wrap';
  wrap.id = 'wtRingWrap';
  var size = 64, r = WT_RING_R, c = (2*Math.PI*r).toFixed(2);
  wrap.innerHTML =
    '<div style="position:relative;width:'+size+'px;height:'+size+'px;">' +
      '<svg width="'+size+'" height="'+size+'" viewBox="0 0 '+size+' '+size+'">' +
        '<circle class="wt-progress-ring-bg" cx="'+(size/2)+'" cy="'+(size/2)+'" r="'+r+'"/>' +
        '<circle id="wtRingFill" class="wt-progress-ring-fill" cx="'+(size/2)+'" cy="'+(size/2)+'" r="'+r+'" stroke-dasharray="'+c+'" stroke-dashoffset="'+c+'"/>' +
      '</svg>' +
      '<div class="wt-progress-ring-pct" id="wtRingPct">0%</div>' +
    '</div>' +
    '<div class="wt-progress-ring-lbl" id="wtRingLbl">Situational Awareness</div>';
  overlayEl.appendChild(wrap);
}

function wtLerpColor(c1, c2, t){
  var r1=parseInt(c1.substr(1,2),16), g1=parseInt(c1.substr(3,2),16), b1=parseInt(c1.substr(5,2),16);
  var r2=parseInt(c2.substr(1,2),16), g2=parseInt(c2.substr(3,2),16), b2=parseInt(c2.substr(5,2),16);
  var r=Math.round(r1+(r2-r1)*t), g=Math.round(g1+(g2-g1)*t), b=Math.round(b1+(b2-b1)*t);
  return 'rgb('+r+','+g+','+b+')';
}

function wtUpdateProgressRing(i){
  var pct = Math.round(((i+1)/WT_STEPS.length)*100);
  var c = 2*Math.PI*WT_RING_R;
  var fill = document.getElementById('wtRingFill');
  var pctEl = document.getElementById('wtRingPct');
  var lblEl = document.getElementById('wtRingLbl');
  if(fill) fill.style.strokeDashoffset = (c - (c*pct/100)).toFixed(2);
  if(pctEl) pctEl.textContent = pct + '%';

  var color = wtLerpColor('#ff4757', '#2ed573', pct/100);
  if(fill) fill.style.stroke = color;
  if(pctEl) pctEl.style.color = color;

  if(lblEl) lblEl.textContent = WT_STEP_TRUST_LABEL[i] || 'Situational Awareness';
}


function wtBuildCommandCenter(){
  var panel = document.createElement('div');
  panel.className = 'wt-cc-panel';
  panel.id = 'wtCCPanel';
  var rows = WT_CC_MODULES.map(function(m){
    return '<div class="wt-cc-row" id="wtCC_'+m.key+'"><span class="wt-cc-name">'+m.name+'</span><span class="wt-cc-dot">OFF</span></div>';
  }).join('');
  panel.innerHTML = '<div class="wt-cc-title">⌁ Command Center</div>' + rows;
  overlayEl.appendChild(panel);

  WT_CC_MODULES.forEach(function(m){
    var row = document.getElementById('wtCC_' + m.key);
    if(!row) return;
    var targetStep = wtModuleStepMap[m.key];
    if(targetStep === undefined) return;

    row.addEventListener('mouseenter', function(){
      if(!row.classList.contains('online')) return;
      wtPreviewStep = targetStep;
    });
    row.addEventListener('mouseleave', function(){
      wtPreviewStep = null;
    });
    row.addEventListener('click', function(){
      if(!row.classList.contains('online')) return;
      wtPreviewStep = null;
      wtJumpToStep(targetStep);
    });
  });
}

function wtJumpToStep(i){
  wtPaused = false;
  window.speechSynthesis && window.speechSynthesis.cancel();
  wtSpeakStep(i);
}

function wtUpdateCommandCenter(i){
  for(var s = 0; s <= i; s++){
    var key = WT_STEP_MODULE_MAP[s];
    if(key) wtSetModuleOnline(key);
  }
  if(i === WT_STEPS.length - 1){
    WT_CC_MODULES.forEach(function(m){ wtSetModuleOnline(m.key); });
  }
}
function wtSetModuleOnline(key){
  var row = document.getElementById('wtCC_' + key);
  if(!row || row.classList.contains('online')) return;
  row.classList.add('online');
  var dot = row.querySelector('.wt-cc-dot');
  if(dot) dot.textContent = 'ONLINE';
}


function wtBuildTelemetry(){
  var wrap = document.createElement('div');
  wrap.className = 'wt-telemetry';
  wrap.id = 'wtTelemetry';
  var track = document.createElement('div');
  track.className = 'wt-telemetry-track';
  track.id = 'wtTelemetryTrack';
  wrap.appendChild(track);
  overlayEl.appendChild(wrap);
  wtRenderTelemetry();
}
function wtRenderTelemetry(){
  var track = document.getElementById('wtTelemetryTrack');
  if(!track) return;
  var html = WT_TELEMETRY_LINES.map(function(l){ return '<span>'+l+'</span>'; }).join('');
  track.innerHTML = html + html;
}
function wtPushTelemetry(msg){
  if(!msg || WT_TELEMETRY_LINES[0] === msg) return;
  WT_TELEMETRY_LINES.unshift(msg);
  if(WT_TELEMETRY_LINES.length > 8) WT_TELEMETRY_LINES.pop();
  wtRenderTelemetry();
}


function wtGetBrowserName(ua){
  if(ua.indexOf('Edg/') > -1) return 'Edge';
  if(ua.indexOf('OPR/') > -1 || ua.indexOf('Opera') > -1) return 'Opera';
  if(ua.indexOf('Chrome/') > -1) return 'Chrome';
  if(ua.indexOf('Firefox/') > -1) return 'Firefox';
  if(ua.indexOf('Safari/') > -1) return 'Safari';
  return 'Browser';
}
function wtGetSystemInfoLine(){
  var browser = wtGetBrowserName(navigator.userAgent || '');
  var w = screen.width || window.innerWidth;
  var h = screen.height || window.innerHeight;
  var tz = 'Unknown';
  try{ tz = Intl.DateTimeFormat().resolvedOptions().timeZone || tz; }catch(e){}
  return 'Session: ' + browser + ' · ' + w + '×' + h + ' · ' + tz;
}


function wtBuildLiveStats(){
  var wrap = document.createElement('div');
  wrap.className = 'wt-live-stats';
  wrap.id = 'wtLiveStats';
  wrap.innerHTML =
    '<div>Threats analyzed: <span id="wtThreatCount">0</span></div>' +
    '<div>Mouse activity: <span id="wtMouseCount">0</span></div>';
  overlayEl.appendChild(wrap);
}
function wtAttachMouseTracking(){
  if(wtMouseListenerAttached) return;
  wtMouseListenerAttached = true;
  document.addEventListener('mousemove', function(){
    wtMouseMoveCount++;
  });
}
function wtStartLiveStats(){
  wtStopLiveStats();
  wtLiveStatsInterval = setInterval(function(){
    wtThreatCount += Math.floor(Math.random() * 3) + 1;
    var tEl = document.getElementById('wtThreatCount');
    var mEl = document.getElementById('wtMouseCount');
    if(tEl) tEl.textContent = wtThreatCount.toLocaleString();
    if(mEl) mEl.textContent = wtMouseMoveCount.toLocaleString();
  }, 400);
}
function wtStopLiveStats(){
  if(wtLiveStatsInterval){ clearInterval(wtLiveStatsInterval); wtLiveStatsInterval = null; }
}


function wtBuildGridFlashLayer(){
  var flash = document.createElement('div');
  flash.className = 'wt-grid-flash';
  flash.id = 'wtGridFlash';
  overlayEl.appendChild(flash);
}
function wtReactToKeywords(text){
  var el = document.getElementById('wtGridFlash');
  if(!el) return;
  var t = (text || '').toLowerCase();
  var cls = null;
  if(t.indexOf('threat') > -1 || t.indexOf('attack') > -1 || t.indexOf('malware') > -1 || t.indexOf('malicious') > -1) cls = 'flash-threat';
  else if(t.indexOf('browser') > -1) cls = 'flash-browser';
  else if(t.indexOf('timeline') > -1 || t.indexOf('journey') > -1 || t.indexOf('history') > -1) cls = 'flash-timeline';
  else if(t.indexOf('guardian') > -1) cls = 'flash-guardian';
  if(!cls) return;
  el.className = 'wt-grid-flash';
  void el.offsetWidth;
  el.classList.add(cls);

  if(cls === 'flash-threat'){
    overlayEl.classList.remove('wt-shake');
    void overlayEl.offsetWidth;
    overlayEl.classList.add('wt-shake');
  }
  if(cls === 'flash-guardian'){
    var card = overlayEl.querySelector('.wt-glass-card');
    if(card){
      card.classList.remove('wt-guardian-pulse');
      void card.offsetWidth;
      card.classList.add('wt-guardian-pulse');
    }
  }
}


function wtFocalX(w){ return w * 0.78; }
function wtBandX0(w){ return w * 0.60; }
function wtBandX1(w){ return w * 0.97; }
function wtBandW(w){ return wtBandX1(w) - wtBandX0(w); }

function wtBuildHolograms(){
  wtHoloCanvasA = document.createElement('canvas');
  wtHoloCanvasB = document.createElement('canvas');
  wtHoloCanvasA.className = 'wt-holo-layer';
  wtHoloCanvasB.className = 'wt-holo-layer';
  overlayEl.appendChild(wtHoloCanvasA);
  overlayEl.appendChild(wtHoloCanvasB);
  wtHoloCanvasA.style.opacity = '1';
  wtHoloCanvasB.style.opacity = '0';
  wtHoloCtxA = wtHoloCanvasA.getContext('2d');
  wtHoloCtxB = wtHoloCanvasB.getContext('2d');
  wtResizeHolograms();
  window.addEventListener('resize', wtResizeHolograms);
  wtHoloStartTime = performance.now();
  wtHoloRAF = requestAnimationFrame(wtHoloLoop);
}
function wtResizeHolograms(){
  [wtHoloCanvasA, wtHoloCanvasB].forEach(function(c){
    if(!c || !overlayEl) return;
    c.width = overlayEl.clientWidth || window.innerWidth;
    c.height = overlayEl.clientHeight || window.innerHeight;
  });
}
function wtHoloLoop(now){
  var t = (now - wtHoloStartTime) / 1000;
  var activeCtx = wtHoloActive === 'A' ? wtHoloCtxA : wtHoloCtxB;
  var activeCanvas = wtHoloActive === 'A' ? wtHoloCanvasA : wtHoloCanvasB;
  // 🆕 draw the preview step (if hovering a Command Center row), else the real current step
  var stepToDraw = (wtPreviewStep !== null) ? wtPreviewStep : wtHoloCurrentStep;
  if(activeCtx && activeCanvas && activeCanvas.width > 0){
    wtDrawScene(activeCtx, stepToDraw, activeCanvas.width, activeCanvas.height, t);
  }
  wtHoloRAF = requestAnimationFrame(wtHoloLoop);
}
function wtSwapHologram(stepIndex){
  wtHoloCurrentStep = stepIndex;
  var nextCanvas = wtHoloActive === 'A' ? wtHoloCanvasB : wtHoloCanvasA;
  var curCanvas  = wtHoloActive === 'A' ? wtHoloCanvasA : wtHoloCanvasB;
  nextCanvas.style.opacity = '1';
  curCanvas.style.opacity = '0';
  wtHoloActive = wtHoloActive === 'A' ? 'B' : 'A';

  // 🆕 glitch-cut instead of plain fade on odd steps
  if(stepIndex % 2 === 1){
    nextCanvas.classList.remove('wt-holo-glitch');
    void nextCanvas.offsetWidth;
    nextCanvas.classList.add('wt-holo-glitch');
  }
}
function wtStopHolograms(){
  if(wtHoloRAF) cancelAnimationFrame(wtHoloRAF);
  window.removeEventListener('resize', wtResizeHolograms);
}

function wtRand(seed){
  var x = Math.sin(seed * 12.9898) * 43758.5453;
  return x - Math.floor(x);
}
function wtRoundRect(ctx,x,y,w,h,r){
  ctx.beginPath();
  ctx.moveTo(x+r,y);
  ctx.arcTo(x+w,y,x+w,y+h,r);
  ctx.arcTo(x+w,y+h,x,y+h,r);
  ctx.arcTo(x,y+h,x,y,r);
  ctx.arcTo(x,y,x+w,y,r);
  ctx.closePath();
}

function wtDrawScene(ctx, step, w, h, t){
  ctx.clearRect(0,0,w,h);
  if(w < WT_HOLO_MIN_WIDTH) return;
  switch(step){
    case 0:  wtSceneWorldAttack(ctx,w,h,t); break;
    case 1:  wtSceneAlertFatigue(ctx,w,h,t); break;
    case 2:  wtSceneDashboardBlueprint(ctx,w,h,t); break;
    case 3:  wtSceneBrowserMonitor(ctx,w,h,t); break;
    case 4:  wtSceneProcessTree(ctx,w,h,t); break;
    case 5:  wtSceneAlertExpand(ctx,w,h,t); break;
    case 6:  wtSceneThreatVerification(ctx,w,h,t); break;
    case 7:  wtSceneKillChain(ctx,w,h,t); break;
    case 8:  wtSceneReports(ctx,w,h,t); break;
    case 9:  wtSceneGuardianAssistant(ctx,w,h,t); break;
    case 10: wtSceneFinal(ctx,w,h,t); break;
    default: wtSceneWorldAttack(ctx,w,h,t);
  }
}

function wtSceneWorldAttack(ctx,w,h,t){
  var cx=wtFocalX(w), cy=h/2, x0=wtBandX0(w), bw=wtBandW(w);
  for(var i=0;i<90;i++){
    var rx=x0+wtRand(i*7.1)*bw, ry=wtRand(i*3.3+50)*h;
    ctx.fillStyle='rgba(120,140,200,0.18)';
    ctx.beginPath();ctx.arc(rx,ry,1.4,0,Math.PI*2);ctx.fill();
  }
  for(var j=0;j<10;j++){
    var seed=j*17.3;
    var nx=x0+wtRand(seed)*bw, ny=wtRand(seed+9)*h;
    var blink=0.4+0.6*Math.abs(Math.sin(t*2.2+j));
    ctx.strokeStyle='rgba(255,71,87,'+(0.12*blink)+')';
    ctx.lineWidth=1;
    ctx.beginPath();ctx.moveTo(nx,ny);ctx.lineTo(cx,cy);ctx.stroke();
    ctx.fillStyle='rgba(255,71,87,'+(0.6*blink)+')';
    ctx.beginPath();ctx.arc(nx,ny,3,0,Math.PI*2);ctx.fill();
  }
  var sweepAngle=(t*0.7)%(Math.PI*2);
  ctx.save();
  ctx.translate(cx,cy);ctx.rotate(sweepAngle);
  var sweepGrad=ctx.createLinearGradient(0,0,130,0);
  sweepGrad.addColorStop(0,'rgba(91,108,249,0.28)');
  sweepGrad.addColorStop(1,'rgba(91,108,249,0)');
  ctx.fillStyle=sweepGrad;
  ctx.beginPath();ctx.moveTo(0,0);ctx.arc(0,0,130,-0.26,0.26);ctx.closePath();ctx.fill();
  ctx.restore();
  ctx.strokeStyle='rgba(91,108,249,0.14)';
  [50,85,120].forEach(function(r){ctx.beginPath();ctx.arc(cx,cy,r,0,Math.PI*2);ctx.stroke();});
  var pulse=0.5+0.5*Math.sin(t*1.6);
  var glow=ctx.createRadialGradient(cx,cy,4,cx,cy,36+pulse*8);
  glow.addColorStop(0,'rgba(91,108,249,'+(0.45+0.15*pulse)+')');
  glow.addColorStop(1,'rgba(91,108,249,0)');
  ctx.fillStyle=glow;
  ctx.beginPath();ctx.arc(cx,cy,36+pulse*8,0,Math.PI*2);ctx.fill();
}

function wtSceneAlertFatigue(ctx,w,h,t){
  var cx=wtFocalX(w), cy=h/2, x0=wtBandX0(w), bw=wtBandW(w);
  var cycle=t%7;
  var floodOpacity = cycle<3 ? 1 : cycle<4.5 ? 1-((cycle-3)/1.5) : 0;
  if(floodOpacity>0){
    for(var i=0;i<16;i++){
      var seed=i*5.7;
      var bw2=Math.min(86,bw*0.6);
      var bx=x0+wtRand(seed)*(bw-bw2);
      var by=wtRand(seed+3)*h*0.7+h*0.1;
      var flicker=0.5+0.5*Math.sin(t*4+i);
      var label=WT_FAKE_ALERTS[i%WT_FAKE_ALERTS.length];
      ctx.globalAlpha=floodOpacity*0.55*flicker;
      ctx.fillStyle='rgba(255,165,2,0.18)';
      ctx.strokeStyle='rgba(255,165,2,0.4)';
      wtRoundRect(ctx,bx,by,bw2,22,5);ctx.fill();ctx.stroke();
      ctx.fillStyle='rgba(255,210,150,0.85)';
      ctx.font='9px monospace';
      ctx.fillText(label,bx+7,by+14);
    }
    ctx.globalAlpha=1;
  }
  if(cycle>=4.2){
    var cleanOp=Math.min(1,(cycle-4.2)/1);
    ctx.globalAlpha=cleanOp;
    ctx.fillStyle='rgba(46,213,115,0.12)';
    ctx.strokeStyle='rgba(46,213,115,0.55)';
    wtRoundRect(ctx,cx-90,cy-20,180,40,10);ctx.fill();ctx.stroke();
    ctx.fillStyle='rgba(160,255,190,0.95)';
    ctx.font='10px monospace';ctx.textAlign='center';
    ctx.fillText('🛡 Guardian: one clear summary',cx,cy+5);
    ctx.textAlign='left';
  }
  ctx.globalAlpha=1;
}

function wtSceneDashboardBlueprint(ctx,w,h,t){
  var cx=wtFocalX(w), cy=h/2;
  var labels=['Browser','Processes','Timeline','Reports','Guardian Assistant'];
  var n=labels.length, radius=Math.min(wtBandW(w)*0.9,h*0.34)/1.6;
  var reveal=t%6, pts=[];
  for(var i=0;i<n;i++){
    var ang=-Math.PI/2+i*(Math.PI*2/n);
    pts.push([cx+Math.cos(ang)*radius, cy+Math.sin(ang)*radius]);
  }
  ctx.strokeStyle='rgba(91,108,249,0.35)';
  for(var i=0;i<n;i++){
    var appearAt=i*0.9;
    if(reveal>appearAt){
      ctx.globalAlpha=Math.min(1,(reveal-appearAt)/0.6)*0.5;
      ctx.beginPath();ctx.moveTo(cx,cy);ctx.lineTo(pts[i][0],pts[i][1]);ctx.stroke();
    }
  }
  ctx.globalAlpha=1;
  for(var i=0;i<n;i++){
    var appearAt=i*0.9+0.3;
    if(reveal>appearAt){
      ctx.globalAlpha=Math.min(1,(reveal-appearAt)/0.5);
      var bw=84,bh=30,bx=pts[i][0]-bw/2,by=pts[i][1]-bh/2;
      ctx.fillStyle='rgba(91,108,249,0.07)';
      ctx.strokeStyle='rgba(91,108,249,0.4)';
      wtRoundRect(ctx,bx,by,bw,bh,7);ctx.fill();ctx.stroke();
      ctx.fillStyle='rgba(200,215,255,0.9)';
      ctx.font='8px monospace';ctx.textAlign='center';
      ctx.fillText(labels[i],pts[i][0],pts[i][1]+3);
      ctx.textAlign='left';
    }
  }
  ctx.globalAlpha=1;
  ctx.fillStyle='rgba(91,108,249,0.5)';
  ctx.beginPath();ctx.arc(cx,cy,5,0,Math.PI*2);ctx.fill();
}

function wtSceneBrowserMonitor(ctx,w,h,t){
  var x0=wtBandX0(w), bw=wtBandW(w);
  var labels=['HTTPS','DNS','TLS','Cookies','Redirect'];
  for(var i=0;i<5;i++){
    var bx=x0+(i*(bw/5))+Math.sin(t*0.6+i)*8;
    var by=h*0.28+Math.cos(t*0.5+i*1.3)*14;
    ctx.fillStyle='rgba(91,108,249,0.6)';
    ctx.font='9px monospace';
    ctx.fillText(labels[i],bx,by);
  }
  for(var p=0;p<8;p++){
    var seed=p*3.14;
    var speed=0.15+wtRand(seed)*0.1;
    var prog=(t*speed+wtRand(seed+1))%1;
    var py=h*0.45+wtRand(seed+2)*h*0.25;
    var px=x0+prog*bw;
    var cyc=t%8;
    var badActive=(p===3)&&cyc>4;
    ctx.fillStyle=badActive?'rgba(255,71,87,0.85)':'rgba(0,229,255,0.5)';
    ctx.beginPath();ctx.arc(px,py,badActive?4:2.5,0,Math.PI*2);ctx.fill();
    if(badActive){
      ctx.strokeStyle='rgba(255,71,87,0.3)';
      ctx.beginPath();ctx.arc(px,py,10+3*Math.sin(t*8),0,Math.PI*2);ctx.stroke();
    }
  }
  var cyc=t%8;
  if(cyc>5.4&&cyc<6.4){
    var op=1-Math.abs(cyc-5.9)/0.5;
    ctx.globalAlpha=op*0.4;
    ctx.fillStyle='rgba(91,108,249,0.5)';
    ctx.beginPath();ctx.arc(x0+bw*0.9,h*0.55,22,0,Math.PI*2);ctx.fill();
    ctx.globalAlpha=1;
  }
}

function wtSceneProcessTree(ctx,w,h,t){
  var x0=wtFocalX(w)-40;
  var procs=['chrome.exe','explorer.exe','powershell.exe','discord.exe','svchost.exe','node.exe'];
  var rowH=26, scroll=(t*14)%(rowH*procs.length);
  ctx.font='10px monospace';
  for(var i=0;i<procs.length+1;i++){
    var y=h*0.3+(i*rowH-scroll);
    if(y<h*0.15||y>h*0.75) continue;
    var idx=i%procs.length;
    var flagged=procs[idx]==='powershell.exe';
    var glow=flagged?0.5+0.5*Math.sin(t*3):0;
    ctx.fillStyle=flagged?'rgba(255,165,2,'+(0.5+glow*0.4)+')':'rgba(150,165,210,0.35)';
    ctx.fillText(procs[idx], x0, y);
    if(flagged){
      ctx.strokeStyle='rgba(255,165,2,'+(0.5+glow*0.3)+')';
      ctx.beginPath();ctx.ellipse(x0+60,y-3,64,12,0,0,Math.PI*2);ctx.stroke();
    }
  }
}

function wtSceneAlertExpand(ctx,w,h,t){
  var cx=wtFocalX(w), items=['CPU Spike','Registry Change','Network Connection','Suspicious Behaviour'];
  var cycle=t%6, cy0=h*0.28;
  ctx.textAlign='center';
  ctx.fillStyle='rgba(255,165,2,0.8)';ctx.font='11px monospace';
  ctx.fillText('⚠ WHY?',cx,cy0);
  for(var i=0;i<items.length;i++){
    var appearAt=0.6+i*0.9;
    if(cycle>appearAt){
      var op=Math.min(1,(cycle-appearAt)/0.5), y=cy0+34+i*30;
      ctx.globalAlpha=op;
      ctx.strokeStyle='rgba(255,165,2,0.25)';
      ctx.beginPath();ctx.moveTo(cx,cy0+12+i*30);ctx.lineTo(cx,y-8);ctx.stroke();
      ctx.fillStyle='rgba(255,200,140,0.9)';
      ctx.font='10px monospace';
      ctx.fillText(items[i],cx,y);
    }
  }
  ctx.globalAlpha=1;ctx.textAlign='left';
}

function wtSceneThreatVerification(ctx,w,h,t){
  var cx=wtFocalX(w), cy=h/2-20;
  var cols=6, rows=4, cellW=20, cellH=16, gx=cx-(cols*cellW)/2, gy=cy-70;
  for(var r=0;r<rows;r++){
    for(var c=0;c<cols;c++){
      var idx=r*cols+c;
      var active=((Math.floor(t*3)+idx)%9)<3;
      ctx.strokeStyle='rgba(0,229,255,0.25)';
      ctx.fillStyle=active?'rgba(0,229,255,0.35)':'rgba(0,229,255,0.04)';
      var x=gx+c*cellW, y=gy+r*cellH;
      ctx.fillRect(x,y,cellW-3,cellH-3);
      ctx.strokeRect(x,y,cellW-3,cellH-3);
    }
  }
  var cyc=(t%6)/6, pct=Math.round(12+cyc*(81-12));
  var barW=160, barX=cx-barW/2, barY=cy+50;
  ctx.strokeStyle='rgba(255,255,255,0.15)';ctx.strokeRect(barX,barY,barW,10);
  ctx.fillStyle=pct>60?'rgba(255,71,87,0.7)':pct>35?'rgba(255,165,2,0.7)':'rgba(0,229,255,0.7)';
  ctx.fillRect(barX,barY,barW*(pct/100),10);
  ctx.fillStyle='rgba(220,230,255,0.85)';ctx.font='10px monospace';ctx.textAlign='center';
  ctx.fillText('SUSPICION: '+pct+'%',cx,barY+26);
  ctx.textAlign='left';
}

function wtSceneKillChain(ctx,w,h,t){
  var labels=['Website','Download','Execution','Persist.','Priv. Esc.','Impact'];
  var n=labels.length, spacing=Math.min(60, wtBandW(w)/(n+0.5));
  var cx=wtFocalX(w), startX=cx-((n-1)*spacing)/2, y=h*0.5, cyc=t%7;
  ctx.font='8px monospace';ctx.textAlign='center';
  for(var i=0;i<n;i++){
    var appearAt=i*1.0, x=startX+i*spacing;
    if(cyc>appearAt){
      ctx.globalAlpha=Math.min(1,(cyc-appearAt)/0.5);
      if(i>0){
        ctx.strokeStyle='rgba(91,108,249,0.3)';
        ctx.beginPath();ctx.moveTo(x-spacing+10,y);ctx.lineTo(x-10,y);ctx.stroke();
        var flowT=(t*1.4+i)%1;
        var fx=(x-spacing+10)+(x-10-(x-spacing+10))*flowT;
        ctx.fillStyle='rgba(91,108,249,0.8)';
        ctx.beginPath();ctx.arc(fx,y,2.2,0,Math.PI*2);ctx.fill();
      }
      var glowPulse=0.5+0.5*Math.sin(t*3+i);
      ctx.fillStyle='rgba(91,108,249,'+(0.15+glowPulse*0.1)+')';
      ctx.beginPath();ctx.arc(x,y,10,0,Math.PI*2);ctx.fill();
      ctx.strokeStyle='rgba(91,108,249,0.6)';
      ctx.beginPath();ctx.arc(x,y,10,0,Math.PI*2);ctx.stroke();
      ctx.fillStyle='rgba(210,220,255,0.85)';
      ctx.fillText(labels[i],x,y+24);
    }
  }
  ctx.globalAlpha=1;ctx.textAlign='left';
}

function wtSceneReports(ctx,w,h,t){
  var cx=wtFocalX(w), cy=h/2;
  var baseX=cx-95, baseY=cy+40, cyc=t%6;
  for(var i=0;i<5;i++){
    var target=16+wtRand(i*4)*38;
    var grow=Math.min(1,Math.max(0,(cyc-i*0.3)/1));
    ctx.fillStyle='rgba(0,229,255,0.4)';
    ctx.fillRect(baseX+i*18,baseY-target*grow,12,target*grow);
  }
  var pieX=cx+70, pieY=cy-10, pieR=26;
  var segs=[0.4,0.25,0.2,0.15];
  var colors=['rgba(0,229,255,0.5)','rgba(91,108,249,0.5)','rgba(46,213,115,0.5)','rgba(255,165,2,0.5)'];
  var cyc2=cyc/6, start=-Math.PI/2;
  for(var s=0;s<segs.length;s++){
    var segFrac=Math.min(segs[s],Math.max(0,cyc2*4-s));
    var end=start+segFrac*Math.PI*2;
    ctx.fillStyle=colors[s];
    ctx.beginPath();ctx.moveTo(pieX,pieY);ctx.arc(pieX,pieY,pieR,start,end);ctx.closePath();ctx.fill();
    start+=segs[s]*Math.PI*2;
  }
  if(cyc>5){
    ctx.globalAlpha=Math.min(1,(cyc-5)/0.7);
    ctx.strokeStyle='rgba(46,213,115,0.8)';ctx.lineWidth=2;
    ctx.strokeRect(cx-55,cy-60,110,32);
    ctx.fillStyle='rgba(46,213,115,0.9)';ctx.font='bold 11px monospace';ctx.textAlign='center';
    ctx.fillText('✓ COMPLETE',cx,cy-38);
    ctx.textAlign='left';ctx.lineWidth=1;ctx.globalAlpha=1;
  }
}

function wtSceneGuardianAssistant(ctx,w,h,t){
  var cx=wtFocalX(w), cy=h/2;
  var bubbleW=Math.min(220, wtBandW(w)*0.85);
  var bx=cx-bubbleW/2;
  var q='Why was Chrome flagged?', a='Because it contacted a suspicious domain.';
  var cyc=t%7;
  ctx.font='9px monospace';ctx.textAlign='left';
  var qChars=Math.min(q.length, Math.floor(cyc*14));
  ctx.fillStyle='rgba(0,229,255,0.12)';
  wtRoundRect(ctx,bx,cy-40,bubbleW,26,8);ctx.fill();
  ctx.fillStyle='rgba(0,229,255,0.85)';
  ctx.fillText(q.substring(0,qChars),bx+10,cy-23);
  if(cyc>2.2){
    var aChars=Math.min(a.length, Math.floor((cyc-2.2)*12));
    ctx.fillStyle='rgba(91,108,249,0.14)';
    wtRoundRect(ctx,bx,cy+10,bubbleW,32,8);ctx.fill();
    ctx.fillStyle='rgba(200,210,255,0.9)';
    ctx.fillText(a.substring(0,aChars),bx+10,cy+29,bubbleW-20);
  }
}

function wtSceneFinal(ctx,w,h,t){
  var cx=wtFocalX(w), cy=h/2, n=44, maxDist=Math.min(wtBandW(w)*0.9,170);
  for(var i=0;i<n;i++){
    var seed=i*9.7;
    var ang=wtRand(seed)*Math.PI*2, dist=50+wtRand(seed+1)*maxDist;
    var conv=Math.min(1,(t%4)/2.2);
    var r=dist*(1-conv);
    var x=cx+Math.cos(ang+t*0.3)*(r+(1-conv)*30);
    var y=cy+Math.sin(ang+t*0.3)*(r+(1-conv)*30);
    ctx.fillStyle='rgba(91,108,249,'+(0.3+0.3*Math.sin(t*4+i))+')';
    ctx.beginPath();ctx.arc(x,y,1.8,0,Math.PI*2);ctx.fill();
  }
  var cyc=t%4;
  if(cyc>2){
    ctx.globalAlpha=Math.min(1,(cyc-2)/1.2);
    ctx.strokeStyle='rgba(91,108,249,0.8)';ctx.lineWidth=2;
    ctx.beginPath();
    ctx.moveTo(cx,cy-46);
    ctx.quadraticCurveTo(cx+46,cy-30,cx+40,cy+10);
    ctx.quadraticCurveTo(cx+30,cy+50,cx,cy+66);
    ctx.quadraticCurveTo(cx-30,cy+50,cx-40,cy+10);
    ctx.quadraticCurveTo(cx-46,cy-30,cx,cy-46);
    ctx.closePath();ctx.stroke();
    var pulse=0.5+0.5*Math.sin(t*3);
    ctx.fillStyle='rgba(91,108,249,'+(0.08+pulse*0.08)+')';
    ctx.fill();
    ctx.lineWidth=1;ctx.globalAlpha=1;
  }
}

})();
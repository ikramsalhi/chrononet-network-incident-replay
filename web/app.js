const $ = (id) => document.getElementById(id);
let currentScenario = null;
let replayTimer = null;

async function json(url, options) {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);
  return data;
}

function formatSeconds(seconds) {
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

function switchView(viewId) {
  document.querySelectorAll('.workspace-view').forEach(view => {
    const active = view.id === viewId;
    view.classList.toggle('active', active);
    view.hidden = !active;
  });
  document.querySelectorAll('.command-tab').forEach(tab => {
    tab.classList.toggle('active', tab.dataset.view === viewId);
  });
}

function renderCaptureSummary(capture) {
  const box = $('captureSummary');
  if (!capture) {
    box.hidden = true;
    box.innerHTML = '';
    return;
  }
  const protocols = Object.entries(capture.protocols || {})
    .map(([name, count]) => `${escapeHtml(name)} ${count}`)
    .join(' · ') || 'structured events';
  box.hidden = false;
  box.innerHTML = `<header class="module-head"><div><span class="module-number">IN</span><div><small>CAPTURE SUMMARY</small><h2>${escapeHtml(capture.filename || 'Imported file')}</h2></div></div></header>
    <div class="summary-grid">
      <div><small>FORMAT</small><strong>${escapeHtml(String(capture.format || 'unknown').toUpperCase())}</strong></div>
      <div><small>EVENTS</small><strong>${capture.event_records ?? 0}</strong></div>
      <div><small>PACKETS</small><strong>${capture.packets_total ?? '—'}</strong></div>
      <div><small>DECODED</small><strong>${capture.packets_decoded ?? '—'}</strong></div>
      <div class="summary-wide"><small>PROTOCOL MIX</small><strong>${protocols}</strong></div>
    </div>`;
}

function renderScenario(data) {
  currentScenario = data;
  const a = data.analysis;
  $('scenarioName').textContent = data.name;
  $('scenarioDescription').textContent = data.description;
  $('caseCode').textContent = data.category === 'uploaded-capture'
    ? `CN-CAPTURE-${Date.now().toString().slice(-6)}`
    : `CN-${String(data.id).toUpperCase().replace(/[^A-Z0-9]+/g, '-').slice(0, 18)}`;
  $('healthScore').textContent = a.health_score;
  $('eventCount').textContent = a.event_count;
  $('nodeCount').textContent = a.affected_nodes.length;
  $('duration').textContent = formatSeconds(a.duration_seconds);
  renderCaptureSummary(data.capture);

  $('timeline').innerHTML = data.events.map((event, index) => {
    const date = new Date(event.timestamp);
    const t = Number.isNaN(date.getTime()) ? '--:--:--' : date.toISOString().slice(11, 19);
    return `<div class="event ${event.severity || 'info'}" data-event="${index}">
      <div class="event-time">${t}</div>
      <div class="event-dot" title="${escapeHtml(event.severity || 'info')}"></div>
      <div class="event-body">
        <div class="event-title">${escapeHtml(event.type)} / ${escapeHtml(event.status || 'observed')}</div>
        <div class="event-meta">${escapeHtml(event.source || '?')} -> ${escapeHtml(event.target || '?')} / ${escapeHtml(event.message || '')}</div>
      </div>
    </div>`;
  }).join('');

  const finding = a.findings[0];
  if (finding) {
    $('finding').innerHTML = `<div class="finding-main">
      <div class="severity">${escapeHtml(finding.severity.toUpperCase())} / CORRELATED FINDING</div>
      <h4>${escapeHtml(finding.title)}</h4>
      <div class="confidence"><span>${finding.confidence}% CONFIDENCE</span><div class="confidence-bar"><span style="width:${finding.confidence}%"></span></div></div>
      <div class="recommendation"><strong>NEXT CHECK</strong><br>${escapeHtml(finding.recommendation)}</div>
    </div>`;
    $('evidence').innerHTML = finding.evidence.map((item, index) => `<div>${String(index + 1).padStart(2, '0')} / ${escapeHtml(item)}</div>`).join('');
  } else {
    $('finding').innerHTML = '<div class="finding-main"><div class="severity">NO HIGH-CONFIDENCE MATCH</div><h4>Correlation inconclusive</h4><div class="recommendation">The current rule set did not produce a strong root-cause hypothesis. Review the replay timeline and packet/event mix.</div></div>';
    $('evidence').innerHTML = '';
  }

  $('nodes').innerHTML = a.affected_nodes.length
    ? a.affected_nodes.map(node => `<span class="node">${escapeHtml(node)}</span>`).join('')
    : '<span class="empty-state">No affected endpoint identified.</span>';
  const maxCount = Math.max(1, ...a.top_event_types.map(item => item.count));
  $('bars').innerHTML = a.top_event_types.map(item => `<div class="bar-row"><span>${escapeHtml(item.type)}</span><div class="bar-track"><div class="bar-fill" style="width:${(item.count / maxCount) * 100}%"></div></div><strong>${item.count}</strong></div>`).join('');
  resetReplay();
}

function resetReplay() {
  clearInterval(replayTimer);
  replayTimer = null;
  document.querySelectorAll('.event').forEach(el => el.classList.remove('visible'));
  $('replayState').textContent = 'READY';
  $('replayBtn').textContent = 'START REPLAY';
}

function replay() {
  if (!currentScenario) return;
  switchView('replayView');
  resetReplay();
  const events = [...document.querySelectorAll('.event')];
  let i = 0;
  $('replayState').textContent = 'RUNNING';
  $('replayBtn').textContent = 'RESTART REPLAY';
  replayTimer = setInterval(() => {
    if (i >= events.length) {
      clearInterval(replayTimer);
      replayTimer = null;
      $('replayState').textContent = 'COMPLETE';
      return;
    }
    events[i].classList.add('visible');
    events[i].scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    i += 1;
  }, 180);
}

async function loadScenario(id) {
  const data = await json(`/api/scenarios/${encodeURIComponent(id)}`);
  renderScenario(data);
  switchView('replayView');
}

async function importFile(file) {
  if (!file) return;
  if (file.size > 12 * 1024 * 1024) {
    $('uploadState').textContent = 'ERROR / FILE EXCEEDS 12 MB';
    return;
  }
  $('uploadState').textContent = `UPLOADING / ${file.name}`;
  try {
    const response = await fetch('/api/import', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Filename': encodeURIComponent(file.name),
      },
      body: file,
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || `Upload failed: HTTP ${response.status}`);
    renderScenario(data);
    $('uploadState').textContent = `ANALYZED / ${file.name}`;
    switchView('replayView');
  } catch (error) {
    $('uploadState').textContent = `ERROR / ${error.message}`;
  }
}

function exportCurrentReport() {
  if (!currentScenario) return;
  if (currentScenario.category !== 'uploaded-capture') {
    window.open(`/api/scenarios/${encodeURIComponent(currentScenario.id)}/report`, '_blank');
    return;
  }
  const a = currentScenario.analysis;
  const finding = a.findings[0];
  const lines = [
    '# ChronoNet Incident Report', '',
    `**Investigation:** ${currentScenario.name}`, '',
    `**Events analyzed:** ${a.event_count}`,
    `**Health score:** ${a.health_score}/100`,
    `**Affected nodes:** ${a.affected_nodes.length}`,
    `**Incident window:** ${formatSeconds(a.duration_seconds)}`, '',
    '## Root-cause assessment', '',
    finding ? `${finding.title} — ${finding.confidence}% confidence (${finding.severity})` : 'No high-confidence root cause matched.', '',
    ...(finding ? ['## Evidence', '', ...finding.evidence.map(item => `- ${item}`), '', '## Recommended next check', '', finding.recommendation, ''] : []),
    '## Affected endpoints', '',
    ...(a.affected_nodes.length ? a.affected_nodes.map(node => `- ${node}`) : ['- None identified']), '',
    '> Generated by ChronoNet. Treat automated correlation as investigation support, not proof of causation.'
  ];
  const blob = new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'chrononet-incident-report.md';
  link.click();
  URL.revokeObjectURL(url);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[ch]));
}

async function boot() {
  try {
    const [health, data] = await Promise.all([json('/api/health'), json('/api/scenarios')]);
    const online = health.mode === 'online';
    $('nodeLabel').textContent = online ? 'PUBLIC ANALYSIS NODE' : 'LOCAL ANALYSIS NODE';
    $('nodeValue').textContent = window.location.host;
    $('engineMode').textContent = online ? 'ONLINE' : 'LOCAL';
    $('modeFlag').textContent = online ? 'ONLINE MODE · CAPTURE ANALYSIS' : 'LOCAL MODE · CAPTURE ANALYSIS';
    $('footerMode').textContent = online ? 'ONLINE ANALYSIS SESSION' : 'LOCAL ANALYSIS SESSION';

    $('scenarioSelect').innerHTML = data.scenarios.map(s => `<option value="${s.id}">${escapeHtml(s.name)}</option>`).join('');
    $('scenarioSelect').addEventListener('change', event => loadScenario(event.target.value));
    $('replayBtn').addEventListener('click', replay);
    $('reportBtn').addEventListener('click', exportCurrentReport);

    document.querySelectorAll('.command-tab').forEach(tab => tab.addEventListener('click', () => switchView(tab.dataset.view)));

    const fileInput = $('captureFile');
    $('chooseFileBtn').addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', () => importFile(fileInput.files[0]));
    const dropZone = $('dropZone');
    ['dragenter', 'dragover'].forEach(name => dropZone.addEventListener(name, event => {
      event.preventDefault();
      dropZone.classList.add('dragging');
    }));
    ['dragleave', 'drop'].forEach(name => dropZone.addEventListener(name, event => {
      event.preventDefault();
      dropZone.classList.remove('dragging');
    }));
    dropZone.addEventListener('drop', event => importFile(event.dataTransfer.files[0]));

    switchView('replayView');
    if (data.scenarios.length) await loadScenario(data.scenarios[0].id);
  } catch (error) {
    $('scenarioName').textContent = 'Workbench unavailable';
    $('scenarioDescription').textContent = error.message;
  }
}

boot();

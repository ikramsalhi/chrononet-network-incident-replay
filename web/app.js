const $ = (id) => document.getElementById(id);
let currentScenario = null;
let replayTimer = null;

async function json(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
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

function renderScenario(data) {
  currentScenario = data;
  const a = data.analysis;
  $('scenarioName').textContent = data.name;
  $('scenarioDescription').textContent = data.description;
  $('caseCode').textContent = `CN-${String(data.id).toUpperCase().replace(/[^A-Z0-9]+/g, '-').slice(0, 18)}`;
  $('healthScore').textContent = a.health_score;
  $('eventCount').textContent = a.event_count;
  $('nodeCount').textContent = a.affected_nodes.length;
  $('duration').textContent = formatSeconds(a.duration_seconds);

  $('timeline').innerHTML = data.events.map((event, index) => {
    const t = new Date(event.timestamp).toISOString().slice(11, 19);
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
      <div class="confidence">
        <span>${finding.confidence}% CONFIDENCE</span>
        <div class="confidence-bar"><span style="width:${finding.confidence}%"></span></div>
      </div>
      <div class="recommendation"><strong>NEXT CHECK</strong><br>${escapeHtml(finding.recommendation)}</div>
    </div>`;
    $('evidence').innerHTML = finding.evidence.map((item, index) => `<div>${String(index + 1).padStart(2, '0')} / ${escapeHtml(item)}</div>`).join('');
  } else {
    $('finding').innerHTML = '<div class="finding-main"><div class="severity">NO HIGH-CONFIDENCE MATCH</div><h4>Correlation inconclusive</h4><div class="recommendation">The current rule set did not produce a strong root-cause hypothesis for this scenario.</div></div>';
    $('evidence').innerHTML = '';
  }

  $('nodes').innerHTML = a.affected_nodes.map(node => `<span class="node">${escapeHtml(node)}</span>`).join('');
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
  }, 330);
}

async function loadScenario(id) {
  const data = await json(`/api/scenarios/${encodeURIComponent(id)}`);
  renderScenario(data);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[ch]));
}

async function boot() {
  try {
    const data = await json('/api/scenarios');
    $('scenarioSelect').innerHTML = data.scenarios.map(s => `<option value="${s.id}">${escapeHtml(s.name)}</option>`).join('');
    $('scenarioSelect').addEventListener('change', event => loadScenario(event.target.value));
    $('replayBtn').addEventListener('click', replay);
    $('reportBtn').addEventListener('click', () => {
      if (!currentScenario) return;
      window.open(`/api/scenarios/${encodeURIComponent(currentScenario.id)}/report`, '_blank');
    });

    document.querySelectorAll('.command-tab').forEach(tab => {
      tab.addEventListener('click', () => switchView(tab.dataset.view));
    });

    switchView('replayView');
    if (data.scenarios.length) await loadScenario(data.scenarios[0].id);
  } catch (error) {
    $('scenarioName').textContent = 'Workbench unavailable';
    $('scenarioDescription').textContent = error.message;
  }
}

boot();

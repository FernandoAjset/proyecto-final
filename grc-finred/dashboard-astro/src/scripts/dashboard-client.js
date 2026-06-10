import Chart from 'chart.js/auto';
import { HEATMAP, ACTORS, TITLES } from '../data/dashboard.js';

/* TAB SWITCHING */
let initialized = {};

document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => {
    const tab = item.dataset.tab;
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    item.classList.add('active');
    document.getElementById('tab-' + tab).classList.add('active');
    document.getElementById('pageTitle').textContent = TITLES[tab][0];
    document.getElementById('pageSub').textContent = TITLES[tab][1];
    if (!initialized[tab]) { initTab(tab); initialized[tab] = true; }
    runCounters(document.getElementById('tab-' + tab));
  });
});

/* ANIMATED COUNTERS */
function runCounters(scope) {
  scope.querySelectorAll('[data-counter]').forEach(el => {
    const target = parseFloat(el.dataset.counter);
    const decimals = parseInt(el.dataset.decimals || "0");
    const prefix = el.dataset.prefix || "";
    const suffix = el.dataset.suffix || "";
    const start = performance.now();
    const dur = 1300;
    function step(now) {
      const p = Math.min((now - start) / dur, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      const val = (target * eased).toFixed(decimals);
      el.textContent = prefix + val + suffix;
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  });
  scope.querySelectorAll('[data-width]').forEach(el => {
    const w = el.dataset.width;
    requestAnimationFrame(() => { el.style.width = w + '%'; });
  });
  scope.querySelectorAll('[data-fill]').forEach(el => {
    const w = el.dataset.fill;
    setTimeout(() => { el.style.width = w + '%'; }, 100);
  });
  scope.querySelectorAll('[data-target-offset]').forEach(el => {
    const offset = el.dataset.targetOffset;
    setTimeout(() => {
      el.style.transition = 'stroke-dashoffset 1.4s cubic-bezier(.22,1,.36,1)';
      el.style.strokeDashoffset = offset;
    }, 100);
  });
}

/* CHART.JS GLOBAL DEFAULTS */
Chart.defaults.color = '#8291ab';
Chart.defaults.borderColor = '#1a2d4a';
Chart.defaults.font.family = "'DM Sans', sans-serif";

/* TAB INIT FUNCTIONS */
function initTab(tab) {
  if (tab === 'ejecutivo') initEjecutivo();
  if (tab === 'incidente') initIncidente();
  if (tab === 'riesgos') initRiesgos();
  if (tab === 'amenazas') initAmenazas();
  if (tab === 'cumplimiento') initCumplimiento();
  if (tab === 'forense') initForense();
}

function initEjecutivo() {
  new Chart(document.getElementById('chartRiskEvo'), {
    type: 'bar',
    data: {
      labels: ['Muy Alto', 'Alto', 'Medio', 'Bajo', 'Muy Bajo'],
      datasets: [
        { label: 'Inherente', data: [4,13,17,5,0], backgroundColor: 'rgba(239,68,68,.7)', borderRadius: 4 },
        { label: 'Residual', data: [0,0,1,1,37], backgroundColor: 'rgba(16,185,129,.7)', borderRadius: 4 },
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#e2e8f0' } } },
      scales: { x: { grid: { display: false } }, y: { grid: { color: '#1a2d4a' }, title: { display: true, text: '# de escenarios', color: '#8291ab' } } }
    }
  });

  new Chart(document.getElementById('chartFrameworkRadar'), {
    type: 'radar',
    data: {
      labels: ['ISO/IEC 27001', 'COBIT 2019', 'NIST CSF 2.0', 'ISO/IEC 27005', 'NIST 800-207 (ZT)'],
      datasets: [{
        label: 'Madurez actual %',
        data: [45, 33, 44, 60, 33],
        backgroundColor: 'rgba(13,211,224,.15)',
        borderColor: '#0dd3e0',
        pointBackgroundColor: '#0dd3e0',
        borderWidth: 2,
      },{
        label: 'Meta %',
        data: [85, 80, 85, 80, 80],
        backgroundColor: 'rgba(124,58,237,.06)',
        borderColor: 'rgba(124,58,237,.5)',
        borderDash: [4,4],
        pointBackgroundColor: 'rgba(124,58,237,.5)',
        borderWidth: 1,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom', labels: { color: '#e2e8f0', font:{size:11}, boxWidth:14, padding:12 } } },
      scales: { r: { angleLines:{color:'#1a2d4a'}, grid:{color:'#1a2d4a'}, pointLabels:{color:'#cbd5e1', font:{size:11}}, ticks:{display:false, backdropColor:'transparent'}, suggestedMin:0, suggestedMax:100 } }
    }
  });

  // animate ROSI gauge arc
  setTimeout(() => {
    const arc = document.getElementById('rosiArc');
    const total = 251;
    const pct = Math.min(116.4 / 150, 1); // scale relative to 150% max
    arc.style.transition = 'stroke-dashoffset 1.6s cubic-bezier(.22,1,.36,1)';
    arc.style.strokeDashoffset = total - (total * pct);
  }, 100);
}

function initIncidente() {
  new Chart(document.getElementById('chartALE'), {
    type: 'bar',
    data: {
      labels: ['Ransomware', 'Exfiltración API', 'Phishing/Soporte', 'Insider Threat'],
      datasets: [
        { label: 'ALE Inherente (Q)', data: [1081200, 873600, 343200, 187200], backgroundColor: 'rgba(239,68,68,.75)', borderRadius: 4 },
        { label: 'ALE Residual (Q)', data: [183804, 174720, 102960, 65520], backgroundColor: 'rgba(16,185,129,.75)', borderRadius: 4 },
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#e2e8f0', font:{size:11} } }, tooltip: { callbacks: { label: c => `Q ${c.raw.toLocaleString('es-GT')}` } } },
      scales: { x: { grid: { display:false } }, y: { grid: { color:'#1a2d4a' }, ticks: { callback: v => `Q${(v/1000).toFixed(0)}K` } } }
    }
  });

  new Chart(document.getElementById('chartROI'), {
    type: 'bar',
    data: {
      labels: ['Object Lock WORM', 'API Gateway + WAF', 'mTLS Microsegmentación', 'MFA FIDO2', 'SIEM Cloud'],
      datasets: [
        { label: 'Costo anual (Q)', data: [46800, 78000, 62400, 46800, 156000], backgroundColor: 'rgba(29,110,245,.7)', borderRadius: 4 },
        { label: 'ALE mitigada (Q)', data: [897540, 698880, 540000, 240000, 480000], backgroundColor: 'rgba(13,211,224,.55)', borderRadius: 4 },
      ]
    },
    options: {
      indexAxis: 'y',
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#e2e8f0', font:{size:11} } }, tooltip: { callbacks: { label: c => `Q ${c.raw.toLocaleString('es-GT')}` } } },
      scales: { x: { grid: { color:'#1a2d4a' }, ticks: { callback: v => `Q${(v/1000).toFixed(0)}K` } }, y: { grid: { display:false } } }
    }
  });
}

function initRiesgos() {
  // heatmap
  const canvas = document.getElementById('heatmapCanvas');
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const padL = 60, padB = 50, padT = 20, padR = 20;
  const gridW = W - padL - padR, gridH = H - padT - padB;
  const cellW = gridW / 5, cellH = gridH / 5;

  function colorFor(score) {
    if (score >= 17) return ['rgba(239,68,68,.85)', '#ef4444'];
    if (score >= 13) return ['rgba(245,158,11,.7)', '#f59e0b'];
    if (score >= 9)  return ['rgba(245,158,11,.4)', '#f59e0b'];
    if (score >= 5)  return ['rgba(16,185,129,.4)', '#10b981'];
    return ['rgba(16,185,129,.18)', '#10b981'];
  }

  ctx.clearRect(0,0,W,H);
  HEATMAP.forEach(cell => {
    const col = cell.i - 1;
    const row = 5 - cell.p;
    const x = padL + col * cellW;
    const y = padT + row * cellH;
    const score = cell.p * cell.i;
    const [bg, border] = colorFor(score);
    ctx.fillStyle = bg;
    ctx.fillRect(x+2, y+2, cellW-4, cellH-4);
    ctx.strokeStyle = border;
    ctx.lineWidth = 1;
    ctx.strokeRect(x+2, y+2, cellW-4, cellH-4);
    if (cell.c > 0) {
      ctx.fillStyle = '#f8fafc';
      ctx.font = '700 22px "Barlow Condensed", sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(cell.c, x + cellW/2, y + cellH/2 + 8);
      ctx.fillStyle = '#8291ab';
      ctx.font = '500 9px "JetBrains Mono", monospace';
      ctx.fillText('P'+cell.p+'×I'+cell.i, x + cellW/2, y + cellH/2 + 24);
    }
  });

  // axis labels
  ctx.fillStyle = '#cbd5e1';
  ctx.font = '600 12px "DM Sans", sans-serif';
  ctx.textAlign = 'center';
  for (let i = 1; i <= 5; i++) {
    ctx.fillText('I=' + i, padL + (i-0.5)*cellW, H - padB + 22);
  }
  ctx.save();
  for (let p = 1; p <= 5; p++) {
    const row = 5 - p;
    ctx.fillText('P=' + p, 0, padT + (row+0.5)*cellH + 4);
  }
  ctx.restore();
  ctx.textAlign = 'left';
  ctx.fillStyle = '#8291ab';
  ctx.font = '500 11px "DM Sans", sans-serif';
  ctx.fillText('Impacto →', padL + gridW/2 - 30, H - 6);
  ctx.save();
  ctx.translate(14, padT + gridH/2 + 30);
  ctx.rotate(-Math.PI/2);
  ctx.fillText('Probabilidad →', 0, 0);
  ctx.restore();

  // distribution chart
  new Chart(document.getElementById('chartRiskDist'), {
    type: 'doughnut',
    data: {
      labels: ['Muy Bajo', 'Bajo', 'Medio', 'Alto', 'Muy Alto'],
      datasets: [
        {
          label: 'Inherente',
          data: [0, 5, 17, 13, 4],
          backgroundColor: ['#10b981','#3b82f6','#f59e0b','#fb923c','#ef4444'],
          borderColor: '#0c1628', borderWidth: 3,
        },
        {
          label: 'Residual',
          data: [37, 1, 1, 0, 0],
          backgroundColor: ['#10b981','#3b82f6','#f59e0b','#fb923c','#ef4444'],
          borderColor: '#0c1628', borderWidth: 3,
        }
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom', labels: { color: '#e2e8f0', font:{size:11}, padding: 12 } },
        title: { display: true, text: 'Anillo externo: Inherente · Anillo interno: Residual', color: '#8291ab', font:{size:11}, padding:{bottom:10} },
        tooltip: { callbacks: { label: c => ` ${c.label}: ${c.raw} de 39 escenarios (${c.dataset.label})` } }
      },
    }
  });
}

function initAmenazas() {
  new Chart(document.getElementById('chartActorRadar'), {
    type: 'polarArea',
    data: {
      labels: ACTORS.map(a => a.name),
      datasets: [{
        data: ACTORS.map(a => a.relevance),
        backgroundColor: ACTORS.map(a => a.color.replace(')', ',.45)').replace('var(--red','rgba(239,68,68').replace('var(--purple','rgba(124,58,237').replace('var(--amber','rgba(245,158,11').replace('var(--blue','rgba(29,110,245').replace('var(--cyan','rgba(13,211,224')),
        borderWidth: 0,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom', labels: { color: '#cbd5e1', font:{size:10}, boxWidth: 12 } } },
      scales: { r: { ticks: { display:false, backdropColor:'transparent' }, grid:{color:'#1a2d4a'}, angleLines:{color:'#1a2d4a'} } }
    }
  });
}

function initCumplimiento() {
  // bar/ring animations handled generically by runCounters via data-width / data-target-offset
}

function initForense() {
  // try fetching real sha256 if served via http
  fetch('./outputs/dashboard_data.json').then(r => r.json()).then(d => {
    if (d.incidente && d.incidente.sha256) document.getElementById('shaBox').textContent = d.incidente.sha256;
  }).catch(() => {});
}

/* boot */
initTab('ejecutivo');
initialized.ejecutivo = true;
runCounters(document.getElementById('tab-ejecutivo'));

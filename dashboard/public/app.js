const api = {
  overview: () => fetch('/api/overview').then((r) => r.json()),
  sites: () => fetch('/api/sites').then((r) => r.json()),
  addSite: (body) => fetch('/api/sites', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }).then((r) => r.json()),
  deleteSite: (id) => fetch(`/api/sites/${id}`, { method: 'DELETE' }),
  startScan: (id) => fetch(`/api/sites/${id}/scan/start`, { method: 'POST' }).then((r) => r.json()),
  stopScan: (id) => fetch(`/api/sites/${id}/scan/stop`, { method: 'POST' }).then((r) => r.json()),
  resumeScan: (id) => fetch(`/api/sites/${id}/scan/resume`, { method: 'POST' }).then((r) => r.json()),
  findings: (id) => fetch(`/api/sites/${id}/findings`).then((r) => r.json()),
};

const summaryEl = document.getElementById('summary');
const sitesTbody = document.querySelector('#sites-table tbody');
const findingsPanel = document.getElementById('findings-panel');
const findingsTitle = document.getElementById('findings-title');
const findingsTbody = document.querySelector('#findings-table tbody');
const dialog = document.getElementById('add-site-dialog');

document.getElementById('add-site-btn').onclick = () => dialog.showModal();
document.getElementById('cancel-add-site').onclick = () => dialog.close();
document.getElementById('close-findings').onclick = () => { findingsPanel.hidden = true; };

document.getElementById('add-site-form').addEventListener('submit', async (e) => {
  const form = new FormData(e.target);
  const body = Object.fromEntries(form.entries());
  const result = await api.addSite(body);
  if (result.error) {
    alert(result.error);
    return;
  }
  e.target.reset();
  await refresh();
});

async function refresh() {
  const [overview, sites] = await Promise.all([api.overview(), api.sites()]);
  renderSummary(overview);
  renderSites(sites, overview.sites);
}

function renderSummary(overview) {
  summaryEl.innerHTML = `
    <div class="card"><div class="value">${overview.site_count}</div><div class="label">Managed sites</div></div>
    <div class="card ${overview.total_vulnerable > 0 ? 'danger' : ''}"><div class="value">${overview.total_vulnerable}</div><div class="label">Vulnerable items</div></div>
  `;
}

function renderSites(sites, overviewSites) {
  const overviewById = Object.fromEntries(overviewSites.map((s) => [s.id, s]));
  sitesTbody.innerHTML = '';
  for (const site of sites) {
    const ov = overviewById[site.id] || {};
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${escapeHtml(site.name)}</strong><br /><span style="color:var(--muted)">${escapeHtml(site.url)}</span></td>
      <td>${site.last_scan_at ? new Date(site.last_scan_at + 'Z').toLocaleString() : 'Never'}</td>
      <td>${ov.scanned ? `<span class="badge ${ov.vulnerable_count ? 'vulnerable' : 'safe'}">${ov.vulnerable_count} / ${ov.total_items}</span>` : '—'}</td>
      <td><code>${escapeHtml(site.schedule_cron)}</code>${site.scheduled ? '' : ' <span style="color:var(--muted)">(paused)</span>'}</td>
      <td>${site.scan_enabled ? (site.scan_running ? 'Scanning…' : 'Enabled') : '<span style="color:var(--danger)">Stopped</span>'}</td>
      <td class="actions-cell"></td>
    `;
    const actions = tr.querySelector('.actions-cell');

    const scanBtn = mkBtn('Scan now', async () => {
      scanBtn.disabled = true;
      try {
        await api.startScan(site.id);
        await refresh();
      } catch (err) {
        alert(err.message);
      } finally {
        scanBtn.disabled = false;
      }
    });
    actions.appendChild(scanBtn);

    const toggleBtn = site.scan_enabled
      ? mkBtn('Stop', () => api.stopScan(site.id).then(refresh), 'danger')
      : mkBtn('Resume', () => api.resumeScan(site.id).then(refresh));
    actions.appendChild(toggleBtn);

    actions.appendChild(mkBtn('View findings', () => showFindings(site)));
    actions.appendChild(mkBtn('Remove', async () => {
      if (confirm(`Remove ${site.name}?`)) {
        await api.deleteSite(site.id);
        await refresh();
      }
    }, 'secondary'));

    sitesTbody.appendChild(tr);
  }
}

function mkBtn(label, onClick, cls) {
  const btn = document.createElement('button');
  btn.textContent = label;
  if (cls) btn.classList.add(cls);
  btn.onclick = onClick;
  return btn;
}

async function showFindings(site) {
  findingsTitle.textContent = `Findings — ${site.name}`;
  findingsPanel.hidden = false;
  findingsTbody.innerHTML = '<tr><td colspan="6">Loading…</td></tr>';

  const { findings, scan_id } = await api.findings(site.id);
  if (!scan_id) {
    findingsTbody.innerHTML = '<tr><td colspan="6">No completed scans yet. Click "Scan now" first.</td></tr>';
    return;
  }
  if (!findings.length) {
    findingsTbody.innerHTML = '<tr><td colspan="6">No plugins/themes found.</td></tr>';
    return;
  }

  findingsTbody.innerHTML = '';
  for (const f of findings) {
    const tr = document.createElement('tr');
    const vulnList = f.vulnerabilities.length
      ? `<ul class="vuln-list">${f.vulnerabilities.map(vulnItem).join('')}</ul>`
      : '<span style="color:var(--muted)">None known</span>';

    tr.innerHTML = `
      <td>${f.type}</td>
      <td>${escapeHtml(f.name)}<br /><span style="color:var(--muted)">${escapeHtml(f.slug)}</span></td>
      <td>${escapeHtml(f.installed_version)}</td>
      <td><span class="badge ${f.is_vulnerable ? 'vulnerable' : 'safe'}">${f.is_vulnerable ? 'Vulnerable' : 'Safe'}</span></td>
      <td>${vulnList}</td>
      <td>${f.recommended_version ? `<strong>${escapeHtml(f.recommended_version)}</strong>` : '—'}<br /><span style="color:var(--muted)">${escapeHtml(f.recommendation_reason || '')}</span></td>
    `;
    findingsTbody.appendChild(tr);
  }
}

function vulnItem(v) {
  const cve = Array.isArray(v.cve) && v.cve.length ? ` (${v.cve.join(', ')})` : '';
  const sev = v.severity ? `<span class="badge severity-${v.severity}">${v.severity}</span>` : '';
  const fixed = v.fixed_in ? ` — fixed in ${escapeHtml(v.fixed_in)}` : ' — unpatched';
  return `<li>${sev} ${escapeHtml(v.title || 'Unknown issue')}${cve}${fixed}</li>`;
}

function escapeHtml(str) {
  return String(str ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

refresh();
setInterval(refresh, 15000);

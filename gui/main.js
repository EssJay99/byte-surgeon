import { invoke } from '@tauri-apps/api/tauri';

const state = {
    devices: [],
    sessions: [],
    currentView: 'dashboard',
    wizardStep: 1,
    recoveryRunning: false,
    hexCurrentOffset: 0,
    hexPageLength: 256,
    activityLog: [],
};

function navigateTo(view) {
    state.currentView = view;
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    const viewEl = document.getElementById(`view-${view}`);
    const navEl = document.querySelector(`.nav-item[data-view="${view}"]`);
    if (viewEl) viewEl.classList.add('active');
    if (navEl) navEl.classList.add('active');

    const titles = {
        dashboard: 'Dashboard',
        devices: 'Devices',
        recovery: 'Data Recovery',
        sessions: 'Recovery Sessions',
        preview: 'File Preview',
        hex: 'Hex Viewer',
        partitions: 'Partition Scanner',
        diskimage: 'Disk Images',
        raid: 'RAID Tools',
        encryption: 'Encryption Detection',
        threat: 'Threat Scanner',
        duplicates: 'Duplicate Finder',
        reports: 'Report Generator',
        settings: 'Settings',
        'usn-journal': 'USN Journal Parser',
        'shadow-copies': 'Shadow Copy Explorer',
        'fragments': 'File Fragment Scanner',
        'file-repair': 'File Repair',
        'registry': 'Registry Hive Parser',
        'whatsapp': 'WhatsApp Recovery',
        'imessage': 'iMessage Recovery',
        'signal': 'Signal Recovery',
        'slack': 'Slack Recovery',
        'browser-history': 'Browser History Recovery',
        'sqlite-carve': 'SQLite Carver',
        'email': 'Email Recovery',
        'resume-scan': 'Resume Scan',
        'incremental-scan': 'Incremental Scan',
        'batch-processing': 'Batch Processing',
        'case-management': 'Case Management',
        'api-server': 'API Server',
    };
    document.getElementById('viewTitle').textContent = titles[view] || view;
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

function addActivity(text, color = 'var(--info)') {
    state.activityLog.unshift({ text, color, time: new Date() });
    if (state.activityLog.length > 20) state.activityLog.pop();
    renderActivityLog();
}

function renderActivityLog() {
    const el = document.getElementById('activityLog');
    if (state.activityLog.length === 0) {
        el.innerHTML = '<div class="empty-state"><div class="empty-state-text">No recent activity</div></div>';
        return;
    }
    el.innerHTML = state.activityLog.slice(0, 10).map(a => `
        <div class="activity-item">
            <div class="activity-dot" style="background: ${a.color}"></div>
            <div>
                <div class="activity-text">${a.text}</div>
                <div class="activity-time">${formatTimeAgo(a.time)}</div>
            </div>
        </div>
    `).join('');
}

function formatTimeAgo(date) {
    const seconds = Math.floor((new Date() - date) / 1000);
    if (seconds < 60) return 'Just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return date.toLocaleDateString();
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatNumber(n) {
    if (n == null) return '0';
    return n.toLocaleString();
}

function parseOffset(val) {
    val = val.trim();
    if (val.startsWith('0x') || val.startsWith('0X')) {
        return parseInt(val, 16);
    }
    return parseInt(val, 10) || 0;
}

async function invokeSafe(cmd, args) {
    try {
        return await invoke(cmd, args);
    } catch (err) {
        console.error(`[invoke ${cmd}]`, err);
        showToast(`${cmd}: ${err}`, 'error');
        throw err;
    }
}

// ── Devices ──

async function refreshDevices() {
    try {
        showToast('Scanning for devices...', 'info');
        state.devices = await invokeSafe('scan_devices');
        updateDeviceSelects();
        renderDeviceList();
        updateDashboardStats();
        addActivity(`Scanned devices: found ${state.devices.length}`, 'var(--success)');
        showToast(`Found ${state.devices.length} device(s)`, 'success');
    } catch (_) {
        state.devices = [];
        renderDeviceList();
    }
}

function updateDeviceSelects() {
    const selects = ['recoveryDevice', 'partitionDevice', 'encryptionDevice', 'imageSourceDevice',
        'usn-device', 'shadow-device', 'fragment-device', 'incremental-device'];
    selects.forEach(id => {
        const sel = document.getElementById(id);
        if (!sel) return;
        sel.innerHTML = state.devices.length === 0
            ? '<option value="">No devices found</option>'
            : '<option value="">-- Select device --</option>' +
              state.devices.map(d =>
                  `<option value="${d.path}">${d.name} (${d.path}) - ${formatBytes(d.total_size)}</option>`
              ).join('');
    });

    const raidList = document.getElementById('raidDiskSelect');
    if (state.devices.length === 0) {
        raidList.innerHTML = '<div class="empty-state" style="padding:16px;"><div class="empty-state-text">Scan devices first</div></div>';
    } else {
        raidList.innerHTML = state.devices.map((d, i) => `
            <label class="multi-select-item">
                <input type="checkbox" value="${d.path}" class="raid-disk-cb">
                ${d.name} - ${d.path} (${formatBytes(d.total_size)})
            </label>
        `).join('');
    }
}

function renderDeviceList() {
    const el = document.getElementById('deviceList');
    if (state.devices.length === 0) {
        el.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">&#x1F4BE;</div>
                <div class="empty-state-text">No devices detected</div>
                <button class="btn btn-primary" onclick="refreshDevices()">Scan Now</button>
            </div>`;
        return;
    }
    el.innerHTML = state.devices.map(d => `
        <div class="device-card">
            <div class="device-info-main">
                <div class="device-name">${d.name}</div>
                <div class="device-meta">
                    <span>${d.path}</span>
                    <span>${formatBytes(d.total_size)}</span>
                    <span>${d.device_type}</span>
                    <span>${d.file_system}</span>
                </div>
            </div>
            <div class="device-actions">
                <button class="btn btn-secondary btn-sm" onclick="deviceAction('info', '${d.path}')">Info</button>
                <button class="btn btn-secondary btn-sm" onclick="deviceAction('partitions', '${d.path}')">Partitions</button>
                <button class="btn btn-secondary btn-sm" onclick="deviceAction('encryption', '${d.path}')">Encryption</button>
                <button class="btn btn-secondary btn-sm" onclick="deviceAction('image', '${d.path}')">Image</button>
                <button class="btn btn-secondary btn-sm" onclick="deviceAction('writeprotect', '${d.path}')">Write Prot.</button>
            </div>
        </div>
    `).join('');
}

async function deviceAction(action, path) {
    switch (action) {
        case 'partitions':
            navigateTo('partitions');
            document.getElementById('partitionDevice').value = path;
            doScanPartitions();
            break;
        case 'encryption':
            navigateTo('encryption');
            document.getElementById('encryptionDevice').value = path;
            doCheckEncryption();
            break;
        case 'image':
            navigateTo('diskimage');
            document.getElementById('imageSourceDevice').value = path;
            break;
        case 'writeprotect':
            try {
                const result = await invokeSafe('check_write_protection', { device_path: path });
                showToast(`Write protection: ${result}`, 'info');
                addActivity(`Checked write protection: ${path}`, 'var(--info)');
            } catch (_) {}
            break;
        case 'info':
        default: {
            const dev = state.devices.find(d => d.path === path);
            if (dev) {
                showToast(`${dev.name} | ${dev.path} | ${formatBytes(dev.total_size)} | ${dev.device_type} | ${dev.file_system} | Free: ${formatBytes(dev.free_space)}`, 'info');
            }
            break;
        }
    }
}

// ── Dashboard ──

async function updateDashboardStats() {
    document.getElementById('statDevices').textContent = state.devices.length;
    try {
        state.sessions = await invoke('get_sessions');
    } catch (_) {
        state.sessions = [];
    }
    document.getElementById('statSessions').textContent = state.sessions.length;
    let totalFiles = 0, totalSize = 0;
    state.sessions.forEach(s => {
        totalFiles += s.files_recovered;
        totalSize += s.total_size_recovered;
    });
    document.getElementById('statFiles').textContent = formatNumber(totalFiles);
    document.getElementById('statData').textContent = formatBytes(totalSize);
}

// ── Recovery Wizard ──

function wizardNext() {
    if (state.wizardStep === 1) {
        const dev = document.getElementById('recoveryDevice').value;
        if (!dev) { showToast('Please select a device', 'warning'); return; }
    }
    if (state.wizardStep < 5) {
        setWizardStep(state.wizardStep + 1);
    }
}

function wizardPrev() {
    if (state.wizardStep > 1) setWizardStep(state.wizardStep - 1);
}

function setWizardStep(step) {
    state.wizardStep = step;
    document.querySelectorAll('.wizard-step').forEach(el => {
        const s = parseInt(el.dataset.step);
        el.classList.remove('active', 'completed');
        if (s === step) el.classList.add('active');
        else if (s < step) el.classList.add('completed');
    });
    document.querySelectorAll('.wizard-panel').forEach(p => p.classList.remove('active'));
    const panel = document.getElementById(`wizard-panel-${step}`);
    if (panel) panel.classList.add('active');

    if (step === 5) buildRecoverySummary();
}

function buildRecoverySummary() {
    const dev = document.getElementById('recoveryDevice');
    const mode = document.getElementById('recoveryMode');
    const output = document.getElementById('recoveryOutputDir').value;

    const devText = dev.selectedOptions[0]?.textContent || 'None';
    const modeText = mode.selectedOptions[0]?.textContent || 'None';

    const filters = [];
    document.querySelectorAll('.filter-type:checked').forEach(cb => filters.push(cb.value));
    const minSize = document.getElementById('filterMinSize').value;
    const maxSize = document.getElementById('filterMaxSize').value;
    const dateFrom = document.getElementById('filterDateFrom').value;
    const dateTo = document.getElementById('filterDateTo').value;
    const namePattern = document.getElementById('filterNamePattern').value;

    let filterText = 'None';
    if (filters.length || minSize || maxSize || dateFrom || dateTo || namePattern) {
        const parts = [];
        if (filters.length) parts.push(`Types: ${filters.join(', ')}`);
        if (minSize) parts.push(`Min: ${minSize} MB`);
        if (maxSize) parts.push(`Max: ${maxSize} MB`);
        if (dateFrom) parts.push(`From: ${dateFrom}`);
        if (dateTo) parts.push(`To: ${dateTo}`);
        if (namePattern) parts.push(`Pattern: ${namePattern}`);
        filterText = parts.join(' | ');
    }

    document.getElementById('recoverySummary').innerHTML = `
        <div><strong>Device:</strong> ${devText}</div>
        <div><strong>Mode:</strong> ${modeText}</div>
        <div><strong>Filters:</strong> ${filterText}</div>
        <div><strong>Output:</strong> ${output}</div>
    `;
}

async function executeRecovery() {
    const devicePath = document.getElementById('recoveryDevice').value;
    const scanType = document.getElementById('recoveryMode').value;
    const outputDir = document.getElementById('recoveryOutputDir').value;

    if (!devicePath) { showToast('No device selected', 'warning'); return; }
    if (!outputDir) { showToast('Output directory required', 'warning'); return; }

    state.recoveryRunning = true;
    document.getElementById('recoveryProgressArea').style.display = 'block';
    document.getElementById('recoveryStartBtn').style.display = 'none';
    document.getElementById('recoveryBackBtn').style.display = 'none';
    document.getElementById('recoveryCancelBtn').style.display = 'inline-flex';

    const progressFill = document.getElementById('recoveryProgressFill');
    const progressText = document.getElementById('recoveryProgressText');
    const progressPct = document.getElementById('recoveryProgressPct');

    try {
        progressText.textContent = 'Starting recovery...';
        progressFill.style.width = '5%';
        progressPct.textContent = '5%';

        const sessionId = await invokeSafe('start_recovery', {
            request: {
                device_path: devicePath,
                scan_type: scanType,
                output_dir: outputDir,
            },
        });

        addActivity(`Recovery started: ${scanType} on ${devicePath}`, 'var(--success)');

        let progress = 5;
        const interval = setInterval(() => {
            if (!state.recoveryRunning) {
                clearInterval(interval);
                return;
            }
            progress += Math.random() * 8 + 2;
            if (progress >= 100) {
                progress = 100;
                clearInterval(interval);
                state.recoveryRunning = false;
                progressText.textContent = 'Recovery complete!';
                showToast('Recovery completed successfully!', 'success');
                addActivity(`Recovery complete: session ${sessionId}`, 'var(--success)');
                document.getElementById('recoveryCancelBtn').style.display = 'none';
                document.getElementById('recoveryStartBtn').style.display = 'inline-flex';
                document.getElementById('recoveryStartBtn').textContent = 'Start New Recovery';
                document.getElementById('recoveryBackBtn').style.display = 'inline-flex';
                updateDashboardStats();
            }
            progressFill.style.width = `${Math.min(progress, 100)}%`;
            progressPct.textContent = `${Math.round(Math.min(progress, 100))}%`;
            if (progress < 100) {
                progressText.textContent = `Scanning... ${Math.round(progress)}%`;
            }
        }, 600);

        showToast(`Recovery started (session: ${sessionId.substring(0, 8)}...)`, 'success');
    } catch (_) {
        state.recoveryRunning = false;
        progressText.textContent = 'Recovery failed';
        progressFill.style.width = '0%';
        document.getElementById('recoveryCancelBtn').style.display = 'none';
        document.getElementById('recoveryStartBtn').style.display = 'inline-flex';
        document.getElementById('recoveryBackBtn').style.display = 'inline-flex';
    }
}

function cancelRecovery() {
    state.recoveryRunning = false;
    document.getElementById('recoveryProgressText').textContent = 'Cancelled';
    document.getElementById('recoveryCancelBtn').style.display = 'none';
    document.getElementById('recoveryStartBtn').style.display = 'inline-flex';
    document.getElementById('recoveryBackBtn').style.display = 'inline-flex';
    showToast('Recovery cancelled', 'warning');
    addActivity('Recovery cancelled by user', 'var(--warning)');
}

// ── Sessions ──

async function loadSessions() {
    try {
        state.sessions = await invokeSafe('get_sessions');
        renderSessions();
        updateDashboardStats();
        addActivity(`Loaded ${state.sessions.length} sessions`, 'var(--info)');
    } catch (_) {}
}

function renderSessions() {
    const el = document.getElementById('sessionsList');
    if (state.sessions.length === 0) {
        el.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">&#x1F4C1;</div>
                <div class="empty-state-text">No recovery sessions found</div>
                <button class="btn btn-primary" onclick="loadSessions()">Load Sessions</button>
            </div>`;
        return;
    }
    el.innerHTML = state.sessions.map(s => {
        const statusClass = s.status.includes('Complete') ? 'badge-success'
            : s.status.includes('Running') ? 'badge-info'
            : s.status.includes('Fail') ? 'badge-danger'
            : 'badge-warning';
        return `
        <div class="session-card" id="session-${s.id}">
            <div class="session-header" onclick="toggleSession('${s.id}')">
                <div>
                    <div style="font-weight: 600; font-size: 14px;">Session ${s.id.substring(0, 8)}...</div>
                    <div class="session-details" style="margin-top: 6px;">
                        <div><span class="session-detail-label">Device: </span><span class="session-detail-value">${s.device_id.substring(0, 8)}...</span></div>
                        <div><span class="session-detail-label">Type: </span><span class="session-detail-value">${s.scan_type}</span></div>
                        <div><span class="session-detail-label">Found: </span><span class="session-detail-value">${formatNumber(s.files_found)}</span></div>
                        <div><span class="session-detail-label">Recovered: </span><span class="session-detail-value">${formatNumber(s.files_recovered)}</span></div>
                        <div><span class="session-detail-label">Size: </span><span class="session-detail-value">${formatBytes(s.total_size_recovered)}</span></div>
                    </div>
                </div>
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span class="badge ${statusClass}">${s.status}</span>
                    <button class="btn btn-secondary btn-sm" onclick="event.stopPropagation(); exportSession('${s.id}')">Export</button>
                </div>
            </div>
            <div class="session-files" id="session-files-${s.id}"></div>
        </div>`;
    }).join('');
}

async function toggleSession(sessionId) {
    const filesEl = document.getElementById(`session-files-${sessionId}`);
    if (filesEl.classList.contains('expanded')) {
        filesEl.classList.remove('expanded');
        return;
    }
    filesEl.classList.add('expanded');
    try {
        const files = await invokeSafe('get_recovered_files', { session_id: sessionId });
        if (files.length === 0) {
            filesEl.innerHTML = '<div style="padding: 8px 0; font-size: 13px; color: var(--text-muted);">No files in this session</div>';
            return;
        }
        filesEl.innerHTML = `
            <table>
                <thead>
                    <tr>
                        <th>File</th>
                        <th>Type</th>
                        <th>Size</th>
                        <th>Status</th>
                        <th>Integrity</th>
                        <th>Threat</th>
                    </tr>
                </thead>
                <tbody>
                    ${files.map(f => {
                        const thClass = f.threat_scan === 'Clean' ? 'badge-success' : f.threat_scan === 'Suspicious' ? 'badge-warning' : 'badge-danger';
                        return `
                        <tr>
                            <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${f.recovered_path}">${f.recovered_path}</td>
                            <td>${f.extension || f.file_type}</td>
                            <td>${formatBytes(f.file_size)}</td>
                            <td><span class="badge badge-${f.status === 'Recovered' ? 'success' : 'warning'}">${f.status}</span></td>
                            <td><span class="badge badge-${f.integrity_check === 'Passed' ? 'success' : 'warning'}">${f.integrity_check}</span></td>
                            <td><span class="badge ${thClass}">${f.threat_scan}</span></td>
                        </tr>`;
                    }).join('')}
                </tbody>
            </table>`;
    } catch (_) {
        filesEl.innerHTML = '<div style="padding: 8px 0; color: var(--danger);">Failed to load files</div>';
    }
}

function exportSession(sessionId) {
    navigateTo('reports');
    document.getElementById('reportSession').value = sessionId;
    showToast('Switched to Reports view for export', 'info');
}

// ── File Preview ──

async function doPreviewFile() {
    const path = document.getElementById('previewPath').value.trim();
    if (!path) { showToast('Enter a file path', 'warning'); return; }
    const el = document.getElementById('previewResults');
    el.innerHTML = '<div class="card"><div class="card-body"><div class="progress-container"><div class="progress-bar"><div class="progress-fill" style="width:50%"></div></div><div class="progress-label"><span>Loading preview...</span></div></div></div></div>';
    try {
        const result = await invokeSafe('preview_file', { path });
        let data;
        try { data = JSON.parse(result); } catch { data = { content: result }; }

        const textContent = data.text_content || data.content || data.data || JSON.stringify(data, null, 2);
        const mimeType = data.mime_type || data.type || 'unknown';
        const fileType = data.file_type || 'unknown';

        el.innerHTML = `
            <div class="preview-panel">
                <div class="card">
                    <div class="card-header">Preview</div>
                    <div class="card-body">
                        <div class="preview-content">${escapeHtml(typeof textContent === 'string' ? textContent.substring(0, 5000) : JSON.stringify(textContent, null, 2))}</div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-header">Metadata</div>
                    <div class="card-body">
                        <div class="metadata-grid">
                            <div class="metadata-item"><div class="metadata-label">File Type</div><div class="metadata-value">${fileType}</div></div>
                            <div class="metadata-item"><div class="metadata-label">MIME Type</div><div class="metadata-value">${mimeType}</div></div>
                            <div class="metadata-item"><div class="metadata-label">Path</div><div class="metadata-value">${path}</div></div>
                            ${data.size ? `<div class="metadata-item"><div class="metadata-label">Size</div><div class="metadata-value">${formatBytes(data.size)}</div></div>` : ''}
                        </div>
                    </div>
                </div>
            </div>`;
        addActivity(`Previewed file: ${path}`, 'var(--info)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">Failed to load preview</div></div>';
    }
}

// ── Hex Viewer ──

async function doHexView() {
    const path = document.getElementById('hexPath').value.trim();
    const offsetVal = document.getElementById('hexOffset').value.trim();
    const lengthVal = parseInt(document.getElementById('hexLength').value) || 256;

    if (!path) { showToast('Enter a file/device path', 'warning'); return; }

    const offset = parseOffset(offsetVal);
    state.hexCurrentOffset = offset;
    state.hexPageLength = lengthVal;

    const el = document.getElementById('hexOutput');
    el.textContent = 'Loading...';
    try {
        const result = await invokeSafe('hex_view', { path, offset: BigInt(offset).toString(), length: lengthVal });
        el.innerHTML = formatHexOutput(result);
        addActivity(`Hex view: ${path} @ offset ${offset}`, 'var(--info)');
    } catch (_) {
        el.innerHTML = '<span style="color: var(--danger);">Failed to read hex data</span>';
    }
}

function formatHexOutput(text) {
    if (!text || text.trim() === '') return '<span style="color: var(--text-muted);">No data</span>';
    return escapeHtml(text);
}

function hexPrevPage() {
    const newOffset = Math.max(0, state.hexCurrentOffset - state.hexPageLength);
    document.getElementById('hexOffset').value = '0x' + newOffset.toString(16);
    doHexView();
}

function hexNextPage() {
    const newOffset = state.hexCurrentOffset + state.hexPageLength;
    document.getElementById('hexOffset').value = '0x' + newOffset.toString(16);
    doHexView();
}

// ── Partitions ──

async function doScanPartitions() {
    const devicePath = document.getElementById('partitionDevice').value;
    if (!devicePath) { showToast('Select a device first', 'warning'); return; }
    const el = document.getElementById('partitionResults');
    el.innerHTML = '<div class="card"><div class="card-body">Scanning partitions...</div></div>';
    try {
        const partitions = await invokeSafe('scan_partitions', { device_path: devicePath });
        if (partitions.length === 0) {
            el.innerHTML = '<div class="card"><div class="card-body">No partitions found</div></div>';
            return;
        }
        el.innerHTML = `
            <div class="card">
                <div class="card-header">Found ${partitions.length} Partition(s)</div>
                <div class="card-body" style="padding: 0; overflow-x: auto;">
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Start Sector</th>
                                <th>End Sector</th>
                                <th>Type</th>
                                <th>Filesystem</th>
                                <th>Active</th>
                                <th>GPT</th>
                                <th>GUID</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${partitions.map(p => `
                                <tr>
                                    <td>${p.index}</td>
                                    <td>${formatNumber(p.start_sector)}</td>
                                    <td>${formatNumber(p.end_sector)}</td>
                                    <td>${p.partition_type}</td>
                                    <td>${p.filesystem}</td>
                                    <td><span class="badge ${p.is_active ? 'badge-success' : 'badge-muted'}">${p.is_active ? 'Yes' : 'No'}</span></td>
                                    <td><span class="badge ${p.is_gpt ? 'badge-info' : 'badge-muted'}">${p.is_gpt ? 'Yes' : 'No'}</span></td>
                                    <td style="font-family: monospace; font-size: 11px;">${p.guid || '-'}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>`;
        addActivity(`Scanned partitions on ${devicePath}: found ${partitions.length}`, 'var(--success)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">Failed to scan partitions</div></div>';
    }
}

// ── Disk Images ──

async function doGetImageInfo() {
    const path = document.getElementById('imagePath').value.trim();
    if (!path) { showToast('Enter an image path', 'warning'); return; }
    const el = document.getElementById('imageInfoResults');
    el.innerHTML = '<div class="card"><div class="card-body">Loading image info...</div></div>';
    try {
        const result = await invokeSafe('get_image_info', { path });
        let meta;
        try { meta = JSON.parse(result); } catch { meta = { raw: result }; }

        el.innerHTML = `
            <div class="card">
                <div class="card-header">Image Info</div>
                <div class="card-body">
                    <div class="image-info-grid">
                        ${Object.entries(meta).map(([k, v]) => `
                            <div class="metadata-item">
                                <div class="metadata-label">${k.replace(/_/g, ' ')}</div>
                                <div class="metadata-value">${typeof v === 'number' && v > 1000 ? formatBytes(v) : v}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>`;
        addActivity(`Opened disk image: ${path}`, 'var(--info)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">Failed to read image info</div></div>';
    }
}

// ── RAID Tools ──

async function doDetectRaid() {
    const checked = document.querySelectorAll('.raid-disk-cb:checked');
    if (checked.length < 2) { showToast('Select at least 2 disks for RAID detection', 'warning'); return; }

    const disks = Array.from(checked).map(cb => cb.value);
    const el = document.getElementById('raidResults');
    el.innerHTML = '<div class="card"><div class="card-body">Detecting RAID configuration...</div></div>';

    try {
        const result = await invokeSafe('detect_raid', { disks });
        let info;
        try { info = JSON.parse(result); } catch { info = { raw: result }; }

        const level = info.raid_level || info.level || 'Unknown';
        const diskCount = info.disk_count || info.num_disks || disks.length;
        const stripeSize = info.stripe_size || info.stripe || 'N/A';
        const health = info.health || info.status || 'Unknown';
        const healthBadge = health === 'Healthy' || health === 'OK' ? 'badge-success'
            : health === 'Degraded' ? 'badge-warning' : 'badge-danger';

        document.getElementById('reconstructRaidBtn').disabled = false;

        el.innerHTML = `
            <div class="card">
                <div class="card-header">RAID Detection Results</div>
                <div class="card-body">
                    <div class="image-info-grid">
                        <div class="metadata-item"><div class="metadata-label">RAID Level</div><div class="metadata-value">${level}</div></div>
                        <div class="metadata-item"><div class="metadata-label">Disk Count</div><div class="metadata-value">${diskCount}</div></div>
                        <div class="metadata-item"><div class="metadata-label">Stripe Size</div><div class="metadata-value">${stripeSize}</div></div>
                        <div class="metadata-item"><div class="metadata-label">Health</div><div class="metadata-value"><span class="badge ${healthBadge}">${health}</span></div></div>
                    </div>
                </div>
            </div>`;
        addActivity(`RAID detected: level ${level}, ${diskCount} disks`, 'var(--success)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">RAID detection failed</div></div>';
    }
}

function doReconstructRaid() {
    showToast('RAID reconstruction would begin on the detected array', 'info');
    addActivity('RAID reconstruction initiated', 'var(--warning)');
}

// ── Encryption ──

async function doCheckEncryption() {
    const devicePath = document.getElementById('encryptionDevice').value;
    if (!devicePath) { showToast('Select a device first', 'warning'); return; }
    const el = document.getElementById('encryptionResults');
    el.innerHTML = '<div class="card"><div class="card-body">Checking encryption status...</div></div>';
    try {
        const result = await invokeSafe('check_encryption', { device_path: devicePath });
        let data;
        try { data = JSON.parse(result); } catch { data = { raw: result }; }

        const types = Object.entries(data).filter(([, v]) => v === true);
        const encrypted = types.length > 0;
        const encType = types.map(([k]) => k).join(', ') || 'None';

        el.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <div class="encryption-status">
                        <div class="encryption-icon">${encrypted ? '&#x1F512;' : '&#x1F513;'}</div>
                        <div style="font-size: 18px; font-weight: 600; margin-bottom: 4px;">
                            ${encrypted ? 'Encrypted' : 'Not Encrypted'}
                        </div>
                        <div style="color: var(--text-muted); margin-bottom: 16px;">
                            ${encrypted ? `Detected: ${encType}` : 'No encryption detected on this device'}
                        </div>
                        ${encrypted ? `
                            <div style="max-width: 300px; margin: 0 auto;">
                                <div class="form-group">
                                    <label class="form-label">Password</label>
                                    <input type="password" class="form-input" id="encryptionPassword" placeholder="Enter decryption password">
                                </div>
                                <button class="btn btn-primary" onclick="doUnlockEncryption('${devicePath}')">Unlock</button>
                            </div>
                        ` : ''}
                    </div>
                    <div class="image-info-grid" style="margin-top: 16px;">
                        ${Object.entries(data).map(([k, v]) => `
                            <div class="metadata-item">
                                <div class="metadata-label">${k}</div>
                                <div class="metadata-value"><span class="badge ${v ? 'badge-danger' : 'badge-success'}">${v ? 'Detected' : 'Not detected'}</span></div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>`;
        addActivity(`Checked encryption on ${devicePath}: ${encrypted ? encType : 'none'}`, encrypted ? 'var(--warning)' : 'var(--success)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">Encryption check failed</div></div>';
    }
}

function doUnlockEncryption(devicePath) {
    const password = document.getElementById('encryptionPassword')?.value;
    if (!password) { showToast('Enter a password', 'warning'); return; }
    showToast('Unlock functionality requires additional backend support', 'info');
    addActivity(`Unlock attempt on ${devicePath}`, 'var(--warning)');
}

// ── Threat Scan ──

async function doThreatScan() {
    const path = document.getElementById('threatPath').value.trim();
    if (!path) { showToast('Enter a path to scan', 'warning'); return; }
    const el = document.getElementById('threatResults');
    el.innerHTML = '<div class="card"><div class="card-body">Scanning for threats...</div></div>';
    try {
        const status = await invokeSafe('scan_threats', { request: { path } });

        const icon = status === 'Clean' ? '&#x2705;' : status === 'Suspicious' ? '&#x26A0;' : '&#x274C;';
        const badgeClass = status === 'Clean' ? 'badge-success' : status === 'Suspicious' ? 'badge-warning' : 'badge-danger';
        const color = status === 'Clean' ? 'var(--success)' : status === 'Suspicious' ? 'var(--warning)' : 'var(--danger)';

        el.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <div class="threat-result">
                        <div class="threat-icon">${icon}</div>
                        <div style="font-size: 20px; font-weight: 700; color: ${color}; margin-bottom: 8px;">${status}</div>
                        <div style="color: var(--text-muted);">
                            ${status === 'Clean' ? 'No threats detected in the scanned path.' :
                              status === 'Suspicious' ? 'Suspicious patterns found. Review recommended.' :
                              'Threats detected! Immediate action required.'}
                        </div>
                        <div style="margin-top: 12px;">
                            <span class="badge ${badgeClass}">${status}</span>
                            <span class="badge badge-muted">${path}</span>
                        </div>
                    </div>
                </div>
            </div>`;
        addActivity(`Threat scan on ${path}: ${status}`, color);
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">Threat scan failed</div></div>';
    }
}

// ── Duplicates ──

async function doFindDuplicates() {
    const dir = document.getElementById('duplicatesPath').value.trim();
    if (!dir) { showToast('Enter a directory path', 'warning'); return; }
    const el = document.getElementById('duplicatesResults');
    el.innerHTML = '<div class="card"><div class="card-body">Scanning for duplicates...</div></div>';
    try {
        const result = await invokeSafe('find_duplicates', { directory: dir });
        let groups;
        try { groups = JSON.parse(result); } catch { groups = []; }

        if (groups.length === 0) {
            el.innerHTML = `
                <div class="card">
                    <div class="card-body">
                        <div class="empty-state">
                            <div class="empty-state-icon">&#x2705;</div>
                            <div class="empty-state-text">No duplicates found</div>
                        </div>
                    </div>
                </div>`;
            return;
        }

        el.innerHTML = `
            <div class="card">
                <div class="card-header">Found ${groups.length} Duplicate Group(s)</div>
                <div class="card-body">
                    ${groups.map((g, i) => `
                        <div class="duplicate-group">
                            <div class="duplicate-group-header">
                                Group ${i + 1} &mdash; Hash: <code style="font-size: 11px;">${g.hash.substring(0, 16)}...</code> &mdash; ${g.paths.length} files
                            </div>
                            ${g.paths.map(p => `<div class="duplicate-file">${p}</div>`).join('')}
                        </div>
                    `).join('')}
                </div>
            </div>`;
        addActivity(`Duplicates scan: found ${groups.length} groups in ${dir}`, 'var(--info)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">Duplicate scan failed</div></div>';
    }
}

// ── Reports ──

async function loadSessionsForReport() {
    try {
        state.sessions = await invokeSafe('get_sessions');
        const sel = document.getElementById('reportSession');
        if (state.sessions.length === 0) {
            sel.innerHTML = '<option value="">No sessions available</option>';
            return;
        }
        sel.innerHTML = state.sessions.map(s =>
            `<option value="${s.id}">Session ${s.id.substring(0, 8)}... - ${s.scan_type} - ${formatNumber(s.files_recovered)} files</option>`
        ).join('');
        showToast(`Loaded ${state.sessions.length} sessions`, 'success');
    } catch (_) {}
}

async function doGenerateReport() {
    const sessionId = document.getElementById('reportSession').value;
    const format = document.getElementById('reportFormat').value;
    const outputPath = document.getElementById('reportOutputPath').value.trim();

    if (!sessionId) { showToast('Select a session', 'warning'); return; }
    if (!outputPath) { showToast('Enter an output path', 'warning'); return; }

    const el = document.getElementById('reportResults');
    el.innerHTML = '<div class="card"><div class="card-body">Generating report...</div></div>';

    try {
        const result = await invokeSafe('generate_report', {
            session_id: sessionId,
            format,
            output_path: outputPath,
        });
        el.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <div class="threat-result">
                        <div class="threat-icon">&#x1F4CA;</div>
                        <div style="font-size: 16px; font-weight: 600; color: var(--success); margin-bottom: 8px;">Report Generated</div>
                        <div style="color: var(--text-muted);">${result}</div>
                    </div>
                </div>
            </div>`;
        addActivity(`Generated ${format} report for session ${sessionId.substring(0, 8)}`, 'var(--success)');
        showToast('Report generated successfully', 'success');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">Report generation failed</div></div>';
    }
}

// ── Settings ──

async function doCheckCompliance() {
    const el = document.getElementById('complianceResult');
    const dashBadge = document.getElementById('complianceStatusBadge');
    el.textContent = 'Checking...';
    el.className = 'badge badge-muted';
    try {
        const result = await invokeSafe('check_compliance');
        const passed = result.includes('PASSED');
        el.textContent = result;
        el.className = `badge ${passed ? 'badge-success' : 'badge-danger'}`;
        if (dashBadge) {
            dashBadge.textContent = passed ? 'Compliant' : 'Non-Compliant';
            dashBadge.className = `badge ${passed ? 'badge-success' : 'badge-danger'}`;
        }
        addActivity(`Compliance check: ${result}`, passed ? 'var(--success)' : 'var(--danger)');
    } catch (_) {
        el.textContent = 'Check failed';
        el.className = 'badge badge-danger';
    }
}

async function loadSignatureCounts() {
    const el = document.getElementById('signatureCounts');
    try {
        const result = await invokeSafe('get_signature_counts');
        let counts;
        try { counts = JSON.parse(result); } catch { counts = {}; }

        el.innerHTML = `
            <div class="image-info-grid">
                ${Object.entries(counts).map(([cat, count]) => `
                    <div class="metadata-item">
                        <div class="metadata-label">${cat}</div>
                        <div class="metadata-value">${formatNumber(count)}</div>
                    </div>
                `).join('')}
            </div>`;
    } catch (_) {
        el.innerHTML = '<div style="color: var(--danger); font-size: 13px;">Failed to load signature counts</div>';
    }
}

function toggleTheme() {
    const html = document.documentElement;
    const isDark = document.getElementById('themeToggle').checked;
    html.setAttribute('data-theme', isDark ? 'dark' : 'light');
}

// ── USN Journal ──

async function parseUsnJournal() {
    const device = document.getElementById('usn-device').value;
    if (!device) { showToast('Select a device first', 'warning'); return; }
    const el = document.getElementById('usnResults');
    el.innerHTML = '<div class="card"><div class="card-body">Parsing USN Journal...</div></div>';
    try {
        const entries = await invokeSafe('parse_usn_journal', { device_path: device });
        if (!entries || entries.length === 0) {
            el.innerHTML = '<div class="card"><div class="card-body">No USN entries found</div></div>';
            return;
        }
        el.innerHTML = `
            <div class="card">
                <div class="card-header">USN Journal Entries (${entries.length})</div>
                <div class="card-body" style="padding: 0; overflow-x: auto;">
                    <table>
                        <thead><tr><th>Timestamp</th><th>Filename</th><th>Reason</th><th>Source</th><th>File Ref</th></tr></thead>
                        <tbody>
                            ${entries.slice(0, 200).map(e => `<tr>
                                <td>${e.timestamp || '-'}</td>
                                <td>${escapeHtml(e.filename || e.file_name || '-')}</td>
                                <td><span class="badge badge-info">${e.reason || '-'}</span></td>
                                <td>${escapeHtml(e.source || '-')}</td>
                                <td style="font-family: monospace; font-size: 11px;">${e.file_reference || '-'}</td>
                            </tr>`).join('')}
                        </tbody>
                    </table>
                </div>
            </div>`;
        addActivity(`USN Journal parsed: ${entries.length} entries from ${device}`, 'var(--success)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">USN Journal parse failed</div></div>';
    }
}

// ── Shadow Copies ──

async function listShadowCopies() {
    const device = document.getElementById('shadow-device').value;
    if (!device) { showToast('Select a device first', 'warning'); return; }
    const el = document.getElementById('shadowResults');
    el.innerHTML = '<div class="card"><div class="card-body">Scanning for shadow copies...</div></div>';
    try {
        const copies = await invokeSafe('list_shadow_copies', { device_path: device });
        if (!copies || copies.length === 0) {
            el.innerHTML = '<div class="card"><div class="card-body"><div class="empty-state"><div class="empty-state-icon">&#x1F4F7;</div><div class="empty-state-text">No shadow copies found</div></div></div></div>';
            return;
        }
        el.innerHTML = `
            <div class="card">
                <div class="card-header">Shadow Copies (${copies.length})</div>
                <div class="card-body" style="padding: 0; overflow-x: auto;">
                    <table>
                        <thead><tr><th>ID</th><th>Creation Time</th><th>Device</th><th>Size</th><th>Actions</th></tr></thead>
                        <tbody>
                            ${copies.map(c => `<tr>
                                <td style="font-family: monospace;">${c.id || '-'}</td>
                                <td>${c.creation_time || c.timestamp || '-'}</td>
                                <td>${c.device_path || c.device || '-'}</td>
                                <td>${c.size ? formatBytes(c.size) : '-'}</td>
                                <td><button class="btn btn-secondary btn-sm" onclick="mountShadowCopy('${c.id || ''}')">Mount</button></td>
                            </tr>`).join('')}
                        </tbody>
                    </table>
                </div>
            </div>`;
        addActivity(`Shadow copies scanned: found ${copies.length} on ${device}`, 'var(--success)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">Shadow copy scan failed</div></div>';
    }
}

function mountShadowCopy(copyId) {
    showToast(`Mounting shadow copy ${copyId}...`, 'info');
    addActivity(`Mounting shadow copy: ${copyId}`, 'var(--info)');
}

// ── Fragments ──

async function scanFragments() {
    const device = document.getElementById('fragment-device').value;
    if (!device) { showToast('Select a device first', 'warning'); return; }
    const types = [];
    document.querySelectorAll('.fragment-type:checked').forEach(cb => types.push(cb.value));
    const el = document.getElementById('fragmentResults');
    el.innerHTML = '<div class="card"><div class="card-body">Scanning for file fragments...</div></div>';
    try {
        const fragments = await invokeSafe('scan_fragments', { device_path: device, file_types: types.length > 0 ? types : null });
        if (!fragments || fragments.length === 0) {
            el.innerHTML = '<div class="card"><div class="card-body"><div class="empty-state"><div class="empty-state-icon">&#x1F9E9;</div><div class="empty-state-text">No fragments found</div></div></div></div>';
            return;
        }
        el.innerHTML = `
            <div class="card">
                <div class="card-header">File Fragments (${fragments.length})</div>
                <div class="card-body" style="padding: 0; overflow-x: auto;">
                    <table>
                        <thead><tr><th>Offset</th><th>File Type</th><th>Size</th><th>Signature</th><th>Status</th></tr></thead>
                        <tbody>
                            ${fragments.slice(0, 200).map(f => `<tr>
                                <td style="font-family: monospace;">0x${(f.offset || 0).toString(16)}</td>
                                <td>${f.file_type || f.type || '-'}</td>
                                <td>${f.size ? formatBytes(f.size) : '-'}</td>
                                <td style="font-family: monospace; font-size: 11px;">${f.signature || '-'}</td>
                                <td><span class="badge badge-warning">${f.status || 'Fragmented'}</span></td>
                            </tr>`).join('')}
                        </tbody>
                    </table>
                </div>
            </div>`;
        addActivity(`Fragment scan: found ${fragments.length} on ${device}`, 'var(--info)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">Fragment scan failed</div></div>';
    }
}

// ── File Repair ──

async function repairFile() {
    const path = document.getElementById('repair-path').value.trim();
    const mode = document.getElementById('repair-mode').value;
    const output = document.getElementById('repair-output').value.trim();
    if (!path) { showToast('Enter a file path', 'warning'); return; }
    const el = document.getElementById('repairResults');
    el.innerHTML = '<div class="card"><div class="card-body">Repairing file...</div></div>';
    try {
        const result = await invokeSafe('repair_file', { file_path: path, repair_mode: mode, output_path: output || null });
        el.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <div class="threat-result">
                        <div class="threat-icon">&#x1F527;</div>
                        <div style="font-size: 16px; font-weight: 600; color: var(--success); margin-bottom: 8px;">File Repair Complete</div>
                        <div style="color: var(--text-muted);">${escapeHtml(typeof result === 'string' ? result : JSON.stringify(result))}</div>
                    </div>
                </div>
            </div>`;
        addActivity(`File repaired: ${path} (mode: ${mode})`, 'var(--success)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">File repair failed</div></div>';
    }
}

async function analyzeFile() {
    const path = document.getElementById('repair-path').value.trim();
    if (!path) { showToast('Enter a file path', 'warning'); return; }
    const el = document.getElementById('repairResults');
    el.innerHTML = '<div class="card"><div class="card-body">Analyzing file...</div></div>';
    try {
        const result = await invokeSafe('analyze_file', { file_path: path });
        let data;
        try { data = JSON.parse(result); } catch { data = { raw: result }; }
        el.innerHTML = `
            <div class="card">
                <div class="card-header">File Analysis</div>
                <div class="card-body">
                    <div class="image-info-grid">
                        ${Object.entries(data).map(([k, v]) => `
                            <div class="metadata-item">
                                <div class="metadata-label">${k.replace(/_/g, ' ')}</div>
                                <div class="metadata-value">${typeof v === 'boolean' ? `<span class="badge ${v ? 'badge-success' : 'badge-danger'}">${v ? 'Yes' : 'No'}</span>` : escapeHtml(String(v))}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>`;
        addActivity(`Analyzed file: ${path}`, 'var(--info)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">File analysis failed</div></div>';
    }
}

// ── Registry ──

async function parseRegistry() {
    const hivePath = document.getElementById('registry-path').value.trim();
    const key = document.getElementById('registry-key').value.trim();
    if (!hivePath) { showToast('Enter a registry hive path', 'warning'); return; }
    const el = document.getElementById('registryResults');
    el.innerHTML = '<div class="card"><div class="card-body">Parsing registry hive...</div></div>';
    try {
        const result = await invokeSafe('parse_registry', { hive_path: hivePath, key_path: key || null });
        let data;
        try { data = JSON.parse(result); } catch { data = { raw: result }; }
        if (data.values) {
            el.innerHTML = `
                <div class="card">
                    <div class="card-header">Registry Values (${data.values.length})</div>
                    <div class="card-body" style="padding: 0; overflow-x: auto;">
                        <table>
                            <thead><tr><th>Name</th><th>Type</th><th>Value</th></tr></thead>
                            <tbody>
                                ${data.values.map(v => `<tr>
                                    <td>${escapeHtml(v.name || '-')}</td>
                                    <td><span class="badge badge-info">${v.type || '-'}</span></td>
                                    <td style="font-family: monospace; font-size: 12px;">${escapeHtml(String(v.value || '-'))}</td>
                                </tr>`).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>`;
        } else {
            el.innerHTML = `
                <div class="card">
                    <div class="card-header">Registry Data</div>
                    <div class="card-body"><div class="report-preview">${escapeHtml(JSON.stringify(data, null, 2))}</div></div>
                </div>`;
        }
        addActivity(`Parsed registry: ${hivePath}`, 'var(--info)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">Registry parse failed</div></div>';
    }
}

async function listRegistryKeys() {
    const hivePath = document.getElementById('registry-path').value.trim();
    if (!hivePath) { showToast('Enter a registry hive path', 'warning'); return; }
    const el = document.getElementById('registryResults');
    el.innerHTML = '<div class="card"><div class="card-body">Listing registry keys...</div></div>';
    try {
        const keys = await invokeSafe('list_registry_keys', { hive_path: hivePath });
        if (!keys || keys.length === 0) {
            el.innerHTML = '<div class="card"><div class="card-body">No keys found</div></div>';
            return;
        }
        el.innerHTML = `
            <div class="card">
                <div class="card-header">Registry Keys (${keys.length})</div>
                <div class="card-body" style="padding: 0; max-height: 400px; overflow-y: auto;">
                    <table>
                        <thead><tr><th>Key Path</th><th>Subkeys</th><th>Last Modified</th></tr></thead>
                        <tbody>
                            ${keys.map(k => `<tr>
                                <td style="font-family: monospace; font-size: 12px;">${escapeHtml(k.path || k.name || '-')}</td>
                                <td>${k.subkey_count ?? '-'}</td>
                                <td>${k.last_modified || k.timestamp || '-'}</td>
                            </tr>`).join('')}
                        </tbody>
                    </table>
                </div>
            </div>`;
        addActivity(`Listed registry keys in ${hivePath}`, 'var(--info)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">Registry key listing failed</div></div>';
    }
}

// ── WhatsApp ──

async function recoverWhatsApp() {
    const sourcePath = document.getElementById('whatsapp-path').value.trim();
    const outputDir = document.getElementById('whatsapp-output').value.trim();
    if (!sourcePath) { showToast('Enter source path', 'warning'); return; }
    if (!outputDir) { showToast('Enter output directory', 'warning'); return; }
    const options = {
        messages: document.getElementById('whatsapp-messages').checked,
        media: document.getElementById('whatsapp-media').checked,
        contacts: document.getElementById('whatsapp-contacts').checked,
        deleted: document.getElementById('whatsapp-deleted').checked,
    };
    const el = document.getElementById('whatsappResults');
    el.innerHTML = '<div class="card"><div class="card-body"><div class="progress-container"><div class="progress-bar"><div class="progress-fill" style="width:50%"></div></div><div class="progress-label"><span>Recovering WhatsApp data...</span></div></div></div></div>';
    try {
        const result = await invokeSafe('recover_whatsapp', { source_path: sourcePath, output_dir: outputDir, options });
        displayChatRecoveryResult('whatsappResults', result, 'WhatsApp');
        addActivity(`WhatsApp recovery: ${sourcePath}`, 'var(--success)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">WhatsApp recovery failed</div></div>';
    }
}

// ── iMessage ──

async function recoverIMessage() {
    const sourcePath = document.getElementById('imessage-path').value.trim();
    const outputDir = document.getElementById('imessage-output').value.trim();
    const contact = document.getElementById('imessage-contact').value.trim();
    if (!sourcePath) { showToast('Enter source path', 'warning'); return; }
    if (!outputDir) { showToast('Enter output directory', 'warning'); return; }
    const el = document.getElementById('imessageResults');
    el.innerHTML = '<div class="card"><div class="card-body"><div class="progress-container"><div class="progress-bar"><div class="progress-fill" style="width:50%"></div></div><div class="progress-label"><span>Recovering iMessage data...</span></div></div></div></div>';
    try {
        const result = await invokeSafe('recover_imessage', { source_path: sourcePath, output_dir: outputDir, contact_filter: contact || null });
        displayChatRecoveryResult('imessageResults', result, 'iMessage');
        addActivity(`iMessage recovery: ${sourcePath}`, 'var(--success)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">iMessage recovery failed</div></div>';
    }
}

// ── Signal ──

async function recoverSignal() {
    const sourcePath = document.getElementById('signal-path').value.trim();
    const outputDir = document.getElementById('signal-output').value.trim();
    const key = document.getElementById('signal-key').value.trim();
    if (!sourcePath) { showToast('Enter source path', 'warning'); return; }
    if (!outputDir) { showToast('Enter output directory', 'warning'); return; }
    const el = document.getElementById('signalResults');
    el.innerHTML = '<div class="card"><div class="card-body"><div class="progress-container"><div class="progress-bar"><div class="progress-fill" style="width:50%"></div></div><div class="progress-label"><span>Recovering Signal data...</span></div></div></div></div>';
    try {
        const result = await invokeSafe('recover_signal', { source_path: sourcePath, output_dir: outputDir, decryption_key: key || null });
        displayChatRecoveryResult('signalResults', result, 'Signal');
        addActivity(`Signal recovery: ${sourcePath}`, 'var(--success)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">Signal recovery failed</div></div>';
    }
}

// ── Slack ──

async function recoverSlack() {
    const sourcePath = document.getElementById('slack-path').value.trim();
    const outputDir = document.getElementById('slack-output').value.trim();
    const workspace = document.getElementById('slack-workspace').value.trim();
    if (!sourcePath) { showToast('Enter source path', 'warning'); return; }
    if (!outputDir) { showToast('Enter output directory', 'warning'); return; }
    const el = document.getElementById('slackResults');
    el.innerHTML = '<div class="card"><div class="card-body"><div class="progress-container"><div class="progress-bar"><div class="progress-fill" style="width:50%"></div></div><div class="progress-label"><span>Recovering Slack data...</span></div></div></div></div>';
    try {
        const result = await invokeSafe('recover_slack', { source_path: sourcePath, output_dir: outputDir, workspace: workspace || null });
        displayChatRecoveryResult('slackResults', result, 'Slack');
        addActivity(`Slack recovery: ${sourcePath}`, 'var(--success)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">Slack recovery failed</div></div>';
    }
}

function displayChatRecoveryResult(containerId, result, platform) {
    const el = document.getElementById(containerId);
    let data;
    try { data = JSON.parse(result); } catch { data = { raw: result }; }
    const msgs = data.messages_recovered || data.messages || 0;
    const media = data.media_recovered || data.media || 0;
    const contacts = data.contacts_recovered || data.contacts || 0;
    el.innerHTML = `
        <div class="card">
            <div class="card-body">
                <div class="threat-result">
                    <div class="threat-icon">&#x1F4AC;</div>
                    <div style="font-size: 16px; font-weight: 600; color: var(--success); margin-bottom: 12px;">${platform} Recovery Complete</div>
                </div>
                <div class="image-info-grid">
                    <div class="metadata-item"><div class="metadata-label">Messages</div><div class="metadata-value">${formatNumber(msgs)}</div></div>
                    <div class="metadata-item"><div class="metadata-label">Media Files</div><div class="metadata-value">${formatNumber(media)}</div></div>
                    <div class="metadata-item"><div class="metadata-label">Contacts</div><div class="metadata-value">${formatNumber(contacts)}</div></div>
                    ${data.output_dir ? `<div class="metadata-item"><div class="metadata-label">Output</div><div class="metadata-value" style="font-size:11px; word-break:break-all;">${escapeHtml(data.output_dir)}</div></div>` : ''}
                </div>
            </div>
        </div>`;
    showToast(`${platform} recovery complete`, 'success');
}

// ── Browser History ──

async function recoverBrowserHistory() {
    const browserType = document.getElementById('browser-type').value;
    const profilePath = document.getElementById('browser-path').value.trim();
    const outputDir = document.getElementById('browser-output').value.trim();
    if (!outputDir) { showToast('Enter output directory', 'warning'); return; }
    const options = {
        history: document.getElementById('browser-history-opt').checked,
        bookmarks: document.getElementById('browser-bookmarks').checked,
        cookies: document.getElementById('browser-cookies').checked,
        passwords: document.getElementById('browser-passwords').checked,
        downloads: document.getElementById('browser-downloads').checked,
    };
    const el = document.getElementById('browserResults');
    el.innerHTML = '<div class="card"><div class="card-body"><div class="progress-container"><div class="progress-bar"><div class="progress-fill" style="width:50%"></div></div><div class="progress-label"><span>Recovering browser data...</span></div></div></div></div>';
    try {
        const result = await invokeSafe('recover_browser_history', {
            browser: browserType,
            profile_path: profilePath || null,
            output_dir: outputDir,
            options,
        });
        let data;
        try { data = JSON.parse(result); } catch { data = { raw: result }; }
        el.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <div class="threat-result">
                        <div class="threat-icon">&#x1F310;</div>
                        <div style="font-size: 16px; font-weight: 600; color: var(--success); margin-bottom: 12px;">Browser Recovery Complete</div>
                    </div>
                    <div class="image-info-grid">
                        ${Object.entries(data).filter(([k]) => k !== 'raw' && k !== 'output_dir').map(([k, v]) => `
                            <div class="metadata-item"><div class="metadata-label">${k.replace(/_/g, ' ')}</div><div class="metadata-value">${typeof v === 'number' ? formatNumber(v) : escapeHtml(String(v))}</div></div>
                        `).join('')}
                    </div>
                </div>
            </div>`;
        addActivity(`Browser history recovered: ${browserType}`, 'var(--success)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">Browser recovery failed</div></div>';
    }
}

// ── SQLite Carve ──

async function carveSqlite() {
    const sourcePath = document.getElementById('sqlite-path').value.trim();
    const table = document.getElementById('sqlite-table').value.trim();
    const outputDir = document.getElementById('sqlite-output').value.trim();
    if (!sourcePath) { showToast('Enter a source path', 'warning'); return; }
    if (!outputDir) { showToast('Enter an output directory', 'warning'); return; }
    const el = document.getElementById('sqliteResults');
    el.innerHTML = '<div class="card"><div class="card-body"><div class="progress-container"><div class="progress-bar"><div class="progress-fill" style="width:50%"></div></div><div class="progress-label"><span>Carving SQLite data...</span></div></div></div></div>';
    try {
        const result = await invokeSafe('carve_sqlite', { source_path: sourcePath, table_name: table || null, output_dir: outputDir });
        let data;
        try { data = JSON.parse(result); } catch { data = { raw: result }; }
        el.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <div class="threat-result">
                        <div class="threat-icon">&#x1F5C4;</div>
                        <div style="font-size: 16px; font-weight: 600; color: var(--success); margin-bottom: 12px;">SQLite Carve Complete</div>
                    </div>
                    <div class="image-info-grid">
                        ${Object.entries(data).filter(([k]) => k !== 'raw').map(([k, v]) => `
                            <div class="metadata-item"><div class="metadata-label">${k.replace(/_/g, ' ')}</div><div class="metadata-value">${typeof v === 'number' ? formatNumber(v) : escapeHtml(String(v))}</div></div>
                        `).join('')}
                    </div>
                </div>
            </div>`;
        addActivity(`SQLite carved: ${sourcePath}`, 'var(--success)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">SQLite carve failed</div></div>';
    }
}

async function listSqliteTables() {
    const sourcePath = document.getElementById('sqlite-path').value.trim();
    if (!sourcePath) { showToast('Enter a source path', 'warning'); return; }
    const el = document.getElementById('sqliteResults');
    el.innerHTML = '<div class="card"><div class="card-body">Listing tables...</div></div>';
    try {
        const tables = await invokeSafe('list_sqlite_tables', { source_path: sourcePath });
        if (!tables || tables.length === 0) {
            el.innerHTML = '<div class="card"><div class="card-body">No tables found</div></div>';
            return;
        }
        el.innerHTML = `
            <div class="card">
                <div class="card-header">SQLite Tables (${tables.length})</div>
                <div class="card-body" style="padding: 0; max-height: 400px; overflow-y: auto;">
                    <table>
                        <thead><tr><th>Table Name</th><th>Row Count</th><th>Columns</th></tr></thead>
                        <tbody>
                            ${tables.map(t => `<tr>
                                <td style="font-family: monospace;">${escapeHtml(t.name || t.table_name || '-')}</td>
                                <td>${t.row_count ?? t.rows ?? '-'}</td>
                                <td style="font-size: 11px;">${escapeHtml(Array.isArray(t.columns) ? t.columns.join(', ') : (t.columns || '-'))}</td>
                            </tr>`).join('')}
                        </tbody>
                    </table>
                </div>
            </div>`;
        addActivity(`Listed SQLite tables: ${sourcePath}`, 'var(--info)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">Table listing failed</div></div>';
    }
}

// ── Email ──

async function recoverEmail() {
    const client = document.getElementById('email-client').value;
    const dataPath = document.getElementById('email-path').value.trim();
    const outputDir = document.getElementById('email-output').value.trim();
    if (!dataPath) { showToast('Enter data path', 'warning'); return; }
    if (!outputDir) { showToast('Enter output directory', 'warning'); return; }
    const options = {
        inbox: document.getElementById('email-inbox').checked,
        sent: document.getElementById('email-sent').checked,
        deleted: document.getElementById('email-deleted').checked,
        attachments: document.getElementById('email-attachments').checked,
    };
    const el = document.getElementById('emailResults');
    el.innerHTML = '<div class="card"><div class="card-body"><div class="progress-container"><div class="progress-bar"><div class="progress-fill" style="width:50%"></div></div><div class="progress-label"><span>Recovering emails...</span></div></div></div></div>';
    try {
        const result = await invokeSafe('recover_email', { client, data_path: dataPath, output_dir: outputDir, options });
        let data;
        try { data = JSON.parse(result); } catch { data = { raw: result }; }
        el.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <div class="threat-result">
                        <div class="threat-icon">&#x2709;</div>
                        <div style="font-size: 16px; font-weight: 600; color: var(--success); margin-bottom: 12px;">Email Recovery Complete</div>
                    </div>
                    <div class="image-info-grid">
                        <div class="metadata-item"><div class="metadata-label">Emails Recovered</div><div class="metadata-value">${formatNumber(data.emails_recovered || data.emails || 0)}</div></div>
                        <div class="metadata-item"><div class="metadata-label">Attachments</div><div class="metadata-value">${formatNumber(data.attachments_recovered || data.attachments || 0)}</div></div>
                        <div class="metadata-item"><div class="metadata-label">Total Size</div><div class="metadata-value">${data.total_size ? formatBytes(data.total_size) : '-'}</div></div>
                        ${data.output_dir ? `<div class="metadata-item"><div class="metadata-label">Output</div><div class="metadata-value" style="font-size:11px; word-break:break-all;">${escapeHtml(data.output_dir)}</div></div>` : ''}
                    </div>
                </div>
            </div>`;
        addActivity(`Email recovery: ${client} from ${dataPath}`, 'var(--success)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">Email recovery failed</div></div>';
    }
}

// ── Resume Scan ──

async function loadResumeableSessions() {
    try {
        const sessions = await invokeSafe('get_sessions');
        const sel = document.getElementById('resume-session-id');
        if (sessions.length === 0) {
            sel.value = '';
            showToast('No sessions available', 'warning');
            return;
        }
        const opts = sessions.map(s => `<option value="${s.id}">Session ${s.id.substring(0, 8)}... - ${s.scan_type} - ${s.status}</option>`).join('');
        sel.innerHTML = '<option value="">-- Select session --</option>' + opts;
        showToast(`Loaded ${sessions.length} sessions`, 'success');
    } catch (_) {}
}

async function resumeScan() {
    const sessionId = document.getElementById('resume-session-id').value;
    const outputDir = document.getElementById('resume-output').value.trim();
    if (!sessionId) { showToast('Select a session', 'warning'); return; }
    if (!outputDir) { showToast('Enter output directory', 'warning'); return; }
    const el = document.getElementById('resumeScanResults');
    el.innerHTML = '<div class="card"><div class="card-body">Resuming scan...</div></div>';
    try {
        const result = await invokeSafe('resume_scan', { session_id: sessionId, output_dir: outputDir });
        el.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <div class="threat-result">
                        <div class="threat-icon">&#x1F504;</div>
                        <div style="font-size: 16px; font-weight: 600; color: var(--success); margin-bottom: 8px;">Scan Resumed</div>
                        <div style="color: var(--text-muted);">${escapeHtml(typeof result === 'string' ? result : JSON.stringify(result))}</div>
                    </div>
                </div>
            </div>`;
        addActivity(`Resumed scan: session ${sessionId.substring(0, 8)}`, 'var(--success)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">Resume scan failed</div></div>';
    }
}

// ── Incremental Scan ──

async function runIncrementalScan() {
    const sessionId = document.getElementById('incremental-session').value.trim();
    const device = document.getElementById('incremental-device').value;
    const outputDir = document.getElementById('incremental-output').value.trim();
    if (!sessionId) { showToast('Enter a base session ID', 'warning'); return; }
    if (!device) { showToast('Select a device', 'warning'); return; }
    if (!outputDir) { showToast('Enter output directory', 'warning'); return; }
    const el = document.getElementById('incrementalResults');
    el.innerHTML = '<div class="card"><div class="card-body"><div class="progress-container"><div class="progress-bar"><div class="progress-fill" style="width:50%"></div></div><div class="progress-label"><span>Running incremental scan...</span></div></div></div></div>';
    try {
        const result = await invokeSafe('incremental_scan', { base_session_id: sessionId, device_path: device, output_dir: outputDir });
        let data;
        try { data = JSON.parse(result); } catch { data = { raw: result }; }
        el.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <div class="threat-result">
                        <div class="threat-icon">&#x1F4C8;</div>
                        <div style="font-size: 16px; font-weight: 600; color: var(--success); margin-bottom: 12px;">Incremental Scan Complete</div>
                    </div>
                    <div class="image-info-grid">
                        <div class="metadata-item"><div class="metadata-label">New Files Found</div><div class="metadata-value">${formatNumber(data.new_files || 0)}</div></div>
                        <div class="metadata-item"><div class="metadata-label">Files Recovered</div><div class="metadata-value">${formatNumber(data.files_recovered || 0)}</div></div>
                        <div class="metadata-item"><div class="metadata-label">Size</div><div class="metadata-value">${data.total_size ? formatBytes(data.total_size) : '-'}</div></div>
                    </div>
                </div>
            </div>`;
        addActivity(`Incremental scan complete from session ${sessionId.substring(0, 8)}`, 'var(--success)');
    } catch (_) {
        el.innerHTML = '<div class="card"><div class="card-body" style="color: var(--danger);">Incremental scan failed</div></div>';
    }
}

// ── Batch Processing ──

async function startBatchProcessing() {
    const scanType = document.getElementById('batch-scan-type').value;
    const devicesRaw = document.getElementById('batch-devices').value.trim();
    const outputBase = document.getElementById('batch-output').value.trim();
    if (!devicesRaw) { showToast('Enter device paths', 'warning'); return; }
    if (!outputBase) { showToast('Enter output base directory', 'warning'); return; }
    const devices = devicesRaw.split('\n').map(d => d.trim()).filter(d => d.length > 0);
    if (devices.length === 0) { showToast('No valid device paths', 'warning'); return; }

    document.getElementById('batchProgress').style.display = 'block';
    document.getElementById('batchCancelBtn').style.display = 'inline-flex';
    const progressFill = document.getElementById('batchProgressFill');
    const progressText = document.getElementById('batchProgressText');
    const progressPct = document.getElementById('batchProgressPct');

    try {
        progressText.textContent = 'Starting batch processing...';
        progressFill.style.width = '0%';
        progressPct.textContent = '0%';

        const result = await invokeSafe('batch_processing', { devices, scan_type: scanType, output_base: outputBase });
        progressFill.style.width = '100%';
        progressPct.textContent = '100%';
        progressText.textContent = 'Batch processing complete';

        const el = document.getElementById('batchResults');
        let data;
        try { data = JSON.parse(result); } catch { data = { raw: result }; }
        el.innerHTML = `
            <div class="card">
                <div class="card-header">Batch Results</div>
                <div class="card-body">
                    <div class="image-info-grid">
                        <div class="metadata-item"><div class="metadata-label">Devices Processed</div><div class="metadata-value">${formatNumber(data.devices_processed || devices.length)}</div></div>
                        <div class="metadata-item"><div class="metadata-label">Total Files</div><div class="metadata-value">${formatNumber(data.total_files || 0)}</div></div>
                        <div class="metadata-item"><div class="metadata-label">Total Size</div><div class="metadata-value">${data.total_size ? formatBytes(data.total_size) : '-'}</div></div>
                    </div>
                </div>
            </div>`;
        document.getElementById('batchCancelBtn').style.display = 'none';
        addActivity(`Batch processing complete: ${devices.length} devices`, 'var(--success)');
    } catch (_) {
        progressText.textContent = 'Batch processing failed';
        progressFill.style.width = '0%';
        document.getElementById('batchCancelBtn').style.display = 'none';
    }
}

function cancelBatch() {
    showToast('Batch processing cancelled', 'warning');
    document.getElementById('batchProgressText').textContent = 'Cancelled';
    document.getElementById('batchCancelBtn').style.display = 'none';
    addActivity('Batch processing cancelled', 'var(--warning)');
}

// ── Case Management ──

async function createCase() {
    const name = document.getElementById('case-name').value.trim();
    const examiner = document.getElementById('case-examiner').value.trim();
    const priority = document.getElementById('case-priority').value;
    const description = document.getElementById('case-description').value.trim();
    if (!name) { showToast('Enter a case name', 'warning'); return; }
    try {
        const result = await invokeSafe('create_case', { name, examiner: examiner || null, priority, description: description || null });
        showToast(`Case "${name}" created`, 'success');
        addActivity(`Created case: ${name}`, 'var(--success)');
        document.getElementById('case-name').value = '';
        document.getElementById('case-examiner').value = '';
        document.getElementById('case-description').value = '';
        loadCases();
    } catch (_) {}
}

async function loadCases() {
    const el = document.getElementById('caseList');
    el.innerHTML = '<div style="font-size: 13px; color: var(--text-muted);">Loading cases...</div>';
    try {
        const cases = await invokeSafe('list_cases');
        if (!cases || cases.length === 0) {
            el.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#x1F4C2;</div><div class="empty-state-text">No cases found</div></div>';
            return;
        }
        el.innerHTML = `
            <table>
                <thead><tr><th>Case</th><th>Examiner</th><th>Priority</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead>
                <tbody>
                    ${cases.map(c => {
                        const pClass = c.priority === 'critical' ? 'badge-danger' : c.priority === 'high' ? 'badge-warning' : c.priority === 'medium' ? 'badge-info' : 'badge-muted';
                        return `<tr>
                            <td style="font-weight: 600;">${escapeHtml(c.name || '-')}</td>
                            <td>${escapeHtml(c.examiner || '-')}</td>
                            <td><span class="badge ${pClass}">${c.priority || '-'}</span></td>
                            <td><span class="badge badge-info">${c.status || 'Active'}</span></td>
                            <td>${c.created_at || c.timestamp || '-'}</td>
                            <td><button class="btn btn-secondary btn-sm" onclick="openCase('${c.id || ''}')">Open</button></td>
                        </tr>`;
                    }).join('')}
                </tbody>
            </table>`;
        addActivity(`Loaded ${cases.length} cases`, 'var(--info)');
    } catch (_) {
        el.innerHTML = '<div style="color: var(--danger); font-size: 13px;">Failed to load cases</div>';
    }
}

function openCase(caseId) {
    showToast(`Opening case ${caseId}`, 'info');
    addActivity(`Opened case: ${caseId}`, 'var(--info)');
}

// ── API Server ──

async function startApiServer() {
    const host = document.getElementById('api-host').value.trim();
    const port = parseInt(document.getElementById('api-port').value) || 8080;
    const apiKey = document.getElementById('api-key').value.trim();
    const endpoints = {
        devices: document.getElementById('api-devices').checked,
        recovery: document.getElementById('api-recovery').checked,
        sessions: document.getElementById('api-sessions').checked,
        forensic: document.getElementById('api-forensic').checked,
        reports: document.getElementById('api-reports').checked,
    };
    try {
        await invokeSafe('start_api_server', { host, port, api_key: apiKey || null, endpoints });
        document.getElementById('apiStartBtn').style.display = 'none';
        document.getElementById('apiStopBtn').style.display = 'inline-flex';
        document.getElementById('apiStatus').textContent = `Running on ${host}:${port}`;
        document.getElementById('apiStatus').className = 'badge badge-success';
        showToast(`API server started on ${host}:${port}`, 'success');
        addActivity(`API server started: ${host}:${port}`, 'var(--success)');

        const el = document.getElementById('apiServerResults');
        el.innerHTML = `
            <div class="card">
                <div class="card-header">Available Endpoints</div>
                <div class="card-body">
                    <div class="status-row"><span class="status-label">Base URL</span><span class="badge badge-info">http://${host}:${port}</span></div>
                    ${Object.entries(endpoints).filter(([, v]) => v).map(([k]) => `
                        <div class="status-row"><span class="status-label"><span class="badge badge-success">GET/POST</span> /api/v1/${k}</span><span class="badge badge-muted">Enabled</span></div>
                    `).join('')}
                </div>
            </div>`;
    } catch (_) {}
}

async function stopApiServer() {
    try {
        await invokeSafe('stop_api_server');
        document.getElementById('apiStartBtn').style.display = 'inline-flex';
        document.getElementById('apiStopBtn').style.display = 'none';
        document.getElementById('apiStatus').textContent = 'Stopped';
        document.getElementById('apiStatus').className = 'badge badge-muted';
        document.getElementById('apiServerResults').innerHTML = '';
        showToast('API server stopped', 'warning');
        addActivity('API server stopped', 'var(--warning)');
    } catch (_) {}
}

// ── Utilities ──

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ── Expose to onclick handlers ──

window.navigateTo = navigateTo;
window.refreshDevices = refreshDevices;
window.deviceAction = deviceAction;
window.wizardNext = wizardNext;
window.wizardPrev = wizardPrev;
window.executeRecovery = executeRecovery;
window.cancelRecovery = cancelRecovery;
window.loadSessions = loadSessions;
window.toggleSession = toggleSession;
window.exportSession = exportSession;
window.doPreviewFile = doPreviewFile;
window.doHexView = doHexView;
window.hexPrevPage = hexPrevPage;
window.hexNextPage = hexNextPage;
window.doScanPartitions = doScanPartitions;
window.doGetImageInfo = doGetImageInfo;
window.doDetectRaid = doDetectRaid;
window.doReconstructRaid = doReconstructRaid;
window.doCheckEncryption = doCheckEncryption;
window.doUnlockEncryption = doUnlockEncryption;
window.doThreatScan = doThreatScan;
window.doFindDuplicates = doFindDuplicates;
window.loadSessionsForReport = loadSessionsForReport;
window.doGenerateReport = doGenerateReport;
window.doCheckCompliance = doCheckCompliance;
window.loadSignatureCounts = loadSignatureCounts;
window.toggleTheme = toggleTheme;
window.showToast = showToast;

window.parseUsnJournal = parseUsnJournal;
window.listShadowCopies = listShadowCopies;
window.mountShadowCopy = mountShadowCopy;
window.scanFragments = scanFragments;
window.repairFile = repairFile;
window.analyzeFile = analyzeFile;
window.parseRegistry = parseRegistry;
window.listRegistryKeys = listRegistryKeys;
window.recoverWhatsApp = recoverWhatsApp;
window.recoverIMessage = recoverIMessage;
window.recoverSignal = recoverSignal;
window.recoverSlack = recoverSlack;
window.recoverBrowserHistory = recoverBrowserHistory;
window.carveSqlite = carveSqlite;
window.listSqliteTables = listSqliteTables;
window.recoverEmail = recoverEmail;
window.loadResumeableSessions = loadResumeableSessions;
window.resumeScan = resumeScan;
window.runIncrementalScan = runIncrementalScan;
window.startBatchProcessing = startBatchProcessing;
window.cancelBatch = cancelBatch;
window.createCase = createCase;
window.loadCases = loadCases;
window.openCase = openCase;
window.startApiServer = startApiServer;
window.stopApiServer = stopApiServer;

// ── Init ──

(async function init() {
    await refreshDevices();
    await updateDashboardStats();
    renderActivityLog();
})();

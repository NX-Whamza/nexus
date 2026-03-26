(function () {
    'use strict';

    const CAMBIUM_STORAGE_KEY = 'cambiumRadios';
    const cambiumState = {
        radios: [],
        providers: [],
        catalog: [],
        taskId: null,
        taskStream: null,
        taskPollInterval: null,
        globalStreamStarted: false,
        isProcessing: false,
        initComplete: false
    };

    let cambiumApiOverride = null;

    function cambiumGetUsername() {
        if (typeof getUsername === 'function') return getUsername();
        if (window.currentUser && typeof window.currentUser === 'string') return window.currentUser;
        if (window.currentUser && typeof window.currentUser === 'object') {
            return window.currentUser.username || window.currentUser.email || '';
        }
        return '';
    }

    function cambiumEscapeHtml(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function getApiRoot() {
        return ((typeof AI_API_BASE !== 'undefined' ? AI_API_BASE : window.AI_API_BASE) || '/api').replace(/\/+$/, '');
    }

    function getCambiumApiBase() {
        if (cambiumApiOverride) return cambiumApiOverride;
        return `${getApiRoot()}/cambium`;
    }

    function getCambiumCandidateBases() {
        const bases = [];
        const originBase = `${window.location.origin}/api/cambium`;
        const apiBase = getCambiumApiBase();
        const isFile = window.location.protocol === 'file:' || window.location.origin === 'null';
        bases.push(originBase);
        if (apiBase && apiBase !== originBase) bases.push(apiBase);
        if (isFile) bases.push('http://localhost:5000/api/cambium');
        return Array.from(new Set(bases.filter(Boolean)));
    }

    function getProviderCandidates() {
        const bases = [];
        const apiRoot = getApiRoot();
        const isFile = window.location.protocol === 'file:' || window.location.origin === 'null';
        if (window.location.origin && window.location.origin !== 'null') {
            bases.push(`${window.location.origin}/api/firmware-updater/providers`);
        }
        if (apiRoot) bases.push(`${apiRoot}/firmware-updater/providers`);
        if (isFile) bases.push('http://localhost:5000/api/firmware-updater/providers');
        return Array.from(new Set(bases.filter(Boolean)));
    }

    async function cambiumFetch(path, options) {
        const bases = getCambiumCandidateBases();
        let lastError = null;
        for (const base of bases) {
            try {
                const response = await fetch(`${base}${path}`, options);
                if (response.ok) {
                    cambiumApiOverride = base;
                    syncEndpointHint();
                }
                if (![403, 404, 405].includes(response.status) || base === bases[bases.length - 1]) {
                    return response;
                }
            } catch (err) {
                lastError = err;
            }
        }
        throw lastError || new Error('Cambium API unavailable');
    }

    async function parseJson(response) {
        const contentType = response.headers.get('content-type') || '';
        if (!contentType.includes('application/json')) {
            return { error: `Unexpected response (${response.status})` };
        }
        try {
            return await response.json();
        } catch (err) {
            return { error: `Invalid JSON response (${response.status})` };
        }
    }

    function normalizeStatus(status, successFlag) {
        if (!status) return successFlag ? 'success' : 'pending';
        const lower = String(status).toLowerCase();
        if (['pending', 'queued', 'processing', 'running', 'verifying', 'success', 'error', 'manual', 'scheduled'].includes(lower)) {
            return lower === 'running' ? 'processing' : lower;
        }
        if (['completed', 'done', 'ok'].includes(lower)) return 'success';
        if (['failed', 'fail'].includes(lower)) return 'error';
        return successFlag === true ? 'success' : lower;
    }

    function statusIcon(status) {
        return {
            pending: '.',
            queued: 'Q',
            processing: '~',
            verifying: 'V',
            scheduled: 'S',
            manual: 'M',
            success: 'OK',
            error: 'X'
        }[status] || '?';
    }

    function normalizeRadio(radio) {
        return {
            ip: radio.ip || radio.host || radio.address || '',
            device_type: radio.device_type || radio.deviceType || '',
            model: radio.model || radio.platform || radio.device_type || radio.deviceType || radio.family || '',
            family: String(radio.family || radio.device_family || '').toLowerCase(),
            provider: String(radio.provider || 'cambium').toLowerCase(),
            currentVersion: radio.currentVersion || radio.current_version || radio.version || radio.firmware || '',
            targetVersion: radio.targetVersion || radio.target_version || '',
            firmwareStatus: normalizeStatus(radio.firmwareStatus || radio.firmware_status, radio.firmware_ok),
            backupStatus: normalizeStatus(radio.backupStatus || radio.backup_status, radio.backup_ok),
            verifyStatus: normalizeStatus(radio.verifyStatus || radio.verify_status, radio.verify_ok),
            status: normalizeStatus(radio.status, radio.success),
            detail: radio.detail || radio.message || '',
            username: radio.username || ''
        };
    }

    function persistRadios() {
        try {
            localStorage.setItem(CAMBIUM_STORAGE_KEY, JSON.stringify(cambiumState.radios));
        } catch (e) {
            // ignore storage errors
        }
    }

    function restoreRadios() {
        try {
            const raw = localStorage.getItem(CAMBIUM_STORAGE_KEY);
            if (!raw) return;
            const parsed = JSON.parse(raw);
            if (Array.isArray(parsed)) cambiumState.radios = parsed.map(normalizeRadio);
        } catch (e) {
            // ignore storage errors
        }
    }

    function setCatalogMeta(message) {
        const meta = document.getElementById('cambiumCatalogMeta');
        if (meta) meta.textContent = message;
    }

    function addLog(message, type = 'info', meta = {}) {
        const logBox = document.getElementById('cambiumLogBox');
        if (!logBox) return;
        const date = meta && meta.ts ? new Date(meta.ts) : new Date();
        const time = Number.isNaN(date.getTime()) ? '--:--:--' : date.toLocaleTimeString();
        const entry = document.createElement('div');
        entry.className = `aviat-log-entry log-${type}`;
        entry.innerHTML = `<span class="aviat-log-time">[${time}]</span> ${cambiumEscapeHtml(message)}`;
        logBox.appendChild(entry);
        logBox.scrollTop = logBox.scrollHeight;
    }

    function clearLog() {
        const logBox = document.getElementById('cambiumLogBox');
        if (!logBox) return;
        logBox.innerHTML = '<div class="aviat-log-entry"><span class="aviat-log-time">[--:--:--]</span> Log cleared.</div>';
    }

    function setRunState(isProcessing) {
        cambiumState.isProcessing = !!isProcessing;
        const runBtn = document.getElementById('cambiumRunBtn');
        const abortBtn = document.getElementById('cambiumAbortBtn');
        if (runBtn) runBtn.disabled = cambiumState.isProcessing;
        if (abortBtn) {
            abortBtn.disabled = true;
            abortBtn.title = 'Abort is not available in the current backend contract.';
        }
    }

    function upsertRadio(rawRadio) {
        const radio = normalizeRadio(rawRadio);
        if (!radio.ip) return;
        const existing = cambiumState.radios.find(item => item.ip === radio.ip);
        if (existing) {
            Object.assign(existing, {
                ...existing,
                ...radio,
                model: radio.model || existing.model,
                family: radio.family || existing.family,
                provider: radio.provider || existing.provider,
                currentVersion: radio.currentVersion || existing.currentVersion,
                targetVersion: radio.targetVersion || existing.targetVersion,
                detail: radio.detail || existing.detail
            });
        } else {
            cambiumState.radios.push(radio);
        }
    }

    function applyResults(results) {
        if (!Array.isArray(results)) return;
        results.forEach(upsertRadio);
        updateUI();
    }

    function updateUI() {
        const statsBar = document.getElementById('cambiumStatsBar');
        const radioListCard = document.getElementById('cambiumRadioListCard');
        const radioList = document.getElementById('cambiumRadioList');
        if (!statsBar || !radioListCard || !radioList) return;

        if (cambiumState.radios.length === 0) {
            statsBar.style.display = 'none';
            radioListCard.style.display = 'none';
            return;
        }

        statsBar.style.display = 'flex';
        radioListCard.style.display = 'block';
        document.getElementById('cambiumStatTotal').textContent = cambiumState.radios.length;
        document.getElementById('cambiumStatPending').textContent = cambiumState.radios.filter(r => normalizeStatus(r.status) === 'pending').length;
        document.getElementById('cambiumStatProcessing').textContent = cambiumState.radios.filter(r => normalizeStatus(r.status) === 'processing').length;
        document.getElementById('cambiumStatQueued').textContent = cambiumState.radios.filter(r => ['queued', 'scheduled', 'verifying'].includes(normalizeStatus(r.status))).length;
        document.getElementById('cambiumStatSuccess').textContent = cambiumState.radios.filter(r => normalizeStatus(r.status) === 'success').length;
        document.getElementById('cambiumStatError').textContent = cambiumState.radios.filter(r => normalizeStatus(r.status) === 'error').length;

        radioList.innerHTML = cambiumState.radios.map(radio => {
            const mainStatus = normalizeStatus(radio.status);
            const firmwareStatus = normalizeStatus(radio.firmwareStatus);
            const backupStatus = normalizeStatus(radio.backupStatus);
            const verifyStatus = normalizeStatus(radio.verifyStatus);
            const ipValue = cambiumEscapeHtml(radio.ip);
            const detail = radio.detail ? `<div style="margin-top: 6px; color: var(--text-color-secondary); font-size: 12px;">${cambiumEscapeHtml(radio.detail)}</div>` : '';
            const currentPill = radio.currentVersion ? `<span class="aviat-pill">Current ${cambiumEscapeHtml(radio.currentVersion)}</span>` : '';
            const targetPill = radio.targetVersion ? `<span class="aviat-pill">Target ${cambiumEscapeHtml(radio.targetVersion)}</span>` : '';
            return `
                <div class="aviat-queue-item">
                    <div>
                        <span class="aviat-status-badge ${mainStatus}">${statusIcon(mainStatus)}</span>
                        ${ipValue}
                        <div style="margin-top: 6px; display: flex; gap: 6px; flex-wrap: wrap;">
                            <span class="aviat-status-badge ${firmwareStatus}" title="Firmware">${statusIcon(firmwareStatus)}</span>
                            <span class="aviat-status-badge ${backupStatus}" title="Backup">${statusIcon(backupStatus)}</span>
                            <span class="aviat-status-badge ${verifyStatus}" title="Verify">${statusIcon(verifyStatus)}</span>
                            ${radio.model ? `<span class="aviat-pill">${cambiumEscapeHtml(radio.model)}</span>` : ''}
                            ${currentPill}
                            ${targetPill}
                        </div>
                        ${detail}
                    </div>
                    <div style="display: flex; gap: 6px; align-items: center;">
                        <button class="aviat-btn secondary" onclick="cambiumRunSingle('${ipValue}')" ${cambiumState.isProcessing ? 'disabled' : ''}>Run</button>
                        <button class="aviat-btn secondary" onclick="cambiumInspectSingle('${ipValue}')" ${cambiumState.isProcessing ? 'disabled' : ''}>Inspect</button>
                        <button class="aviat-btn danger" onclick="cambiumRemoveRadio('${ipValue}')" ${cambiumState.isProcessing ? 'disabled' : ''}>Remove</button>
                    </div>
                </div>
            `;
        }).join('');

        persistRadios();
    }

    function normalizeProviders(payload) {
        const raw = Array.isArray(payload)
            ? payload
            : Array.isArray(payload?.providers)
                ? payload.providers
                : Array.isArray(payload?.items)
                    ? payload.items
                    : [];
        return raw.map((provider, index) => {
            if (typeof provider === 'string') {
                return { value: provider.toLowerCase(), label: provider };
            }
            const value = String(provider.value || provider.key || provider.name || provider.id || `provider-${index}`).trim();
            return {
                value: value.toLowerCase(),
                label: provider.label || provider.display_name || provider.name || provider.id || value
            };
        });
    }

    function normalizeCatalog(payload) {
        // Handle backend format: { devices: { CNEP3K: { label, family, available_versions, ... } } }
        if (payload?.devices && typeof payload.devices === 'object' && !Array.isArray(payload.devices)) {
            return Object.entries(payload.devices).flatMap(([deviceType, meta]) => {
                const versions = Array.isArray(meta.available_versions) && meta.available_versions.length
                    ? meta.available_versions
                    : meta.default_version ? [meta.default_version] : [];
                return versions.map(version => ({
                    device_type: deviceType,
                    family: String(meta.family || deviceType).toLowerCase(),
                    channel: '',
                    version: String(version),
                    label: `${meta.label || deviceType} v${version}`
                }));
            }).filter(e => e.version);
        }
        const raw = Array.isArray(payload)
            ? payload
            : Array.isArray(payload?.catalog)
                ? payload.catalog
                : Array.isArray(payload?.versions)
                    ? payload.versions
                    : Array.isArray(payload?.items)
                        ? payload.items
                        : [];
        return raw.map((entry, index) => {
            if (typeof entry === 'string') {
                return { device_type: '', family: '', channel: '', version: entry, label: entry };
            }
            const version = String(entry.version || entry.target_version || entry.release || entry.name || `version-${index}`).trim();
            return {
                device_type: String(entry.device_type || entry.deviceType || ''),
                family: String(entry.family || entry.device_family || entry.platform || '').toLowerCase(),
                channel: String(entry.channel || entry.track || entry.stream || '').toLowerCase(),
                version,
                label: entry.label || `${version}${entry.channel ? ` (${entry.channel})` : ''}`
            };
        }).filter(entry => entry.version);
    }

    function renderProviders() {
        const select = document.getElementById('cambiumProvider');
        if (!select) return;
        const providers = cambiumState.providers.length ? cambiumState.providers : [{ value: 'cambium', label: 'Cambium' }];
        const currentValue = select.value || 'cambium';
        select.innerHTML = providers.map(provider => `<option value="${cambiumEscapeHtml(provider.value)}">${cambiumEscapeHtml(provider.label)}</option>`).join('');
        select.value = providers.find(provider => provider.value === currentValue)?.value || providers[0].value;
    }

    function renderCatalog() {
        const versionSelect = document.getElementById('cambiumCatalogVersion');
        const familySelect = document.getElementById('cambiumFamily');
        const sourceSelect = document.getElementById('cambiumFirmwareSource');
        if (!versionSelect || !familySelect || !sourceSelect) return;

        const family = String(familySelect.value || '').toLowerCase();
        const channel = String(sourceSelect.value || '').toLowerCase();
        const filtered = cambiumState.catalog.filter(entry => {
            const familyOk = !family || !entry.family ||
                entry.family === family ||
                (entry.device_type && entry.device_type.toLowerCase() === family.toLowerCase());
            const channelOk = !channel || channel === 'manual' || !entry.channel || entry.channel === channel;
            return familyOk && channelOk;
        });
        const versions = filtered.length ? filtered : cambiumState.catalog;
        versionSelect.innerHTML = ['<option value="">Select from catalog</option>']
            .concat(versions.map(entry => `<option value="${cambiumEscapeHtml(entry.version)}">${cambiumEscapeHtml(entry.label)}</option>`))
            .join('');
        setCatalogMeta(cambiumState.catalog.length ? `${cambiumState.catalog.length} catalog entries loaded` : 'Catalog not loaded');
    }

    async function loadProviders(options = {}) {
        try {
            let response = null;
            let lastError = null;
            for (const candidate of getProviderCandidates()) {
                try {
                    response = await fetch(candidate);
                    if (response.ok || ![403, 404, 405].includes(response.status)) break;
                } catch (err) {
                    lastError = err;
                }
            }
            if (!response) throw lastError || new Error('Provider fetch failed');
            const data = await parseJson(response);
            if (!response.ok) throw new Error(data.error || `Provider fetch failed (${response.status})`);
            cambiumState.providers = normalizeProviders(data).filter(provider => provider.value.includes('cambium') || provider.label.toLowerCase().includes('cambium'));
            if (cambiumState.providers.length === 0) cambiumState.providers = [{ value: 'cambium', label: 'Cambium' }];
            renderProviders();
            if (!options.quiet) addLog('Loaded firmware providers', 'info');
        } catch (err) {
            cambiumState.providers = [{ value: 'cambium', label: 'Cambium' }];
            renderProviders();
            if (!options.quiet) addLog(`Provider load failed: ${err.message}`, 'warning');
        }
    }

    async function loadCatalog(options = {}) {
        try {
            const response = await cambiumFetch('/catalog');
            const data = await parseJson(response);
            if (!response.ok) throw new Error(data.error || `Catalog fetch failed (${response.status})`);
            cambiumState.catalog = normalizeCatalog(data);
            renderCatalog();
            if (!options.quiet) addLog(`Loaded Cambium catalog (${cambiumState.catalog.length} entries)`, 'info');
        } catch (err) {
            cambiumState.catalog = [];
            renderCatalog();
            if (!options.quiet) addLog(`Catalog load failed: ${err.message}`, 'warning');
        }
    }

    function selectedTasks() {
        const tasks = [];
        if (document.getElementById('cambiumTaskFirmware')?.checked) tasks.push('firmware');
        if (document.getElementById('cambiumTaskBackup')?.checked) tasks.push('backup');
        if (document.getElementById('cambiumTaskVerify')?.checked) tasks.push('verify');
        return tasks;
    }

    function selectedProfile() {
        const deviceType = document.getElementById('cambiumFamily')?.value || 'CNEP3K';
        return {
            provider: document.getElementById('cambiumProvider')?.value || 'cambium',
            device_type: deviceType,
            family: deviceType,
            firmware_source: document.getElementById('cambiumFirmwareSource')?.value || 'stable',
            target_version: (document.getElementById('cambiumTargetVersion')?.value || '').trim(),
            activation_mode: document.getElementById('cambiumActivationMode')?.value || 'immediate',
            activation_time: document.getElementById('cambiumActivationTime')?.value || '',
            tasks: selectedTasks()
        };
    }

    function parseIps(raw) {
        return String(raw || '').split(/[\n,]+/).map(ip => ip.trim()).filter(Boolean);
    }

    async function mutateQueue(mode, radios) {
        const response = await cambiumFetch('/queue', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                mode,
                action: mode,
                radios,
                devices: radios,
                username: cambiumGetUsername()
            })
        });
        const data = await parseJson(response);
        if (!response.ok) throw new Error(data.error || `Queue update failed (${response.status})`);
        const nextQueue = Array.isArray(data.radios) ? data.radios : Array.isArray(data.devices) ? data.devices : null;
        if (Array.isArray(nextQueue) && nextQueue.length > 0) {
            cambiumState.radios = nextQueue.map(normalizeRadio);
            updateUI();
        }
        return data;
    }

    async function fetchDeviceInfoForIps(ips, options = {}) {
        const results = [];
        for (const ip of ips) {
            try {
                const existingRadio = cambiumState.radios.find(r => r.ip === ip);
                const deviceType = (existingRadio && (existingRadio.device_type || existingRadio.model)) || selectedProfile().device_type || '';
                const response = await cambiumFetch('/device-info', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip, device_type: deviceType, username: cambiumGetUsername() })
                });
                const data = await parseJson(response);
                if (!response.ok) throw new Error(data.error || `Device info failed (${response.status})`);
                const result = data.device || data.radio || data.result || data;
                results.push({ ip, ...result });
            } catch (err) {
                results.push({ ip, status: 'error', verifyStatus: 'error', detail: err.message });
                if (!options.quiet) addLog(`Device info failed for ${ip}: ${err.message}`, 'warning');
            }
        }
        applyResults(results);
        return results;
    }

    async function addRadios() {
        const input = document.getElementById('cambiumQueueInput');
        if (!input) return;
        const profile = selectedProfile();
        const ips = parseIps(input.value).filter(ip => !cambiumState.radios.find(r => r.ip === ip));
        if (ips.length === 0) return;
        const radios = ips.map(ip => ({
            ip,
            device_type: profile.device_type,
            provider: profile.provider,
            family: profile.device_type,
            targetVersion: profile.target_version,
            status: 'pending',
            firmwareStatus: 'pending',
            backupStatus: 'pending',
            verifyStatus: 'pending',
            username: cambiumGetUsername()
        }));
        cambiumState.radios = cambiumState.radios.concat(radios.map(normalizeRadio));
        updateUI();
        try {
            await mutateQueue('add', radios);
            await fetchDeviceInfoForIps(ips, { quiet: true });
            addLog(`Added ${ips.length} Cambium radio(s) to queue`, 'info');
            input.value = '';
        } catch (err) {
            addLog(`Queue add failed: ${err.message}`, 'error');
        }
    }

    async function replaceRadios() {
        const input = document.getElementById('cambiumQueueInput');
        if (!input) return;
        const profile = selectedProfile();
        const ips = parseIps(input.value);
        const radios = ips.map(ip => ({
            ip,
            device_type: profile.device_type,
            provider: profile.provider,
            family: profile.device_type,
            targetVersion: profile.target_version,
            status: 'pending',
            firmwareStatus: 'pending',
            backupStatus: 'pending',
            verifyStatus: 'pending',
            username: cambiumGetUsername()
        }));
        cambiumState.radios = radios.map(normalizeRadio);
        updateUI();
        try {
            await mutateQueue('replace', radios);
            await fetchDeviceInfoForIps(ips, { quiet: true });
            addLog(`Replaced queue with ${ips.length} Cambium radio(s)`, 'info');
            input.value = '';
        } catch (err) {
            addLog(`Queue replace failed: ${err.message}`, 'error');
        }
    }

    window.cambiumRemoveRadio = async function (ip) {
        cambiumState.radios = cambiumState.radios.filter(r => r.ip !== ip);
        updateUI();
        try {
            await mutateQueue('remove', [{ ip }]);
            addLog(`Removed ${ip} from queue`, 'info');
        } catch (err) {
            addLog(`Remove failed: ${err.message}`, 'error');
        }
    };

    async function clearAll() {
        cambiumState.radios = [];
        updateUI();
        try {
            await mutateQueue('replace', []);
            addLog('Cleared all Cambium radios', 'info');
        } catch (err) {
            addLog(`Clear failed: ${err.message}`, 'error');
        }
    }

    async function clearCompleted() {
        const remaining = cambiumState.radios.filter(r => normalizeStatus(r.status) !== 'success');
        cambiumState.radios = remaining;
        updateUI();
        try {
            await mutateQueue('replace', remaining);
            addLog('Cleared completed Cambium radios', 'info');
        } catch (err) {
            addLog(`Clear completed failed: ${err.message}`, 'error');
        }
    }

    function applyEventPayload(payload) {
        if (!payload) return;
        if (Array.isArray(payload.results)) {
            applyResults(payload.results);
        } else if (Array.isArray(payload.radios)) {
            applyResults(payload.radios);
        } else if (payload.radio || payload.device || payload.result) {
            applyResults([payload.radio || payload.device || payload.result]);
        } else if (payload.ip || payload.host) {
            applyResults([payload]);
        }
        if (payload.message) addLog(payload.message, payload.level || 'info', { ts: payload.ts });
    }

    function startGlobalStream() {
        if (cambiumState.globalStreamStarted) return;
        if (typeof EventSource === 'undefined') {
            addLog('Cambium live stream is not available in this browser session.', 'warning');
            return;
        }
        cambiumState.globalStreamStarted = true;
        let eventSource;
        try {
            eventSource = new EventSource(`${getCambiumApiBase()}/stream/global`);
        } catch (err) {
            cambiumState.globalStreamStarted = false;
            addLog(`Cambium global stream failed to start: ${err.message}`, 'warning');
            return;
        }
        eventSource.onopen = function () {
            addLog('Cambium global stream connected', 'info');
        };
        eventSource.onmessage = function (event) {
            try {
                applyEventPayload(JSON.parse(event.data));
            } catch (err) {
                addLog('Cambium global stream parse failed.', 'warning');
            }
        };
        eventSource.onerror = function () {
            eventSource.close();
            cambiumState.globalStreamStarted = false;
            addLog('Cambium global stream disconnected. Retrying...', 'warning');
            setTimeout(() => {
                if (!cambiumState.globalStreamStarted) startGlobalStream();
            }, 5000);
        };
    }

    function startTaskStream(taskId) {
        if (cambiumState.taskStream) {
            try { cambiumState.taskStream.close(); } catch (err) {}
        }
        if (typeof EventSource === 'undefined') return;
        let eventSource;
        try {
            eventSource = new EventSource(`${getCambiumApiBase()}/stream/${encodeURIComponent(taskId)}`);
        } catch (err) {
            addLog(`Cambium task stream failed to start: ${err.message}`, 'warning');
            return;
        }
        cambiumState.taskStream = eventSource;
        eventSource.onmessage = function (event) {
            try {
                applyEventPayload(JSON.parse(event.data));
            } catch (err) {
                addLog('Cambium task stream parse failed.', 'warning');
            }
        };
        eventSource.onerror = function () {
            if (cambiumState.taskStream === eventSource) {
                eventSource.close();
                cambiumState.taskStream = null;
            }
        };
    }

    function stopTaskWatchers() {
        if (cambiumState.taskPollInterval) {
            clearInterval(cambiumState.taskPollInterval);
            cambiumState.taskPollInterval = null;
        }
        if (cambiumState.taskStream) {
            try { cambiumState.taskStream.close(); } catch (err) {}
            cambiumState.taskStream = null;
        }
    }

    async function pollTaskStatus(taskId) {
        try {
            const response = await cambiumFetch(`/status/${taskId}`);
            const data = await parseJson(response);
            if (!response.ok) throw new Error(data.error || `Status poll failed (${response.status})`);
            applyEventPayload(data);
            const status = String(data.status || '').toLowerCase();
            if (['completed', 'success', 'failed', 'error', 'aborted'].includes(status) || data.done === true) {
                stopTaskWatchers();
                cambiumState.taskId = null;
                setRunState(false);
                addLog(`Cambium task ${status || 'completed'}`, status === 'completed' || status === 'success' ? 'success' : (status === 'aborted' ? 'warning' : 'info'));
            }
        } catch (err) {
            addLog(`Status monitor error: ${err.message}`, 'warning');
        }
    }

    function monitorTask(taskId) {
        stopTaskWatchers();
        startTaskStream(taskId);
        cambiumState.taskPollInterval = setInterval(() => {
            pollTaskStatus(taskId);
        }, 2500);
    }

    async function submitRun(ips) {
        const profile = selectedProfile();
        if (!profile.target_version) {
            addLog('Select or enter a target Cambium version before running.', 'warning');
            return;
        }
        if (profile.tasks.length === 0) {
            addLog('Select at least one Cambium task before running.', 'warning');
            return;
        }
        if (profile.activation_mode === 'scheduled' && !profile.activation_time) {
            addLog('Activation time is required for scheduled Cambium runs.', 'warning');
            return;
        }

        cambiumState.taskId = null;
        setRunState(true);
        cambiumState.radios.forEach(radio => {
            if (ips.includes(radio.ip)) {
                radio.provider = profile.provider;
                radio.family = profile.family || radio.family;
                radio.targetVersion = profile.target_version;
                radio.status = profile.activation_mode === 'stage-only' ? 'queued' : 'processing';
                radio.firmwareStatus = 'processing';
                radio.detail = `Queued for ${profile.target_version}`;
            }
        });
        updateUI();

        try {
            const response = await cambiumFetch('/run', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    provider: profile.provider,
                    device_type: profile.device_type,
                    family: profile.device_type,
                    target_version: profile.target_version,
                    update_version: profile.target_version,
                    activation_mode: profile.activation_mode,
                    activation_time: profile.activation_time,
                    tasks: profile.tasks,
                    ips,
                    devices: ips,
                    username: cambiumGetUsername()
                })
            });
            const data = await parseJson(response);
            if (!response.ok) throw new Error(data.error || `Run failed (${response.status})`);
            applyEventPayload(data);
            cambiumState.taskId = data.task_id || data.taskId || null;
            addLog(`Cambium run started for ${ips.length} radio(s)`, 'info');
            if (cambiumState.taskId) {
                monitorTask(cambiumState.taskId);
            } else {
                setRunState(false);
            }
        } catch (err) {
            cambiumState.radios.forEach(radio => {
                if (ips.includes(radio.ip)) {
                    radio.status = 'error';
                    radio.firmwareStatus = 'error';
                    radio.detail = err.message;
                }
            });
            updateUI();
            setRunState(false);
            addLog(`Cambium run failed: ${err.message}`, 'error');
        }
    }

    window.cambiumRunSingle = async function (ip) {
        await submitRun([ip]);
    };

    window.cambiumInspectSingle = async function (ip) {
        await fetchDeviceInfoForIps([ip]);
    };

    async function runAll() {
        const ips = cambiumState.radios.map(radio => radio.ip);
        if (ips.length === 0) {
            addLog('No Cambium radios are queued.', 'warning');
            return;
        }
        await submitRun(ips);
    }

    async function refreshDeviceInfo() {
        const ips = cambiumState.radios.map(radio => radio.ip);
        if (ips.length === 0) {
            addLog('No Cambium radios in queue to inspect.', 'info');
            return;
        }
        addLog(`Fetching device info for ${ips.length} Cambium radio(s)...`, 'info');
        await fetchDeviceInfoForIps(ips);
    }

    function handleCatalogVersionChange() {
        const versionSelect = document.getElementById('cambiumCatalogVersion');
        const targetInput = document.getElementById('cambiumTargetVersion');
        if (versionSelect && targetInput && versionSelect.value) targetInput.value = versionSelect.value;
    }

    function handleCatalogFilterChange() {
        renderCatalog();
    }

    function syncEndpointHint() {
        const endpointInput = document.getElementById('cambiumEndpointHint');
        if (endpointInput) endpointInput.value = getCambiumApiBase();
    }

    function bindControls() {
        const bindings = [
            ['cambiumAddBtn', 'click', addRadios],
            ['cambiumReplaceBtn', 'click', replaceRadios],
            ['cambiumClearDoneBtn', 'click', clearCompleted],
            ['cambiumClearAllBtn', 'click', clearAll],
            ['cambiumRefreshBtn', 'click', refreshDeviceInfo],
            ['cambiumCheckStatusBtn', 'click', refreshDeviceInfo],
            ['cambiumRunBtn', 'click', runAll],
            ['cambiumLogRefreshBtn', 'click', refreshDeviceInfo],
            ['cambiumLogStatusBtn', 'click', async () => {
                if (cambiumState.taskId) {
                    await pollTaskStatus(cambiumState.taskId);
                } else {
                    await refreshDeviceInfo();
                }
            }],
            ['cambiumReloadProvidersBtn', 'click', () => loadProviders()],
            ['cambiumReloadCatalogBtn', 'click', () => loadCatalog()],
            ['cambiumReloadUiBtn', 'click', async () => {
                syncEndpointHint();
                renderProviders();
                renderCatalog();
                updateUI();
                await loadProviders({ quiet: true });
                await loadCatalog({ quiet: true });
                addLog('Cambium UI reloaded.', 'info');
            }],
            ['cambiumClearLogBtn', 'click', clearLog]
        ];

        bindings.forEach(([id, eventName, handler]) => {
            const element = document.getElementById(id);
            if (!element) return;
            element.addEventListener(eventName, handler);
        });

        const activationMode = document.getElementById('cambiumActivationMode');
        const activationTime = document.getElementById('cambiumActivationTime');
        if (activationMode && activationTime) {
            activationMode.addEventListener('change', () => {
                activationTime.disabled = activationMode.value !== 'scheduled';
            });
            activationTime.disabled = activationMode.value !== 'scheduled';
        }

        const catalogVersion = document.getElementById('cambiumCatalogVersion');
        if (catalogVersion) catalogVersion.addEventListener('change', handleCatalogVersionChange);

        const familySelect = document.getElementById('cambiumFamily');
        if (familySelect) familySelect.addEventListener('change', handleCatalogFilterChange);

        const sourceSelect = document.getElementById('cambiumFirmwareSource');
        if (sourceSelect) sourceSelect.addEventListener('change', handleCatalogFilterChange);

        const abortBtn = document.getElementById('cambiumAbortBtn');
        if (abortBtn) {
            abortBtn.disabled = true;
            abortBtn.title = 'Abort is not available in the current backend contract.';
        }
    }

    async function initCambiumUpdater() {
        if (cambiumState.initComplete) return;
        cambiumState.initComplete = true;
        restoreRadios();
        syncEndpointHint();
        renderProviders();
        renderCatalog();
        updateUI();
        setRunState(false);
        bindControls();
        startGlobalStream();
        await loadProviders({ quiet: true });
        await loadCatalog({ quiet: true });
        addLog('Cambium firmware updater ready.', 'info');
    }

    window.getCambiumApiBase = getCambiumApiBase;

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            initCambiumUpdater().catch(err => {
                console.error('[Cambium] Failed to initialize updater', err);
            });
        }, { once: true });
    } else {
        initCambiumUpdater().catch(err => {
            console.error('[Cambium] Failed to initialize updater', err);
        });
    }
})();

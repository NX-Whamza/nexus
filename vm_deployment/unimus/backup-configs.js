(function () {
    const API_BASE = ((typeof AI_API_BASE !== 'undefined' ? AI_API_BASE : window.AI_API_BASE) || '/api').replace(/\/+$/, '');

    function getHeaders(contentType = null) {
        const headers = {};
        if (contentType) headers['Content-Type'] = contentType;
        const token = localStorage.getItem('auth_token');
        if (token) headers['Authorization'] = `Bearer ${token}`;
        return headers;
    }

    async function apiFetch(url, options = {}) {
        const fetcher = typeof window.robustFetch === 'function' ? window.robustFetch : window.fetch.bind(window);
        return fetcher(url, {
            ...options,
            headers: {
                ...getHeaders(),
                ...(options.headers || {}),
            },
        });
    }

    function escapeHtml(value) {
        return String(value ?? '').replace(/[&<>"']/g, (char) => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
        }[char]));
    }

    function formatTimestamp(value) {
        if (!value) return '-';
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return String(value);
        return new Intl.DateTimeFormat(undefined, {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: 'numeric',
            minute: '2-digit',
        }).format(date);
    }

    function $(id) {
        return document.getElementById(id);
    }

    function getUrlState() {
        return new URLSearchParams(window.location.search);
    }

    function syncUrlState(next = {}) {
        const params = getUrlState();
        params.set('tab', 'unimus-backup-configs');
        if (next.address) params.set('address', String(next.address).trim());
        else params.delete('address');
        const query = params.toString();
        const nextUrl = `${window.location.pathname}${query ? `?${query}` : ''}${window.location.hash || ''}`;
        window.history.replaceState({}, '', nextUrl);
    }

    function isSmallViewport() {
        return window.matchMedia('(max-width: 720px)').matches;
    }

    function isSearchFieldFocused(inputEl) {
        return !!inputEl && document.activeElement === inputEl;
    }

    function dismissMobileKeyboard(inputEl) {
        if (!isSmallViewport() || !isSearchFieldFocused(inputEl)) return;
        inputEl.blur();
    }

    let initialized = false;

    function createModal() {
        if ($('unimusBcModal')) return $('unimusBcModal');
        const modal = document.createElement('div');
        modal.className = 'unimus-bc-modal';
        modal.id = 'unimusBcModal';
        modal.innerHTML = `
            <div class="unimus-bc-modal-panel">
                <div class="unimus-bc-modal-header">
                    <div>
                        <h3 id="unimusBcModalTitle">Config Viewer</h3>
                        <div class="unimus-bc-modal-meta" id="unimusBcModalMeta"></div>
                    </div>
                    <button type="button" class="unimus-bc-modal-close" id="unimusBcModalClose">&times;</button>
                </div>
                <div class="unimus-bc-modal-toolbar">
                    <label><input type="checkbox" id="unimusBcShowFullDiff"> Show Full Config</label>
                </div>
                <div class="unimus-bc-modal-body">
                    <pre class="unimus-bc-pre" id="unimusBcModalPre">Loading...</pre>
                    <div class="unimus-bc-diff unimus-bc-hidden" id="unimusBcModalDiff"></div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        const close = () => modal.classList.remove('is-open');
        modal.addEventListener('click', (event) => {
            if (event.target === modal) close();
        });
        $('unimusBcModalClose').addEventListener('click', close);
        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape') close();
        });
        return modal;
    }

    function init() {
        if (initialized) return;
        const pane = $('unimus-backup-configs-pane');
        if (!pane) return;
        initialized = true;

        const modal = createModal();
        const state = {
            searchTimer: null,
            searchResults: [],
            searchIndex: -1,
            searchController: null,
            currentDeviceId: '',
            currentAddress: '',
            backups: [],
            selectedBackupIds: [],
            currentPage: 0,
            pageSize: 10,
            hasMore: false,
            backupCache: new Map(),
            activeDiff: null,
        };

        const els = {
            searchInput: $('unimusBcSearchInput'),
            searchButton: $('unimusBcSearchButton'),
            suggest: $('unimusBcSuggest'),
            summaryValue: $('unimusBcSummaryValue'),
            summaryNote: $('unimusBcSummaryNote'),
            emptyState: $('unimusBcEmptyState'),
            missingState: $('unimusBcMissingState'),
            workspace: $('unimusBcWorkspace'),
            zabbixCard: $('unimusBcZabbixCard'),
            zabbixPill: $('unimusBcZabbixPill'),
            zabbixDetail: $('unimusBcZabbixDetail'),
            unimusCard: $('unimusBcUnimusCard'),
            unimusPill: $('unimusBcUnimusPill'),
            unimusDetail: $('unimusBcUnimusDetail'),
            remoteCore: $('unimusBcRemoteCore'),
            description: $('unimusBcDescription'),
            address: $('unimusBcAddress'),
            credential: $('unimusBcCredential'),
            vendor: $('unimusBcVendor'),
            type: $('unimusBcType'),
            model: $('unimusBcModel'),
            connectionType: $('unimusBcConnectionType'),
            connectionPort: $('unimusBcConnectionPort'),
            downloadExtension: $('unimusBcDownloadExtension'),
            countBadge: $('unimusBcCountBadge'),
            backupsBody: $('unimusBcBackupsBody'),
            loadMoreWrap: $('unimusBcLoadMoreWrap'),
            loadMoreButton: $('unimusBcLoadMoreButton'),
            viewButton: $('unimusBcViewButton'),
            diffButton: $('unimusBcDiffButton'),
            downloadButton: $('unimusBcDownloadButton'),
            backupNowButton: $('unimusBcBackupNowButton'),
            inlineMessage: $('unimusBcInlineMessage'),
            modal,
            modalTitle: $('unimusBcModalTitle'),
            modalMeta: $('unimusBcModalMeta'),
            modalPre: $('unimusBcModalPre'),
            modalDiff: $('unimusBcModalDiff'),
            showFullDiff: $('unimusBcShowFullDiff'),
        };

        const scrollHost = document.querySelector('.content-area');

        function showInlineMessage(message, kind = '') {
            els.inlineMessage.textContent = message || '';
            els.inlineMessage.classList.remove('unimus-bc-hidden', 'is-success', 'is-error');
            if (kind === 'success') els.inlineMessage.classList.add('is-success');
            if (kind === 'error') els.inlineMessage.classList.add('is-error');
            if (!message) els.inlineMessage.classList.add('unimus-bc-hidden');
        }

        function hideInlineMessage() {
            els.inlineMessage.textContent = '';
            els.inlineMessage.classList.add('unimus-bc-hidden');
            els.inlineMessage.classList.remove('is-success', 'is-error');
        }

        function updateActionButtons() {
            els.viewButton.disabled = state.selectedBackupIds.length !== 1;
            els.downloadButton.disabled = state.selectedBackupIds.length !== 1;
            els.diffButton.disabled = state.selectedBackupIds.length !== 2;
        }

        function setStatusCard(card, pill, detail, payload, fallbackDetail = '') {
            const label = String(payload?.label || '-');
            const stateValue = String(payload?.state || '');
            card.classList.remove('state-up', 'state-down');
            if (stateValue === 'up') card.classList.add('state-up');
            if (stateValue === 'down') card.classList.add('state-down');
            pill.textContent = label;
            detail.textContent = String(payload?.detail || fallbackDetail || '');
        }

        function setField(el, value, fallback = '') {
            if (el) el.value = value == null || value === '' ? fallback : value;
        }

        function hideSuggest() {
            els.suggest.classList.remove('is-open');
            els.suggest.innerHTML = '';
            state.searchIndex = -1;
            state.searchResults = [];
        }

        function renderSuggest(items) {
            state.searchResults = items;
            state.searchIndex = -1;
            if (!items.length) {
                hideSuggest();
                return;
            }
            els.suggest.innerHTML = items.map((item, index) => `
                <div class="unimus-bc-suggest-item" data-index="${index}">
                    <div class="unimus-bc-suggest-primary">${escapeHtml(item.label || item.name || item.host || item.ip || '')}</div>
                    <div class="unimus-bc-suggest-secondary">${escapeHtml(item.ip || '')}${item.disabled ? ' • Disabled' : ''}</div>
                </div>
            `).join('');
            els.suggest.classList.add('is-open');
            els.suggest.querySelectorAll('.unimus-bc-suggest-item').forEach((itemEl) => {
                itemEl.addEventListener('mousedown', (event) => {
                    event.preventDefault();
                    const idx = Number(itemEl.getAttribute('data-index'));
                    const item = state.searchResults[idx];
                    if (item?.ip) {
                        dismissMobileKeyboard(els.searchInput);
                        loadHost(item.ip);
                    }
                });
            });
        }

        function highlightSuggest(index) {
            state.searchIndex = index;
            els.suggest.querySelectorAll('.unimus-bc-suggest-item').forEach((row, rowIndex) => {
                row.classList.toggle('active', rowIndex === index);
            });
        }

        async function loadSummary() {
            try {
                const response = await apiFetch(`${API_BASE}/unimus-backup-configs/summary`);
                const payload = await response.json().catch(() => ({}));
                if (!response.ok) throw new Error(payload.detail || payload.error || `HTTP ${response.status}`);
                if (payload.configured) {
                    els.summaryValue.textContent = `Ready • ${payload.remote_core_count || 0} ${payload.remote_core_label || 'Remote Cores'}`;
                    els.summaryNote.textContent = 'Unimus integration is configured for this Nexus instance.';
                } else {
                    els.summaryValue.textContent = 'Not Configured';
                    els.summaryNote.textContent = 'Set the Unimus environment values on the backend container before using this tool.';
                }
            } catch (error) {
                els.summaryValue.textContent = 'Unavailable';
                els.summaryNote.textContent = error.message || 'Unable to load the Unimus integration summary.';
            }
        }

        function setWorkspaceMode(mode) {
            els.emptyState.classList.toggle('unimus-bc-hidden', mode !== 'empty');
            els.missingState.classList.toggle('unimus-bc-hidden', mode !== 'missing');
            els.workspace.classList.toggle('unimus-bc-hidden', mode !== 'workspace');
        }

        function getConnectionInfo(connections) {
            const first = Array.isArray(connections) && connections.length ? connections[0] : {};
            const firstCredential = Array.isArray(first?.credentials) && first.credentials.length ? first.credentials[0] : {};
            return {
                credential: first?.credential?.name || first?.credentialName || firstCredential?.description || firstCredential?.username || '',
                type: first?.typeString || first?.type || '',
                port: first?.port || '',
            };
        }

        function renderBackups() {
            els.countBadge.textContent = `${state.backups.length} backups`;
            if (!state.backups.length) {
                els.backupsBody.innerHTML = '<tr><td colspan="3" class="unimus-bc-table-empty">No backups returned for this device.</td></tr>';
                els.loadMoreWrap.classList.add('unimus-bc-hidden');
                updateActionButtons();
                return;
            }
            els.backupsBody.innerHTML = state.backups.map((backup, index) => {
                const checked = state.selectedBackupIds.includes(String(backup.id)) ? 'checked' : '';
                const end = formatTimestamp(backup.validUntilIso || backup.validUntil);
                const endLabel = end === '-' ? (index === 0 ? 'Current' : '') : end;
                return `
                    <tr>
                        <td><input type="checkbox" data-backup-id="${escapeHtml(backup.id)}" ${checked}></td>
                        <td><span class="unimus-bc-backup-id">${escapeHtml(backup.id)}</span></td>
                        <td>
                            <div class="unimus-bc-backup-timeline">
                                <span>${escapeHtml(formatTimestamp(backup.validSinceIso || backup.validSince))}</span>
                                <span class="unimus-bc-backup-arrow">→</span>
                                <span>${escapeHtml(endLabel)}</span>
                            </div>
                        </td>
                    </tr>
                `;
            }).join('');
            els.backupsBody.querySelectorAll('input[type="checkbox"]').forEach((checkbox) => {
                checkbox.addEventListener('change', () => {
                    const id = String(checkbox.getAttribute('data-backup-id'));
                    if (checkbox.checked) {
                        if (!state.selectedBackupIds.includes(id)) {
                            if (state.selectedBackupIds.length === 2) {
                                state.selectedBackupIds.shift();
                            }
                            state.selectedBackupIds.push(id);
                        }
                    } else {
                        state.selectedBackupIds = state.selectedBackupIds.filter((value) => value !== id);
                    }
                    renderBackups();
                    updateActionButtons();
                });
            });
            els.loadMoreWrap.classList.toggle('unimus-bc-hidden', !state.hasMore);
            updateActionButtons();
        }

        async function fetchBackupText(backupId) {
            const key = String(backupId);
            if (state.backupCache.has(key)) return state.backupCache.get(key);
            const params = new URLSearchParams({
                device_id: state.currentDeviceId,
                backup_id: key,
            });
            const response = await apiFetch(`${API_BASE}/unimus-backup-configs/host-backup?${params.toString()}`);
            const payload = await response.json().catch(() => ({}));
            if (!response.ok) throw new Error(payload.detail || payload.error || `Failed to load backup ${key}`);
            state.backupCache.set(key, payload);
            return payload;
        }

        function openModal(title, meta, mode) {
            els.modalTitle.textContent = title;
            els.modalMeta.textContent = meta || '';
            els.modal.classList.add('is-open');
            els.modalPre.classList.toggle('unimus-bc-hidden', mode === 'diff');
            els.modalDiff.classList.toggle('unimus-bc-hidden', mode !== 'diff');
            els.showFullDiff.parentElement.style.visibility = mode === 'diff' ? 'visible' : 'hidden';
        }

        function renderDiffRows(rows) {
            els.modalDiff.innerHTML = rows.map((row) => {
                if (row.type === 'skip') {
                    return `<div class="unimus-bc-diff-skip">... ${row.count} common lines hidden ...</div>`;
                }
                const prefix = row.type === 'added' ? '+' : row.type === 'removed' ? '-' : ' ';
                const className = row.type === 'added'
                    ? 'unimus-bc-diff-line added'
                    : row.type === 'removed'
                        ? 'unimus-bc-diff-line removed'
                        : 'unimus-bc-diff-line';
                return `<div class="${className}"><span>${prefix}</span><span>${escapeHtml(row.text)}</span></div>`;
            }).join('');
        }

        function buildDiffRows(parts, showWholeConfig) {
            const rows = [];
            parts.forEach((part) => {
                part.value.split('\n').forEach((line, index, list) => {
                    if (index === list.length - 1 && line === '') return;
                    rows.push({
                        type: part.added ? 'added' : part.removed ? 'removed' : 'common',
                        text: line,
                    });
                });
            });
            if (showWholeConfig) return rows;
            const keep = new Set();
            const context = 2;
            rows.forEach((row, index) => {
                if (row.type === 'added' || row.type === 'removed') {
                    for (let cursor = Math.max(0, index - context); cursor <= Math.min(rows.length - 1, index + context); cursor += 1) {
                        keep.add(cursor);
                    }
                }
            });
            const filtered = [];
            let hiddenCount = 0;
            rows.forEach((row, index) => {
                if (keep.has(index)) {
                    if (hiddenCount > 0) {
                        filtered.push({ type: 'skip', count: hiddenCount });
                        hiddenCount = 0;
                    }
                    filtered.push(row);
                } else {
                    hiddenCount += 1;
                }
            });
            if (hiddenCount > 0) filtered.push({ type: 'skip', count: hiddenCount });
            return filtered;
        }

        function rerenderDiff() {
            if (!state.activeDiff) return;
            const diffParts = window.Diff ? window.Diff.diffLines(state.activeDiff.olderText, state.activeDiff.newerText) : [];
            renderDiffRows(buildDiffRows(diffParts, !!els.showFullDiff.checked));
        }

        async function loadBackupsPage(page) {
            const params = new URLSearchParams({
                device_id: state.currentDeviceId,
                page: String(page),
                size: String(state.pageSize),
            });
            const response = await apiFetch(`${API_BASE}/unimus-backup-configs/host-backups?${params.toString()}`);
            const payload = await response.json().catch(() => ({}));
            if (!response.ok) throw new Error(payload.detail || payload.error || `HTTP ${response.status}`);
            state.currentPage = payload.page || page;
            state.hasMore = !!payload.has_more;
            state.backups = page === 0 ? (payload.backups || []) : [...state.backups, ...(payload.backups || [])];
            state.selectedBackupIds = state.selectedBackupIds.filter((id) => state.backups.some((backup) => String(backup.id) === String(id)));
            renderBackups();
        }

        async function loadHost(address) {
            hideSuggest();
            hideInlineMessage();
            els.searchInput.value = address;
            els.searchButton.disabled = true;
            els.searchButton.textContent = 'Loading...';
            try {
                const params = new URLSearchParams({ address: String(address || '').trim() });
                const response = await apiFetch(`${API_BASE}/unimus-backup-configs/host-details?${params.toString()}`);
                const payload = await response.json().catch(() => ({}));
                if (response.status === 404 && payload?.code === 'device_not_found') {
                    state.currentAddress = address;
                    state.currentDeviceId = '';
                    state.backups = [];
                    state.selectedBackupIds = [];
                    syncUrlState({ address });
                    setWorkspaceMode('missing');
                    return;
                }
                if (!response.ok) throw new Error(payload.detail || payload.error || `HTTP ${response.status}`);
                state.currentAddress = payload.address || address;
                state.currentDeviceId = payload.device_id || '';
                state.backups = Array.isArray(payload.backups) ? payload.backups : [];
                state.currentPage = Number(payload.backups_page || 0);
                state.pageSize = Number(payload.backups_page_size || 10);
                state.hasMore = !!payload.backups_has_more;
                state.selectedBackupIds = [];
                state.backupCache.clear();
                syncUrlState({ address: state.currentAddress });
                setWorkspaceMode('workspace');

                const device = payload.device || {};
                const conn = getConnectionInfo(payload.connections);
                setStatusCard(els.zabbixCard, els.zabbixPill, els.zabbixDetail, payload.zabbix_status);
                setStatusCard(els.unimusCard, els.unimusPill, els.unimusDetail, payload.unimus_status);
                els.remoteCore.textContent = payload.remote_core_name
                    ? `${payload.remote_core_name}${payload.remote_core_type ? ` • ${payload.remote_core_type}` : ''}`
                    : 'Remote core unavailable';
                setField(els.description, device.description || device.name || state.currentAddress);
                setField(els.address, payload.address || device.address || '');
                setField(els.credential, conn.credential);
                setField(els.vendor, device.vendor || '');
                setField(els.type, device.type || '');
                setField(els.model, device.model || '');
                setField(els.connectionType, conn.type);
                setField(els.connectionPort, conn.port);
                setField(els.downloadExtension, payload.download_extension || '.cfg');
                renderBackups();
            } catch (error) {
                setWorkspaceMode('empty');
                showInlineMessage(error.message || 'Failed to load the selected host.', 'error');
            } finally {
                els.searchButton.disabled = false;
                els.searchButton.textContent = 'Load Host';
            }
        }

        async function runSearch() {
            const query = String(els.searchInput.value || '').trim();
            if (!query) return;
            if (state.searchIndex >= 0 && state.searchResults[state.searchIndex]?.ip) {
                dismissMobileKeyboard(els.searchInput);
                loadHost(state.searchResults[state.searchIndex].ip);
                return;
            }
            if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(query)) {
                dismissMobileKeyboard(els.searchInput);
                loadHost(query);
                return;
            }
            try {
                const response = await apiFetch(`${API_BASE}/unimus-backup-configs/host-search?q=${encodeURIComponent(query)}&limit=50`);
                const payload = await response.json().catch(() => ({}));
                if (!response.ok) throw new Error(payload.detail || payload.error || `HTTP ${response.status}`);
                const first = Array.isArray(payload.results) ? payload.results[0] : null;
                if (first?.ip) {
                    dismissMobileKeyboard(els.searchInput);
                    loadHost(first.ip);
                    return;
                }
                showInlineMessage('No matching Zabbix host was found for that search.', 'error');
            } catch (error) {
                showInlineMessage(error.message || 'Search failed.', 'error');
            }
        }

        async function refreshSuggestions() {
            const query = String(els.searchInput.value || '').trim();
            if (query.length < 2) {
                hideSuggest();
                return;
            }
            try {
                if (state.searchController) {
                    state.searchController.abort();
                }
                state.searchController = new AbortController();
                const response = await apiFetch(`${API_BASE}/unimus-backup-configs/host-search?q=${encodeURIComponent(query)}&limit=50`, {
                    signal: state.searchController.signal,
                });
                const payload = await response.json().catch(() => ({}));
                if (!response.ok) throw new Error(payload.detail || payload.error || `HTTP ${response.status}`);
                renderSuggest(Array.isArray(payload.results) ? payload.results : []);
            } catch (error) {
                if (error?.name === 'AbortError') return;
                hideSuggest();
            }
        }

        els.searchInput.addEventListener('input', () => {
            clearTimeout(state.searchTimer);
            state.searchTimer = window.setTimeout(refreshSuggestions, 325);
        });

        els.searchInput.addEventListener('focus', () => {
            if (String(els.searchInput.value || '').trim().length >= 2) {
                refreshSuggestions();
            }
        });

        els.searchInput.addEventListener('keydown', (event) => {
            if (event.key === 'ArrowDown') {
                event.preventDefault();
                if (!state.searchResults.length) return;
                highlightSuggest(Math.min(state.searchResults.length - 1, state.searchIndex + 1));
            } else if (event.key === 'ArrowUp') {
                event.preventDefault();
                if (!state.searchResults.length) return;
                highlightSuggest(Math.max(0, state.searchIndex - 1));
            } else if (event.key === 'Enter') {
                event.preventDefault();
                runSearch();
            } else if (event.key === 'Escape') {
                hideSuggest();
            }
        });

        els.searchButton.addEventListener('click', runSearch);
        els.loadMoreButton.addEventListener('click', () => loadBackupsPage(state.currentPage + 1).catch((error) => {
            showInlineMessage(error.message || 'Failed to load more backups.', 'error');
        }));

        els.viewButton.addEventListener('click', async () => {
            if (state.selectedBackupIds.length !== 1) return;
            try {
                const backupId = state.selectedBackupIds[0];
                const backup = state.backups.find((row) => String(row.id) === String(backupId));
                const payload = await fetchBackupText(backupId);
                els.modalPre.textContent = payload.text || 'No text returned for this backup.';
                els.showFullDiff.checked = false;
                state.activeDiff = null;
                openModal('Config Viewer', `${backup?.id || backupId} • ${formatTimestamp(payload.validSinceIso || payload.validSince)}`, 'single');
            } catch (error) {
                showInlineMessage(error.message || 'Failed to load the selected backup.', 'error');
            }
        });

        els.diffButton.addEventListener('click', async () => {
            if (state.selectedBackupIds.length !== 2) return;
            try {
                const selected = [...state.selectedBackupIds].sort((left, right) => {
                    const leftBackup = state.backups.find((row) => String(row.id) === String(left));
                    const rightBackup = state.backups.find((row) => String(row.id) === String(right));
                    return Number(leftBackup?.validSince || 0) - Number(rightBackup?.validSince || 0);
                });
                const [olderPayload, newerPayload] = await Promise.all([
                    fetchBackupText(selected[0]),
                    fetchBackupText(selected[1]),
                ]);
                state.activeDiff = {
                    olderText: olderPayload.text || '',
                    newerText: newerPayload.text || '',
                };
                els.showFullDiff.checked = false;
                openModal('Config Diff', `${selected[0]} → ${selected[1]}`, 'diff');
                rerenderDiff();
            } catch (error) {
                showInlineMessage(error.message || 'Failed to diff the selected backups.', 'error');
            }
        });

        els.showFullDiff.addEventListener('change', rerenderDiff);

        els.downloadButton.addEventListener('click', async () => {
            if (state.selectedBackupIds.length !== 1) return;
            try {
                const params = new URLSearchParams({
                    device_id: state.currentDeviceId,
                    backup_id: state.selectedBackupIds[0],
                    download: '1',
                });
                const response = await apiFetch(`${API_BASE}/unimus-backup-configs/host-backup?${params.toString()}`);
                if (!response.ok) {
                    const payload = await response.json().catch(() => ({}));
                    throw new Error(payload.detail || payload.error || `HTTP ${response.status}`);
                }
                const blob = await response.blob();
                const disposition = response.headers.get('Content-Disposition') || '';
                const filenameMatch = disposition.match(/filename=\"?([^"]+)\"?/i);
                const filename = filenameMatch ? filenameMatch[1] : 'unimus-backup.cfg';
                const url = URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url;
                link.download = filename;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                window.setTimeout(() => URL.revokeObjectURL(url), 1000);
            } catch (error) {
                showInlineMessage(error.message || 'Failed to download the selected backup.', 'error');
            }
        });

        els.backupNowButton.addEventListener('click', async () => {
            if (!state.currentDeviceId) return;
            hideInlineMessage();
            els.backupNowButton.disabled = true;
            els.backupNowButton.textContent = 'Running...';
            try {
                const params = new URLSearchParams({ device_id: state.currentDeviceId });
                const response = await apiFetch(`${API_BASE}/unimus-backup-configs/host-backup-now?${params.toString()}`, {
                    method: 'POST',
                });
                const payload = await response.json().catch(() => ({}));
                if (!response.ok && response.status !== 202) {
                    throw new Error(payload.detail || payload.error || `HTTP ${response.status}`);
                }
                if (Array.isArray(payload.backups)) {
                    state.backups = payload.backups;
                    state.selectedBackupIds = [];
                    state.hasMore = false;
                    renderBackups();
                }
                setStatusCard(els.zabbixCard, els.zabbixPill, els.zabbixDetail, payload.zabbix_status);
                setStatusCard(els.unimusCard, els.unimusPill, els.unimusDetail, payload.unimus_status);
                showInlineMessage(
                    response.status === 202
                        ? (payload.message || 'Backup request accepted, but completion was not confirmed before timeout.')
                        : 'Backup completed and the latest backup list was refreshed.',
                    response.status === 202 ? '' : 'success'
                );
            } catch (error) {
                showInlineMessage(error.message || 'Backup failed. Ensure the device is online and reachable via SSH.', 'error');
            } finally {
                els.backupNowButton.disabled = false;
                els.backupNowButton.textContent = 'Backup Now';
            }
        });

        document.addEventListener('click', (event) => {
            if (!els.suggest.contains(event.target) && event.target !== els.searchInput) {
                hideSuggest();
            }
        });

        const dismissOnScroll = () => dismissMobileKeyboard(els.searchInput);
        els.suggest.addEventListener('scroll', dismissOnScroll, { passive: true });
        els.suggest.addEventListener('touchmove', dismissOnScroll, { passive: true });
        window.addEventListener('scroll', dismissOnScroll, { passive: true });
        scrollHost?.addEventListener('scroll', dismissOnScroll, { passive: true });

        loadSummary();
        setWorkspaceMode('empty');

        const urlState = getUrlState();
        const directAddress = String(urlState.get('address') || '').trim();
        if (directAddress) {
            els.searchInput.value = directAddress;
            window.setTimeout(() => loadHost(directAddress), 150);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();

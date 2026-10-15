/**
 * HS_WSS - HS Tech Web Secret Scanner Client Application
 * Layout Simples e Objetivo com 3 Guias:
 * 1. Varredura (Configuração e Disparo)
 * 2. Status da varredura (Acompanhamento em Tempo Real)
 * 3. Histórico (Execuções Anteriores + Detalhes Inline)
 */

(() => {
    'use strict';

    // Application State
    let activeScanId = null;
    let selectedHistoryScanId = null;
    let isScanRunning = false;
    let sseSource = null;
    let currentFindings = [];

    // =========================================================================
    // DOM Elements - Navegação das Guias
    // =========================================================================
    const tabVarreduraBtn = document.getElementById('tabVarreduraBtn');
    const tabStatusBtn = document.getElementById('tabStatusBtn');
    const tabHistoricoBtn = document.getElementById('tabHistoricoBtn');

    const tabVarreduraContent = document.getElementById('tabVarreduraContent');
    const tabStatusContent = document.getElementById('tabStatusContent');
    const tabHistoricoContent = document.getElementById('tabHistoricoContent');

    const statusLiveIndicator = document.getElementById('statusLiveIndicator');
    const historyCountBadge = document.getElementById('historyCountBadge');
    const historyActionWrapper = document.getElementById('historyActionWrapper');
    const clearHistoryBtn = document.getElementById('clearHistoryBtn');
    const goToVarreduraBtn = document.getElementById('goToVarreduraBtn');

    // =========================================================================
    // DOM Elements - Guia 1: Varredura
    // =========================================================================
    const scanForm = document.getElementById('scanForm');
    const targetUrlInput = document.getElementById('targetUrlInput');
    const maxDepthInput = document.getElementById('maxDepthInput');
    const maxPagesInput = document.getElementById('maxPagesInput');
    const startScanBtn = document.getElementById('startScanBtn');

    const authToggle = document.getElementById('authToggle');
    const authFieldsContainer = document.getElementById('authFieldsContainer');
    const authLoginUrl = document.getElementById('authLoginUrl');
    const authUsername = document.getElementById('authUsername');
    const authPassword = document.getElementById('authPassword');

    // =========================================================================
    // DOM Elements - Guia 2: Status da Varredura
    // =========================================================================
    const noActiveScanBox = document.getElementById('noActiveScanBox');
    const activeScanPanel = document.getElementById('activeScanPanel');
    const scanStatusBadge = document.getElementById('scanStatusBadge');
    const scanTargetDisplay = document.getElementById('scanTargetDisplay');
    const scanTimeDisplay = document.getElementById('scanTimeDisplay');
    const stopScanBtn = document.getElementById('stopScanBtn');
    const liveProgressWrapper = document.getElementById('liveProgressWrapper');
    const currentCrawlingUrl = document.getElementById('currentCrawlingUrl');

    const kpiPagesScanned = document.getElementById('kpiPagesScanned');
    const kpiCriticalCount = document.getElementById('kpiCriticalCount');
    const kpiHighCount = document.getElementById('kpiHighCount');
    const kpiSecretsFound = document.getElementById('kpiSecretsFound');
    const realtimeSecretsBadge = document.getElementById('realtimeSecretsBadge');

    const findingsTableBody = document.getElementById('findingsTableBody');
    const emptyFindingsRow = document.getElementById('emptyFindingsRow');
    const statusExportJsonBtn = document.getElementById('statusExportJsonBtn');
    const statusExportCsvBtn = document.getElementById('statusExportCsvBtn');

    // Auth Alert Boxes
    const authAlertBox = document.getElementById('authAlertBox');
    const authAlertMessage = document.getElementById('authAlertMessage');
    const authSuccessBox = document.getElementById('authSuccessBox');
    const authSuccessMessage = document.getElementById('authSuccessMessage');

    // =========================================================================
    // DOM Elements - Guia 3: Histórico & Detalhes Inline
    // =========================================================================
    const historyTableBody = document.getElementById('historyTableBody');
    const historyDetailsPanel = document.getElementById('historyDetailsPanel');
    const detailScanId = document.getElementById('detailScanId');
    const detailScanTarget = document.getElementById('detailScanTarget');
    const detailScanMeta = document.getElementById('detailScanMeta');
    const detailAuthAlertBox = document.getElementById('detailAuthAlertBox');
    const detailAuthAlertMsg = document.getElementById('detailAuthAlertMsg');
    const detailAuthSuccessBox = document.getElementById('detailAuthSuccessBox');
    const historyDetailsTableBody = document.getElementById('historyDetailsTableBody');
    const historyExportJsonBtn = document.getElementById('historyExportJsonBtn');
    const historyExportCsvBtn = document.getElementById('historyExportCsvBtn');
    const closeHistoryDetailsBtn = document.getElementById('closeHistoryDetailsBtn');

    // =========================================================================
    // DOM Elements - Modal de Detalhes do Segredo
    // =========================================================================
    const snippetModal = document.getElementById('snippetModal');
    const modalUrl = document.getElementById('modalUrl');
    const modalSnippet = document.getElementById('modalSnippet');
    const modalRawSecretBox = document.getElementById('modalRawSecretBox');
    const modalRawSecretVal = document.getElementById('modalRawSecretVal');
    const modalCopySecretBtn = document.getElementById('modalCopySecretBtn');
    const closeModalBtn = document.getElementById('closeModalBtn');
    const modalCloseActionBtn = document.getElementById('modalCloseActionBtn');

    // =========================================================================
    // Lógica do Menu de Guias
    // =========================================================================
    function switchTab(tabName) {
        // Desativa todos os botões e conteúdos
        tabVarreduraBtn.classList.remove('active');
        tabStatusBtn.classList.remove('active');
        tabHistoricoBtn.classList.remove('active');

        tabVarreduraContent.classList.add('hidden');
        tabStatusContent.classList.add('hidden');
        tabHistoricoContent.classList.add('hidden');
        historyActionWrapper.classList.add('hidden');

        if (tabName === 'varredura') {
            tabVarreduraBtn.classList.add('active');
            tabVarreduraContent.classList.remove('hidden');
        } else if (tabName === 'status') {
            tabStatusBtn.classList.add('active');
            tabStatusContent.classList.remove('hidden');
        } else if (tabName === 'historico') {
            tabHistoricoBtn.classList.add('active');
            tabHistoricoContent.classList.remove('hidden');
            historyActionWrapper.classList.remove('hidden');
            loadScanHistory();
        }
    }

    tabVarreduraBtn.addEventListener('click', () => switchTab('varredura'));
    tabStatusBtn.addEventListener('click', () => switchTab('status'));
    tabHistoricoBtn.addEventListener('click', () => switchTab('historico'));
    if (goToVarreduraBtn) {
        goToVarreduraBtn.addEventListener('click', () => switchTab('varredura'));
    }

    // Toggle de Autenticação Opcional
    if (authToggle && authFieldsContainer) {
        authToggle.addEventListener('change', () => {
            if (authToggle.checked) {
                authFieldsContainer.classList.remove('hidden');
            } else {
                authFieldsContainer.classList.add('hidden');
            }
        });
    }

    // =========================================================================
    // Criação de Badges e Elementos de Tabela
    // =========================================================================
    function createSeverityBadge(severity) {
        const span = document.createElement('span');
        const sevUpper = (severity || 'HIGH').toUpperCase();
        
        let icon = '🟡';
        let className = 'badge-medium';

        if (sevUpper === 'CRITICAL') {
            icon = '🔴';
            className = 'badge-critical';
        } else if (sevUpper === 'HIGH') {
            icon = '🟠';
            className = 'badge-high';
        } else if (sevUpper === 'LOW') {
            icon = '🔵';
            className = 'badge-low';
        }

        span.className = className;
        span.textContent = `${icon} ${sevUpper}`;
        return span;
    }

    function createSourceBadge(sourceType) {
        const span = document.createElement('span');
        span.textContent = sourceType || 'DOM';
        span.className = 'badge-source';
        return span;
    }

    function createFindingRow(finding) {
        const tr = document.createElement('tr');

        // 1. Severidade
        const tdSev = document.createElement('td');
        tdSev.appendChild(createSeverityBadge(finding.severity));
        tr.appendChild(tdSev);

        // 2. Tipo & Valor Mascarado (com botão Revelar / Ocultar)
        const tdSecret = document.createElement('td');
        const titleDiv = document.createElement('div');
        titleDiv.className = 'font-bold text-white text-sm';
        titleDiv.textContent = finding.secret_type || 'Chave Detectada';

        const valCapsule = document.createElement('div');
        valCapsule.className = 'secret-capsule mt-1';

        const valSpan = document.createElement('span');
        valSpan.className = 'text-xs font-mono text-amber select-all';
        valSpan.textContent = finding.masked_value || '****';
        valCapsule.appendChild(valSpan);

        if (finding.raw_value) {
            let isRevealed = false;
            const revealBtn = document.createElement('button');
            revealBtn.type = 'button';
            revealBtn.className = 'btn-secondary';
            revealBtn.style.padding = '0.2rem 0.5rem';
            revealBtn.style.fontSize = '0.75rem';
            revealBtn.textContent = '👁️ Revelar';
            revealBtn.title = 'Apenas exibir em tela o valor completo';

            revealBtn.addEventListener('click', () => {
                isRevealed = !isRevealed;
                if (isRevealed) {
                    valSpan.textContent = finding.raw_value;
                    valSpan.className = 'text-xs font-mono text-rose font-bold select-all';
                    revealBtn.textContent = '🔒 Ocultar';
                } else {
                    valSpan.textContent = finding.masked_value;
                    valSpan.className = 'text-xs font-mono text-amber select-all';
                    revealBtn.textContent = '👁️ Revelar';
                }
            });
            valCapsule.appendChild(revealBtn);
        }

        tdSecret.appendChild(titleDiv);
        tdSecret.appendChild(valCapsule);
        tr.appendChild(tdSecret);

        // 3. Localização (URL)
        const tdUrl = document.createElement('td');
        tdUrl.className = 'text-xs font-mono text-sky truncate';
        tdUrl.style.maxWidth = '260px';
        tdUrl.textContent = finding.url || '';
        tdUrl.setAttribute('title', finding.url || '');
        tr.appendChild(tdUrl);

        // 4. Origem
        const tdSrc = document.createElement('td');
        tdSrc.appendChild(createSourceBadge(finding.source_type));
        tr.appendChild(tdSrc);

        // 5. Ação
        const tdAct = document.createElement('td');
        tdAct.style.textAlign = 'right';
        const viewBtn = document.createElement('button');
        viewBtn.type = 'button';
        viewBtn.className = 'btn-secondary';
        viewBtn.textContent = '🔍 Detalhes';
        viewBtn.addEventListener('click', () => {
            showSnippetModal(finding.url, finding.context_snippet, finding.raw_value);
        });
        tdAct.appendChild(viewBtn);
        tr.appendChild(tdAct);

        return tr;
    }

    // =========================================================================
    // Modal de Detalhes do Trecho do Código
    // =========================================================================
    function showSnippetModal(url, snippet, rawValue) {
        modalUrl.textContent = url || 'N/A';
        modalSnippet.textContent = snippet || 'Nenhum trecho de contexto adicional disponível.';
        if (rawValue && modalRawSecretBox && modalRawSecretVal) {
            modalRawSecretVal.value = rawValue;
            modalRawSecretBox.classList.remove('hidden');
        } else if (modalRawSecretBox) {
            modalRawSecretBox.classList.add('hidden');
        }
        snippetModal.classList.remove('hidden');
    }

    function hideSnippetModal() {
        snippetModal.classList.add('hidden');
    }

    closeModalBtn.addEventListener('click', hideSnippetModal);
    modalCloseActionBtn.addEventListener('click', hideSnippetModal);
    snippetModal.addEventListener('click', (e) => {
        if (e.target === snippetModal) hideSnippetModal();
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && !snippetModal.classList.contains('hidden')) {
            hideSnippetModal();
        }
    });

    if (modalCopySecretBtn && modalRawSecretVal) {
        modalCopySecretBtn.addEventListener('click', async () => {
            if (modalRawSecretVal.value) {
                try {
                    await navigator.clipboard.writeText(modalRawSecretVal.value);
                    const orig = modalCopySecretBtn.textContent;
                    modalCopySecretBtn.textContent = 'Copiado!';
                    setTimeout(() => { modalCopySecretBtn.textContent = orig; }, 2000);
                } catch (e) {
                    modalRawSecretVal.select();
                }
            }
        });
    }

    // =========================================================================
    // Gerenciador de Status da Varredura (Guia 2)
    // =========================================================================
    function updateStatusUI(status, targetUrl = null, pagesScanned = 0, secretsFound = 0, authStatus = null, authMessage = null) {
        const norm = (status || 'idle').toLowerCase();

        if (targetUrl) {
            scanTargetDisplay.textContent = targetUrl;
        }

        kpiPagesScanned.textContent = String(pagesScanned);
        kpiSecretsFound.textContent = String(secretsFound);
        realtimeSecretsBadge.textContent = String(secretsFound);

        let crit = 0;
        let high = 0;
        for (const f of currentFindings) {
            const s = (f.severity || '').toUpperCase();
            if (s === 'CRITICAL') crit++;
            else if (s === 'HIGH') high++;
        }
        kpiCriticalCount.textContent = String(crit);
        kpiHighCount.textContent = String(high);

        // Alertas de Autenticação
        if (authAlertBox && authSuccessBox && authStatus !== undefined) {
            if (authStatus === 'failed') {
                authAlertBox.classList.remove('hidden');
                authSuccessBox.classList.add('hidden');
                if (authAlertMessage) {
                    authAlertMessage.textContent = authMessage || 'Atenção: A autenticação com usuário e senha fornecidos falhou no site.';
                }
            } else if (authStatus === 'success') {
                authSuccessBox.classList.remove('hidden');
                authAlertBox.classList.add('hidden');
                if (authSuccessMessage) {
                    authSuccessMessage.textContent = authMessage || 'Sessão autenticada com sucesso! Varredura acessando áreas restritas.';
                }
            } else if (authStatus === 'authenticating') {
                authAlertBox.classList.add('hidden');
                authSuccessBox.classList.add('hidden');
            } else if (!authStatus) {
                authAlertBox.classList.add('hidden');
                authSuccessBox.classList.add('hidden');
            }
        }

        if (norm === 'running' || norm === 'scanning') {
            isScanRunning = true;
            noActiveScanBox.classList.add('hidden');
            activeScanPanel.classList.remove('hidden');
            statusLiveIndicator.classList.remove('hidden');
            stopScanBtn.classList.remove('hidden');
            liveProgressWrapper.classList.remove('hidden');

            scanStatusBadge.className = 'status-badge status-running';
            scanStatusBadge.textContent = 'Executando';
            scanTimeDisplay.textContent = 'Varredura ativa rastreando aplicação...';

        } else if (norm === 'completed') {
            isScanRunning = false;
            noActiveScanBox.classList.add('hidden');
            activeScanPanel.classList.remove('hidden');
            statusLiveIndicator.classList.add('hidden');
            stopScanBtn.classList.add('hidden');
            liveProgressWrapper.classList.add('hidden');

            scanStatusBadge.className = 'status-badge status-completed';
            scanStatusBadge.textContent = 'Concluído';
            scanTimeDisplay.textContent = `Varredura finalizada. ${pagesScanned} páginas analisadas.`;

        } else if (norm === 'cancelled') {
            isScanRunning = false;
            noActiveScanBox.classList.add('hidden');
            activeScanPanel.classList.remove('hidden');
            statusLiveIndicator.classList.add('hidden');
            stopScanBtn.classList.add('hidden');
            liveProgressWrapper.classList.add('hidden');

            scanStatusBadge.className = 'status-badge status-cancelled';
            scanStatusBadge.textContent = 'Interrompido';
            scanTimeDisplay.textContent = 'A varredura foi cancelada pelo usuário.';

        } else if (norm === 'failed') {
            isScanRunning = false;
            noActiveScanBox.classList.add('hidden');
            activeScanPanel.classList.remove('hidden');
            statusLiveIndicator.classList.add('hidden');
            stopScanBtn.classList.add('hidden');
            liveProgressWrapper.classList.add('hidden');

            scanStatusBadge.className = 'status-badge status-failed';
            scanStatusBadge.textContent = 'Falhou';
            scanTimeDisplay.textContent = 'Falha ao acessar o alvo ou inicializar o Playwright.';

        } else {
            isScanRunning = false;
            statusLiveIndicator.classList.add('hidden');
            if (!activeScanId) {
                noActiveScanBox.classList.remove('hidden');
                activeScanPanel.classList.add('hidden');
            }
        }
    }

    // =========================================================================
    // Disparo da Varredura (Guia 1)
    // =========================================================================
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const targetUrl = targetUrlInput.value.trim();
        const maxDepth = parseInt(maxDepthInput.value, 10);
        const maxPages = parseInt(maxPagesInput.value, 10);

        if (!targetUrl) return;

        const authEnabled = authToggle ? authToggle.checked : false;
        const authUser = authUsername ? authUsername.value.trim() : null;
        const authPass = authPassword ? authPassword.value : null;
        const authUrl = authLoginUrl ? authLoginUrl.value.trim() : null;

        startScanBtn.disabled = true;

        try {
            const res = await fetch('/api/scans', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target_url: targetUrl,
                    max_depth: maxDepth,
                    max_pages: maxPages,
                    auth_enabled: authEnabled,
                    auth_username: authUser || null,
                    auth_password: authPass || null,
                    auth_login_url: authUrl || null
                })
            });

            // Apaga senha volátil do campo cliente
            if (authPassword) authPassword.value = '';

            if (!res.ok) {
                const errData = await res.json();
                alert(errData.detail || 'Falha ao iniciar varredura.');
                return;
            }

            const scan = await res.json();
            activeScanId = scan.id;
            currentFindings = [];
            findingsTableBody.replaceChildren();

            // Alterna imediatamente para a Guia "Status da varredura" para acompanhar
            switchTab('status');
            updateStatusUI('running', scan.target_url, 0, 0);

        } catch (err) {
            console.error('Erro ao iniciar varredura:', err);
            alert('Erro de conexão ao iniciar varredura.');
        } finally {
            startScanBtn.disabled = false;
        }
    });

    // Interromper varredura
    stopScanBtn.addEventListener('click', async () => {
        stopScanBtn.disabled = true;
        try {
            await fetch('/api/scans/active/stop', { method: 'POST' });
            updateStatusUI('cancelled');
        } catch (err) {
            console.error('Erro ao interromper varredura:', err);
        } finally {
            stopScanBtn.disabled = false;
        }
    });

    // =========================================================================
    // SSE Stream em Tempo Real
    // =========================================================================
    function initEventStream() {
        if (sseSource) sseSource.close();

        try {
            sseSource = new EventSource('/api/stream');

            sseSource.addEventListener('scan_started', (e) => {
                const data = JSON.parse(e.data);
                activeScanId = data.data.scan_id;
                currentFindings = [];
                findingsTableBody.replaceChildren();
                updateStatusUI('running', data.data.target_url, 0, 0, null, null);
                loadScanHistory();
            });

            sseSource.addEventListener('scan_progress', (e) => {
                const prog = JSON.parse(e.data).data;
                currentCrawlingUrl.textContent = prog.current_url || '';
                updateStatusUI(prog.status, null, prog.pages_scanned, prog.secrets_found, prog.auth_status, prog.auth_message);
            });

            sseSource.addEventListener('secret_found', (e) => {
                const finding = JSON.parse(e.data).data;
                currentFindings.push(finding);

                if (emptyFindingsRow && emptyFindingsRow.parentNode) {
                    emptyFindingsRow.remove();
                }

                const row = createFindingRow(finding);
                findingsTableBody.prepend(row);
                updateStatusUI('running', null, parseInt(kpiPagesScanned.textContent, 10), currentFindings.length);
            });

            sseSource.addEventListener('scan_finished', (e) => {
                const fin = JSON.parse(e.data).data;
                updateStatusUI(fin.status, null, fin.pages_scanned, fin.secrets_found, fin.auth_status, fin.auth_message);
                loadScanHistory();
            });

            sseSource.onerror = () => {
                setTimeout(initEventStream, 5000);
            };
        } catch (err) {
            console.warn('SSE fallback ativo.');
        }
    }

    // =========================================================================
    // Guia 3: Histórico de Varreduras & Detalhes Inline
    // =========================================================================
    async function loadScanHistory() {
        try {
            const res = await fetch('/api/scans?limit=50');
            if (!res.ok) return;
            const scans = await res.json();
            
            if (historyCountBadge) {
                historyCountBadge.textContent = String(scans.length);
            }

            historyTableBody.replaceChildren();

            if (scans.length === 0) {
                const tr = document.createElement('tr');
                const td = document.createElement('td');
                td.setAttribute('colspan', '7');
                td.style.padding = '2rem';
                td.style.textAlign = 'center';
                td.style.color = '#94a3b8';
                td.textContent = 'Nenhuma varredura anterior registrada.';
                tr.appendChild(td);
                historyTableBody.appendChild(tr);
                return;
            }

            for (const scan of scans) {
                const tr = document.createElement('tr');
                tr.setAttribute('data-scan-id', String(scan.id));
                if (selectedHistoryScanId === scan.id) {
                    tr.classList.add('selected-row');
                }

                // ID
                const tdId = document.createElement('td');
                tdId.className = 'text-xs font-mono text-muted';
                tdId.textContent = `#${scan.id}`;
                tr.appendChild(tdId);

                // Aplicação
                const tdDom = document.createElement('td');
                tdDom.className = 'font-bold text-white truncate';
                tdDom.style.maxWidth = '240px';
                
                const domainSpan = document.createElement('span');
                domainSpan.textContent = scan.domain || scan.target_url;
                tdDom.appendChild(domainSpan);

                if (scan.auth_status === 'failed') {
                    const authFailBadge = document.createElement('span');
                    authFailBadge.className = 'badge-critical';
                    authFailBadge.style.fontSize = '0.7rem';
                    authFailBadge.style.padding = '0.15rem 0.45rem';
                    authFailBadge.style.marginLeft = '0.5rem';
                    authFailBadge.textContent = '⚠️ Login Falhou';
                    authFailBadge.title = scan.auth_message || 'As credenciais fornecidas não foram aceitas pelo site.';
                    tdDom.appendChild(authFailBadge);
                } else if (scan.auth_status === 'success') {
                    const authOkBadge = document.createElement('span');
                    authOkBadge.className = 'badge-low';
                    authOkBadge.style.fontSize = '0.7rem';
                    authOkBadge.style.padding = '0.15rem 0.45rem';
                    authOkBadge.style.marginLeft = '0.5rem';
                    authOkBadge.textContent = '🔐 Autenticado';
                    authOkBadge.title = 'Varredura realizada com sessão autenticada';
                    tdDom.appendChild(authOkBadge);
                }
                tr.appendChild(tdDom);

                // Status
                const tdStat = document.createElement('td');
                const badge = document.createElement('span');
                badge.textContent = (scan.status || 'DONE').toUpperCase();
                badge.className = scan.status === 'completed'
                    ? (scan.secrets_count > 0 ? 'badge-critical' : 'badge-low')
                    : (scan.status === 'running' ? 'badge-high' : 'badge-medium');
                tdStat.appendChild(badge);
                tr.appendChild(tdStat);

                // Páginas
                const tdPages = document.createElement('td');
                tdPages.className = 'text-xs font-mono text-secondary';
                tdPages.textContent = String(scan.pages_scanned);
                tr.appendChild(tdPages);

                // Segredos
                const tdSec = document.createElement('td');
                tdSec.className = 'text-xs font-mono font-bold ' + (scan.secrets_count > 0 ? 'text-rose' : 'text-muted');
                tdSec.textContent = String(scan.secrets_count);
                tr.appendChild(tdSec);

                // Data/Hora
                const tdDate = document.createElement('td');
                tdDate.className = 'text-xs text-muted';
                const dt = new Date(scan.started_at);
                tdDate.textContent = dt.toLocaleString('pt-BR');
                tr.appendChild(tdDate);

                // Ação: Visualizar detalhes inline
                const tdAct = document.createElement('td');
                tdAct.style.textAlign = 'right';
                const viewBtn = document.createElement('button');
                viewBtn.type = 'button';
                viewBtn.className = 'btn-secondary';
                viewBtn.textContent = '👁️ Visualizar';
                viewBtn.title = 'Abrir detalhes e segredos desta análise logo abaixo';
                viewBtn.addEventListener('click', () => {
                    openHistoryScanDetails(scan.id);
                });
                tdAct.appendChild(viewBtn);
                tr.appendChild(tdAct);

                historyTableBody.appendChild(tr);
            }
        } catch (err) {
            console.error('Falha ao carregar histórico:', err);
        }
    }

    // Abrir detalhes inline logo abaixo da tabela de histórico
    async function openHistoryScanDetails(scanId) {
        selectedHistoryScanId = scanId;

        // Destaca a linha selecionada na tabela
        const allRows = historyTableBody.querySelectorAll('tr');
        allRows.forEach(r => {
            if (r.getAttribute('data-scan-id') === String(scanId)) {
                r.classList.add('selected-row');
            } else {
                r.classList.remove('selected-row');
            }
        });

        historyDetailsPanel.classList.remove('hidden');
        historyDetailsTableBody.replaceChildren();

        if (detailAuthAlertBox) detailAuthAlertBox.classList.add('hidden');
        if (detailAuthSuccessBox) detailAuthSuccessBox.classList.add('hidden');

        const loadingTr = document.createElement('tr');
        const loadingTd = document.createElement('td');
        loadingTd.setAttribute('colspan', '5');
        loadingTd.style.padding = '2rem';
        loadingTd.style.textAlign = 'center';
        loadingTd.style.color = '#94a3b8';
        loadingTd.textContent = 'Carregando segredos da varredura #' + scanId + '...';
        loadingTr.appendChild(loadingTd);
        historyDetailsTableBody.appendChild(loadingTr);

        try {
            const res = await fetch(`/api/scans/${scanId}`);
            if (!res.ok) return;
            const scan = await res.json();

            detailScanId.textContent = `Varredura #${scan.id}`;
            detailScanTarget.textContent = scan.target_url;
            detailScanMeta.textContent = `${scan.pages_scanned} páginas analisadas • ${scan.secrets_count} segredos encontrados • Status: ${scan.status.toUpperCase()}`;

            if (detailAuthAlertBox && detailAuthSuccessBox) {
                if (scan.auth_status === 'failed') {
                    detailAuthAlertBox.classList.remove('hidden');
                    detailAuthSuccessBox.classList.add('hidden');
                    if (detailAuthAlertMsg) {
                        detailAuthAlertMsg.textContent = scan.auth_message || '⚠️ Atenção: A autenticação com usuário e senha falhou nesta varredura.';
                    }
                } else if (scan.auth_status === 'success') {
                    detailAuthSuccessBox.classList.remove('hidden');
                    detailAuthAlertBox.classList.add('hidden');
                } else {
                    detailAuthAlertBox.classList.add('hidden');
                    detailAuthSuccessBox.classList.add('hidden');
                }
            }

            historyDetailsTableBody.replaceChildren();

            const findings = scan.findings || [];
            if (findings.length === 0) {
                const emptyTr = document.createElement('tr');
                const emptyTd = document.createElement('td');
                emptyTd.setAttribute('colspan', '5');
                emptyTd.style.padding = '2.5rem';
                emptyTd.style.textAlign = 'center';
                emptyTd.style.color = '#34d399';
                emptyTd.textContent = '✓ Nenhum segredo ou credencial foi exposto nesta varredura.';
                emptyTr.appendChild(emptyTd);
                historyDetailsTableBody.appendChild(emptyTr);
            } else {
                for (const f of findings) {
                    const row = createFindingRow(f);
                    historyDetailsTableBody.appendChild(row);
                }
            }

            // Scroll suave até o painel de detalhes
            historyDetailsPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

        } catch (err) {
            console.error('Erro ao buscar detalhes da varredura:', err);
        }
    }

    if (closeHistoryDetailsBtn) {
        closeHistoryDetailsBtn.addEventListener('click', () => {
            historyDetailsPanel.classList.add('hidden');
            if (detailAuthAlertBox) detailAuthAlertBox.classList.add('hidden');
            if (detailAuthSuccessBox) detailAuthSuccessBox.classList.add('hidden');
            selectedHistoryScanId = null;
            const allRows = historyTableBody.querySelectorAll('tr');
            allRows.forEach(r => r.classList.remove('selected-row'));
        });
    }

    // Limpar Histórico
    if (clearHistoryBtn) {
        clearHistoryBtn.addEventListener('click', async () => {
            if (isScanRunning) {
                alert('Não é possível limpar o histórico durante uma varredura em andamento.');
                return;
            }
            if (!confirm('Deseja realmente limpar todas as varreduras anteriores do banco de dados local?')) {
                return;
            }

            clearHistoryBtn.disabled = true;
            try {
                const res = await fetch('/api/scans/clear', { method: 'POST' });
                if (res.ok) {
                    activeScanId = null;
                    selectedHistoryScanId = null;
                    currentFindings = [];
                    findingsTableBody.replaceChildren();
                    historyDetailsPanel.classList.add('hidden');
                    updateStatusUI('idle', null, 0, 0);
                    await loadScanHistory();
                }
            } catch (err) {
                console.error('Erro ao limpar histórico:', err);
            } finally {
                clearHistoryBtn.disabled = false;
            }
        });
    }

    // Exportações da Guia Status
    if (statusExportJsonBtn) {
        statusExportJsonBtn.addEventListener('click', () => {
            if (!activeScanId) return;
            window.location.href = `/api/scans/${activeScanId}/export?format=json`;
        });
    }
    if (statusExportCsvBtn) {
        statusExportCsvBtn.addEventListener('click', () => {
            if (!activeScanId) return;
            window.location.href = `/api/scans/${activeScanId}/export?format=csv`;
        });
    }

    // Exportações da Guia Histórico
    if (historyExportJsonBtn) {
        historyExportJsonBtn.addEventListener('click', () => {
            if (!selectedHistoryScanId) return;
            window.location.href = `/api/scans/${selectedHistoryScanId}/export?format=json`;
        });
    }
    if (historyExportCsvBtn) {
        historyExportCsvBtn.addEventListener('click', () => {
            if (!selectedHistoryScanId) return;
            window.location.href = `/api/scans/${selectedHistoryScanId}/export?format=csv`;
        });
    }

    // =========================================================================
    // Inicialização da Aplicação
    // =========================================================================
    async function init() {
        initEventStream();
        await loadScanHistory();

        // Verifica se há varredura ativa ou recente para preencher a aba de status
        try {
            const res = await fetch('/api/scans/active');
            if (res.ok) {
                const activeData = await res.json();
                if (activeData.is_active && activeData.scan) {
                    activeScanId = activeData.scan.id;
                    currentFindings = activeData.scan.findings || [];
                    findingsTableBody.replaceChildren();
                    if (currentFindings.length > 0) {
                        for (const f of currentFindings) {
                            findingsTableBody.appendChild(createFindingRow(f));
                        }
                    }
                    updateStatusUI(
                        activeData.scan.status,
                        activeData.scan.target_url,
                        activeData.scan.pages_scanned,
                        activeData.scan.secrets_count,
                        activeData.scan.auth_status,
                        activeData.scan.auth_message
                    );
                    // Se estiver rodando agora, leva o usuário direto para a aba de status
                    switchTab('status');
                } else if (activeData.scan) {
                    activeScanId = activeData.scan.id;
                    currentFindings = activeData.scan.findings || [];
                    findingsTableBody.replaceChildren();
                    if (currentFindings.length > 0) {
                        for (const f of currentFindings) {
                            findingsTableBody.appendChild(createFindingRow(f));
                        }
                    }
                    updateStatusUI(
                        activeData.scan.status,
                        activeData.scan.target_url,
                        activeData.scan.pages_scanned,
                        activeData.scan.secrets_count,
                        activeData.scan.auth_status,
                        activeData.scan.auth_message
                    );
                } else {
                    updateStatusUI('idle');
                }
            }
        } catch (err) {
            console.error('Erro na inicialização:', err);
            updateStatusUI('idle');
        }
    }

    document.addEventListener('DOMContentLoaded', init);
})();

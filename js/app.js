/**
 * Main application controller.
 * Orchestrates upload → config → processing → download flow.
 */

(function () {
  'use strict';

  // ── State ──────────────────────────────────────────────────────────
  let currentFile        = null;
  let extractedText      = '';
  let anonymizedText     = '';
  let currentStep        = 1;
  let sourceIsPdf        = false;
  let sourceIsDigitalPdf = false;
  let processingComplete = false;
  let allMatches         = [];
  let excludedMatchIds   = new Set();

  // ── Element shortcuts ──────────────────────────────────────────────
  const $ = id => document.getElementById(id);

  const steps = {
    1: $('step-upload'),
    2: $('step-config'),
    3: $('step-preview'),
    4: $('step-download'),
  };

  const btnNext    = $('btn-next');
  const btnBack    = $('btn-back');
  const btnProcess = $('btn-process');
  const btnConfirm = $('btn-confirm');
  const btnNew     = $('btn-new');

  // ── File type helpers ──────────────────────────────────────────────
  function getExt(name) { return name.split('.').pop().toLowerCase(); }

  function getFileIconLabel(ext) {
    return { pdf: 'PDF', docx: 'DOC', rtf: 'RTF', txt: 'TXT',
             jpg: 'IMG', jpeg: 'IMG', png: 'IMG', gif: 'IMG', webp: 'IMG' }[ext] || 'DOC';
  }

  function getFileIconClass(ext) {
    if (ext === 'pdf')  return 'pdf';
    if (ext === 'docx') return 'docx';
    if (ext === 'rtf')  return 'rtf';
    if (['jpg','jpeg','png','gif','webp'].includes(ext)) return 'img';
    return 'txt';
  }

  function formatBytes(bytes) {
    if (bytes < 1024)        return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }

  // ── Dark mode ──────────────────────────────────────────────────────
  function applyTheme(dark) {
    document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
    const sunEl  = $('icon-sun');
    const moonEl = $('icon-moon');
    if (sunEl)  sunEl.classList.toggle('hidden', dark);
    if (moonEl) moonEl.classList.toggle('hidden', !dark);
    localStorage.setItem('anon-theme', dark ? 'dark' : 'light');
  }

  $('btn-theme').addEventListener('click', () => {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    applyTheme(!isDark);
  });

  // Restore theme on load
  applyTheme(localStorage.getItem('anon-theme') === 'dark');

  // ── Session history (persist toggle states) ────────────────────────
  const SETTING_KEYS = [
    'chk-names','chk-company','chk-dni','chk-cuil','chk-rfc','chk-rut',
    'chk-passport','chk-phone','chk-email','chk-address','chk-dates',
    'chk-iban','chk-ss','chk-plate','chk-ip','chk-coords','chk-redact-images',
    'chk-receta','chk-sexo','chk-matricula',
  ];

  function saveSettings() {
    try {
      const s = { mode: document.querySelector('input[name="mode"]:checked')?.value || 'label', checks: {} };
      for (const id of SETTING_KEYS) { s.checks[id] = $(id)?.checked ?? true; }
      localStorage.setItem('anon-settings', JSON.stringify(s));
    } catch (_) {}
  }

  function loadSettings() {
    try {
      const raw = localStorage.getItem('anon-settings');
      if (!raw) return;
      const s = JSON.parse(raw);
      if (s.mode) {
        const r = document.querySelector(`input[name="mode"][value="${s.mode}"]`);
        if (r) r.checked = true;
      }
      for (const [id, val] of Object.entries(s.checks || {})) {
        const el = $(id);
        if (el) el.checked = val;
      }
    } catch (_) {}
  }

  // Attach change listeners to all toggles/radios for auto-save
  for (const id of SETTING_KEYS) {
    $(id)?.addEventListener('change', saveSettings);
  }
  document.querySelectorAll('input[name="mode"]').forEach(r => r.addEventListener('change', saveSettings));

  loadSettings();

  // ── Export / Import configuration ──────────────────────────────────
  function exportConfig() {
    const opts = getOptions();
    const cfg = {
      version: 1,
      mode: opts.mode,
      enabled: opts.enabled,
      redactImages: opts.redactImages,
      custom: $('custom-terms').value || '',
    };
    const blob = new Blob([JSON.stringify(cfg, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = 'perfil-anonimizacion.json';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 3000);
  }

  function applyConfig(cfg) {
    if (!cfg || cfg.version !== 1) { alert('Perfil no válido o versión incompatible.'); return; }
    if (cfg.mode) {
      const r = document.querySelector(`input[name="mode"][value="${cfg.mode}"]`);
      if (r) r.checked = true;
    }
    // Map enabled keys → checkbox IDs
    const keyToChk = {
      names: 'chk-names', namesCtx: 'chk-names', namesTitleCase: 'chk-names', namesAllCaps: 'chk-names',
      company: 'chk-company',
      dni: 'chk-dni', dniAR: 'chk-dni', nif: 'chk-dni',
      cuil: 'chk-cuil', rfc: 'chk-rfc', rut: 'chk-rut',
      passport: 'chk-passport', phone: 'chk-phone', email: 'chk-email',
      address: 'chk-address', addressCtx: 'chk-address', postcode: 'chk-address',
      birthdate: 'chk-dates', birthdateText: 'chk-dates',
      iban: 'chk-iban', ss: 'chk-ss', plate: 'chk-plate',
      ip: 'chk-ip', coords: 'chk-coords',
      receta: 'chk-receta', sexo: 'chk-sexo', matricula: 'chk-matricula',
    };
    const seen = new Set();
    for (const [key, val] of Object.entries(cfg.enabled || {})) {
      const chkId = keyToChk[key];
      if (chkId && !seen.has(chkId)) {
        seen.add(chkId);
        const el = $(chkId);
        if (el) el.checked = !!val;
      }
    }
    if (cfg.redactImages !== undefined) {
      const el = $('chk-redact-images');
      if (el) el.checked = !!cfg.redactImages;
    }
    if (cfg.custom !== undefined) $('custom-terms').value = cfg.custom;
    saveSettings();
  }

  $('btn-export-config').addEventListener('click', exportConfig);

  $('btn-import-config').addEventListener('click', () => $('import-config-input').click());
  $('import-config-input').addEventListener('change', e => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => {
      try { applyConfig(JSON.parse(ev.target.result)); }
      catch (_) { alert('No se pudo leer el perfil. Asegúrate de que sea un JSON válido.'); }
    };
    reader.readAsText(file);
    e.target.value = '';
  });

  // Preset profiles
  $('btn-preset-medico').addEventListener('click', () => applyConfig({
    version: 1, mode: 'label',
    enabled: {
      names: true, namesCtx: true, namesTitleCase: true, namesAllCaps: true,
      company: false, dni: true, dniAR: true, nif: false, cuil: true,
      rfc: false, rut: false, passport: false, phone: true, email: true,
      address: true, addressCtx: true, postcode: false, birthdate: true, birthdateText: true,
      iban: false, ss: true, plate: false, ip: false, coords: false,
      receta: true, sexo: true, matricula: true,
    },
    redactImages: false, custom: '',
  }));

  $('btn-preset-juridico').addEventListener('click', () => applyConfig({
    version: 1, mode: 'label',
    enabled: {
      names: true, namesCtx: true, namesTitleCase: true, namesAllCaps: true,
      company: true, dni: true, dniAR: true, nif: true, cuil: true,
      rfc: true, rut: true, passport: true, phone: true, email: true,
      address: true, addressCtx: true, postcode: true, birthdate: true, birthdateText: true,
      iban: true, ss: true, plate: true, ip: false, coords: false,
      receta: false, sexo: false, matricula: false,
    },
    redactImages: false, custom: '',
  }));

  // ── Navigation ─────────────────────────────────────────────────────
  function showStep(n) {
    Object.values(steps).forEach(s => s.classList.add('hidden'));
    steps[n].classList.remove('hidden');
    currentStep = n;

    btnBack.classList.toggle('hidden', n === 1 || n === 4);
    btnNext.classList.toggle('hidden', n >= 3);
    btnNext.disabled = (n === 1 && !currentFile);

    if (n === 3) {
      const done = processingComplete;
      btnProcess.classList.toggle('hidden', done);
      btnConfirm.classList.toggle('hidden', !done);
    } else {
      btnProcess.classList.add('hidden');
      btnConfirm.classList.add('hidden');
    }
  }

  btnNext.addEventListener('click', () => showStep(currentStep + 1));
  btnBack.addEventListener('click', () => showStep(currentStep - 1));

  btnNew.addEventListener('click', () => {
    currentFile        = null;
    extractedText      = '';
    anonymizedText     = '';
    sourceIsPdf        = false;
    sourceIsDigitalPdf = false;
    processingComplete = false;
    $('file-input').value = '';
    $('file-info').classList.add('hidden');
    $('drop-zone').classList.remove('hidden');
    $('preview-container').classList.add('hidden');
    $('processing-status').classList.add('hidden');
    $('stats-bar').classList.add('hidden');
    $('confirm-banner').classList.add('hidden');
    $('preview-original').textContent   = '';
    $('preview-anonymized').textContent = '';
    const confEl = $('stat-confidence');
    if (confEl) confEl.classList.add('hidden');
    allMatches       = [];
    excludedMatchIds = new Set();
    btnProcess.disabled = false;
    selectionTooltip.classList.add('hidden');
    showStep(1);
  });

  btnConfirm.addEventListener('click', () => showStep(4));

  // ── File input ─────────────────────────────────────────────────────
  const ALLOWED_EXTS = ['pdf', 'docx', 'rtf', 'txt', 'jpg', 'jpeg', 'png', 'gif', 'webp'];

  function handleFile(file) {
    if (!file) return;
    const ext = getExt(file.name);
    if (!ALLOWED_EXTS.includes(ext)) {
      alert('Formato no soportado. Por favor usa PDF, DOCX, RTF, TXT o imágenes JPG/PNG.');
      return;
    }
    currentFile = file;
    renderFileInfo(file);
    btnNext.disabled = false;
  }

  function renderFileInfo(file) {
    const ext   = getExt(file.name);
    const icon  = $('file-icon');
    icon.textContent = getFileIconLabel(ext);
    icon.className   = `file-icon ${getFileIconClass(ext)}`;
    $('file-name').textContent = file.name;
    $('file-size').textContent = formatBytes(file.size);
    $('file-info').classList.remove('hidden');
    $('drop-zone').classList.add('hidden');
  }

  $('file-input').addEventListener('change', e => handleFile(e.target.files[0]));
  $('btn-remove-file').addEventListener('click', () => {
    currentFile = null;
    $('file-input').value = '';
    $('file-info').classList.add('hidden');
    $('drop-zone').classList.remove('hidden');
    btnNext.disabled = true;
  });

  // Drag & drop
  const dropZone = $('drop-zone');
  dropZone.addEventListener('dragover',  e => { e.preventDefault(); dropZone.classList.add('dragover'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    handleFile(e.dataTransfer.files[0]);
  });

  $('select-link').addEventListener('click', e => {
    e.stopPropagation();
    $('file-input').click();
  });
  dropZone.addEventListener('click', () => $('file-input').click());

  // ── Build options from UI ──────────────────────────────────────────
  function getOptions() {
    const mode = document.querySelector('input[name="mode"]:checked').value;
    const customRaw = $('custom-terms').value || '';
    const custom = customRaw.split('\n').map(s => s.trim()).filter(Boolean);

    const enabled = {
      names:          $('chk-names').checked,
      namesCtx:       $('chk-names').checked,
      namesTitleCase: $('chk-names').checked,
      namesAllCaps:   $('chk-names').checked,
      company:        $('chk-company').checked,
      dni:            $('chk-dni').checked,
      dniAR:          $('chk-dni').checked,
      nif:            $('chk-dni').checked,
      cuil:           $('chk-cuil').checked,
      rfc:            $('chk-rfc').checked,
      rut:            $('chk-rut').checked,
      passport:       $('chk-passport').checked,
      phone:          $('chk-phone').checked,
      email:          $('chk-email').checked,
      address:        $('chk-address').checked,
      addressCtx:     $('chk-address').checked,
      postcode:       $('chk-address').checked,
      birthdate:      $('chk-dates').checked,
      birthdateText:  $('chk-dates').checked,
      iban:           $('chk-iban').checked,
      ss:             $('chk-ss').checked,
      plate:          $('chk-plate').checked,
      ip:             $('chk-ip').checked,
      coords:         $('chk-coords').checked,
      receta:         $('chk-receta').checked,
      sexo:           $('chk-sexo').checked,
      matricula:      $('chk-matricula').checked,
    };

    const redactImages = $('chk-redact-images')?.checked ?? false;
    return { mode, custom, enabled, redactImages };
  }

  // ── Highlight helpers for preview ─────────────────────────────────
  function highlightAnonymized(text) {
    return escapeHtml(text).replace(
      /(\[[\wÁÉÍÓÚÜÑáéíóúüñ\/\s\.]+\]|████████)/g,
      m => `<mark class="highlight-replaced">${m}</mark>`
    );
  }

  function escapeHtml(str) {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  /**
   * Render the original text with each detected PII item wrapped in a clickable
   * <mark> so the user can toggle false-positive exclusions before confirming.
   *
   * Visual states:
   *  • highlight-found    – included (high/medium confidence), click to exclude
   *  • highlight-excluded – manually excluded, click to restore
   *  • highlight-suggestion – low-confidence, auto-excluded by default, click to include
   */
  function renderClickableMatches(text, matches, excludedIds) {
    const sorted = [...matches].sort((a, b) => a.start - b.start);
    const deduped = [];
    let lastEnd = -1;
    for (const m of sorted) {
      if (m.start >= lastEnd) { deduped.push(m); lastEnd = m.end; }
    }

    let html = '';
    let pos  = 0;
    for (const m of deduped) {
      html += escapeHtml(text.slice(pos, m.start));
      const ex  = excludedIds.has(m.id);
      let cls, tip;
      if (ex && m.confidence === 'low') {
        cls = 'highlight-suggestion highlight-pii-click';
        tip = `${m.label} — confianza baja, no activo. Clic para incluir`;
      } else if (ex) {
        cls = 'highlight-excluded highlight-pii-click';
        tip = `${m.label} — excluido (clic para volver a incluir)`;
      } else {
        cls = 'highlight-found highlight-pii-click';
        tip = `${m.label} — clic para marcar como falso positivo`;
      }
      html += `<mark class="${cls}" data-match-id="${m.id}" title="${escapeHtml(tip)}">${escapeHtml(text.slice(m.start, m.end))}</mark>`;
      pos = m.end;
    }
    html += escapeHtml(text.slice(pos));
    return html;
  }

  /** Update the stats bar with a stats object, total count, and confidence breakdown. */
  function renderStats(stats, total, confidenceStats) {
    $('stat-total').textContent = total;
    const breakdown = $('stat-breakdown');
    breakdown.innerHTML = '';
    for (const [label, count] of Object.entries(stats)) {
      const chip = document.createElement('span');
      chip.className = 'stat-chip';
      chip.innerHTML = `<strong>${count}</strong> ${label}`;
      breakdown.appendChild(chip);
    }
    // Confidence breakdown
    const confEl = $('stat-confidence');
    if (confEl && confidenceStats && total > 0) {
      confEl.innerHTML = '';
      const { high = 0, medium = 0, low = 0 } = confidenceStats;
      if (high)   { const s = document.createElement('span'); s.className = 'conf-chip conf-high';   s.textContent = `${high} alta`;                        confEl.appendChild(s); }
      if (medium) { const s = document.createElement('span'); s.className = 'conf-chip conf-medium'; s.textContent = `${medium} media`;                      confEl.appendChild(s); }
      if (low)    { const s = document.createElement('span'); s.className = 'conf-chip conf-low';    s.textContent = `${low} baja — sugerencias (no activas)`; confEl.appendChild(s); }
      confEl.classList.remove('hidden');
    } else if (confEl) {
      confEl.classList.add('hidden');
    }
  }

  // ── Process ────────────────────────────────────────────────────────
  btnProcess.addEventListener('click', async () => {
    const status   = $('processing-status');
    const msgEl    = $('processing-msg');
    const preview  = $('preview-container');
    const statsBar = $('stats-bar');

    status.classList.remove('hidden');
    preview.classList.add('hidden');
    statsBar.classList.add('hidden');
    btnProcess.disabled = true;

    const setMsg = msg => { msgEl.textContent = msg; };

    try {
      // 1. Extract
      setMsg('Extrayendo texto del documento…');
      const extracted = await Extractors.extractText(currentFile, setMsg);
      extractedText      = extracted.text;
      sourceIsPdf        = extracted.isPdf;
      sourceIsDigitalPdf = extracted.isDigitalPdf;

      if (!extractedText.trim()) {
        throw new Error('No se pudo extraer texto del documento. Verifica que no esté protegido.');
      }

      // 2. Detect PII positions
      setMsg('Detectando y anonimizando datos personales…');
      const options = getOptions();
      allMatches = Anonymizer.findMatchPositions(extractedText, options)
        .map((m, i) => ({ ...m, id: i }));
      // Low-confidence matches are opt-in: excluded by default, shown as gray suggestions
      excludedMatchIds = new Set(allMatches.filter(m => m.confidence === 'low').map(m => m.id));
      const { result, stats, total, confidenceStats } = Anonymizer.anonymizeFromPositions(
        extractedText, allMatches, excludedMatchIds, options.mode
      );
      anonymizedText = result;

      // 3. Preview
      $('preview-original').innerHTML  = renderClickableMatches(extractedText, allMatches, excludedMatchIds);
      $('preview-anonymized').innerHTML = highlightAnonymized(anonymizedText);

      // 4. Stats
      renderStats(stats, total, confidenceStats);

      status.classList.add('hidden');
      preview.classList.remove('hidden');
      statsBar.classList.remove('hidden');
      $('confirm-banner').classList.remove('hidden');

      processingComplete = true;
      btnProcess.classList.add('hidden');
      btnConfirm.classList.remove('hidden');

    } catch (err) {
      status.classList.add('hidden');
      alert('Error al procesar el documento:\n' + err.message);
      btnProcess.disabled = false;
    }
  });

  // ── Manual review: toggle false positives by clicking highlighted PII ──────
  $('preview-original').addEventListener('click', e => {
    try {
      const mark = e.target.closest('[data-match-id]');
      if (!mark) return;
      const id = parseInt(mark.dataset.matchId, 10);
      if (isNaN(id)) return;
      if (excludedMatchIds.has(id)) {
        excludedMatchIds.delete(id);
      } else {
        excludedMatchIds.add(id);
      }
      const opts = getOptions();
      $('preview-original').innerHTML = renderClickableMatches(extractedText, allMatches, excludedMatchIds);
      const { result, stats, total, confidenceStats } = Anonymizer.anonymizeFromPositions(
        extractedText, allMatches, excludedMatchIds, opts.mode
      );
      anonymizedText = result;
      $('preview-anonymized').innerHTML = highlightAnonymized(anonymizedText);
      renderStats(stats, total, confidenceStats);
    } catch (err) {
      console.error('Error al excluir dato:', err);
    }
  });

  // ── Manual selection to anonymize ─────────────────────────────────
  const selectionTooltip = $('selection-tooltip');
  const btnAddSelection  = $('btn-add-selection');

  $('preview-original').addEventListener('mouseup', () => {
    if (!processingComplete) return;
    const sel  = window.getSelection();
    const text = sel?.toString().trim();
    if (!text || text.length < 2) {
      selectionTooltip.classList.add('hidden');
      return;
    }
    // Position tooltip near the bottom of the selection
    const range = sel.getRangeAt(0);
    const rect  = range.getBoundingClientRect();
    selectionTooltip.style.top  = `${rect.bottom + 6}px`;
    selectionTooltip.style.left = `${Math.max(4, rect.left)}px`;
    selectionTooltip.dataset.pending = text;
    selectionTooltip.classList.remove('hidden');
  });

  // Hide tooltip when clicking outside it
  document.addEventListener('mousedown', e => {
    if (!selectionTooltip.contains(e.target) && e.target !== selectionTooltip) {
      selectionTooltip.classList.add('hidden');
    }
  });

  btnAddSelection.addEventListener('click', () => {
    const text = selectionTooltip.dataset.pending;
    if (!text) return;
    selectionTooltip.classList.add('hidden');
    window.getSelection()?.removeAllRanges();

    // Append to custom terms textarea
    const customEl = $('custom-terms');
    const existing = customEl.value.trim();
    customEl.value = existing ? existing + '\n' + text : text;

    // Re-run detection with the new custom term
    const opts = getOptions();
    allMatches = Anonymizer.findMatchPositions(extractedText, opts)
      .map((m, i) => ({ ...m, id: i }));
    excludedMatchIds = new Set(allMatches.filter(m => m.confidence === 'low').map(m => m.id));
    const { result, stats, total, confidenceStats } = Anonymizer.anonymizeFromPositions(
      extractedText, allMatches, excludedMatchIds, opts.mode
    );
    anonymizedText = result;
    $('preview-original').innerHTML  = renderClickableMatches(extractedText, allMatches, excludedMatchIds);
    $('preview-anonymized').innerHTML = highlightAnonymized(anonymizedText);
    renderStats(stats, total, confidenceStats);
  });

  // ── Downloads ──────────────────────────────────────────────────────
  function baseName() {
    return (currentFile?.name || 'documento').replace(/\.[^.]+$/, '');
  }

  $('btn-download-txt').addEventListener('click',
    () => Exporters.downloadTxt(anonymizedText, baseName()));

  $('btn-download-docx').addEventListener('click',
    () => Exporters.downloadDocx(anonymizedText, baseName()));

  $('btn-download-pdf').addEventListener('click', () => {
    if (sourceIsDigitalPdf) {
      const opts = getOptions();
      if (excludedMatchIds.size > 0) {
        opts.skipTexts = allMatches
          .filter(m => excludedMatchIds.has(m.id))
          .map(m => extractedText.slice(m.start, m.end).toLowerCase());
      }
      Exporters.downloadPdfRedacted(currentFile, baseName(), opts, anonymizedText);
    } else {
      Exporters.downloadPdf(anonymizedText, baseName());
    }
  });

  // ── Init ──────────────────────────────────────────────────────────
  showStep(1);

})();

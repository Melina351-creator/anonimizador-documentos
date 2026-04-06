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
  let sourceIsPdf        = false;   // original file is a PDF
  let sourceIsDigitalPdf = false;   // PDF has a selectable text layer (not scanned)
  let processingComplete = false;   // true after processing finishes; gates btn-confirm
  let allMatches         = [];      // match positions (with .id) from last findMatchPositions call
  let excludedMatchIds   = new Set(); // match IDs marked as false positives by the user

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
    return { pdf: 'PDF', docx: 'DOC', rtf: 'RTF' }[ext] || 'DOC';
  }

  function formatBytes(bytes) {
    if (bytes < 1024)        return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }

  // ── Navigation ─────────────────────────────────────────────────────
  function showStep(n) {
    Object.values(steps).forEach(s => s.classList.add('hidden'));
    steps[n].classList.remove('hidden');
    currentStep = n;

    btnBack.classList.toggle('hidden', n === 1 || n === 4);
    btnNext.classList.toggle('hidden', n >= 3);
    btnNext.disabled = (n === 1 && !currentFile);

    // Step 3 nav: show either "Procesar" or "Confirmar" depending on processing state
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
    allMatches       = [];
    excludedMatchIds = new Set();
    btnProcess.disabled = false;
    showStep(1);
  });

  btnConfirm.addEventListener('click', () => showStep(4));

  // ── File input ─────────────────────────────────────────────────────
  function handleFile(file) {
    if (!file) return;
    const ext = getExt(file.name);
    if (!['pdf', 'docx', 'rtf'].includes(ext)) {
      alert('Formato no soportado. Por favor usa PDF, DOCX o RTF.');
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
    icon.className   = `file-icon ${ext}`;
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

  // Bug 1: the "selecciona un archivo" span handles its own click and stops propagation
  // so the drop-zone click handler below doesn't also trigger (which would open the dialog twice).
  $('select-link').addEventListener('click', e => {
    e.stopPropagation();
    $('file-input').click();
  });
  // Clicking anywhere else in the drop-zone (icon, formats text, empty area) opens the dialog once.
  dropZone.addEventListener('click', () => $('file-input').click());

  // ── Build options from UI ──────────────────────────────────────────
  function getOptions() {
    const mode = document.querySelector('input[name="mode"]:checked').value;
    const customRaw = $('custom-terms').value || '';
    const custom = customRaw.split('\n').map(s => s.trim()).filter(Boolean);

    const enabled = {
      // Name detection – all sub-patterns share the same toggle
      names:          $('chk-names').checked,
      namesCtx:       $('chk-names').checked,
      namesTitleCase: $('chk-names').checked,
      namesAllCaps:   $('chk-names').checked,
      // Document ID detection
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
      iban:           $('chk-iban').checked,
      ss:             $('chk-ss').checked,
      plate:          $('chk-plate').checked,
      ip:             $('chk-ip').checked,
      coords:         $('chk-coords').checked,
      // Clinical data
      receta:         $('chk-receta').checked,
      sexo:           $('chk-sexo').checked,
      matricula:      $('chk-matricula').checked,
    };

    const redactImages = $('chk-redact-images')?.checked ?? false;
    return { mode, custom, enabled, redactImages };
  }

  // ── Highlight helpers for preview ─────────────────────────────────
  function highlightOriginal(text, options) {
    let html = escapeHtml(text);
    const { PATTERNS } = window.Anonymizer;
    const { enabled } = options;
    for (const [key, { re }] of Object.entries(PATTERNS)) {
      if (enabled[key] === false) continue;
      re.lastIndex = 0;
      html = html.replace(re, m =>
        `<mark class="highlight-found">${escapeHtml(m)}</mark>`
      );
      re.lastIndex = 0;
    }
    return html;
  }

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
   */
  function renderClickableMatches(text, matches, excludedIds) {
    // Deduplicate overlapping positions (first by start wins — same order as replacement)
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
      const cls = ex ? 'highlight-excluded' : 'highlight-found highlight-pii-click';
      const tip = ex
        ? `${m.label} — excluido (clic para volver a incluir)`
        : `${m.label} — clic para marcar como falso positivo`;
      html += `<mark class="${cls}" data-match-id="${m.id}" title="${escapeHtml(tip)}">${escapeHtml(text.slice(m.start, m.end))}</mark>`;
      pos = m.end;
    }
    html += escapeHtml(text.slice(pos));
    return html;
  }

  /** Update the stats bar with a stats object and total count. */
  function renderStats(stats, total) {
    $('stat-total').textContent = total;
    const breakdown = $('stat-breakdown');
    breakdown.innerHTML = '';
    for (const [label, count] of Object.entries(stats)) {
      const chip = document.createElement('span');
      chip.className = 'stat-chip';
      chip.innerHTML = `<strong>${count}</strong> ${label}`;
      breakdown.appendChild(chip);
    }
  }

  // ── Process ────────────────────────────────────────────────────────
  btnProcess.addEventListener('click', async () => {
    const status = $('processing-status');
    const msgEl  = $('processing-msg');
    const preview = $('preview-container');
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

      // 2. Detect PII positions (needed for interactive review + anonymization)
      setMsg('Detectando y anonimizando datos personales…');
      const options = getOptions();
      allMatches = Anonymizer.findMatchPositions(extractedText, options)
        .map((m, i) => ({ ...m, id: i }));
      excludedMatchIds = new Set();
      const { result, stats, total } = Anonymizer.anonymizeFromPositions(
        extractedText, allMatches, excludedMatchIds, options.mode
      );
      anonymizedText = result;

      // 3. Preview – original panel shows clickable PII marks for manual review
      const origEl  = $('preview-original');
      const anonEl  = $('preview-anonymized');
      origEl.innerHTML  = renderClickableMatches(extractedText, allMatches, excludedMatchIds);
      anonEl.innerHTML  = highlightAnonymized(anonymizedText);

      // 4. Stats
      renderStats(stats, total);

      status.classList.add('hidden');
      preview.classList.remove('hidden');
      statsBar.classList.remove('hidden');
      $('confirm-banner').classList.remove('hidden');

      // Bug 3: stay on step 3 so the user can review the preview.
      // Swap "Procesar" for the green "Confirmar y descargar" button.
      processingComplete = true;
      btnProcess.classList.add('hidden');
      btnConfirm.classList.remove('hidden');

    } catch (err) {
      status.classList.add('hidden');
      alert('Error al procesar el documento:\n' + err.message);
      btnProcess.disabled = false;
    }
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
      // Bug 2: redact in-place on the original PDF to preserve layout
      Exporters.downloadPdfRedacted(currentFile, baseName(), getOptions());
    } else {
      // Non-PDF source (DOCX, RTF, OCR): generate text-based PDF
      Exporters.downloadPdf(anonymizedText, baseName());
    }
  });

  // ── Init ──────────────────────────────────────────────────────────
  showStep(1);

})();

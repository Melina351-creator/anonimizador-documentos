/**
 * Main application controller.
 * Orchestrates upload → config → processing → download flow.
 */

(function () {
  'use strict';

  // ── State ──────────────────────────────────────────────────────────
  let currentFile  = null;
  let extractedText = '';
  let anonymizedText = '';
  let currentStep  = 1;

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
    btnProcess.classList.toggle('hidden', n !== 3);
    btnNext.disabled = (n === 1 && !currentFile);
  }

  btnNext.addEventListener('click', () => showStep(currentStep + 1));
  btnBack.addEventListener('click', () => showStep(currentStep - 1));

  btnNew.addEventListener('click', () => {
    currentFile    = null;
    extractedText  = '';
    anonymizedText = '';
    $('file-input').value = '';
    $('file-info').classList.add('hidden');
    $('drop-zone').classList.remove('hidden');
    $('preview-container').classList.add('hidden');
    $('processing-status').classList.add('hidden');
    $('stats-bar').classList.add('hidden');
    $('preview-original').textContent   = '';
    $('preview-anonymized').textContent = '';
    showStep(1);
  });

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
  dropZone.addEventListener('click', () => $('file-input').click());

  // ── Build options from UI ──────────────────────────────────────────
  function getOptions() {
    const mode = document.querySelector('input[name="mode"]:checked').value;
    const customRaw = $('custom-terms').value || '';
    const custom = customRaw.split('\n').map(s => s.trim()).filter(Boolean);

    const enabled = {
      names:    $('chk-names').checked,
      dni:      $('chk-dni').checked,
      nif:      $('chk-dni').checked,       // bundled with DNI toggle
      passport: $('chk-passport').checked,
      phone:    $('chk-phone').checked,
      email:    $('chk-email').checked,
      address:  $('chk-address').checked,
      postcode: $('chk-address').checked,   // bundled
      birthdate:$('chk-dates').checked,
      iban:     $('chk-iban').checked,
      ss:       $('chk-ss').checked,
      plate:    $('chk-plate').checked,
      ip:       $('chk-ip').checked,
      coords:   $('chk-coords').checked,
    };

    return { mode, custom, enabled };
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
      extractedText = await Extractors.extractText(currentFile, setMsg);

      if (!extractedText.trim()) {
        throw new Error('No se pudo extraer texto del documento. Verifica que no esté protegido.');
      }

      // 2. Anonymize
      setMsg('Detectando y anonimizando datos personales…');
      const options = getOptions();
      const { result, stats, total } = Anonymizer.anonymizeText(extractedText, options);
      anonymizedText = result;

      // 3. Preview
      const origEl  = $('preview-original');
      const anonEl  = $('preview-anonymized');
      origEl.innerHTML  = highlightOriginal(extractedText, options);
      anonEl.innerHTML  = highlightAnonymized(anonymizedText);

      // 4. Stats
      $('stat-total').textContent = total;
      const breakdown = $('stat-breakdown');
      breakdown.innerHTML = '';
      for (const [label, count] of Object.entries(stats)) {
        const chip = document.createElement('span');
        chip.className = 'stat-chip';
        chip.innerHTML = `<strong>${count}</strong> ${label}`;
        breakdown.appendChild(chip);
      }

      status.classList.add('hidden');
      preview.classList.remove('hidden');
      statsBar.classList.remove('hidden');

      // Auto-advance to download
      setTimeout(() => showStep(4), 400);

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

  $('btn-download-pdf').addEventListener('click',
    () => Exporters.downloadPdf(anonymizedText, baseName()));

  // ── Init ──────────────────────────────────────────────────────────
  showStep(1);

})();

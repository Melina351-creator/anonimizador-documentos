/**
 * Text extractors for each supported format.
 * All operations run client-side in the browser.
 */

// PDF.js worker
if (typeof pdfjsLib !== 'undefined') {
  pdfjsLib.GlobalWorkerOptions.workerSrc =
    'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
}

/**
 * Read a File as an ArrayBuffer.
 */
function readAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload  = e => resolve(e.target.result);
    reader.onerror = () => reject(new Error('Error al leer el archivo'));
    reader.readAsArrayBuffer(file);
  });
}

/**
 * Read a File as a text string.
 */
function readAsText(file, encoding = 'utf-8') {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload  = e => resolve(e.target.result);
    reader.onerror = () => reject(new Error('Error al leer el archivo'));
    reader.readAsText(file, encoding);
  });
}

/**
 * Extract text from a DOCX file using mammoth.js.
 */
async function extractDocx(file) {
  const buffer = await readAsArrayBuffer(file);

  // Extract main body text with mammoth
  const bodyResult = await mammoth.extractRawText({ arrayBuffer: buffer });
  const bodyText   = bodyResult.value;

  // Also extract text from DOCX header/footer XML via JSZip so that PII
  // embedded in letterheads (names, company data) is also anonymized.
  let headerFooterText = '';
  try {
    const zip = await JSZip.loadAsync(buffer.slice(0));
    const hfTexts = [];
    for (const [path, entry] of Object.entries(zip.files)) {
      if (/^word\/(header|footer)\d*\.xml$/i.test(path)) {
        const xml  = await entry.async('string');
        // Pull text runs from <w:t> elements
        const runs = Array.from(xml.matchAll(/<w:t(?:\s[^>]*)?>([^<]*)<\/w:t>/g), m => m[1]);
        const text = runs.join(' ').trim();
        if (text) hfTexts.push(text);
      }
    }
    if (hfTexts.length) {
      headerFooterText = '\n\n--- Encabezado / Pie de página ---\n' + hfTexts.join('\n');
    }
  } catch (_) {
    // JSZip unavailable or ZIP parse failed – body-only extraction is fine
  }

  return bodyText + headerFooterText;
}

/**
 * Strip RTF control words and return plain text.
 */
async function extractRtf(file) {
  const text = await readAsText(file, 'utf-8');

  // Remove RTF header, control words, and groups
  let plain = text
    .replace(/\{\\rtf[^}]*\}/g, '')                   // RTF header group
    .replace(/\\([a-z]+)(-?\d+)?\*?/gi, ' ')           // control words
    .replace(/\{[^}]*\}/g, ' ')                        // remaining groups
    .replace(/\\\n/g, '\n')                            // line breaks
    .replace(/\\par\b/gi, '\n')
    .replace(/\\line\b/gi, '\n')
    .replace(/\\tab\b/gi, '\t')
    .replace(/\\['"]{1}[0-9a-f]{2}/gi, '')             // hex chars
    .replace(/[{}\\]/g, ' ')
    .replace(/[ \t]{2,}/g, ' ')
    .trim();

  return plain;
}

/**
 * Extract text from a digital (text-layer) PDF using pdf.js.
 * Returns the text and also whether it appears to be scanned (low text density).
 */
async function extractPdfDigital(file) {
  const buffer = await readAsArrayBuffer(file);
  const pdf = await pdfjsLib.getDocument({ data: buffer }).promise;
  const parts = [];

  for (let i = 1; i <= pdf.numPages; i++) {
    const page = await pdf.getPage(i);
    const content = await page.getTextContent();
    const pageText = content.items.map(item => item.str).join(' ');
    parts.push(pageText);
  }

  const fullText = parts.join('\n\n');
  const isScanned = fullText.trim().length < 80 * pdf.numPages; // heuristic
  return { text: fullText, isScanned, numPages: pdf.numPages };
}

/**
 * Extract text from a scanned PDF using Tesseract.js OCR.
 * Renders each page as an image then runs OCR.
 */
async function extractPdfOcr(file, onProgress) {
  const buffer = await readAsArrayBuffer(file);
  const pdf = await pdfjsLib.getDocument({ data: buffer }).promise;
  const parts = [];
  const worker = await Tesseract.createWorker('spa+eng', 1, {
    // silence Tesseract logs
    logger: () => {},
  });

  for (let i = 1; i <= pdf.numPages; i++) {
    if (onProgress) onProgress(`OCR página ${i} de ${pdf.numPages}…`);
    const page = await pdf.getPage(i);
    const viewport = page.getViewport({ scale: 2.0 });
    const canvas = document.createElement('canvas');
    canvas.width  = viewport.width;
    canvas.height = viewport.height;
    const ctx = canvas.getContext('2d');
    await page.render({ canvasContext: ctx, viewport }).promise;
    const dataUrl = canvas.toDataURL('image/png');
    const { data: { text } } = await worker.recognize(dataUrl);
    parts.push(text);
  }

  await worker.terminate();
  return parts.join('\n\n');
}

/**
 * Master extraction function. Selects the right strategy automatically.
 * @param {File} file
 * @param {function} onProgress  – callback(message: string)
 * @returns {Promise<string>}    – extracted plain text
 */
async function extractText(file, onProgress = () => {}) {
  const ext = file.name.split('.').pop().toLowerCase();

  if (ext === 'docx') {
    onProgress('Extrayendo texto del documento Word…');
    const text = await extractDocx(file);
    return { text, isPdf: false, isDigitalPdf: false };
  }

  if (ext === 'rtf') {
    onProgress('Extrayendo texto RTF…');
    const text = await extractRtf(file);
    return { text, isPdf: false, isDigitalPdf: false };
  }

  if (ext === 'pdf') {
    onProgress('Analizando PDF…');
    const { text, isScanned, numPages } = await extractPdfDigital(file);

    if (isScanned) {
      onProgress(`PDF escaneado detectado (${numPages} páginas). Iniciando OCR…`);
      const ocrText = await extractPdfOcr(file, onProgress);
      return { text: ocrText, isPdf: true, isDigitalPdf: false };
    }

    onProgress('PDF digital procesado.');
    return { text, isPdf: true, isDigitalPdf: true };
  }

  throw new Error(`Formato no soportado: .${ext}`);
}

window.Extractors = { extractText };

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
 * Read a File as a Data URL (for Tesseract OCR on images).
 */
function readAsDataURL(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload  = e => resolve(e.target.result);
    reader.onerror = () => reject(new Error('Error al leer el archivo'));
    reader.readAsDataURL(file);
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

  let plain = text
    .replace(/\{\\rtf[^}]*\}/g, '')
    .replace(/\\([a-z]+)(-?\d+)?\*?/gi, ' ')
    .replace(/\{[^}]*\}/g, ' ')
    .replace(/\\\n/g, '\n')
    .replace(/\\par\b/gi, '\n')
    .replace(/\\line\b/gi, '\n')
    .replace(/\\tab\b/gi, '\t')
    .replace(/\\['"]{1}[0-9a-f]{2}/gi, '')
    .replace(/[{}\\]/g, ' ')
    .replace(/[ \t]{2,}/g, ' ')
    .trim();

  return plain;
}

/**
 * Extract text from a plain-text (.txt) file.
 * Tries UTF-8 first, falls back to latin-1 if the result has replacement chars.
 */
async function extractTxt(file) {
  try {
    const text = await readAsText(file, 'utf-8');
    // If many replacement characters appear, retry with latin-1
    const replacementCount = (text.match(/\uFFFD/g) || []).length;
    if (replacementCount > 5) {
      return readAsText(file, 'iso-8859-1');
    }
    return text;
  } catch (_) {
    return readAsText(file, 'iso-8859-1');
  }
}

/**
 * Extract text from an image file (JPG, PNG, GIF, WebP) using Tesseract.js OCR.
 */
async function extractImageOcr(file, onProgress) {
  if (onProgress) onProgress('Iniciando OCR en imagen…');
  const dataUrl = await readAsDataURL(file);
  const worker  = await Tesseract.createWorker('spa+eng', 1, { logger: () => {} });
  if (onProgress) onProgress('Reconociendo texto en la imagen…');
  const { data: { text } } = await worker.recognize(dataUrl);
  await worker.terminate();
  return text;
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
 * Supported: .pdf, .docx, .rtf, .txt, .jpg, .jpeg, .png, .gif, .webp
 * @param {File} file
 * @param {function} onProgress  – callback(message: string)
 * @returns {Promise<{text, isPdf, isDigitalPdf}>}
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

  if (ext === 'txt') {
    onProgress('Leyendo archivo de texto…');
    const text = await extractTxt(file);
    return { text, isPdf: false, isDigitalPdf: false };
  }

  if (['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(ext)) {
    onProgress('Detectando texto en la imagen…');
    const text = await extractImageOcr(file, onProgress);
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

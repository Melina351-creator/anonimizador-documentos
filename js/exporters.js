/**
 * Exporters – create downloadable files from anonymized text.
 * All generation is client-side.
 */

/**
 * Trigger a file download in the browser.
 */
function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a   = document.createElement('a');
  a.href    = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

/**
 * Read a File as an ArrayBuffer (self-contained copy for exporters).
 */
function _readBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload  = e => resolve(e.target.result);
    reader.onerror = () => reject(new Error('Error al leer el archivo'));
    reader.readAsArrayBuffer(file);
  });
}

/**
 * Normalize typographic characters that lie outside the WinAnsi range
 * supported by jsPDF's built-in fonts. Prevents garbled output.
 */
function normalizeForPdf(text) {
  return text
    .replace(/[\u2018\u2019]/g, "'")   // curly single quotes → straight
    .replace(/[\u201C\u201D]/g, '"')   // curly double quotes → straight
    .replace(/\u2014/g, '--')          // em dash
    .replace(/\u2013/g, '-')           // en dash
    .replace(/\u2026/g, '...')         // ellipsis
    .replace(/\uFB00/g, 'ff')          // ff ligature
    .replace(/\uFB01/g, 'fi')          // fi ligature
    .replace(/\uFB02/g, 'fl')          // fl ligature
    .replace(/\uFB03/g, 'ffi')         // ffi ligature
    .replace(/\uFB04/g, 'ffl')         // ffl ligature
    .replace(/[\u0080-\u009F]/g, '')   // C1 control chars
    .replace(/[^\x00-\xFF]/g, '?');    // any remaining non-Latin-1
}

/**
 * Download as plain text (.txt).
 */
function downloadTxt(text, baseName) {
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  triggerDownload(blob, `${baseName}_anonimizado.txt`);
}

/**
 * Download as DOCX using the docx library.
 */
async function downloadDocx(text, baseName) {
  const { Document, Packer, Paragraph, TextRun } = docx;

  const lines = text.split('\n');
  const paragraphs = lines.map(line => {
    const trimmed = line.trim();
    if (!trimmed) return new Paragraph({});
    return new Paragraph({
      children: [new TextRun({ text: trimmed, font: 'Calibri', size: 22 })],
    });
  });

  const notice = new Paragraph({
    children: [new TextRun({
      text: 'Documento anonimizado por Anonimizador de Documentos – procesado íntegramente en el navegador.',
      color: '888888', italics: true, size: 18,
    })],
  });

  const doc = new Document({
    sections: [{ properties: {}, children: [notice, new Paragraph({}), ...paragraphs] }],
  });

  const blob = await Packer.toBlob(doc);
  triggerDownload(blob, `${baseName}_anonimizado.docx`);
}

/**
 * Download as PDF using jsPDF (for non-PDF source files: DOCX, RTF, OCR text).
 * Preserves text with proper Latin-1 encoding normalization.
 */
function downloadPdf(text, baseName) {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ orientation: 'p', unit: 'mm', format: 'a4' });

  const marginLeft   = 20;
  const marginRight  = 20;
  const marginTop    = 25;
  const marginBottom = 20;
  const pageWidth    = doc.internal.pageSize.getWidth();
  const pageHeight   = doc.internal.pageSize.getHeight();
  const maxWidth     = pageWidth - marginLeft - marginRight;
  const lineHeight   = 6;

  doc.setFontSize(9);
  doc.setTextColor(150);
  doc.text('Documento anonimizado – procesado localmente en el navegador', marginLeft, 12);
  doc.setDrawColor(200);
  doc.line(marginLeft, 15, pageWidth - marginRight, 15);
  doc.setFontSize(10);
  doc.setTextColor(30);

  // Normalize to avoid garbled characters with built-in PDF fonts
  const safeText = normalizeForPdf(text);
  let y = marginTop;
  const lines = doc.splitTextToSize(safeText, maxWidth);

  for (const line of lines) {
    if (y + lineHeight > pageHeight - marginBottom) {
      doc.addPage();
      y = marginTop;
    }
    doc.text(line, marginLeft, y);
    y += lineHeight;
  }

  doc.save(`${baseName}_anonimizado.pdf`);
}

/**
 * Download a PDF with PII redacted IN-PLACE using pdf-lib.
 * Preserves the original layout, fonts, images and formatting.
 * Only the text items containing detected PII are covered with redaction boxes.
 *
 * @param {File}   file     – original PDF File object
 * @param {string} baseName – output filename base
 * @param {object} options  – same options object used for anonymization
 */
async function downloadPdfRedacted(file, baseName, options) {
  const { PDFDocument, rgb, StandardFonts } = PDFLib;
  const mode = options.mode || 'label';

  // Read buffer once and slice copies so both libraries get independent views
  const rawBuffer = await _readBuffer(file);
  const bufForPdfjs  = rawBuffer.slice(0);
  const bufForPdflib = rawBuffer.slice(0);

  // Load with pdf.js to extract text positions
  const pdfjsDoc = await pdfjsLib.getDocument({ data: bufForPdfjs }).promise;

  // Load with pdf-lib for in-place modification
  const pdfDoc = await PDFDocument.load(bufForPdflib, { ignoreEncryption: true });
  const helvetica = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const pages = pdfDoc.getPages();

  for (let pageIdx = 0; pageIdx < pdfjsDoc.numPages; pageIdx++) {
    const pdfjsPage = await pdfjsDoc.getPage(pageIdx + 1);
    const content   = await pdfjsPage.getTextContent();
    const pdfPage   = pages[pageIdx];

    // Filter to items that have actual text and a positive width
    const items = content.items.filter(
      item => item.str && item.str.trim().length > 0 && item.width > 0
    );
    if (!items.length) continue;

    // ── Build a concatenated page string with a character→item index map ──
    // This lets us detect PII that spans across multiple adjacent text items.
    let pageText = '';
    const itemMap = []; // itemMap[charPos] = index into items[], or -1 for separators

    for (let i = 0; i < items.length; i++) {
      const str = items[i].str;
      for (let j = 0; j < str.length; j++) {
        itemMap.push(i);
        pageText += str[j];
      }
      // Add a space separator between items (not part of any item)
      itemMap.push(-1);
      pageText += ' ';
    }

    // ── Find PII positions in the concatenated page text ──
    const matches = Anonymizer.findMatchPositions(pageText, options);
    if (!matches.length) continue;

    // ── Map matched positions back to text items ──
    const toRedact = new Map(); // itemIdx → label (first match label wins)
    for (const { start, end, label } of matches) {
      for (let pos = start; pos < Math.min(end, itemMap.length); pos++) {
        const idx = itemMap[pos];
        if (idx >= 0 && !toRedact.has(idx)) {
          toRedact.set(idx, label);
        }
      }
    }

    // ── Draw redaction boxes over each PII-containing text item ──
    for (const [idx, label] of toRedact) {
      const item = items[idx];

      // Text matrix: [a, b, c, d, tx, ty]  – tx/ty are in PDF user space (points, origin bottom-left)
      const tx = item.transform[4];
      const ty = item.transform[5];
      const w  = item.width;
      // Use item.height if reliable, otherwise fall back to the font scale from the matrix
      const h  = item.height > 0 ? item.height : Math.abs(item.transform[3]);

      if (w <= 0 || h <= 0) continue;

      // Rectangle covers from slightly below the baseline to slightly above cap height
      const rectY = ty - h * 0.18;
      const rectH = h * 1.32;

      if (mode === 'redact') {
        // Solid black redaction bar
        pdfPage.drawRectangle({ x: tx, y: rectY, width: w, height: rectH, color: rgb(0, 0, 0) });
      } else {
        // Light background + descriptive label
        pdfPage.drawRectangle({
          x: tx, y: rectY, width: w, height: rectH,
          color: rgb(0.93, 0.95, 1.0),
          borderColor: rgb(0.55, 0.65, 0.85),
          borderWidth: 0.5,
        });

        const labelText = mode === 'placeholder'
          ? '[DATO]'
          : `[${label.substring(0, 14)}]`;

        const fontSize = Math.max(Math.min(h * 0.72, 7), 3);
        if (fontSize >= 3) {
          try {
            pdfPage.drawText(labelText, {
              x: tx + 1,
              y: ty + 0.5,
              size: fontSize,
              font: helvetica,
              color: rgb(0.12, 0.32, 0.72),
            });
          } catch (_) {
            // If character encoding fails (rare), the background box is still drawn
          }
        }
      }
    }
  }

  const pdfBytes = await pdfDoc.save();
  const blob = new Blob([pdfBytes], { type: 'application/pdf' });
  triggerDownload(blob, `${baseName}_anonimizado.pdf`);
}

window.Exporters = { downloadTxt, downloadDocx, downloadPdf, downloadPdfRedacted };

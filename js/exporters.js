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
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/\u2014/g, '--')
    .replace(/\u2013/g, '-')
    .replace(/\u2026/g, '...')
    .replace(/\uFB00/g, 'ff')
    .replace(/\uFB01/g, 'fi')
    .replace(/\uFB02/g, 'fl')
    .replace(/\uFB03/g, 'ffi')
    .replace(/\uFB04/g, 'ffl')
    .replace(/[\u0080-\u009F]/g, '')
    .replace(/[^\x00-\xFF]/g, '?');
}

/**
 * Download as plain text (.txt).
 */
function downloadTxt(text, baseName) {
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  triggerDownload(blob, `${baseName}_anonimizado.txt`);
}

/**
 * Download as DOCX.
 */
async function downloadDocx(text, baseName) {
  function xe(str) {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;');
  }

  const lines = text.split('\n');
  const paragraphsXml = lines.map(line => {
    if (!line.trim()) {
      return '<w:p><w:pPr><w:spacing w:after="0"/></w:pPr></w:p>';
    }
    const runs = line.split('\t').map((part, i) => {
      let r = '';
      if (i > 0) r += '<w:r><w:tab/></w:r>';
      if (part) {
        r += `<w:r><w:rPr><w:sz w:val="22"/><w:szCs w:val="22"/></w:rPr>` +
             `<w:t xml:space="preserve">${xe(part)}</w:t></w:r>`;
      }
      return r;
    }).join('');
    return `<w:p><w:pPr><w:spacing w:after="100"/></w:pPr>${runs}</w:p>`;
  }).join('\n');

  const noticeXml =
    `<w:p><w:r><w:rPr><w:color w:val="888888"/><w:i/><w:sz w:val="18"/><w:szCs w:val="18"/></w:rPr>` +
    `<w:t>Documento anonimizado \u2013 procesado localmente en el navegador.</w:t></w:r></w:p>`;

  const documentXml =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<w:document xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"\n` +
    `  xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"\n` +
    `  xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"\n` +
    `  mc:Ignorable="">\n` +
    `  <w:body>\n` +
    `    ${noticeXml}\n<w:p/>\n` +
    `    ${paragraphsXml}\n` +
    `    <w:sectPr>\n` +
    `      <w:pgSz w:w="11906" w:h="16838"/>\n` +
    `      <w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1701"\n` +
    `               w:header="709" w:footer="709" w:gutter="0"/>\n` +
    `    </w:sectPr>\n` +
    `  </w:body>\n` +
    `</w:document>`;

  const contentTypesXml =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n` +
    `  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n` +
    `  <Default Extension="xml"  ContentType="application/xml"/>\n` +
    `  <Override PartName="/word/document.xml"\n` +
    `    ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>\n` +
    `</Types>`;

  const relsXml =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n` +
    `  <Relationship Id="rId1"\n` +
    `    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"\n` +
    `    Target="word/document.xml"/>\n` +
    `</Relationships>`;

  const docRelsXml =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n` +
    `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>`;

  const zip = new JSZip();
  zip.file('[Content_Types].xml',        contentTypesXml);
  zip.file('_rels/.rels',                relsXml);
  zip.file('word/document.xml',          documentXml);
  zip.file('word/_rels/document.xml.rels', docRelsXml);

  const buffer = await zip.generateAsync({ type: 'arraybuffer', compression: 'DEFLATE' });
  const blob = new Blob([buffer], {
    type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  });
  triggerDownload(blob, `${baseName}_anonimizado.docx`);
}

/**
 * Download as PDF using jsPDF (for non-PDF source files).
 */
function downloadPdf(text, baseName) {
  try {
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
  } catch (err) {
    alert('Error al generar el PDF: ' + err.message);
  }
}

// ── PDF in-place redaction helpers ────────────────────────────────────────────

/**
 * Wrap a page's existing content stream(s) in a save/restore graphics-state
 * pair (q … Q).  This guarantees that whatever CTM, colour, or font state the
 * original content leaves behind, it is fully restored before pdf-lib appends
 * its own drawing operators.
 *
 * Without this, some PDFs (especially those generated by Microsoft Word,
 * LibreOffice, or certain print drivers) end their content stream with an
 * active non-identity CTM, causing our annotation boxes to appear at completely
 * wrong positions ("al final del documento").
 *
 * Rendering order after wrapping:
 *   q                    ← save initial (identity) state
 *   <original content>   ← draws the page's text and graphics
 *   Q                    ← restore → CTM is identity again
 *   <pdf-lib operators>  ← our white erase + label boxes, in correct coords
 */
function _wrapPageContentInQQ(pdfDoc, pdfPage) {
  try {
    const { PDFName, PDFArray, PDFDict, PDFNumber, PDFRawStream } = PDFLib;

    const contentsKey   = PDFName.of('Contents');
    const existingValue = pdfPage.node.get(contentsKey);
    if (!existingValue) return; // blank page – nothing to wrap

    // Helper: create a tiny uncompressed content stream holding just one operator
    const makeStreamRef = (operator) => {
      const bytes = new TextEncoder().encode(operator);
      const dict  = PDFDict.withContext(pdfDoc.context);
      dict.set(PDFName.of('Length'), PDFNumber.of(bytes.length));
      const stream = PDFRawStream.of(dict, bytes);
      return pdfDoc.context.register(stream);
    };

    const qRef = makeStreamRef('q\n');  // graphics-state save
    const QRef = makeStreamRef('Q\n');  // graphics-state restore

    // Collect the existing content refs into an array
    let existingRefs;
    if (existingValue instanceof PDFArray) {
      existingRefs = existingValue.asArray();
    } else {
      existingRefs = [existingValue]; // single PDFRef to a stream
    }

    // Build [qRef, ...existing, QRef] and replace Contents
    const newContents = pdfDoc.context.obj([qRef, ...existingRefs, QRef]);
    pdfPage.node.set(contentsKey, newContents);
  } catch (_) {
    // Best-effort: if wrapping fails the download still proceeds
  }
}

/**
 * Download a PDF with PII redacted IN-PLACE using pdf-lib.
 * Preserves the original layout, fonts, images and formatting.
 *
 * Coordinate-system guarantee
 * ───────────────────────────
 * pdf.js getTextContent() returns item.transform[4/5] in the page's user-space
 * (origin bottom-left of the MediaBox, units: points).  pdf-lib draws in the
 * same coordinate space.  _wrapPageContentInQQ() ensures we're in the clean
 * (identity-CTM) state when our operators execute, eliminating the class of
 * bugs where the original content left an active scale/translate/flip on the
 * CTM stack.
 *
 * An additional per-page scale factor (sx/sy) corrects any unit-system
 * mismatch between the two libraries (rare but occurs with non-standard PDFs).
 *
 * @param {File}   file         – original PDF File object
 * @param {string} baseName     – output filename base
 * @param {object} options      – same options object used for anonymization
 * @param {string} [fallbackText] – if provided, used for jsPDF fallback on error
 */
async function downloadPdfRedacted(file, baseName, options, fallbackText = null) {
  try {
    const { PDFDocument, rgb, StandardFonts } = PDFLib;
    const mode = options.mode || 'label';

    const rawBuffer  = await _readBuffer(file);
    const bufForPdfjs  = rawBuffer.slice(0);
    const bufForPdflib = rawBuffer.slice(0);

    const pdfjsDoc = await pdfjsLib.getDocument({ data: bufForPdfjs }).promise;
    const pdfDoc   = await PDFDocument.load(bufForPdflib, { ignoreEncryption: true });
    const helvetica = await pdfDoc.embedFont(StandardFonts.Helvetica);
    const pages = pdfDoc.getPages();

    for (let pageIdx = 0; pageIdx < pdfjsDoc.numPages; pageIdx++) {
      // Yield to UI on every page to keep responsive
      await new Promise(r => setTimeout(r, 0));
      try {
        const pdfjsPage = await pdfjsDoc.getPage(pageIdx + 1);
        const content   = await pdfjsPage.getTextContent();
        const pdfPage   = pages[pageIdx];

        // ── Coordinate-system fix ──────────────────────────────────────────────
        // Wrap the existing page content in q/Q so our appended drawing operators
        // always execute in the canonical (identity-CTM) user-space coordinate system.
        _wrapPageContentInQQ(pdfDoc, pdfPage);

        // Per-page scale: accounts for unit differences between pdf.js and pdf-lib.
        // For standard PDFs both report the same dimensions; scale = 1.0.
        // For PDFs with non-zero MediaBox origin the offset is removed first.
        const view      = pdfjsPage.view;  // [x0, y0, x1, y1]
        const pdfjsW    = view[2] - view[0];
        const pdfjsH    = view[3] - view[1];
        const { width: plW, height: plH } = pdfPage.getSize();
        const sx = pdfjsW > 0 ? plW / pdfjsW : 1;
        const sy = pdfjsH > 0 ? plH / pdfjsH : 1;
        const ox = view[0]; // MediaBox x-origin (usually 0)
        const oy = view[1]; // MediaBox y-origin (usually 0)

        // Filter to items that have actual text
        const items = content.items.filter(
          item => item.str && item.str.trim().length > 0
        );
        if (!items.length) continue;

        // ── Build concatenated page text with char→item mapping ───────────────
        let pageText = '';
        // itemMap[pos] = { i: itemIndex, c: charIndexWithinItem } | null (for separators)
        const itemMap = [];

        for (let i = 0; i < items.length; i++) {
          const str = items[i].str;
          for (let j = 0; j < str.length; j++) {
            itemMap.push({ i, c: j });
            pageText += str[j];
          }
          itemMap.push(null);
          pageText += ' ';
        }

        // ── Find PII positions ────────────────────────────────────────────────
        const rawMatches = Anonymizer.findMatchPositions(pageText, options);
        const matches = options.skipTexts?.length
          ? rawMatches.filter(m =>
              !options.skipTexts.some(t => t === pageText.slice(m.start, m.end).toLowerCase())
            )
          : rawMatches;
        if (!matches.length) continue;

        // ── Map matched char positions → text items ───────────────────────────
        // toRedact: Map<itemIdx, { label, c0, c1 }>
        // c0/c1 = first/last+1 char index within the item that is part of the match
        const toRedact = new Map();
        for (const { start, end, label } of matches) {
          for (let pos = start; pos < Math.min(end, itemMap.length); pos++) {
            const entry = itemMap[pos];
            if (!entry) continue;
            const { i: idx, c } = entry;
            if (!toRedact.has(idx)) {
              toRedact.set(idx, { label, c0: c, c1: c + 1 });
            } else {
              const info = toRedact.get(idx);
              if (c < info.c0) info.c0 = c;
              if (c + 1 > info.c1) info.c1 = c + 1;
            }
          }
        }

        // ── Draw redaction boxes ──────────────────────────────────────────────
        for (const [idx, { label, c0, c1 }] of toRedact) {
          const item = items[idx];
          const totalChars = item.str.length;
          const fStart = totalChars > 0 ? c0 / totalChars : 0;
          const fEnd   = totalChars > 0 ? c1 / totalChars : 1;

          const rawTx = item.transform[4];
          const rawTy = item.transform[5];
          const rawW  = typeof item.width === 'number' ? item.width : 0;
          const rawH  = item.height > 0 ? item.height : Math.abs(item.transform[3]);

          const tx     = (rawTx - ox) * sx;
          const ty     = (rawTy - oy) * sy;
          const itemW  = rawW * sx;
          const h      = Math.max(rawH > 0 ? rawH * sy : 8, 8);

          // Proportional x-offset and width within the item.
          // When item.width is 0 (common in many PDFs) we approximate using
          // ~55 % of the font height as the average character advance width.
          // This ensures the box starts at the matched text, not at the item's
          // left edge (which would cover any preceding label like "RFC:").
          let matchOffX, matchW;
          if (itemW > 0) {
            matchOffX = fStart * itemW;
            matchW    = Math.max((fEnd - fStart) * itemW, 4);
          } else {
            const charW = h * 0.55; // ≈ average advance per character
            matchOffX   = c0 * charW;
            matchW      = Math.max((c1 - c0) * charW, 4);
          }

          const pad   = Math.max(h * 0.25, 2);
          const rectX = tx + matchOffX - 1;
          const rectY = ty - pad;
          const rectW = matchW + 2;
          const rectH = h + pad * 2;

          if (mode === 'redact') {
            // Solid black bar – covers everything underneath
            pdfPage.drawRectangle({
              x: rectX, y: rectY, width: rectW, height: rectH,
              color: rgb(0, 0, 0), opacity: 1,
            });
          } else {
            // ── Layer 1: white "erase" rectangle ──────────────────────────────
            // Drawn slightly LARGER than the annotation box to guarantee the
            // original text glyphs are covered even if the font has large ascenders.
            pdfPage.drawRectangle({
              x: rectX - 1, y: rectY - 1, width: rectW + 2, height: rectH + 2,
              color: rgb(1, 1, 1), opacity: 1,
            });

            // ── Layer 2: coloured annotation box ──────────────────────────────
            pdfPage.drawRectangle({
              x: rectX, y: rectY, width: rectW, height: rectH,
              color: rgb(0.93, 0.95, 1.0),
              borderColor: rgb(0.55, 0.65, 0.85),
              borderWidth: 0.5,
              opacity: 1,
            });

            // ── Layer 3: label text ────────────────────────────────────────────
            const labelText = mode === 'placeholder'
              ? '[DATO]'
              : `[${label.substring(0, 14)}]`;

            const fontSize = Math.max(Math.min(h * 0.65, 7), 3);
            try {
              pdfPage.drawText(labelText, {
                x: rectX + 2,
                y: ty - fontSize * 0.15,  // align label text at the original baseline
                size: fontSize,
                font: helvetica,
                color: rgb(0.12, 0.32, 0.72),
                opacity: 1,
              });
            } catch (_) {
              // Encoding edge-case – the box is still drawn
            }
          }
        }

        // Optional: grey bars over header/footer image regions
        if (options.redactImages) {
          try {
            const resources = pdfPage.node.Resources();
            const xObjs     = resources?.lookupMaybe(PDFLib.PDFName.of('XObject'), PDFLib.PDFDict);
            let hasImg = false;
            if (xObjs) {
              for (const [, ref] of xObjs.entries()) {
                const xobj = pdfDoc.context.lookupMaybe(ref, PDFLib.PDFDict);
                if (xobj) {
                  const sub = xobj.lookupMaybe(PDFLib.PDFName.of('Subtype'), PDFLib.PDFName);
                  if (sub?.encodedName === '/Image') { hasImg = true; break; }
                }
              }
            }
            if (hasImg) {
              const { width, height } = pdfPage.getSize();
              const grey = rgb(0.45, 0.45, 0.45);
              pdfPage.drawRectangle({ x: 0, y: height - 80, width, height: 80, color: grey });
              pdfPage.drawRectangle({ x: 0, y: 0, width, height: 50, color: grey });
            }
          } catch (_) {}
        }
      } catch (pageErr) {
        console.warn(`Página ${pageIdx + 1}: redacción omitida (${pageErr.message})`);
        // continue to next page
      }
    }

    const pdfBytes = await pdfDoc.save();
    const blob = new Blob([pdfBytes], { type: 'application/pdf' });
    triggerDownload(blob, `${baseName}_anonimizado.pdf`);

  } catch (err) {
    if (fallbackText !== null) {
      downloadPdf(fallbackText, baseName);
    } else if (err instanceof RangeError || err.message?.toLowerCase().includes('memory')) {
      alert('El PDF es demasiado grande para procesarlo en el navegador. Descargue en formato TXT como alternativa.');
    } else {
      alert('Error al procesar el PDF: ' + err.message);
    }
  }
}

window.Exporters = { downloadTxt, downloadDocx, downloadPdf, downloadPdfRedacted };

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
 * Download as plain text (.txt)
 */
function downloadTxt(text, baseName) {
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  triggerDownload(blob, `${baseName}_anonimizado.txt`);
}

/**
 * Download as DOCX using the docx library.
 */
async function downloadDocx(text, baseName) {
  const { Document, Packer, Paragraph, TextRun, HeadingLevel } = docx;

  const lines = text.split('\n');
  const paragraphs = lines.map(line => {
    const trimmed = line.trim();
    if (!trimmed) return new Paragraph({});
    return new Paragraph({
      children: [new TextRun({
        text: trimmed,
        font: 'Calibri',
        size: 22,
      })],
    });
  });

  // Add header note
  const notice = new Paragraph({
    children: [new TextRun({
      text: 'Documento anonimizado por Anonimizador de Documentos – procesado íntegramente en el navegador.',
      color: '888888',
      italics: true,
      size: 18,
    })],
  });

  const doc = new Document({
    sections: [{
      properties: {},
      children: [notice, new Paragraph({}), ...paragraphs],
    }],
  });

  const blob = await Packer.toBlob(doc);
  triggerDownload(blob, `${baseName}_anonimizado.docx`);
}

/**
 * Download as PDF using jsPDF.
 * Wraps long lines and adds page header.
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

  // Header on first page
  doc.setFontSize(9);
  doc.setTextColor(150);
  doc.text('Documento anonimizado – procesado localmente en el navegador', marginLeft, 12);
  doc.setDrawColor(200);
  doc.line(marginLeft, 15, pageWidth - marginRight, 15);

  doc.setFontSize(10);
  doc.setTextColor(30);

  let y = marginTop;
  const lines = doc.splitTextToSize(text, maxWidth);

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

window.Exporters = { downloadTxt, downloadDocx, downloadPdf };

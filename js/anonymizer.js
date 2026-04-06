/**
 * Anonymizer engine – all processing is local, no data leaves the browser.
 * Detects PII patterns common in Spanish legal documents and replaces them.
 */

const PATTERNS = {
  dni: {
    label: 'DNI/NIE',
    // Spanish DNI: 8 digits + letter  |  Spanish NIE: X/Y/Z + 7 digits + letter
    re: /\b([0-9]{8}[A-TRWAGMYFPDXBNJZSQVHLCKE]|[XYZ][0-9]{7}[A-TRWAGMYFPDXBNJZSQVHLCKE])\b/gi,
  },
  // cuil runs BEFORE dniAR so that "20-30343469-7" is matched whole,
  // preventing dniAR's \b\d{8}\b from partially matching the inner 8 digits first.
  cuil: {
    label: 'CUIL/CUIT',
    // Argentine CUIL (personal) and CUIT (tax ID):
    //   1. After keyword: "CUIL: 20-20831293-7"  "CUIT 20208312937"
    //   2. Formatted standalone (reliable):       20-20831293-7
    //   3. Plain 11 digits with valid CUIL prefix (20,23,24,27 / 30,33,34)
    re: /\b(?:CUIL|CUIT|C\.U\.I\.L\.?|C\.U\.I\.T\.?)\s*[:\-Nº°#\s]*\d{2}[\-\s]?\d{8}[\-\s]?\d\b|\b\d{2}[\-]\d{8}[\-]\d\b|\b(?:20|23|24|27|30|33|34)\d{9}\b/gi,
  },
  // rut runs BEFORE dniAR: the dotted RUT format (12.345.678-9) starts with
  // XX.XXX.XXX which would be consumed by dniAR's \d{2}\.\d{3}\.\d{3} pattern.
  rut: {
    label: 'RUT',
    // Uruguayan RUT (Registro Único Tributario): 7-8 digit number + check digit
    //   1. With keyword:           RUT: 12.345.678-9  |  RUT 12345678-9
    //   2. Dotted standalone:      12.345.678-9  |  1.234.567-8
    re: /\b(?:RUT|R\.U\.T\.?)\s*[:\-Nº°#]?\s*\d{1,2}\.?\d{3}\.?\d{3}[\-]\d\b|\b\d{1,2}\.\d{3}\.\d{3}[\-]\d\b/gi,
  },
  rfc: {
    label: 'RFC',
    // Mexican RFC (Registro Federal de Contribuyentes): 3-4 letters + 6-digit
    // birthdate (YYMMDD) + 3 alphanumeric homoclave.  Total: 12-13 chars.
    //   1. With keyword:   RFC: FMS100120RG8  |  RFC GOMA820420RU4
    //   2. Standalone pattern (specific enough to avoid false positives)
    re: /\b(?:RFC|R\.F\.C\.?)\s*[:\-Nº°#]?\s*[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}\b|\b[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}\b/gi,
  },
  dniAR: {
    label: 'DNI',
    // Argentine DNI – three formats (CUIL/CUIT/RUT already handled above):
    //   1. After DNI keyword: "DNI 30343469", "DNI: 30.343.469"
    //   2. Dotted format: 30.343.469
    //   3. Context-aware: 7-8 digits after "N°", "número", "nro.", "documento"
    //      (replaces the broad \b\d{8}\b that caused many false positives)
    re: /\bD\.?N\.?I\.?\s*[Nº°#:\s.]*\d[\d.\-\s]{4,10}\d\b|\b\d{2}\.\d{3}\.\d{3}\b|(?<=\b(?:n[uú]mero|n[oº°]\.?|nro\.?|documento|doc\.)\s*[:\-]?\s*)\d{7,8}\b/gi,
  },
  nif: {
    label: 'CIF/NIF',
    re: /\b[ABCDEFGHJKLMNPQRSUVW][0-9]{7}[0-9A-J]\b/gi,
  },
  passport: {
    label: 'Pasaporte',
    re: /\b[A-Z]{2}[0-9]{6,7}\b/g,
  },
  ss: {
    label: 'Nº S.Social',
    re: /\b\d{2}[\/ ]\d{8}[\/ ]\d{2}\b|\b\d{12}\b/g,
  },
  iban: {
    label: 'IBAN',
    re: /\b[A-Z]{2}[0-9]{2}[\s]?([0-9]{4}[\s]?){4,6}[0-9]{1,4}\b/g,
  },
  phone: {
    label: 'Teléfono',
    re: /(?:\+34[\s\-]?)?(?:6|7|8|9)\d{2}[\s\-]?\d{3}[\s\-]?\d{3}\b/g,
  },
  email: {
    label: 'Email',
    re: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
  },
  // addressCtx detects the address VALUE after common field labels.
  // Lookbehind preserves the label ("domicilio: [DIRECCIÓN]" not "[DIRECCIÓN]").
  // This covers Argentine/LATAM formats without street-type keywords
  // (e.g. "Domicilio: GUATEMALA 4242, 2B, CABA").
  addressCtx: {
    label: 'Dirección',
    re: /(?<=\b(?:domicilio(?:\s+\w+)?|direcci[oó]n(?:\s+\w+)?|residencia|domiciliad[ao](?:\s+en)?)\s*[:\-]?\s*)[^\n;]{3,50}(?:,\s*[^\n;,]{1,30}){0,2}/gi,
  },
  address: {
    label: 'Dirección',
    // Added: pasaje/pje, diagonal/diag, bv (boulevard) for wider coverage
    re: /\b(?:calle|c\/|avda?\.?|avenida|plaza|pza\.?|paseo|pso\.?|camino|ronda|travesía|bulevar|bv\.?|pol[ií]gono|urb\.?|urbanización|pasaje|pje\.?|diagonal|diag\.?)\s+[^\n,;]{3,60}(?:,\s*n[oº°]?\s*\d+[^\n,;]{0,30})?/gi,
  },
  postcode: {
    label: 'Código Postal',
    re: /\b(?:CP\.?[\s:]?)?[0-5][0-9]{4}\b/g,
  },
  plate: {
    label: 'Matrícula',
    re: /\b\d{4}[\s\-]?[BCDFGHJKLMNPRSTUVWXYZ]{3}\b|\b[A-Z]{1,2}[\s\-]?\d{4}[\s\-]?[A-Z]{1,2}\b/g,
  },
  ip: {
    label: 'IP',
    re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  },
  coords: {
    label: 'GPS',
    re: /\b[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)\b/g,
  },
  birthdate: {
    label: 'Fecha',
    // SEP matches ASCII hyphen/slash/dot AND non-ASCII variants used by some
    // PDF/DOCX extractors: non-breaking hyphen (U+2011) and en-dash (U+2013).
    // Pattern 1: keyword + date (any separator, any order)
    // Pattern 2: standalone DD-MM-YYYY / DD/MM/YYYY / DD.MM.YYYY
    // Pattern 3: standalone YYYY-MM-DD / YYYY/MM/DD / YYYY.MM.DD
    // Pattern 4: explicit DD-MM-YYYY with hyphen (defensive, covers extraction artifacts)
    re: /\b(?:nacid[ao]|fecha\s+de\s+nacimiento|fecha\s+nac\.?|fec\.?\s*nac\.?|f\.?\s*nac\.?|fecha)[:\s]+\d{1,2}[\-\/\.\u2011\u2013]\d{1,2}[\-\/\.\u2011\u2013]\d{2,4}\b|\b\d{1,2}[\-\/\.\u2011\u2013]\d{1,2}[\-\/\.\u2011\u2013]\d{4}\b|\b(?:19|20)\d{2}[\-\/\.\u2011\u2013]\d{1,2}[\-\/\.\u2011\u2013]\d{1,2}\b|\b(?:0?[1-9]|[12]\d|3[01])-(?:0?[1-9]|1[0-2])-(?:19|20)\d{2}\b/gi,
  },
  receta: {
    label: 'Nº Receta',
    // Prescription number after "receta" keyword (up to 30 non-digit chars between)
    re: /(?<=\breceta\b[^0-9]{0,30})\d{6,16}\b/gi,
  },
  sexo: {
    label: 'Sexo',
    // Patient sex after "sexo" keyword: M / F / Masculino / Femenino
    re: /(?<=\bsexo\s*[:\-]?\s*)(?:[MF]|masculino|femenino|masc\.?|fem\.?|indeterminado)\b/gi,
  },
  matricula: {
    label: 'Matrícula Médica',
    // Medical or professional license number after "matrícula" keyword
    re: /(?<=\bmatr[ií]cula\b[^0-9]{0,20})\d{4,10}\b/gi,
  },
  // company runs BEFORE generic name patterns so "Deksia México S.A." is matched
  // whole (with its legal suffix) and not partially consumed as a person's name.
  company: {
    label: 'Empresa',
    // Razón social: 1-4 capitalized/ALLCAPS words followed by a legal entity suffix.
    // Alternatives ordered from most specific to least to avoid early-exit on short suffixes.
    // Examples: "Deksia México S.A", "Knotion S.A. de C.V.", "García y López S.R.L."
    re: /\b[A-ZÁÉÍÓÚÜÑ][A-ZÁÉÍÓÚÜÑa-záéíóúüñ&]{1,25}(?:\s+(?:(?:y|&|de|del)\s+)?[A-ZÁÉÍÓÚÜÑ][A-ZÁÉÍÓÚÜÑa-záéíóúüñ]{1,25}){0,3}\s+(?:S\.A\.?\s+de\s+C\.V\.?|S\.de\s+R\.L\.?\s+de\s+C\.V\.?|S\.A\.S\.?|S\.R\.?L\.?|S\.A\.?|S\.C\.S\.?|S\.C\.?|Ltda?\.?|Inc\.?|Corp\.?|GmbH|B\.V\.?|LLC\.?|LLP\.?|PLC\.?|A\.C\.?)(?=[\s,;:\n\.]|$)/gi,
  },
  names: {
    label: 'Nombre',
    re: /\b(?:D\.?|D[oañ]\.?|Don|Doña|Sr\.?a?\.?|Dr\.?a?\.?|Lic\.?|Excm[ao]\.?|Ilm[ao]\.?|Prof\.?)\s+[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{1,20}(?:\s+(?:de\s+)?[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{1,20}){0,3}/g,
  },
  namesCtx: {
    label: 'Nombre',
    re: /(?<=\b(?:paciente|nombre\s+(?:y\s+)?apellido|apellido\s+(?:y\s+)?nombre|nombre\s+completo|apellido(?:s)?|nombre(?:s)?|titular|solicitante|requirente|interesado|firmante|beneficiario|compareciente|declarante|denunciante|imputado|acusado|causante|heredero|propietario|apoderado|asegurado|afiliado)\s*[:\-]?\s*)[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{1,20}(?:\s+[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{1,20}){1,4}/gi,
  },
  namesTitleCase: {
    label: 'Nombre',
    // {1,3} = 1-3 additional words, so minimum 2 words total (e.g. "Francisco Firpo")
    re: /\b[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{2,19}(?:\s+[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{2,19}){1,3}\b/g,
  },
  namesAllCaps: {
    label: 'Nombre',
    // {1,3} = 1-3 additional words, so minimum 2 words total (e.g. "HERNÁN RAMÍREZ")
    re: /\b[A-ZÁÉÍÓÚÜÑ]{3,20}(?:\s+[A-ZÁÉÍÓÚÜÑ]{3,20}){1,3}\b/g,
  },
};

/**
 * Returns a replacement string for a matched value.
 * @param {string} mode  - 'label' | 'redact' | 'placeholder'
 * @param {string} label - Descriptive label like 'DNI/NIE'
 */
function makeReplacement(mode, label) {
  if (mode === 'redact')      return '████████';
  if (mode === 'placeholder') return '[DATO PERSONAL]';
  return `[${label.toUpperCase()}]`;
}

/**
 * Anonymize a plain-text string.
 * @param {string} text
 * @param {object} options
 *   enabled   – object keyed by PATTERNS keys, value true/false
 *   mode      – 'label' | 'redact' | 'placeholder'
 *   custom    – array of custom terms to also remove
 * @returns {{ result: string, stats: object }}
 */
function anonymizeText(text, options = {}) {
  const { enabled = {}, mode = 'label', custom = [] } = options;
  const stats = {};
  let result = text;

  // Built-in patterns
  for (const [key, { label, re }] of Object.entries(PATTERNS)) {
    if (enabled[key] === false) continue;
    const replacement = makeReplacement(mode, label);
    // Reset lastIndex for global regexes
    re.lastIndex = 0;
    const matches = result.match(re) || [];
    if (matches.length) {
      stats[label] = (stats[label] || 0) + matches.length;
      re.lastIndex = 0;
      result = result.replace(re, replacement);
    }
    re.lastIndex = 0;
  }

  // Custom terms
  for (const term of custom) {
    const t = term.trim();
    if (!t) continue;
    // Normalize runs of spaces to \s+ so the term matches even when the
    // extracted document has non-breaking spaces, double spaces, etc.
    const escaped = t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+');
    const termRe = new RegExp(escaped, 'gi');
    const matches = result.match(termRe) || [];
    if (matches.length) {
      stats['Personalizado'] = (stats['Personalizado'] || 0) + matches.length;
      result = result.replace(termRe, makeReplacement(mode, 'Personalizado'));
    }
  }

  const total = Object.values(stats).reduce((a, b) => a + b, 0);
  return { result, stats, total };
}

/**
 * Find PII match positions (start/end indices) in a text string without replacing.
 * Used by the PDF redaction engine to locate text items to cover.
 * @returns {Array<{start: number, end: number, label: string}>}
 */
function findMatchPositions(text, options = {}) {
  const { enabled = {}, custom = [] } = options;
  const matches = [];

  for (const [key, { label, re }] of Object.entries(PATTERNS)) {
    if (enabled[key] === false) continue;
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      matches.push({ start: m.index, end: m.index + m[0].length, label });
    }
    re.lastIndex = 0;
  }

  for (const term of custom) {
    const t = term.trim();
    if (!t) continue;
    const escaped = t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+');
    const termRe = new RegExp(escaped, 'gi');
    let m;
    while ((m = termRe.exec(text)) !== null) {
      matches.push({ start: m.index, end: m.index + m[0].length, label: 'Personalizado' });
    }
  }

  // Assign stable IDs so the UI can track individual matches for exclusion
  return matches.map((m, i) => ({ ...m, id: i }));
}

/**
 * Anonymize text using pre-computed match positions (from findMatchPositions),
 * supporting exclusion of specific match IDs (manual review / false positive marking).
 *
 * @param {string} text
 * @param {Array}  allMatches  – output of findMatchPositions (with .id fields)
 * @param {Set}    excludedIds – Set of match .id values to skip
 * @param {string} mode        – 'label' | 'redact' | 'placeholder'
 * @returns {{ result: string, stats: object, total: number }}
 */
function anonymizeFromPositions(text, allMatches, excludedIds, mode = 'label') {
  // Filter out matches the user has marked as false positives
  const active = allMatches.filter(m => !excludedIds.has(m.id));

  // Deduplicate overlapping positions — first match by start position wins
  // (mirrors the sequential pattern execution order in anonymizeText)
  const sorted = [...active].sort((a, b) => a.start - b.start);
  const deduped = [];
  let lastEnd = -1;
  for (const m of sorted) {
    if (m.start >= lastEnd) {
      deduped.push(m);
      lastEnd = m.end;
    }
  }

  // Replace right-to-left so character positions of earlier matches stay valid
  deduped.sort((a, b) => b.start - a.start);

  const stats = {};
  let result = text;
  for (const { start, end, label } of deduped) {
    const replacement = makeReplacement(mode, label);
    result = result.slice(0, start) + replacement + result.slice(end);
    stats[label] = (stats[label] || 0) + 1;
  }

  const total = Object.values(stats).reduce((a, b) => a + b, 0);
  return { result, stats, total };
}

window.Anonymizer = { anonymizeText, anonymizeFromPositions, findMatchPositions, PATTERNS };

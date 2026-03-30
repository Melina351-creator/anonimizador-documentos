/**
 * Anonymizer engine – all processing is local, no data leaves the browser.
 * Detects PII patterns common in Spanish legal documents and replaces them.
 */

const PATTERNS = {
  dni: {
    label: 'DNI/NIE',
    // DNI: 8 digits + letter  |  NIE: X/Y/Z + 7 digits + letter
    re: /\b([0-9]{8}[A-TRWAGMYFPDXBNJZSQVHLCKE]|[XYZ][0-9]{7}[A-TRWAGMYFPDXBNJZSQVHLCKE])\b/gi,
  },
  nif: {
    label: 'CIF/NIF',
    // CIF: letter + 7 digits + control digit/letter
    re: /\b[ABCDEFGHJKLMNPQRSUVW][0-9]{7}[0-9A-J]\b/gi,
  },
  passport: {
    label: 'Pasaporte',
    re: /\b[A-Z]{2}[0-9]{6,7}\b/g,
  },
  ss: {
    label: 'Nº S.Social',
    // Spanish SS: 12 digits grouped as XX/XXXXXXXX/DD or plain
    re: /\b\d{2}[\/ ]\d{8}[\/ ]\d{2}\b|\b\d{12}\b/g,
  },
  iban: {
    label: 'IBAN',
    re: /\b[A-Z]{2}[0-9]{2}[\s]?([0-9]{4}[\s]?){4,6}[0-9]{1,4}\b/g,
  },
  phone: {
    label: 'Teléfono',
    // Spanish mobile/landline: 6xx-9xx, also intl +34
    re: /(?:\+34[\s\-]?)?(?:6|7|8|9)\d{2}[\s\-]?\d{3}[\s\-]?\d{3}\b/g,
  },
  email: {
    label: 'Email',
    re: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
  },
  address: {
    label: 'Dirección',
    // Calle / Av / Pza / etc. followed by name and number
    re: /\b(?:calle|c\/|avda?\.?|avenida|plaza|pza\.?|paseo|pso\.?|camino|ronda|travesía|bulevar|pol[ií]gono|urb\.?|urbanización)\s+[^\n,;]{3,60}(?:,\s*n[oº°]?\s*\d+[^\n,;]{0,30})?/gi,
  },
  postcode: {
    label: 'Código Postal',
    re: /\b(?:CP\.?[\s:]?)?[0-5][0-9]{4}\b/g,
  },
  plate: {
    label: 'Matrícula',
    // Spanish: 4 digits + 3 consonants (2000-present) or old provincial
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
    label: 'Fecha nacimiento',
    // DD/MM/YYYY or DD-MM-YYYY or YYYY-MM-DD
    re: /\b(?:nacid[ao]|fecha\s+de\s+nacimiento|f\.?\s*nac\.?)[:\s]+\d{1,2}[\-\/]\d{1,2}[\-\/]\d{2,4}\b|\b\d{1,2}[\-\/]\d{1,2}[\-\/]\d{4}\b/gi,
  },
  names: {
    label: 'Nombre',
    // Names following common titles in Spanish legal docs
    re: /\b(?:D\.?|D[oañ]\.?|Don|Doña|Sr\.?|Sra\.?|Dr\.?|Dra\.?|Lic\.?|Excm[ao]\.?|Ilm[ao]\.?|Prof\.?)\s+[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{1,20}(?:\s+(?:de\s+)?[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{1,20}){0,3}/g,
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
    const escaped = t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
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
    const escaped = t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const termRe = new RegExp(escaped, 'gi');
    let m;
    while ((m = termRe.exec(text)) !== null) {
      matches.push({ start: m.index, end: m.index + m[0].length, label: 'Personalizado' });
    }
  }

  return matches;
}

window.Anonymizer = { anonymizeText, findMatchPositions, PATTERNS };

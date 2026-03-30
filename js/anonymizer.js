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
  dniAR: {
    label: 'DNI',
    // Argentine DNI – three formats (CUIL/CUIT already handled above):
    //   1. After DNI keyword: "DNI 30343469", "DNI: 30.343.469"
    //   2. Dotted format: 30.343.469
    //   3. Standalone 8-digit number
    re: /\bD\.?N\.?I\.?\s*[Nº°#:\s.]*\d[\d.\-\s]{4,10}\d\b|\b\d{2}\.\d{3}\.\d{3}\b|\b\d{8}\b/gi,
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
  address: {
    label: 'Dirección',
    re: /\b(?:calle|c\/|avda?\.?|avenida|plaza|pza\.?|paseo|pso\.?|camino|ronda|travesía|bulevar|pol[ií]gono|urb\.?|urbanización)\s+[^\n,;]{3,60}(?:,\s*n[oº°]?\s*\d+[^\n,;]{0,30})?/gi,
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
    label: 'Fecha nacimiento',
    // Bug fix: added \. so dates with dots (15.03.1990) are also matched.
    // Also expanded keyword variants: f.nac, fec.nac, fecha nac.
    re: /\b(?:nacid[ao]|fecha\s+de\s+nacimiento|fecha\s+nac\.?|fec\.?\s*nac\.?|f\.?\s*nac\.?)[:\s]+\d{1,2}[\-\/\.]\d{1,2}[\-\/\.]\d{2,4}\b|\b\d{1,2}[\-\/\.]\d{1,2}[\-\/\.]\d{4}\b|\b(?:19|20)\d{2}[\-\/\.]\d{1,2}[\-\/\.]\d{1,2}\b/gi,
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
    re: /\b[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{2,19}(?:\s+[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{2,19}){2,3}\b/g,
  },
  namesAllCaps: {
    label: 'Nombre',
    re: /\b[A-ZÁÉÍÓÚÜÑ]{3,20}(?:\s+[A-ZÁÉÍÓÚÜÑ]{3,20}){2,3}\b/g,
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

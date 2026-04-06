/**
 * Anonymizer engine – all processing is local, no data leaves the browser.
 * Detects PII patterns common in Spanish legal documents and replaces them.
 */

const PATTERNS = {
  dni: {
    label: 'DNI/NIE',
    confidence: 'high',
    // Spanish DNI: 8 digits + letter  |  Spanish NIE: X/Y/Z + 7 digits + letter
    re: /\b([0-9]{8}[A-TRWAGMYFPDXBNJZSQVHLCKE]|[XYZ][0-9]{7}[A-TRWAGMYFPDXBNJZSQVHLCKE])\b/gi,
  },
  // cuil runs BEFORE dniAR so that "20-30343469-7" is matched whole,
  // preventing dniAR's pattern from partially matching the inner digits first.
  cuil: {
    label: 'CUIL/CUIT',
    confidence: 'high',
    re: /\b(?:CUIL|CUIT|C\.U\.I\.L\.?|C\.U\.I\.T\.?)\s*[:\-Nº°#\s]*\d{2}[\-\s]?\d{8}[\-\s]?\d\b|\b\d{2}[\-]\d{8}[\-]\d\b|\b(?:20|23|24|27|30|33|34)\d{9}\b/gi,
  },
  // rut runs BEFORE dniAR: the dotted RUT format starts with XX.XXX.XXX
  // which would be consumed by dniAR's dotted pattern.
  rut: {
    label: 'RUT',
    confidence: 'high',
    re: /\b(?:RUT|R\.U\.T\.?)\s*[:\-Nº°#]?\s*\d{1,2}\.?\d{3}\.?\d{3}[\-]\d\b|\b\d{1,2}\.\d{3}\.\d{3}[\-]\d\b/gi,
  },
  rfc: {
    label: 'RFC',
    confidence: 'high',
    // Mexican RFC: 3-4 letters + 6-digit birthdate (YYMMDD) + 3 alphanumeric homoclave
    re: /\b(?:RFC|R\.F\.C\.?)\s*[:\-Nº°#]?\s*[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}\b|\b[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}\b/gi,
  },
  dniAR: {
    label: 'DNI',
    confidence: 'medium',
    // Argentine DNI – three formats (CUIL/CUIT/RUT already handled above):
    //   1. After DNI keyword: "DNI 30343469", "DNI: 30.343.469"
    //   2. Dotted format: 30.343.469
    //   3. Context-aware: 7-8 digits after "N°", "número", "nro.", "documento"
    re: /\bD\.?N\.?I\.?\s*[Nº°#:\s.]*\d[\d.\-\s]{4,10}\d\b|\b\d{2}\.\d{3}\.\d{3}\b|(?<=\b(?:n[uú]mero|n[oº°]\.?|nro\.?|documento|doc\.)\s*[:\-]?\s*)\d{7,8}\b/gi,
  },
  nif: {
    label: 'CIF/NIF',
    confidence: 'high',
    re: /\b[ABCDEFGHJKLMNPQRSUVW][0-9]{7}[0-9A-J]\b/gi,
  },
  passport: {
    label: 'Pasaporte',
    confidence: 'medium',
    re: /\b[A-Z]{2}[0-9]{6,7}\b/g,
  },
  ss: {
    label: 'Nº S.Social',
    confidence: 'high',
    re: /\b\d{2}[\/ ]\d{8}[\/ ]\d{2}\b|\b\d{12}\b/g,
  },
  iban: {
    label: 'IBAN',
    confidence: 'high',
    re: /\b[A-Z]{2}[0-9]{2}[\s]?([0-9]{4}[\s]?){4,6}[0-9]{1,4}\b/g,
  },
  phone: {
    label: 'Teléfono',
    confidence: 'high',
    re: /(?:\+34[\s\-]?)?(?:6|7|8|9)\d{2}[\s\-]?\d{3}[\s\-]?\d{3}\b/g,
  },
  email: {
    label: 'Email',
    confidence: 'high',
    re: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
  },
  // addressCtx detects the address VALUE after common field labels.
  // Lookbehind preserves the label ("domicilio: [DIRECCIÓN]" not "[DIRECCIÓN]").
  addressCtx: {
    label: 'Dirección',
    confidence: 'medium',
    re: /(?<=\b(?:domicilio(?:\s+\w+)?|direcci[oó]n(?:\s+\w+)?|residencia|domiciliad[ao](?:\s+en)?)\s*[:\-]?\s*)[^\n;]{3,50}(?:,\s*[^\n;,]{1,30}){0,2}/gi,
  },
  address: {
    label: 'Dirección',
    confidence: 'medium',
    re: /\b(?:calle|c\/|avda?\.?|avenida|plaza|pza\.?|paseo|pso\.?|camino|ronda|travesía|bulevar|bv\.?|pol[ií]gono|urb\.?|urbanización|pasaje|pje\.?|diagonal|diag\.?)\s+[^\n,;]{3,60}(?:,\s*n[oº°]?\s*\d+[^\n,;]{0,30})?/gi,
  },
  postcode: {
    label: 'Código Postal',
    confidence: 'medium',
    re: /\b(?:CP\.?[\s:]?)?[0-5][0-9]{4}\b/g,
  },
  plate: {
    label: 'Matrícula',
    confidence: 'high',
    re: /\b\d{4}[\s\-]?[BCDFGHJKLMNPRSTUVWXYZ]{3}\b|\b[A-Z]{1,2}[\s\-]?\d{4}[\s\-]?[A-Z]{1,2}\b/g,
  },
  ip: {
    label: 'IP',
    confidence: 'high',
    re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  },
  coords: {
    label: 'GPS',
    confidence: 'high',
    re: /\b[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)\b/g,
  },
  birthdate: {
    label: 'Fecha',
    confidence: 'medium',
    // Matches numeric dates in multiple formats and separators (including PDF extraction artifacts)
    re: /\b(?:nacid[ao]|fecha\s+de\s+nacimiento|fecha\s+nac\.?|fec\.?\s*nac\.?|f\.?\s*nac\.?|fecha)[:\s]+\d{1,2}[\-\/\.\u2011\u2013]\d{1,2}[\-\/\.\u2011\u2013]\d{2,4}\b|\b\d{1,2}[\-\/\.\u2011\u2013]\d{1,2}[\-\/\.\u2011\u2013]\d{4}\b|\b(?:19|20)\d{2}[\-\/\.\u2011\u2013]\d{1,2}[\-\/\.\u2011\u2013]\d{1,2}\b|\b(?:0?[1-9]|[12]\d|3[01])-(?:0?[1-9]|1[0-2])-(?:19|20)\d{2}\b/gi,
  },
  birthdateText: {
    label: 'Fecha',
    confidence: 'high',
    // Written-out dates: "3 de junio de 2024", "15 de enero del 2024", "1 de marzo de 1985"
    // "del" = "de el" contraction also accepted before the year.
    re: /\b(?:0?[1-9]|[12]\d|3[01])\s+de\s+(?:enero|febrero|marzo|abril|mayo|junio|julio|agosto|septiembre|octubre|noviembre|diciembre)\s+del?\s+(?:19|20)\d{2}\b/gi,
  },
  receta: {
    label: 'Nº Receta',
    confidence: 'high',
    re: /(?<=\breceta\b[^0-9]{0,30})\d{6,16}\b/gi,
  },
  sexo: {
    label: 'Sexo',
    confidence: 'high',
    re: /(?<=\bsexo\s*[:\-]?\s*)(?:[MF]|masculino|femenino|masc\.?|fem\.?|indeterminado)\b/gi,
  },
  matricula: {
    label: 'Matrícula Médica',
    confidence: 'high',
    re: /(?<=\bmatr[ií]cula\b[^0-9]{0,20})\d{4,10}\b/gi,
  },
  // company runs BEFORE generic name patterns so "Deksia México S.A." is matched
  // whole (with its legal suffix) and not partially consumed as a person's name.
  company: {
    label: 'Empresa',
    confidence: 'medium',
    // Two alternatives:
    // 1. Organization names beginning with a recognised entity-type keyword
    //    (Fundación, Asociación, Instituto, Hospital…) – no mandatory legal suffix.
    //    Captures up to 5 additional capitalized words.
    // 2. Standard company name: 1-4 capitalized words + mandatory legal suffix
    //    (S.A., S.R.L., S.A. de C.V., Asociación Civil, A.C., Inc., …).
    re: /\b(?:Fundaci[oó]n|Asociaci[oó]n(?:\s+Civil)?|Instituto|Corporaci[oó]n|Hospital|Cl[ií]nica|Escuela|Centro|Consultorio|Laboratorio(?:s)?|Farmacia(?:s)?)\s+[A-ZÁÉÍÓÚÜÑ][A-ZÁÉÍÓÚÜÑa-záéíóúüñ]{1,25}(?:\s+[A-ZÁÉÍÓÚÜÑ][A-ZÁÉÍÓÚÜÑa-záéíóúüñ]{1,25}){0,5}|\b[A-ZÁÉÍÓÚÜÑ][A-ZÁÉÍÓÚÜÑa-záéíóúüñ&]{1,25}(?:\s+(?:(?:y|&|de|del)\s+)?[A-ZÁÉÍÓÚÜÑ][A-ZÁÉÍÓÚÜÑa-záéíóúüñ]{1,25}){0,3}\s+(?:S\.A\.?\s+de\s+C\.V\.?|S\.de\s+R\.L\.?\s+de\s+C\.V\.?|S\.A\.S\.?|S\.R\.?L\.?|S\.A\.?|S\.C\.S\.?|S\.C\.?|Ltda?\.?|Inc\.?|Corp\.?|GmbH|B\.V\.?|LLC\.?|LLP\.?|PLC\.?|A\.C\.?|Asociaci[oó]n\s+Civil)(?=[\s,;:\n\.]|$)/gi,
  },
  names: {
    label: 'Nombre',
    confidence: 'high',
    re: /\b(?:D\.?|D[oañ]\.?|Don|Doña|Sr\.?a?\.?|Dr\.?a?\.?|Lic\.?|Excm[ao]\.?|Ilm[ao]\.?|Prof\.?)\s+[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{1,20}(?:\s+(?:de\s+)?[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{1,20}){0,3}/g,
  },
  namesCtx: {
    label: 'Nombre',
    confidence: 'high',
    re: /(?<=\b(?:paciente|nombre\s+(?:y\s+)?apellido|apellido\s+(?:y\s+)?nombre|nombre\s+completo|apellido(?:s)?|nombre(?:s)?|titular|solicitante|requirente|interesado|firmante|beneficiario|compareciente|declarante|denunciante|imputado|acusado|causante|heredero|propietario|apoderado|asegurado|afiliado)\s*[:\-]?\s*)[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{1,20}(?:\s+[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{1,20}){1,4}/gi,
  },
  namesTitleCase: {
    label: 'Nombre',
    confidence: 'low',
    // {1,3} = 1-3 additional words, so minimum 2 words total (e.g. "Francisco Firpo")
    // Stopword filtering applied in findMatchPositions to reduce false positives.
    re: /\b[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{2,19}(?:\s+[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{2,19}){1,3}\b/g,
  },
  namesAllCaps: {
    label: 'Nombre',
    confidence: 'low',
    // {1,5} = 1-5 additional words, so 2-6 words total.
    // Allows long full names and organization names (e.g. "HERNÁN RAMÍREZ GUTIÉRREZ").
    // Stopword filtering applied in findMatchPositions to reduce false positives.
    re: /\b[A-ZÁÉÍÓÚÜÑ]{3,20}(?:\s+[A-ZÁÉÍÓÚÜÑ]{3,20}){1,5}\b/g,
  },
};

/**
 * Common job titles, roles, and non-name capitalized words.
 * When ALL words of a namesTitleCase / namesAllCaps match belong to this set,
 * the match is discarded as a false positive (role, not a person's name).
 */
const NAME_STOPWORDS = new Set([
  // English roles
  'head','lead','manager','director','developer','engineer','analyst','designer',
  'architect','consultant','coordinator','administrator','supervisor','president',
  'officer','partner','associate','specialist','senior','junior','intern','trainee',
  'contractor','executive','assistant','secretary','treasurer','auditor','inspector',
  'representative','advisor','mentor','coach','recruiter','researcher','scientist',
  'technician','operator','controller','reviewer','editor','writer','producer',
  'founder','owner','principal','fellow','staff','chief','deputy','vice',
  // Spanish roles
  'gerente','analista','desarrollador','ingeniero','arquitecto',
  'consultor','coordinador','administrador','supervisor','director','presidente',
  'socio','especialista','asistente','auxiliar','técnico','jefe','subjefe',
  'secretario','tesorero','contador','asesor','auditor','inspector','representante',
  'directora','gerenta','asistenta','coordinadora','administradora','presidenta',
  'vicepresidente','vicepresidenta','subdirector','subdirectora',
  // Generic document/org terms
  'artículo','sección','capítulo','anexo','apéndice','contrato','acuerdo',
  'convenio','resolución','decreto','código','reglamento','norma',
  'servicio','producto','empresa','organización','institución','entidad',
  'ministerio','secretaría','departamento','área','división','unidad',
].map(w => w.toLowerCase()));

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
 * Check whether every word in a matched phrase belongs to the stopword list.
 * Used to suppress role/title sequences from being flagged as person names.
 */
function _allStopwords(matchedText) {
  const words = matchedText.toLowerCase().split(/\s+/);
  return words.every(w => NAME_STOPWORDS.has(w));
}

/**
 * Find PII match positions (start/end indices) in a text string without replacing.
 * Used by the interactive preview and PDF redaction engine.
 * @returns {Array<{start, end, label, confidence, id}>}
 */
function findMatchPositions(text, options = {}) {
  const { enabled = {}, custom = [] } = options;
  const matches = [];

  for (const [key, { label, re, confidence }] of Object.entries(PATTERNS)) {
    if (enabled[key] === false) continue;
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      // Suppress generic name patterns when the entire match is role/title stopwords
      if ((key === 'namesTitleCase' || key === 'namesAllCaps') &&
          _allStopwords(m[0])) {
        continue;
      }
      matches.push({ start: m.index, end: m.index + m[0].length, label, confidence: confidence || 'medium' });
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
      matches.push({ start: m.index, end: m.index + m[0].length, label: 'Personalizado', confidence: 'high' });
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
 * @returns {{ result: string, stats: object, total: number, confidenceStats: object }}
 */
function anonymizeFromPositions(text, allMatches, excludedIds, mode = 'label') {
  // Filter out matches the user has marked as false positives
  const active = allMatches.filter(m => !excludedIds.has(m.id));

  // Deduplicate overlapping positions — first match by start position wins
  const sorted = [...active].sort((a, b) => a.start - b.start);
  const deduped = [];
  let lastEnd = -1;
  for (const m of sorted) {
    if (m.start >= lastEnd) {
      deduped.push(m);
      lastEnd = m.end;
    }
  }

  // Confidence breakdown
  const confidenceStats = { high: 0, medium: 0, low: 0 };
  for (const m of deduped) {
    confidenceStats[m.confidence || 'medium']++;
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
  return { result, stats, total, confidenceStats };
}

window.Anonymizer = { anonymizeText, anonymizeFromPositions, findMatchPositions, PATTERNS, NAME_STOPWORDS };

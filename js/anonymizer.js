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
  // cbu runs BEFORE cuil/ss: 22-digit CBU cannot be confused with shorter
  // patterns because word boundaries prevent partial matching.
  cbu: {
    label: 'CBU',
    confidence: 'high',
    // Argentine CBU: 22 consecutive digits (with optional CBU keyword prefix)
    re: /\b(?:CBU\s*[:\-#Nº°]?\s*)?\d{22}\b/g,
  },
  cbuAlias: {
    label: 'CBU Alias',
    confidence: 'high',
    // Argentine CBU alias: 3 dot-separated alphanumeric segments
    // Form 1: after "alias:" keyword, any case
    // Form 2: standalone ALL-CAPS (e.g. NERDO.SOLUTIONS.BBVA)
    re: /(?<=\balias\s*[:\-]?\s*)[A-Za-z][A-Za-z0-9]{1,21}(?:\.[A-Za-z0-9]{2,22}){2}|\b[A-Z][A-Z0-9]{1,21}(?:\.[A-Z][A-Z0-9]{1,21}){2}\b/gi,
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
    // Require "pasaporte" context or a more specific pattern to avoid matching
    // abbreviations + numbers (e.g. "CP 06500", "No 123456")
    re: /(?<=\b(?:pasaporte|passport|nro\.?\s*(?:de\s+)?pasaporte)\s*[:\-#Nº°]?\s*)[A-Z]{1,3}[0-9]{6,9}\b|\b[A-Z]{2}[0-9]{7}\b/gi,
  },
  ss: {
    label: 'Nº S.Social',
    confidence: 'high',
    // Require contextual prefix OR specific format with slashes/spaces.
    // Bare 12-digit numbers are too ambiguous without context.
    re: /\b(?:seguridad\s+social|n[ºo°]?\s*(?:de\s+)?s\.?\s*s\.?|NSS|NUSS|afiliaci[oó]n)\s*[:\-#Nº°]?\s*\d{2}[\/ ]\d{8}[\/ ]\d{2}\b|\b(?:seguridad\s+social|n[ºo°]?\s*(?:de\s+)?s\.?\s*s\.?|NSS|NUSS|afiliaci[oó]n)\s*[:\-#Nº°]?\s*\d{12}\b|\b\d{2}[\/ ]\d{8}[\/ ]\d{2}\b/gi,
  },
  iban: {
    label: 'IBAN',
    confidence: 'high',
    re: /\b[A-Z]{2}[0-9]{2}[\s]?([0-9]{4}[\s]?){4,6}[0-9]{1,4}\b/g,
  },
  phone: {
    label: 'Teléfono',
    confidence: 'high',
    // Contextual: after "tel", "celular", etc. — captures broadly after a phone label
    // Non-contextual: requires country code prefix (+XX) to avoid matching random numbers
    // Negative lookahead/lookbehind prevents matching 12+ digit sequences (CUIT, RUT, etc.)
    re: /(?<=\b(?:tel[eé]fono|tel\.?|celular|cel\.?|m[oó]vil|fax|whatsapp|wsp|contacto)\s*[:\-]?\s*)(?!\d{12,})[\+\d][\d\s\-\(\)\.]{6,16}\d\b|\b\+\d{1,3}[\s\-]?\(?\d{1,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4}\b/g,
  },
  email: {
    label: 'Email',
    confidence: 'high',
    re: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
  },
  // addressCtx detects the address VALUE after common field labels.
  // Requires the captured text to contain at least a number (street number, floor, etc.)
  // Stops at sentence boundaries. Post-processing in findMatchPositions trims legal keywords.
  addressCtx: {
    label: 'Dirección',
    confidence: 'medium',
    re: /(?<=\b(?:domicilio(?:\s+(?:social|legal|fiscal|real|especial|constituido))?\s*(?:(?:en|sito\s+en|ubicado\s+en)\s*)?|direcci[oó]n(?:\s+(?:postal|fiscal|legal))?\s*|residencia|domiciliad[ao](?:\s+en)?)\s*[:\-]?\s*)[A-ZÁÉÍÓÚÜÑ](?:[^\n;.]|\.(?!\s[A-ZÁÉÍÓÚÜÑ])){2,40}\d+(?:[^\n;.]|\.(?!\s[A-ZÁÉÍÓÚÜÑ])){0,80}/gi,
  },
  address: {
    label: 'Dirección',
    confidence: 'medium',
    re: /\b(?:calle|c\/|av(?:d(?:a)?|en(?:ida)?)?\.?|plaza|pza\.?|paseo|pso\.?|camino|ronda|travesía|bulevar|bv\.?|pol[ií]gono|urb\.?|urbanización|pasaje|pje\.?|diagonal|diag\.?)\s+(?:[^\n;.]|\.(?!\s[A-ZÁÉÍÓÚÜÑ]))+/gi,
  },
  // Addresses without a street-type prefix: "Cerrito 517, Montevideo"
  // Confidence low (opt-in) because without a prefix the pattern can also match
  // contract references like "Artículo 32".  The comma+city requirement is
  // mandatory to reduce false positives — bare "Cerrito 517" is not matched.
  addressInline: {
    label: 'Dirección',
    confidence: 'low',
    re: /(?<![A-Za-záéíóúüñÁÉÍÓÚÜÑ\d])[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{3,23}(?:\s+[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{3,23}){0,2}\s+\d{2,5}(?:\s*,\s*[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{3,23}(?:\s+[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{3,23}){0,2})/g,
  },
  postcode: {
    label: 'Código Postal',
    confidence: 'medium',
    // Require "C.P.", "CP", "código postal", or "cod. postal" prefix to avoid matching
    // arbitrary 5-digit numbers in legal documents (amounts, article numbers, etc.)
    re: /\b(?:C\.?\s*P\.?\s*[:\s]?|c[oó]digo\s+postal\s*[:\s]?|cod\.?\s*postal\s*[:\s]?)[0-9]{4,5}\b/gi,
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
  // nit: Colombian NIT (Número de Identificación Tributaria)
  nit: {
    label: 'NIT',
    confidence: 'high',
    re: /\b(?:NIT|N\.I\.T\.?)\s*(?:N[ºo°]\.?\s*|[#:\-]\s*)?\d{3}\.?\d{3}\.?\d{3}[\-]\d\b|\b(?:NIT|N\.I\.T\.?)\s*(?:N[ºo°]\.?\s*|[#:\-]\s*)?\d{9,10}[\-]?\d?\b/gi,
  },
  // cedula: Colombian/Venezuelan cédula de ciudadanía / identidad
  cedula: {
    label: 'Cédula',
    confidence: 'high',
    re: /\b(?:c[eé]dula(?:\s+de\s+(?:ciudadan[ií]a|identidad|extranjer[ií]a))?|C\.?C\.?|C\.?E\.?)\s*(?:N[ºo°]\.?\s*|[#:\-]\s*)?\d[\d.]{5,15}\d\b/gi,
  },
  // rutLong: Uruguayan RUT without dash (12+ digit number after "Rol Único Tributario" or "RUT" keyword)
  rutLong: {
    label: 'RUT',
    confidence: 'high',
    re: /(?<=\b(?:R(?:ol|egistro)\s+[UÚú]nico\s+Tributario|RUT|R\.U\.T\.?)\s*(?:N[ºo°]\.?\s*|[#:\-]\s*)?)\d{10,14}\b/gi,
  },
  // bankAccount: bank account numbers after contextual keywords
  bankAccount: {
    label: 'Cuenta Bancaria',
    confidence: 'high',
    re: /(?<=\b(?:n[uú]mero\s+de\s+(?:cuenta|cta)|cuenta(?:\s+(?:bancaria|corriente|de\s+ahorro))?|cta|n[oº°]\.?\s*(?:de\s+)?(?:cuenta|cta))\s*[.:\-#Nº°]?\s*)\d[\d\-\s]{6,24}\d\b/gi,
  },
  // clabe: Mexican CLABE (Clave Bancaria Estandarizada) — 18 digits, may have spaces
  clabe: {
    label: 'CLABE',
    confidence: 'high',
    re: /(?<=\b(?:CLABE|clave\s+bancaria(?:\s+estandarizada)?)\s*(?:\(\s*CLABE\s*\))?\s*[:\-]?\s*)\d[\d\s]{15,22}\d\b/gi,
  },
  // swift: SWIFT/BIC bank codes (8 or 11 alphanumeric chars)
  swift: {
    label: 'SWIFT',
    confidence: 'high',
    re: /(?<=\b(?:swift|bic|swift\/bic|código\s+swift|codigo\s+swift)\s*[:\-]?\s*)[A-Z0-9]{8,11}\b/gi,
  },
  // companyAlias: company names defined with "en adelante" pattern
  // e.g., (en adelante el "PRESTADOR" y/o "ÜMA") or (en adelante "FARMATODO")
  companyAlias: {
    label: 'Empresa',
    confidence: 'high',
    re: /(?<=en\s+adelante\s+(?:el\s+|la\s+)?[""«']\s*(?:(?:PRESTADOR|CLIENTE|PROVEEDOR|CONTRATANTE|LICENCIANTE|LICENCIATARIO)\s*[""\u201D»']\s*y\/o\s*[""«'\u201C]\s*)?)[A-ZÁÉÍÓÚÜÑ][A-ZÁÉÍÓÚÜÑa-záéíóúüñ&]{0,25}(?:[ \t]+[A-ZÁÉÍÓÚÜÑa-záéíóúüñ]{1,25}){0,3}(?=\s*[""\u201D»'])/gi,
  },
  // umaAlias: ÜMA / UMA brand — always anonymized in all variants
  umaAlias: {
    label: 'Empresa',
    confidence: 'high',
    // \b doesn't work with Ü (non-ASCII), so we use a lookbehind for word boundary
    re: /(?<![A-Za-záéíóúüñÁÉÍÓÚÜÑ\w])[ÜüUu]MA(?:\s+(?:Salud|Health))?(?![A-Za-záéíóúüñÁÉÍÓÚÜÑ\w])/g,
  },
  // whole (with its legal suffix) and not partially consumed as a person's name.
  company: {
    label: 'Empresa',
    confidence: 'medium',
    // Two alternatives:
    // 1. Trade-name followed by parenthetical legal entity
    // 2. Standard company: capitalized words + mandatory legal suffix
    //    Accepts comma before suffix: "Deksia México, S.A. de C.V."
    //    Accepts "SA DE CV" without periods
    re: /(?<![A-Za-záéíóúüñÁÉÍÓÚÜÑ])[A-ZÁÉÍÓÚÜÑ][A-ZÁÉÍÓÚÜÑa-záéíóúüñ&]{1,25}(?:\s+(?:(?:y|&|de|del)\s+)?[A-ZÁÉÍÓÚÜÑ][A-ZÁÉÍÓÚÜÑa-záéíóúüñ]{1,25}){0,2}\s*\(\s*[A-ZÁÉÍÓÚÜÑ][A-ZÁÉÍÓÚÜÑa-záéíóúüñ&]{1,25}(?:\s+(?:(?:y|&|de|del)\s+)?[A-ZÁÉÍÓÚÜÑ][A-ZÁÉÍÓÚÜÑa-záéíóúüñ]{1,25}){0,3}[,]?\s+(?:S\.?A\.?\s+[Dd][Ee]\s+C\.?V\.?|S\.?(?:de\s+)?R\.?L\.?\s+[Dd][Ee]\s+C\.?V\.?|S\.A\.S\.?|S\.?R\.?L\.?|S\.?A\.?|S\.C\.S\.?|S\.C\.?|Ltda?\.?|Inc\.?|Corp\.?|GmbH|B\.V\.?|LLC\.?|LLP\.?|PLC\.?|A\.C\.?|Asociaci[oó]n\s+Civil)\.?\s*\)|(?<![A-Za-záéíóúüñÁÉÍÓÚÜÑ])[A-ZÁÉÍÓÚÜÑ][A-ZÁÉÍÓÚÜÑa-záéíóúüñ&]{1,25}(?:\s+(?:(?:y|&|de|del)\s+)?[A-ZÁÉÍÓÚÜÑ][A-ZÁÉÍÓÚÜÑa-záéíóúüñ]{1,25}){0,3}[,]?\s+(?:S\.?A\.?\s+[Dd][Ee]\s+C\.?V\.?|S\.?(?:de\s+)?R\.?L\.?\s+[Dd][Ee]\s+C\.?V\.?|S\.A\.S\.?|S\.?R\.?L\.?|S\.?A\.?|S\.C\.S\.?|S\.C\.?|Ltda?\.?|Inc\.?|Corp\.?|GmbH|B\.V\.?|LLC\.?|LLP\.?|PLC\.?|A\.C\.?|Asociaci[oó]n\s+Civil)(?=[\s,;:\n\.)]|$)/gi,
  },
  names: {
    label: 'Nombre',
    confidence: 'high',
    // Require a clear word boundary and the title must be preceded by whitespace or
    // start of line. The negative lookbehind prevents matching the trailing "d" in words
    // like "titularidad", "propiedad", "sociedad", etc.
    re: /(?<![A-Za-záéíóúüñÁÉÍÓÚÜÑ])(?:Don|Doña|Sr\.?a?\.?|Dr\.?a?\.?|Lic\.?|Excm[ao]\.?|Ilm[ao]\.?|Prof\.?)\s+[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{1,20}(?:\s+(?:de\s+)?[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{1,20}){0,3}/g,
  },
  namesCtx: {
    label: 'Nombre',
    confidence: 'high',
    // \b after the keyword group ensures the keyword is a complete word.
    // Uses [ \t]+ in name capture to prevent crossing line boundaries.
    re: /(?<=\b(?:paciente|nombre\s+(?:y\s+)?apellido|apellido\s+(?:y\s+)?nombre|nombre\s+completo|apellido(?:s)?|nombre(?:s)?|titular|solicitante|requirente|interesado|firmante|beneficiario|compareciente|declarante|denunciante|imputado|acusado|causante|heredero|propietario|apoderado|asegurado|afiliado|a\s+nombre\s+de|aclaraci[oó]n|atenci[oó]n|si\s+es\s+a[l]?)\b\s*[:\-]?\s*)[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{1,20}(?:[ \t]+[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{1,20}){1,5}/gi,
  },
  // namesPartyList: names in numbered party lists like "(1) Deksia... y (2) Alma Ivette Islas Hernández"
  // Only matches TitleCase sequences after (N) where followed by legal role indicators
  namesPartyList: {
    label: 'Nombre',
    confidence: 'medium',
    re: /(?<=\(\d\)\s+)[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{2,19}(?:[ \t]+(?:de[ \t]+)?[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{2,19}){1,5}(?=\s*[,\n]|\s+(?:por\s+propio|en\s+su\s+ca[lr][aá]cter|como\s+represent))/gi,
  },
  namesApostrophe: {
    label: 'Nombre',
    confidence: 'medium',
    // Italian/Irish-style surnames: D'Alto, D'Angelo, O'Brien, Dell'Orso
    // Matches: 1-4 capital letters, optional apostrophe (straight or curly), then rest
    re: /\b[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{0,3}['\u2019][A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{2,20}(?:\s+[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{2,20}){0,3}\b/g,
  },
  namesTitleCase: {
    label: 'Nombre',
    confidence: 'medium',
    // Context-aware: only match TitleCase sequences after legal context phrases.
    // Removed (i)/(ii)/(iii) triggers — too many false positives in legal clauses.
    re: /(?<=\b(?:representad[ao]?\s+(?:en\s+este\s+acto\s+)?por|por\s+(?:una\s+parte|la\s+otra\s+parte|propio\s+derecho)|en\s+adelante|a\s+favor\s+de|a\s+nombre\s+de|otorgad[ao]\s+por|suscrit[ao]\s+por|firmad[ao]\s+por|apoderad[ao]|notificarse?\s+a|con\s+domicilio|ciudadan[ao]|señor[ae]?s?|atenci[oó]n:?|que\s+celebran:?)\s+)[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{2,19}(?:[ \t]+(?:de[ \t]+)?[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]{2,19}){1,5}/gi,
  },
  namesAllCaps: {
    label: 'Nombre',
    confidence: 'medium',
    // Context-aware: only match ALL-CAPS sequences after legal context phrases.
    // Uses \s+ to allow crossing line breaks (common in PDF extraction where
    // "ESTE\nACTO POR FRANCISCO NEFTALI MORALES\nGUERRERO" spans multiple lines).
    // The strict lookbehind context prevents false positives even with \s+.
    re: /(?<=\b(?:representad[ao]?\s+(?:en\s+este\s+acto\s+)?por|(?:ESTE\s+)?ACTO\s+POR|en\s+adelante|a\s+favor\s+de|a\s+nombre\s+de|suscrit[ao]\s+por|firmad[ao]\s+por|atenci[oó]n:?)\s+)[A-ZÁÉÍÓÚÜÑ]{3,20}(?:\s+[A-ZÁÉÍÓÚÜÑ]{3,20}){1,5}\b/gi,
  },
  // namesSignature: names in signature blocks — ALL CAPS names that appear after
  // a line of underscores/dashes (common pattern: "____\nFRANCISCO JAVIER FIRPO")
  namesSignature: {
    label: 'Nombre',
    confidence: 'medium',
    re: /(?<=_{3,}[)\s]*\n\s*)[A-ZÁÉÍÓÚÜÑ][A-ZÁÉÍÓÚÜÑa-záéíóúüñ.]{1,20}(?:[ \t]+[A-ZÁÉÍÓÚÜÑa-záéíóúüñ.]{1,20}){1,6}/gm,
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
  // Spanish articles and determiners (prevent "La Empresa", "El Cliente" etc.)
  'la','el','los','las','una','un',
  'esta','este','estas','estos','esa','ese','esas','esos',
  'dicha','dicho','dichas','dichos',
  'toda','toda','todos','todas',
  // Contract roles (PARTE REVELADORA, EMPRESA COLABORADORA, etc.)
  'parte','cliente','proveedor','contratante','colaboradora','colaborador',
  'reveladora','revelador','receptora','receptor','emisora','emisor',
  'locatario','locataria','arrendatario','arrendataria','locador','locadora',
  'comitente','mandante','mandatario',
  // Contract boilerplate terms that appear in ALL CAPS
  'presente','considerando','visto','resultando',
  'servicios','oferta','propuesta','factura','cobro','pago',
  'vigencia','rescisión','terminación','vencimiento',
  'objeto','alcance','plazo','monto','precio','tarifa',
  // Generic org terms
  'compañía','asociación','fundación','sociedad','federación',
  'sindicato','gremio','cámara','consorcio',
  // Org-type trigger words (suppress "Instituto Nacional", "Hospital Federal", etc.
  // when ALL words are common – private orgs like "Instituto Ramírez" still match)
  'instituto','hospital','clínica','clinica','escuela','centro',
  'consultorio','laboratorio','farmacia','corporación','corporacion',
  // Spanish number words (prevent "CUATRO MILLONES", "QUINIENTOS MIL", etc.)
  'uno','dos','tres','cuatro','cinco','seis','siete','ocho','nueve','diez',
  'once','doce','trece','catorce','quince','veinte','treinta','cuarenta',
  'cincuenta','sesenta','setenta','ochenta','noventa',
  'cien','ciento','doscientos','doscientas','trescientos','trescientas',
  'cuatrocientos','cuatrocientas','quinientos','quinientas',
  'seiscientos','seiscientas','setecientos','setecientas',
  'ochocientos','ochocientas','novecientos','novecientas',
  'mil','millón','millones','billón','billones','trillón','trillones',
  // Currency words (prevent "PESOS ARGENTINOS", "DÓLARES AMERICANOS", etc.)
  'pesos','dólares','dolares','euros','centavos','dólar','dolar','euro',
  'peso','real','reales','yen','yenes','libra','libras','corona','coronas',
  'franco','francos','bolívar','bolivar','soles','sol',
  // Geographic terms (prevent "Buenos Aires", "Ciudad Autónoma", "República Argentina", etc.)
  'buenos','aires','ciudad','autónoma','autonoma','república','republica',
  'federal','provincial','municipal','bonaerense',
  'argentina','argentino','argentinos','argentina','argentinas',
  'méxico','mexico','mexicano','mexicanos','mexicana','mexicanas',
  'uruguay','uruguayo','uruguayos','uruguaya','uruguayas',
  'paraguay','paraguayo','paraguayos','paraguaya','paraguayas',
  'chile','chileno','chilenos','chilena','chilenas',
  'perú','peru','peruano','peruanos','peruana','peruanas',
  'colombia','colombiano','colombianos','colombiana','colombianas',
  'venezuela','venezolano','venezolanos','venezolana','venezolanas',
  'brasil','brazil','brasileño','brasilena',
  'españa','espana','español','espanol','española','espanola','españoles',
  'estados','unidos',
  'nacional','regional','estadual','distrital',
  // Contract defined terms (prevent "Las Partes", "Datos Personales", "Fecha Efectiva", etc.)
  'partes','parte','datos','personales','información','informacion',
  'confidencial','efectiva','efectivo','vigente',
  'adicional','siguiente','respectiva','respectivo',
  'referida','referido','indicada','indicado','mencionada','mencionado',
  'digital','salud','seguridad','privacidad','protección','proteccion',
  // Common prepositions/conjunctions that land in two-word TitleCase matches
  'con','por','para','sin','sobre','bajo','ante','tras','según','segun',
  'entre','hasta','desde','durante','mediante','excepto','salvo',
  'de','del','al','a','en','que','se','no','ni','o','y','e','u',
  // Legal/contractual terms commonly appearing in TitleCase or ALL CAPS
  'cláusula','clausula','obligaciones','derechos','responsabilidad',
  'responsabilidades','indemnización','indemnizacion','penalidad',
  'penalidades','jurisdicción','jurisdiccion','competencia','arbitraje',
  'mediación','mediacion','notificación','notificacion','modificación',
  'modificacion','cesión','cesion','subcontratación','subcontratacion',
  'confidencialidad','exclusividad','garantía','garantia',
  'garantías','garantias','propiedad','intelectual','industrial',
  'prevención','prevencion','riesgo','riesgos','factores',
  'psicosocial','psicosociales','violencia','laboral','entorno',
  'organizacional','favorable','costos','cubiertos','base',
  'canal','comunicación','comunicacion','slack','notificar',
  'establecer','difundir','contemplar','promover','promoción','promocion',
  'política','politica','programa','procedimiento','protocolo',
  'cumplimiento','incumplimiento','resolución','resolucion',
  'renovación','renovacion','prórroga','prorroga','extensión','extension',
  'contraprestación','contraprestacion','facturación','facturacion',
  'tributario','fiscal','impuesto','impuestos','contribución','contribucion',
  'registro','único','unico','inscripción','inscripcion',
  'domicilio','dirección','direccion','ubicación','ubicacion',
  'oriental','occidental','septentrional','meridional',
  'prestación','prestacion','servicios','marco','general',
  'especial','particular','específico','especifico','adicionales',
  'anexo','apéndice','apendice','sección','seccion','capítulo','capitulo',
  'titularidad','licencia','transmisión','transmision','otorgamiento',
  'software','softwares','aplicación','aplicacion','plataforma',
  'desarrollo','implementación','implementacion','mantenimiento',
  'soporte','consultoría','consultoria','asesoría','asesoria',
  // Words that cause false positives in contract text
  'uso','licencia','entre','otro','otra','otros','otras',
  'deberá','debera','podrá','podra','tendrá','tendra',
  'ingresar','acceder','utilizar','operar','gestionar',
  'apoderado','apoderada','representante','legal','legales',
  'prestador','contratista','beneficiaria','cedente','cesionario',
  'implementación','implementacion','descripción','descripcion',
  'fases','fase','etapa','etapas','conformidad','establecido',
  'anexo','servicios','contrato','acuerdo',
  'carrera','avenida','calle','piso','oficina',
  'bogotá','bogota','montevideo','lima','santiago','quito',
  'caracas','medellín','medellin','barranquilla','cali',
  // Pronouns/determiners that appear after legal triggers like 'a favor de'
  'cualquiera','cualquier','alguna','alguno','algunos','algunas',
  'ninguna','ninguno','ningún','ningun','ambas','ambos',
  'cada','demás','demas','ellas','ellos','misma','mismo','mismas','mismos',
  'tercera','tercero','terceras','terceros','aquella','aquellas',
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
 * Returns true when the character immediately preceding index is an opening
 * quote (straight or typographic).  Used to suppress defined contract terms
 * like "Las Partes" or "Fecha Efectiva" that appear inside quotation marks.
 */
function _isPrecededByQuote(text, index) {
  if (index === 0) return false;
  return /["'"«\u201C\u2018\u00AB]/.test(text[index - 1]);
}

// Pattern keys whose matches should be discarded when preceded by a quote char
// (the term is a defined contract label, not a real person/company name).
// namesCtx is excluded here because its lookbehind context is already strong.
const QUOTE_SENSITIVE = new Set([
  'names', 'namesApostrophe', 'namesTitleCase', 'namesAllCaps',
]);

/**
 * Common legal/contractual phrases that should never be treated as person names.
 * Checked as exact lowercase matches against the full matched text.
 */
const LEGAL_PHRASES = new Set([
  'registro único tributario', 'registro unico tributario',
  'república oriental', 'republica oriental',
  'ciudad de méxico', 'ciudad de mexico',
  'estados unidos mexicanos', 'correo electrónico', 'correo electronico',
  'propiedad intelectual', 'datos personales', 'razón social', 'razon social',
  'objeto social', 'representante legal', 'poder especial', 'poder general',
  'buena fe', 'libre voluntad', 'pleno derecho', 'común acuerdo', 'comun acuerdo',
  'mutuo acuerdo', 'caso fortuito', 'fuerza mayor', 'daños y perjuicios',
  'danos y perjuicios', 'acto jurídico', 'acto juridico', 'hecho ilícito',
  'plazo fijo', 'tiempo determinado', 'tiempo indeterminado',
  'riesgo psicosocial', 'violencia laboral', 'entorno organizacional',
  'prestación de servicios', 'prestacion de servicios',
  'contrato marco', 'marco de prestación', 'marco de prestacion',
  'política de prevención', 'politica de prevencion',
  'centro de trabajo', 'riesgos psicosociales',
  'canal de comunicación', 'canal de comunicacion',
  'propiedad exclusiva', 'titularidad exclusiva',
]);

/**
 * Returns true if the matched text is a known legal/contractual phrase.
 */
function _isLegalPhrase(matchedText) {
  return LEGAL_PHRASES.has(matchedText.toLowerCase().trim());
}

/**
 * Returns true if the match is immediately preceded by legal boilerplate context
 * that indicates the text is part of a clause, not a name.
 */
function _isInLegalClause(text, index) {
  // Look back up to 60 chars for legal clause indicators
  const lookback = text.slice(Math.max(0, index - 60), index).toLowerCase();
  const clauseIndicators = [
    'consisten en', 'contemplen la', 'comprende la', 'incluye la',
    'así como', 'asi como', 'de acuerdo con', 'conforme a',
    'en virtud de', 'con base en', 'a efecto de', 'con el fin de',
    'por concepto de', 'en relación con', 'en relacion con',
    'derivarse de', 'consistir en', 'referirse a',
  ];
  return clauseIndicators.some(ind => lookback.includes(ind));
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
      // 1. Suppress generic name patterns when every word is a known stopword
      if ((key === 'namesTitleCase' || key === 'namesAllCaps' || key === 'company') &&
          _allStopwords(m[0])) {
        continue;
      }
      // 2. Suppress name matches that are quoted contract-defined terms
      if (QUOTE_SENSITIVE.has(key) && _isPrecededByQuote(text, m.index)) {
        continue;
      }
      // 3. Suppress matches that are known legal/contractual phrases
      if (_isLegalPhrase(m[0])) {
        continue;
      }
      // 4. Suppress name-like matches that appear inside legal clause context
      if ((key === 'namesTitleCase' || key === 'namesAllCaps') && _isInLegalClause(text, m.index)) {
        continue;
      }
      // 5. Suppress very short matches (2-3 chars) from name patterns — too ambiguous
      if ((key === 'names' || key === 'namesCtx' || key === 'namesTitleCase' || key === 'namesAllCaps') &&
          m[0].trim().length < 5) {
        continue;
      }
      // 6. For company matches: trim leading stopwords so "USO DE SOFTWARE Entre DEKSIA S.A."
      //    becomes "DEKSIA S.A." — only keep the actual company name + legal suffix.
      if (key === 'company') {
        const words = m[0].split(/\s+/);
        // Find the legal suffix position
        const suffixIdx = words.findIndex(w => /^(?:S\.A|S\.R|S\.C|S\.de|Ltda|Inc|Corp|GmbH|B\.V|LLC|LLP|PLC|A\.C)/i.test(w));
        if (suffixIdx > 0) {
          // Walk backwards from suffix to find where the real company name starts
          let nameStart = suffixIdx - 1;
          while (nameStart > 0 && !NAME_STOPWORDS.has(words[nameStart - 1].toLowerCase().replace(/[.,;:()]/g, ''))) {
            nameStart--;
          }
          if (nameStart > 0) {
            // Recalculate start position by counting chars of trimmed words
            const trimmedText = words.slice(nameStart).join(' ');
            const newStart = m.index + m[0].indexOf(trimmedText);
            if (newStart > m.index) {
              matches.push({ start: newStart, end: m.index + m[0].length, label, confidence: confidence || 'medium' });
              continue;
            }
          }
        }
      }
      // 7. For namesCtx: suppress if the captured text (after the keyword) is all
      //    lowercase words or stopwords — real names have capitalized words
      if (key === 'namesCtx') {
        const capturedWords = m[0].trim().split(/\s+/);
        const hasProperNoun = capturedWords.some(w =>
          /^[A-ZÁÉÍÓÚÜÑ]/.test(w) && !NAME_STOPWORDS.has(w.toLowerCase())
        );
        if (!hasProperNoun) continue;
      }
      // 8. For address matches: trim at legal clause keywords that indicate
      //    the address has ended and a new clause begins
      if (key === 'address' || key === 'addressCtx') {
        const matched = m[0];
        const cutPatterns = /,\s*(?:representad|identificad|constituid|sociedad|con\s+(?:NIT|RUT|RFC|C[eé]dula|Rol)|en\s+su\s+ca[lr][aá]cter)/i;
        const cutMatch = cutPatterns.exec(matched);
        if (cutMatch) {
          const trimmedEnd = m.index + cutMatch.index;
          if (trimmedEnd > m.index + 5) {
            matches.push({ start: m.index, end: trimmedEnd, label, confidence: confidence || 'medium' });
            continue;
          }
        }
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

/**
 * mailward - public API.
 *
 * Everything here is usable as a library, not just through the CLI:
 *
 *   import { auditDomain } from 'mailward';
 *   const report = await auditDomain('example.com');
 *   console.log(report.grade, report.findings);
 */

export { auditDomain } from './audit.js';
export { Resolver, decodeTxt, TYPE, RCODE } from './resolver.js';
export { auditSpf, parseSpfRecord, selectSpfRecords, SPF_LOOKUP_LIMIT } from './spf.js';
export { auditDmarc, parseDmarcRecord } from './dmarc.js';
export { auditDkim, parseDkimRecord, inspectKey, COMMON_SELECTORS } from './dkim.js';
export { auditMx } from './mx.js';
export { auditMtaSts, auditTlsRpt, auditBimi, auditDnssec } from './policies.js';
export { buildFindings, scoreFindings, SEVERITY } from './findings.js';
export { organizationalDomain } from './publicsuffix.js';
export { parseAggregateReport, readReportFile, summarizeReports } from './report/index.js';

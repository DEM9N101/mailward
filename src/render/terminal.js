/**
 * Terminal output.
 *
 * The report has to be readable by someone who does not already know what
 * DMARC alignment is, because that is exactly who needs it. So findings lead
 * with the consequence in plain words and end with a record to paste.
 */

const useColor =
  process.env.NO_COLOR === undefined &&
  process.env.TERM !== 'dumb' &&
  Boolean(process.stdout.isTTY);

const paint = (code) => (text) => (useColor ? `\u001b[${code}m${text}\u001b[0m` : String(text));

export const style = {
  bold: paint('1'),
  dim: paint('2'),
  red: paint('31'),
  green: paint('32'),
  yellow: paint('33'),
  blue: paint('34'),
  magenta: paint('35'),
  cyan: paint('36'),
  grey: paint('90'),
};

const SEVERITY_STYLE = {
  critical: { color: style.red, marker: '●', heading: 'CRITICAL' },
  high: { color: style.red, marker: '●', heading: 'HIGH' },
  medium: { color: style.yellow, marker: '●', heading: 'MEDIUM' },
  low: { color: style.blue, marker: '○', heading: 'LOW' },
  info: { color: style.grey, marker: '·', heading: 'NOTES' },
  good: { color: style.green, marker: '✓', heading: 'LOOKS GOOD' },
};

const GRADE_COLOR = {
  A: style.green,
  B: style.green,
  C: style.yellow,
  D: style.red,
  F: style.red,
};

/**
 * @param {object} report Result of auditDomain().
 * @param {object} [options]
 * @param {boolean} [options.tree] Also draw the SPF include graph.
 */
export function renderAudit(report, options = {}) {
  const lines = [];
  const push = (line = '') => lines.push(line);

  push();
  push(
    `  ${style.bold('mailward')}  ${style.cyan(report.domain)}  ` +
      style.grey(`${report.meta.resolver} · ${report.meta.dnsQueries} queries · ${(report.meta.durationMs / 1000).toFixed(1)}s`),
  );
  push();

  const gradeColor = GRADE_COLOR[report.grade] ?? style.yellow;
  push(`  ${gradeColor(style.bold(`Grade ${report.grade}`))}  ${style.grey(`${report.score}/100`)}`);
  for (const note of report.notes ?? []) push(`  ${style.grey(note)}`);
  push();

  for (const line of summaryRows(report)) push(`  ${line}`);
  push();

  const groups = new Map();
  for (const finding of report.findings) {
    if (!groups.has(finding.severity)) groups.set(finding.severity, []);
    groups.get(finding.severity).push(finding);
  }

  for (const severity of ['critical', 'high', 'medium', 'low', 'info', 'good']) {
    const group = groups.get(severity);
    if (!group?.length) continue;

    const meta = SEVERITY_STYLE[severity];
    push(`  ${meta.color(style.bold(meta.heading))}`);
    push();

    for (const finding of group) {
      push(`    ${meta.color(meta.marker)} ${style.bold(finding.title)}`);
      for (const line of wrap(finding.detail, 76)) push(`      ${style.grey(line)}`);
      if (finding.fix) {
        push();
        for (const line of finding.fix.split('\n')) push(`      ${style.green(line)}`);
      }
      push();
    }
  }

  if (options.tree && report.spf.found) {
    push(`  ${style.bold('SPF LOOKUP TREE')}`);
    push();
    for (const line of renderSpfTree(report.spf)) push(`    ${line}`);
    push();
  }

  return lines.join('\n');
}

function summaryRows(report) {
  const rows = [];
  const label = (name) => style.grey(name.padEnd(9));

  const dmarc = report.dmarc;
  if (dmarc.found) {
    const policy = dmarc.effectivePolicy ?? 'none';
    const color = policy === 'reject' ? style.green : policy === 'quarantine' ? style.yellow : style.red;
    rows.push(
      `${label('DMARC')}${color(`p=${policy}`.padEnd(16))}${style.grey(dmarc.inheritedFrom ? `inherited from ${dmarc.inheritedFrom}` : dmarc.recordName)}`,
    );
  } else {
    rows.push(`${label('DMARC')}${style.red('not published'.padEnd(16))}`);
  }

  const spf = report.spf;
  if (spf.found) {
    const used = spf.lookups.used;
    const color = spf.lookups.exceeded ? style.red : used >= 8 ? style.yellow : style.green;
    rows.push(
      `${label('SPF')}${color(`${used}/${spf.lookups.limit} lookups`.padEnd(16))}${style.grey(truncate(spf.record, 52))}`,
    );
  } else {
    rows.push(`${label('SPF')}${style.red('not published'.padEnd(16))}`);
  }

  const dkim = report.dkim;
  if (dkim.skipped) {
    rows.push(`${label('DKIM')}${style.grey('skipped'.padEnd(16))}`);
  } else if (dkim.found) {
    const selectors = dkim.keys.map((k) => k.selector).join(', ');
    rows.push(
      `${label('DKIM')}${style.green(`${dkim.keys.length} key${dkim.keys.length > 1 ? 's' : ''}`.padEnd(16))}${style.grey(truncate(selectors, 52))}`,
    );
  } else {
    rows.push(
      `${label('DKIM')}${style.yellow('none found'.padEnd(16))}${style.grey(`${dkim.selectorsProbed} selectors probed`)}`,
    );
  }

  const mx = report.mx;
  if (mx.nullMx) rows.push(`${label('MX')}${style.green('null MX'.padEnd(16))}${style.grey('accepts no mail, by design')}`);
  else if (mx.found)
    rows.push(
      `${label('MX')}${style.green(`${mx.hosts.length} host${mx.hosts.length > 1 ? 's' : ''}`.padEnd(16))}${style.grey(truncate(mx.hosts.map((h) => h.host).join(', '), 52))}`,
    );
  else rows.push(`${label('MX')}${style.yellow('none'.padEnd(16))}`);

  const mtaSts = report.mtaSts;
  rows.push(
    `${label('MTA-STS')}` +
      (mtaSts.found
        ? (mtaSts.mode === 'enforce' ? style.green : style.yellow)(`${mtaSts.mode ?? 'announced'}`.padEnd(16))
        : style.grey('not published'.padEnd(16))),
  );

  rows.push(
    `${label('TLS-RPT')}` + (report.tlsRpt.found ? style.green('published'.padEnd(16)) : style.grey('not published'.padEnd(16))),
  );

  if (report.dnssec.determinate) {
    rows.push(
      `${label('DNSSEC')}` + (report.dnssec.signed ? style.green('signed'.padEnd(16)) : style.grey('unsigned'.padEnd(16))),
    );
  }

  return rows;
}

/** Draw the include graph with the running lookup cost, so the expensive branches are obvious. */
export function renderSpfTree(spf) {
  const lines = [];

  const walk = (node, prefix, isLast, isRoot) => {
    if (!isRoot) {
      const connector = isLast ? '└─ ' : '├─ ';
      const cost = node.lookupsAfter - node.lookupsBefore;
      const suffix = node.error
        ? style.red(` ${node.error}`)
        : node.note
          ? style.grey(` ${node.note}`)
          : style.grey(` (${cost} lookup${cost === 1 ? '' : 's'} in this branch)`);
      lines.push(`${prefix}${connector}${style.cyan(node.domain)}${suffix}`);
    } else {
      lines.push(`${style.cyan(node.domain)} ${style.grey(`- ${spf.lookups.used}/${spf.lookups.limit} lookups total`)}`);
    }

    const childPrefix = isRoot ? '' : prefix + (isLast ? '   ' : '│  ');
    const kids = node.children ?? [];
    kids.forEach((child, index) => walk(child, childPrefix, index === kids.length - 1, false));
  };

  if (spf.tree) walk(spf.tree, '', true, true);

  if (spf.lookups.attribution?.length) {
    lines.push('');
    lines.push(style.grey('cost per top-level term:'));
    for (const item of [...spf.lookups.attribution].sort((a, b) => b.cost - a.cost)) {
      lines.push(`  ${String(item.cost).padStart(2)}  ${item.term}`);
    }
  }

  return lines;
}

/** Render an aggregate-report summary. */
export function renderReportSummary(summary) {
  const lines = [];
  const push = (line = '') => lines.push(line);

  push();
  push(`  ${style.bold('mailward')}  ${style.cyan('DMARC aggregate reports')}`);
  push();

  const range = summary.dateRange.begin && summary.dateRange.end
    ? `${summary.dateRange.begin.toISOString().slice(0, 10)} to ${summary.dateRange.end.toISOString().slice(0, 10)}`
    : 'unknown period';

  push(`  ${style.grey('reports'.padEnd(12))}${summary.reportCount} from ${summary.organizations.length} provider${summary.organizations.length === 1 ? '' : 's'}`);
  push(`  ${style.grey('period'.padEnd(12))}${range}`);
  push(`  ${style.grey('domains'.padEnd(12))}${summary.domains.join(', ') || 'none'}`);
  push();

  const rate = (summary.passRate * 100).toFixed(1);
  const rateColor = summary.passRate >= 0.99 ? style.green : summary.passRate >= 0.95 ? style.yellow : style.red;
  push(`  ${style.bold('messages')}      ${summary.totalMessages.toLocaleString('en-US')}`);
  push(`  ${style.bold('authenticated')} ${rateColor(`${rate}%`)}  ${style.grey(`${summary.passing.toLocaleString('en-US')} passed, ${summary.failing.toLocaleString('en-US')} failed`)}`);
  push();

  const readinessColor =
    summary.readiness.level === 'ready' ? style.green : summary.readiness.level === 'not-ready' ? style.red : style.yellow;
  push(`  ${readinessColor(style.bold('Enforcement readiness'))}`);
  for (const line of wrap(summary.readiness.reason, 76)) push(`    ${style.grey(line)}`);
  push();

  if (summary.sources.length > 0) {
    push(`  ${style.bold('SENDING SOURCES')}   ${style.grey('(by volume)')}`);
    push();
    push(`    ${style.grey('messages   pass    source')}`);
    for (const source of summary.sources.slice(0, 20)) {
      const pct = (source.passRate * 100).toFixed(0).padStart(3);
      const color = source.passRate >= 0.99 ? style.green : source.passRate >= 0.5 ? style.yellow : style.red;
      const name = source.sender ?? source.authDomains[0] ?? style.grey('unidentified');
      push(
        `    ${String(source.messages).padStart(8)}   ${color(`${pct}%`)}   ${source.ip.padEnd(24)} ${style.grey(truncate(name, 28))}`,
      );
    }
    if (summary.sources.length > 20) push(`    ${style.grey(`… and ${summary.sources.length - 20} more`)}`);
    push();
  }

  if (summary.failingSources.length > 0) {
    push(`  ${style.red(style.bold('FAILING SOURCES'))}   ${style.grey('(fix or authorise these before enforcing)')}`);
    push();
    for (const source of summary.failingSources.slice(0, 10)) {
      const name = source.sender ? ` ${style.cyan(source.sender)}` : '';
      push(`    ${style.red('●')} ${style.bold(source.ip)}${name}  ${style.grey(`${source.failing} failing of ${source.messages}`)}`);
      const detail = [];
      if (source.spfPassing > 0) detail.push(`SPF passes on ${source.spfPassing}`);
      if (source.dkimPassing > 0) detail.push(`DKIM passes on ${source.dkimPassing}`);
      if (source.authDomains.length) detail.push(`authenticating as ${source.authDomains.slice(0, 3).join(', ')}`);
      if (detail.length) push(`      ${style.grey(detail.join(' · '))}`);
    }
    push();
  }

  return lines.join('\n');
}

/* --------------------------------------------------------------- helpers */

function wrap(text, width) {
  const out = [];
  for (const paragraph of String(text).split('\n')) {
    let line = '';
    for (const word of paragraph.split(/\s+/).filter(Boolean)) {
      if (line.length + word.length + 1 > width) {
        if (line) out.push(line);
        line = word;
      } else {
        line = line ? `${line} ${word}` : word;
      }
    }
    if (line) out.push(line);
  }
  return out;
}

function truncate(text, length) {
  const value = String(text ?? '');
  return value.length <= length ? value : `${value.slice(0, length - 1)}…`;
}

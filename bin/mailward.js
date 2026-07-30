#!/usr/bin/env node
/**
 * mailward CLI.
 */

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { auditDomain } from '../src/audit.js';
import { readReports, summarizeReports } from '../src/report/index.js';
import { renderAudit, renderReportSummary } from '../src/render/terminal.js';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

const HELP = `
  mailward - check that a domain's email is set up so nobody can spoof it,
             and read DMARC reports without uploading them anywhere.

  Usage
    mailward <domain> [options]
    mailward report <file-or-directory> [options]

  Audit options
    --selector <name>   extra DKIM selector to probe (repeatable)
    --fast              probe fewer DKIM selectors
    --no-dkim           skip DKIM probing entirely
    --tree              draw the SPF include graph with per-branch lookup cost
    --system-dns        use the OS resolver instead of DNS-over-HTTPS
    --timeout <ms>      per-query timeout (default 8000)

  Output
    --json              machine-readable output
    --fail-on <level>   exit 1 if any finding is at or above this severity
                        (critical, high, medium, low) - for CI and cron
    --no-color          disable colour (or set NO_COLOR=1)

    -h, --help          show this help
    -v, --version       show version

  Examples
    mailward example.com
    mailward example.com --tree
    mailward example.com --fail-on high
    mailward report ./dmarc-reports/
    mailward example.com --json > audit.json

  Nothing is uploaded and no account is needed. DNS queries go to Cloudflare
  and Google over HTTPS; with --system-dns they go wherever your OS points.
`;

async function main(argv) {
  const args = parseArgs(argv);

  if (args.help || args._.length === 0) {
    process.stdout.write(`${HELP}\n`);
    return 0;
  }

  if (args.version) {
    process.stdout.write(`${await readVersion()}\n`);
    return 0;
  }

  if (args.noColor) process.env.NO_COLOR = '1';

  if (args._[0] === 'report') {
    return runReport(args);
  }

  return runAudit(args);
}

async function runAudit(args) {
  const domain = args._[0];

  const report = await auditDomain(domain, {
    selectors: args.selectors,
    deepDkim: !args.fast,
    skipDkim: args.noDkim,
    systemDns: args.systemDns,
    timeoutMs: args.timeout,
  });

  if (args.json) {
    process.stdout.write(`${JSON.stringify(report, replacer, 2)}\n`);
  } else {
    process.stdout.write(`${renderAudit(report, { tree: args.tree })}\n`);
  }

  return exitCodeFor(report.findings, args.failOn);
}

async function runReport(args) {
  const path = args._[1];
  if (!path) {
    process.stderr.write('mailward report: give me a file or a directory of DMARC reports\n');
    return 2;
  }

  const { reports, errors } = await readReports(path);

  if (reports.length === 0) {
    process.stderr.write(
      `No readable DMARC reports found in ${path}\n` +
        (errors.length ? `${errors.length} file(s) could not be parsed.\n` : ''),
    );
    return 2;
  }

  const summary = summarizeReports(reports);

  if (args.json) {
    process.stdout.write(`${JSON.stringify({ summary, errors }, replacer, 2)}\n`);
  } else {
    process.stdout.write(`${renderReportSummary(summary)}\n`);
    if (errors.length > 0) {
      process.stderr.write(`\n  ${errors.length} file(s) could not be parsed:\n`);
      for (const error of errors.slice(0, 5)) {
        process.stderr.write(`    ${error.file}: ${error.message}\n`);
      }
    }
  }

  return 0;
}

function exitCodeFor(findings, failOn) {
  if (!failOn) return 0;
  const threshold = SEVERITY_ORDER.indexOf(failOn);
  if (threshold === -1) return 0;
  const triggered = findings.some((f) => {
    const rank = SEVERITY_ORDER.indexOf(f.severity);
    return rank !== -1 && rank <= threshold;
  });
  return triggered ? 1 : 0;
}

/** Sets and Dates are not JSON by default; make --json output stable. */
function replacer(_key, value) {
  if (value instanceof Set) return [...value];
  return value;
}

function parseArgs(argv) {
  const args = {
    _: [],
    selectors: [],
    json: false,
    tree: false,
    fast: false,
    noDkim: false,
    systemDns: false,
    noColor: false,
    help: false,
    version: false,
    timeout: undefined,
    failOn: undefined,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case '-h':
      case '--help':
        args.help = true;
        break;
      case '-v':
      case '--version':
        args.version = true;
        break;
      case '--json':
        args.json = true;
        break;
      case '--tree':
        args.tree = true;
        break;
      case '--fast':
        args.fast = true;
        break;
      case '--no-dkim':
        args.noDkim = true;
        break;
      case '--system-dns':
        args.systemDns = true;
        break;
      case '--no-color':
        args.noColor = true;
        break;
      case '--selector':
        args.selectors.push(argv[++i]);
        break;
      case '--timeout':
        args.timeout = Number(argv[++i]);
        break;
      case '--fail-on':
        args.failOn = String(argv[++i] ?? '').toLowerCase();
        break;
      default:
        if (arg.startsWith('--selector=')) args.selectors.push(arg.split('=')[1]);
        else if (arg.startsWith('--timeout=')) args.timeout = Number(arg.split('=')[1]);
        else if (arg.startsWith('--fail-on=')) args.failOn = arg.split('=')[1].toLowerCase();
        else if (arg.startsWith('-')) throw new Error(`unknown option "${arg}"`);
        else args._.push(arg);
    }
  }

  return args;
}

async function readVersion() {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(await readFile(join(here, '..', 'package.json'), 'utf8'));
    return pkg.version;
  } catch {
    return 'unknown';
  }
}

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err) => {
    process.stderr.write(`mailward: ${err.message}\n`);
    process.exitCode = 2;
  });

# mailward

Check that nobody can send email pretending to be your domain, and read your DMARC reports without uploading them to anyone.

One command. No account, no signup, no dependencies, nothing leaves your machine.

```bash
npx github:Mahmoud-ahmadi101/mailward example.com
```

```
  mailward  github.com  DNS-over-HTTPS · 18 queries · 0.3s

  Grade B  78/100

  DMARC    p=quarantine    _dmarc.github.com
  SPF      10/10 lookups   v=spf1 ip4:192.30.252.0/22 include:spf.protection.o…
  DKIM     skipped
  MX       1 host          github-com.mail.protection.outlook.com
  MTA-STS  not published
  TLS-RPT  not published
  DNSSEC   unsigned

  MEDIUM

    ● SPF uses 10 of 10 DNS lookups
      There is little headroom left. Adding one more vendor, or a vendor silently
      adding an include to their own record, will push this over the limit and
      break SPF for the whole domain.

      Trim the include chain now, while it is not yet an outage.
```

Every finding says what will actually happen to your mail, and ends with the record to paste into DNS.

## Why this exists

Google and Yahoo now require DMARC from anyone sending mail in volume. Get it wrong and your invoices land in spam, or somebody spoofs your domain and your customers get phished.

The tools that tell you what is wrong are almost all paid services. The free tiers are lead generation: they show you a red X, then ask for your email address to explain it. The one established open source option, parsedmarc, is good software that expects you to run Elasticsearch and Kibana next to it.

There is no money in a free version of this. That is the whole reason it does not exist, and the whole reason this does.

## What it checks

| Check | What it catches |
| --- | --- |
| **SPF** | Syntax, the ten lookup limit computed across the full include graph, void lookups, `+all`, deprecated `ptr`, broken includes, include loops, multiple records |
| **DMARC** | Syntax, policy strength, `pct`, subdomain policy, organizational domain inheritance, missing report addresses, and whether external report destinations have authorised you |
| **DKIM** | Key discovery across 71 known provider selectors, real RSA modulus length, revoked keys, keys left in testing mode |
| **MX** | Missing, unresolvable, and null MX |
| **MTA-STS** | Record, policy fetched over HTTPS, mode, `max_age`, and whether the policy actually covers your MX hosts |
| **TLS-RPT** | Present and valid |
| **BIMI** | Present, valid, and whether DMARC is strict enough for a logo to ever display |
| **DNSSEC** | Whether any of the above is signed |

### The SPF lookup limit

This is the failure almost nobody catches, so it gets its own feature.

SPF allows ten DNS lookups. Every `include`, `a`, `mx`, `ptr`, `exists` and `redirect` spends one, and the budget is shared across the entire recursive chain, including the includes inside your vendors' records. Add Google Workspace, a helpdesk, a CRM and a newsletter tool and you quietly cross ten.

When you do, receivers stop evaluating and return PermError. SPF then fails for all of your mail, from every server. Nothing in your record looks wrong. Checkers that only pattern match the record text will tell you SPF is fine while your mail is being rejected.

mailward walks the whole graph and counts properly:

```bash
mailward cloudflare.com --tree
```

```
    cloudflare.com - 7/10 lookups total
    ├─ _spf.google.com (0 lookups in this branch)
    ├─ spf1.mcsv.net (0 lookups in this branch)
    ├─ spf.mandrillapp.com (0 lookups in this branch)
    ├─ mail.zendesk.com (0 lookups in this branch)
    ├─ stspg-customer.com (0 lookups in this branch)
    └─ _spf.salesforce.com (1 lookup in this branch)

    cost per top-level term:
       2  include:_spf.salesforce.com
       1  include:_spf.google.com
       1  include:spf1.mcsv.net
```

Now you know which vendor to drop.

## Reading DMARC reports

Publishing a DMARC record starts a daily trickle of gzipped XML from Google, Microsoft, Yahoo and everyone else. It is unreadable by hand, and reading it is the entire point: it is the only way to find out who sends mail as your domain before you switch on enforcement and start blocking your own payroll provider.

Point mailward at the files. It reads `.xml`, `.gz` and `.zip`, and it never sends them anywhere.

```bash
mailward report ./dmarc-reports/
```

```
  reports     3 from 1 provider
  period      2025-07-01 to 2025-07-02
  domains     example.com

  messages      384
  authenticated 93.8%  360 passed, 24 failed

  Enforcement readiness
    Only 93.8% of 384 messages authenticate. Enforcing now would block
    legitimate mail. Work through the failing sources below first.

  SENDING SOURCES   (by volume)

    messages   pass    source
         300   100%   209.85.220.41            example.com
          60   100%   168.245.10.20            SendGrid
          15     0%   203.0.113.99             bulk-mailer.example.net
           9     0%   198.51.100.7             example.com

  FAILING SOURCES   (fix or authorise these before enforcing)

    ● 203.0.113.99  15 failing of 15
      authenticating as bulk-mailer.example.net
```

The readiness verdict is deliberately cautious. The mistake that hurts is enforcing too early and silently blocking your own mail, so mailward tells you what it is basing the answer on instead of just saying yes.

## Running it

Node 18.17 or newer. That is the only requirement.

```bash
# run it without installing anything
npx github:Mahmoud-ahmadi101/mailward example.com

# or clone and run, which needs no install step either
git clone https://github.com/Mahmoud-ahmadi101/mailward.git
cd mailward
node bin/mailward.js example.com
```

There is no build step and there is nothing to compile. The repository is the program.

Not on npm yet. Once it is, the above becomes `npx mailward example.com` and
`npm install -g mailward`. The examples below assume it is on your PATH.

### Options

```
  --selector <name>   extra DKIM selector to probe (repeatable)
  --fast              probe fewer DKIM selectors
  --no-dkim           skip DKIM probing entirely
  --tree              draw the SPF include graph with per-branch lookup cost
  --system-dns        use the OS resolver instead of DNS-over-HTTPS
  --timeout <ms>      per-query timeout (default 8000)
  --json              machine-readable output
  --fail-on <level>   exit 1 if any finding is at or above this severity
  --no-color          disable colour (or set NO_COLOR=1)
```

### Watch for regressions

DNS changes without anyone announcing it. A vendor edits their SPF record, someone adds a TXT record by hand, a certificate on the MTA-STS host expires. `--fail-on` turns mailward into a check you can schedule.

```bash
mailward example.com --fail-on high
```

Exit code is 0 when clean, 1 when something at or above that severity is found, and 2 on error.

```yaml
# .github/workflows/email-security.yml
name: email security
on:
  schedule: [{ cron: '0 7 * * 1' }]
  workflow_dispatch:

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npx github:Mahmoud-ahmadi101/mailward example.com --fail-on high
```

## As a library

```js
import { auditDomain, summarizeReports, readReports } from 'mailward';

const report = await auditDomain('example.com');
console.log(report.grade, report.score);

for (const finding of report.findings) {
  if (finding.severity === 'critical') console.log(finding.title, finding.fix);
}
```

`--json` gives you the same structure from the command line, including the full SPF tree and every parsed record.

## The grade

Severity deductions off 100, then a ceiling based on what your DMARC policy actually enforces:

| DMARC policy | Best possible grade | Why |
| --- | --- | --- |
| none published | F | Nothing stops a forged message |
| `p=none` | C | Monitoring only, forged mail is still delivered |
| `p=quarantine` | B | Forged mail is filtered, not refused |
| `p=reject` | A | Forged mail is refused |

A domain should not be able to score well on tidy peripheral records while remaining trivially spoofable. When a ceiling changes your result, mailward says so on the line under the grade.

## Privacy

Your DMARC reports contain the IP address of every server that sent mail as your domain, which is a fairly complete picture of who you do business with. Uploading that to a free web tool is not free.

- Report files are read locally and never transmitted.
- Domain audits send DNS queries to Cloudflare and Google over HTTPS, because that is how DNS works. `--system-dns` sends them to your own resolver instead.
- MTA-STS policies are fetched from the domain being audited, as the specification requires.
- No telemetry, no analytics, no account, no network calls other than the above.

DNS-over-HTTPS is the default for a practical reason as well as a privacy one: plain DNS on port 53 is blocked or intercepted on a lot of corporate networks, hotel wifi and CI runners, which is exactly where these checks tend to fail confusingly.

## Contributing

The most useful contribution is boring, which is the point.

**DKIM selectors.** DNS gives no way to list the selectors under a domain, so discovery is a guess against a known list. If your provider uses a selector that is not in [`src/dkim.js`](src/dkim.js), add it. That list is the difference between this tool working and not working for the next person on your provider.

**Sender fingerprints.** The list in [`src/report/index.js`](src/report/index.js) turns an anonymous IP in a report into "SendGrid". Same deal.

**Public suffixes.** [`src/publicsuffix.js`](src/publicsuffix.js) carries the multi-label suffixes that matter for organizational domain lookups, rather than bundling and syncing the full Public Suffix List. If your ccTLD is handled wrongly, add it.

Run the tests with `npm test`. They use a fake resolver, so they do not touch the network and do not depend on the state of anyone's real DNS.

Bug reports that include the domain you ran it against are worth ten that do not.

## License

MIT. Use it, fork it, ship it inside something commercial. No attribution ritual required.

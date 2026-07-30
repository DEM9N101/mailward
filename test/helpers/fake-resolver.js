/**
 * An in-memory stand-in for Resolver, so the audit logic can be tested
 * against exact DNS states without touching the network. Tests that depend on
 * real DNS are tests of the internet, not of this code.
 */

import { RCODE } from '../../src/resolver.js';

export class FakeResolver {
  /**
   * @param {Record<string, string[]>} records Keyed as "name|TYPE".
   * @param {object} [options]
   * @param {boolean} [options.ad] DNSSEC authentic-data flag to report.
   */
  constructor(records = {}, options = {}) {
    this.records = {};
    for (const [key, value] of Object.entries(records)) {
      const [name, type] = key.split('|');
      this.records[`${name.toLowerCase()}|${type}`] = value;
    }
    this.ad = options.ad ?? false;
    this.systemDns = false;
    /** Every name/type actually queried, for asserting what was not asked. */
    this.asked = [];
    this.queryCount = 0;
    this.cacheHits = 0;
  }

  async query(name, type) {
    const qname = String(name).trim().replace(/\.$/, '').toLowerCase();
    this.asked.push(`${qname}|${type}`);
    this.queryCount++;

    const key = `${qname}|${type}`;
    const present = Object.hasOwn(this.records, key);

    return {
      name: qname,
      type,
      // A name absent from the fixture is NXDOMAIN; a name present but empty
      // is NOERROR with no answers. Both are void lookups, and both occur.
      status: present ? RCODE.NOERROR : RCODE.NXDOMAIN,
      values: present ? this.records[key] : [],
      ad: this.ad,
      cached: false,
      error: null,
    };
  }

  async txt(name) {
    return this.query(name, 'TXT');
  }

  async mx(name) {
    const result = await this.query(name, 'MX');
    const hosts = result.values
      .map((value) => {
        const match = /^\s*(\d+)\s+(\S*)\s*$/.exec(value);
        if (!match) return null;
        return { preference: Number(match[1]), host: match[2].replace(/\.$/, '').toLowerCase() };
      })
      .filter(Boolean)
      .sort((a, b) => a.preference - b.preference);
    return { ...result, hosts };
  }
}

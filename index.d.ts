/** The IP address family: `4` for IPv4 or `6` for IPv6. */
type IPFamily = 4 | 6

interface LookupOptions {
  /** Restrict resolution to `4` (IPv4) or `6` (IPv6), or `0` for either. Defaults to `0`. */
  family?: `IPv${IPFamily}` | IPFamily | 0
  hints?: number
  /** When `true`, resolve every address for `hostname` instead of just the first. Defaults to `false`. */
  all?: boolean
}

/** An independent resolver for DNS queries, used to look up TXT records via the DNS protocol. */
declare class DNSResolver {
  /**
   * Use the DNS protocol to resolve TXT records for `hostname`. The callback receives an array of records, each itself an array of the strings that make up that record.
   * @param hostname - The host name to query TXT records for.
   * @param cb - Called with `(err, records)`; each record is an array of the strings it is made of.
   */
  resolveTxt(hostname: string, cb: (err: Error | null, records: string[][]) => void): void

  /** Cancel any pending queries on this resolver and release its underlying handle. */
  destroy(): void
}

declare namespace dns {
  /**
   * Resolve `hostname` into an IP address using the operating system's `getaddrinfo` facility, not the DNS protocol directly. With `all: true`, the callback receives every resolved address instead of just the first.
   * @param hostname - The host name to resolve.
   * @param cb - Called with `(err, address, family)`, or `(err, addresses)` when `all: true`.
   */
  export function lookup(
    hostname: string,
    cb: (err: Error | null, address: string | null, family: IPFamily | 0) => void
  ): void

  export function lookup(
    hostname: string,
    opts: LookupOptions & { all?: false },
    cb: (err: Error | null, address: string | null, family: IPFamily | 0) => void
  ): void

  export function lookup(
    hostname: string,
    opts: LookupOptions & { all: true },
    cb: (err: Error | null, addresses: { address: string; family: IPFamily }[] | null) => void
  ): void

  /**
   * Use the DNS protocol to resolve TXT records for `hostname`. The callback receives an array of records, each itself an array of the strings that make up that record.
   * @param hostname - The host name to query TXT records for.
   * @param cb - Called with `(err, records)`; each record is an array of the strings it is made of.
   */
  export function resolveTxt(
    hostname: string,
    cb: (err: Error | null, records: string[][]) => void
  ): void

  export { type IPFamily, type LookupOptions, DNSResolver as Resolver }
}

export = dns

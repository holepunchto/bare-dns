import DNSError from './lib/errors'
import constants from './lib/constants'

/** The IP address family: `4` for IPv4 or `6` for IPv6. */
type IPFamily = 4 | 6

interface LookupOptions {
  /** Restrict resolution to `4` (IPv4) or `6` (IPv6), or `0` for either. Defaults to `0`. */
  family?: `IPv${IPFamily}` | IPFamily | 0
  hints?: number
  /**
   * When `true`, resolve every address for `hostname` instead of just the first. Defaults to
   * `false`.
   */
  all?: boolean
}

interface DNSResolverOptions {
  servers?: string[]
  localAddress?: { ipv4?: string; ipv6?: string }
}

interface RecordWithTTL {
  address: string
  ttl: number
}

interface MXRecord {
  priority: number
  exchange: string
}

interface SRVRecord {
  priority: number
  weight: number
  port: number
  name: string
}

interface NAPTRRecord {
  flags: string
  service: string
  regexp: string
  replacement: string
  order: number
  preference: number
}

interface SOARecord {
  nsname: string
  hostmaster: string
  serial: number
  refresh: number
  retry: number
  expire: number
  minttl: number
}

interface CAARecord {
  critical: number
  issue?: string
  issuewild?: string
  iodef?: string
  contactemail?: string
  contactphone?: string
}

interface TLSARecord {
  certUsage: number
  selector: number
  match: number
  data: Buffer
}

type AnyRecord =
  | ({ type: 'A' } & RecordWithTTL)
  | ({ type: 'AAAA' } & RecordWithTTL)
  | { type: 'CNAME'; value: string }
  | { type: 'NS'; value: string }
  | { type: 'PTR'; value: string }
  | { type: 'TXT'; entries: string[] }
  | ({ type: 'MX' } & MXRecord)
  | ({ type: 'SRV' } & SRVRecord)
  | ({ type: 'NAPTR' } & NAPTRRecord)
  | ({ type: 'SOA' } & SOARecord)

type RecordType =
  | 'A'
  | 'AAAA'
  | 'ANY'
  | 'CAA'
  | 'CNAME'
  | 'MX'
  | 'NAPTR'
  | 'NS'
  | 'PTR'
  | 'SOA'
  | 'SRV'
  | 'TLSA'
  | 'TXT'

type Callback<T> = (err: Error | null, result: T) => void

/** An independent resolver for DNS queries. */
interface DNSResolver {
  getServers(): string[]
  setServers(servers: string[]): void
  setLocalAddress(ipv4?: string | null, ipv6?: string | null): void

  /**
   * Aborts every query outstanding on this resolver. Each pending callback is
   * invoked with `ECANCELLED`.
   */
  cancel(): void

  /**
   * Cancels every query outstanding on this resolver, so that none is left
   * without an answer, and releases the resources it holds. A query made after
   * this throws.
   */
  destroy(): void

  resolve(hostname: string, cb: Callback<string[]>): void
  resolve(
    hostname: string,
    rrtype: 'A' | 'AAAA' | 'CNAME' | 'NS' | 'PTR',
    cb: Callback<string[]>
  ): void
  resolve(hostname: string, rrtype: 'TXT', cb: Callback<string[][]>): void
  resolve(hostname: string, rrtype: 'MX', cb: Callback<MXRecord[]>): void
  resolve(hostname: string, rrtype: 'SRV', cb: Callback<SRVRecord[]>): void
  resolve(hostname: string, rrtype: 'NAPTR', cb: Callback<NAPTRRecord[]>): void
  resolve(hostname: string, rrtype: 'SOA', cb: Callback<SOARecord>): void
  resolve(hostname: string, rrtype: 'CAA', cb: Callback<CAARecord[]>): void
  resolve(hostname: string, rrtype: 'TLSA', cb: Callback<TLSARecord[]>): void
  resolve(hostname: string, rrtype: 'ANY', cb: Callback<AnyRecord[]>): void

  resolve4(hostname: string, cb: Callback<string[]>): void
  resolve4(hostname: string, opts: { ttl?: false }, cb: Callback<string[]>): void
  resolve4(hostname: string, opts: { ttl: true }, cb: Callback<RecordWithTTL[]>): void

  resolve6(hostname: string, cb: Callback<string[]>): void
  resolve6(hostname: string, opts: { ttl?: false }, cb: Callback<string[]>): void
  resolve6(hostname: string, opts: { ttl: true }, cb: Callback<RecordWithTTL[]>): void

  resolveAny(hostname: string, cb: Callback<AnyRecord[]>): void
  resolveCaa(hostname: string, cb: Callback<CAARecord[]>): void
  resolveCname(hostname: string, cb: Callback<string[]>): void
  resolveMx(hostname: string, cb: Callback<MXRecord[]>): void
  resolveNaptr(hostname: string, cb: Callback<NAPTRRecord[]>): void
  resolveNs(hostname: string, cb: Callback<string[]>): void
  resolvePtr(hostname: string, cb: Callback<string[]>): void
  resolveSoa(hostname: string, cb: Callback<SOARecord>): void
  resolveSrv(hostname: string, cb: Callback<SRVRecord[]>): void
  resolveTlsa(hostname: string, cb: Callback<TLSARecord[]>): void
  /**
   * Use the DNS protocol to resolve TXT records for `hostname`. The callback receives an array of
   * records, each itself an array of the strings that make up that record.
   * @param hostname - The host name to query TXT records for.
   * @param cb - Called with `(err, records)`; each record is an array of the strings it is made of.
   */
  resolveTxt(hostname: string, cb: Callback<string[][]>): void

  /**
   * Resolves the pointer records for `ip`.
   *
   * This queries the reverse zone for the address only. Unlike Node.js, the
   * hosts file is not consulted first, so an address that is only named there
   * does not resolve.
   */
  reverse(ip: string, cb: Callback<string[]>): void
}

declare class DNSResolver {
  constructor(opts?: DNSResolverOptions)
}

declare namespace DNSResolver {
  export const global: DNSResolver
}

declare namespace dns {
  /**
   * Resolve `hostname` into an IP address using the operating system's `getaddrinfo` facility, not
   * the DNS protocol directly. With `all: true`, the callback receives every resolved address
   * instead of just the first.
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

  export function getServers(): string[]
  export function setServers(servers: string[]): void
  export function setLocalAddress(ipv4?: string | null, ipv6?: string | null): void
  export function cancel(): void

  export const resolve: DNSResolver['resolve']
  export const resolve4: DNSResolver['resolve4']
  export const resolve6: DNSResolver['resolve6']
  export const resolveAny: DNSResolver['resolveAny']
  export const resolveCaa: DNSResolver['resolveCaa']
  export const resolveCname: DNSResolver['resolveCname']
  export const resolveMx: DNSResolver['resolveMx']
  export const resolveNaptr: DNSResolver['resolveNaptr']
  export const resolveNs: DNSResolver['resolveNs']
  export const resolvePtr: DNSResolver['resolvePtr']
  export const resolveSoa: DNSResolver['resolveSoa']
  export const resolveSrv: DNSResolver['resolveSrv']
  export const resolveTlsa: DNSResolver['resolveTlsa']
  export const resolveTxt: DNSResolver['resolveTxt']
  export const reverse: DNSResolver['reverse']

  export { default as promises } from './lib/promises'

  export {
    type IPFamily,
    type LookupOptions,
    type DNSResolverOptions,
    type RecordType,
    type RecordWithTTL,
    type MXRecord,
    type SRVRecord,
    type NAPTRRecord,
    type SOARecord,
    type CAARecord,
    type TLSARecord,
    type AnyRecord,
    DNSResolver as Resolver,
    DNSError as errors,
    constants
  }
}

export = dns

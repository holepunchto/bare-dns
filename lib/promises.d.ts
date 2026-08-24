import DNSError from './errors'
import constants from './constants'

type IPFamily = 4 | 6

interface LookupOptions {
  family?: `IPv${IPFamily}` | IPFamily | 0
  hints?: number
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

interface DNSPromiseResolver {
  getServers(): string[]
  setServers(servers: string[]): void
  setLocalAddress(ipv4?: string | null, ipv6?: string | null): void

  /**
   * Aborts every query outstanding on this resolver. Each pending promise is
   * rejected with `ECANCELLED`.
   */
  cancel(): void

  /**
   * Cancels every query outstanding on this resolver, so that none is left
   * without an answer, and releases the resources it holds. A query made after
   * this rejects.
   */
  destroy(): void

  resolve(hostname: string, rrtype?: 'A' | 'AAAA' | 'CNAME' | 'NS' | 'PTR'): Promise<string[]>
  resolve(hostname: string, rrtype: 'TXT'): Promise<string[][]>
  resolve(hostname: string, rrtype: 'MX'): Promise<MXRecord[]>
  resolve(hostname: string, rrtype: 'SRV'): Promise<SRVRecord[]>
  resolve(hostname: string, rrtype: 'NAPTR'): Promise<NAPTRRecord[]>
  resolve(hostname: string, rrtype: 'SOA'): Promise<SOARecord>
  resolve(hostname: string, rrtype: 'CAA'): Promise<CAARecord[]>
  resolve(hostname: string, rrtype: 'TLSA'): Promise<TLSARecord[]>
  resolve(hostname: string, rrtype: 'ANY'): Promise<AnyRecord[]>

  resolve4(hostname: string, opts?: { ttl?: false }): Promise<string[]>
  resolve4(hostname: string, opts: { ttl: true }): Promise<RecordWithTTL[]>

  resolve6(hostname: string, opts?: { ttl?: false }): Promise<string[]>
  resolve6(hostname: string, opts: { ttl: true }): Promise<RecordWithTTL[]>

  resolveAny(hostname: string): Promise<AnyRecord[]>
  resolveCaa(hostname: string): Promise<CAARecord[]>
  resolveCname(hostname: string): Promise<string[]>
  resolveMx(hostname: string): Promise<MXRecord[]>
  resolveNaptr(hostname: string): Promise<NAPTRRecord[]>
  resolveNs(hostname: string): Promise<string[]>
  resolvePtr(hostname: string): Promise<string[]>
  resolveSoa(hostname: string): Promise<SOARecord>
  resolveSrv(hostname: string): Promise<SRVRecord[]>
  resolveTlsa(hostname: string): Promise<TLSARecord[]>
  resolveTxt(hostname: string): Promise<string[][]>

  /**
   * Resolves the pointer records for `ip`.
   *
   * This queries the reverse zone for the address only. Unlike Node.js, the
   * hosts file is not consulted first, so an address that is only named there
   * does not resolve.
   */
  reverse(ip: string): Promise<string[]>
}

declare class DNSPromiseResolver {
  constructor(opts?: DNSResolverOptions)
}

declare namespace DNSPromiseResolver {
  export const global: DNSPromiseResolver
}

declare namespace promises {
  export function lookup(
    hostname: string,
    opts?: LookupOptions & { all?: false }
  ): Promise<{ address: string; family: IPFamily | 0 }>

  export function lookup(
    hostname: string,
    opts: LookupOptions & { all: true }
  ): Promise<{ address: string; family: IPFamily }[]>

  export function getServers(): string[]
  export function setServers(servers: string[]): void
  export function setLocalAddress(ipv4?: string | null, ipv6?: string | null): void
  export function cancel(): void

  export const resolve: DNSPromiseResolver['resolve']
  export const resolve4: DNSPromiseResolver['resolve4']
  export const resolve6: DNSPromiseResolver['resolve6']
  export const resolveAny: DNSPromiseResolver['resolveAny']
  export const resolveCaa: DNSPromiseResolver['resolveCaa']
  export const resolveCname: DNSPromiseResolver['resolveCname']
  export const resolveMx: DNSPromiseResolver['resolveMx']
  export const resolveNaptr: DNSPromiseResolver['resolveNaptr']
  export const resolveNs: DNSPromiseResolver['resolveNs']
  export const resolvePtr: DNSPromiseResolver['resolvePtr']
  export const resolveSoa: DNSPromiseResolver['resolveSoa']
  export const resolveSrv: DNSPromiseResolver['resolveSrv']
  export const resolveTlsa: DNSPromiseResolver['resolveTlsa']
  export const resolveTxt: DNSPromiseResolver['resolveTxt']
  export const reverse: DNSPromiseResolver['reverse']

  export {
    type RecordWithTTL,
    type MXRecord,
    type SRVRecord,
    type NAPTRRecord,
    type SOARecord,
    type CAARecord,
    type TLSARecord,
    type AnyRecord,
    DNSPromiseResolver as Resolver,
    DNSError as errors,
    constants
  }
}

export = promises

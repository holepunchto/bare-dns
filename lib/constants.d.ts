declare const constants: {
  readonly type: {
    readonly A: 1
    readonly NS: 2
    readonly CNAME: 5
    readonly SOA: 6
    readonly PTR: 12
    readonly HINFO: 13
    readonly MX: 15
    readonly TXT: 16
    readonly SIG: 24
    readonly AAAA: 28
    readonly SRV: 33
    readonly NAPTR: 35
    readonly OPT: 41
    readonly TLSA: 52
    readonly SVCB: 64
    readonly HTTPS: 65
    readonly ANY: 255
    readonly URI: 256
    readonly CAA: 257
  }
  readonly status: Record<string, number>
}

export = constants

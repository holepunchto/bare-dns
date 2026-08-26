const binding = require('../binding')
const constants = require('./constants')
const errors = require('./errors')
const records = require('./records')

const { type, status } = constants

module.exports = class DNSResolver {
  constructor(opts = {}) {
    const { servers = null, localAddress = null } = opts

    this._handle = binding.initResolver()

    if (servers !== null) this.setServers(servers)

    if (localAddress !== null) {
      this.setLocalAddress(localAddress.ipv4, localAddress.ipv6)
    }
  }

  getServers() {
    if (this._handle === null) throw errors.RESOLVER_DESTROYED()

    const servers = binding.getServers(this._handle)

    return servers === '' ? [] : servers.split(',')
  }

  setServers(servers) {
    if (this._handle === null) throw errors.RESOLVER_DESTROYED()

    binding.setServers(this._handle, servers.join(','))
  }

  setLocalAddress(ipv4 = null, ipv6 = null) {
    if (this._handle === null) throw errors.RESOLVER_DESTROYED()

    binding.setLocalAddress(this._handle, ipv4, ipv6)
  }

  // Aborts every query outstanding on this resolver. Each pending callback is
  // invoked with `ECANCELLED`, releasing the loop.
  cancel() {
    if (this._handle === null) return

    binding.cancel(this._handle)
  }

  // Cancels every query outstanding on this resolver, so that none is left
  // without an answer, and releases the resources it holds.
  destroy() {
    if (this._handle === null) return

    binding.destroyResolver(this._handle)
    this._handle = null
  }

  resolve(hostname, rrtype = 'A', cb = noop) {
    if (typeof rrtype === 'function') {
      cb = rrtype
      rrtype = 'A'
    }

    switch (rrtype) {
      case 'A':
        return this.resolve4(hostname, cb)
      case 'AAAA':
        return this.resolve6(hostname, cb)
      case 'ANY':
        return this.resolveAny(hostname, cb)
      case 'CAA':
        return this.resolveCaa(hostname, cb)
      case 'CNAME':
        return this.resolveCname(hostname, cb)
      case 'MX':
        return this.resolveMx(hostname, cb)
      case 'NAPTR':
        return this.resolveNaptr(hostname, cb)
      case 'NS':
        return this.resolveNs(hostname, cb)
      case 'PTR':
        return this.resolvePtr(hostname, cb)
      case 'SOA':
        return this.resolveSoa(hostname, cb)
      case 'SRV':
        return this.resolveSrv(hostname, cb)
      case 'TLSA':
        return this.resolveTlsa(hostname, cb)
      case 'TXT':
        return this.resolveTxt(hostname, cb)
      default:
        throw errors.UNKNOWN_RECORD_TYPE(`Unknown resource record type '${rrtype}'`)
    }
  }

  resolve4(hostname, opts = {}, cb = noop) {
    if (typeof opts === 'function') {
      cb = opts
      opts = {}
    }

    const { ttl = false } = opts

    this._query(hostname, type.A, 'queryA', records.a(ttl), cb)
  }

  resolve6(hostname, opts = {}, cb = noop) {
    if (typeof opts === 'function') {
      cb = opts
      opts = {}
    }

    const { ttl = false } = opts

    this._query(hostname, type.AAAA, 'queryAaaa', records.aaaa(ttl), cb)
  }

  resolveAny(hostname, cb = noop) {
    this._query(hostname, type.ANY, 'queryAny', records.any, cb)
  }

  resolveCaa(hostname, cb = noop) {
    this._query(hostname, type.CAA, 'queryCaa', records.caa, cb)
  }

  resolveCname(hostname, cb = noop) {
    this._query(hostname, type.CNAME, 'queryCname', records.cname, cb)
  }

  resolveMx(hostname, cb = noop) {
    this._query(hostname, type.MX, 'queryMx', records.mx, cb)
  }

  resolveNaptr(hostname, cb = noop) {
    this._query(hostname, type.NAPTR, 'queryNaptr', records.naptr, cb)
  }

  resolveNs(hostname, cb = noop) {
    this._query(hostname, type.NS, 'queryNs', records.ns, cb)
  }

  resolvePtr(hostname, cb = noop) {
    this._query(hostname, type.PTR, 'queryPtr', records.ptr, cb)
  }

  resolveSoa(hostname, cb = noop) {
    this._query(hostname, type.SOA, 'querySoa', records.soa, cb)
  }

  resolveSrv(hostname, cb = noop) {
    this._query(hostname, type.SRV, 'querySrv', records.srv, cb)
  }

  resolveTlsa(hostname, cb = noop) {
    this._query(hostname, type.TLSA, 'queryTlsa', records.tlsa, cb)
  }

  resolveTxt(hostname, cb = noop) {
    this._query(hostname, type.TXT, 'queryTxt', records.txt, cb)
  }

  // Resolves a pointer record, which is a plain query against the reverse zone
  // for the address. Unlike Node.js, the hosts file is not consulted first, so
  // an address that is only named there does not resolve.
  reverse(ip, cb = noop) {
    let name

    try {
      name = binding.addrToPtr(ip)
    } catch {
      throw errors.INVALID_IP_ADDRESS(`Invalid IP address '${ip}'`)
    }

    this._query(name, type.PTR, 'getHostByAddr', records.ptr, cb, ip)
  }

  _query(name, rrtype, syscall, shape, cb, hostname = name) {
    if (this._handle === null) throw errors.RESOLVER_DESTROYED()

    const req = { hostname, syscall, shape, cb }

    binding.query(this._handle, name, rrtype, req, onquery)
  }

  static global = new this()
}

// The binding hands over an answer on a turn of the loop of its own, including
// one it served from its cache, so a callback never runs before the call that
// issued it.
function onquery(code, record) {
  const req = this

  if (code !== status.SUCCESS) {
    return req.cb(errors.query(code, req.syscall, req.hostname), null)
  }

  const result = req.shape(record)

  if (result === null) {
    return req.cb(errors.query(status.ENODATA, req.syscall, req.hostname), null)
  }

  req.cb(null, result)
}

function noop() {}

const constants = require('./constants')
const errors = require('./errors')
const DNSResolver = require('./resolver')

class DNSPromiseResolver {
  constructor(opts) {
    this._resolver = new DNSResolver(opts)
  }

  getServers() {
    return this._resolver.getServers()
  }

  setServers(servers) {
    return this._resolver.setServers(servers)
  }

  setLocalAddress(ipv4, ipv6) {
    return this._resolver.setLocalAddress(ipv4, ipv6)
  }

  cancel() {
    return this._resolver.cancel()
  }

  destroy() {
    return this._resolver.destroy()
  }

  resolve(hostname, rrtype) {
    return promisify(this._resolver, 'resolve', hostname, rrtype)
  }

  resolve4(hostname, opts) {
    return promisify(this._resolver, 'resolve4', hostname, opts)
  }

  resolve6(hostname, opts) {
    return promisify(this._resolver, 'resolve6', hostname, opts)
  }

  resolveAny(hostname) {
    return promisify(this._resolver, 'resolveAny', hostname)
  }

  resolveCaa(hostname) {
    return promisify(this._resolver, 'resolveCaa', hostname)
  }

  resolveCname(hostname) {
    return promisify(this._resolver, 'resolveCname', hostname)
  }

  resolveMx(hostname) {
    return promisify(this._resolver, 'resolveMx', hostname)
  }

  resolveNaptr(hostname) {
    return promisify(this._resolver, 'resolveNaptr', hostname)
  }

  resolveNs(hostname) {
    return promisify(this._resolver, 'resolveNs', hostname)
  }

  resolvePtr(hostname) {
    return promisify(this._resolver, 'resolvePtr', hostname)
  }

  resolveSoa(hostname) {
    return promisify(this._resolver, 'resolveSoa', hostname)
  }

  resolveSrv(hostname) {
    return promisify(this._resolver, 'resolveSrv', hostname)
  }

  resolveTlsa(hostname) {
    return promisify(this._resolver, 'resolveTlsa', hostname)
  }

  resolveTxt(hostname) {
    return promisify(this._resolver, 'resolveTxt', hostname)
  }

  reverse(ip) {
    return promisify(this._resolver, 'reverse', ip)
  }

  static global = new this()
}

function promisify(resolver, method, ...args) {
  return new Promise((resolve, reject) => {
    resolver[method](...args, (err, result) => {
      if (err) reject(err)
      else resolve(result)
    })
  })
}

exports.Resolver = DNSPromiseResolver

exports.lookup = function lookup(hostname, opts = {}) {
  const dns = require('../')

  return new Promise((resolve, reject) => {
    if (opts && opts.all) {
      dns.lookup(hostname, opts, (err, addresses) => {
        if (err) reject(err)
        else resolve(addresses)
      })
    } else {
      dns.lookup(hostname, opts, (err, address, family) => {
        if (err) reject(err)
        else resolve({ address, family })
      })
    }
  })
}

exports.getServers = function getServers() {
  return DNSPromiseResolver.global.getServers()
}

exports.setServers = function setServers(servers) {
  return DNSPromiseResolver.global.setServers(servers)
}

exports.setLocalAddress = function setLocalAddress(ipv4, ipv6) {
  return DNSPromiseResolver.global.setLocalAddress(ipv4, ipv6)
}

exports.cancel = function cancel() {
  return DNSPromiseResolver.global.cancel()
}

exports.resolve = function resolve(hostname, rrtype) {
  return DNSPromiseResolver.global.resolve(hostname, rrtype)
}

exports.resolve4 = function resolve4(hostname, opts) {
  return DNSPromiseResolver.global.resolve4(hostname, opts)
}

exports.resolve6 = function resolve6(hostname, opts) {
  return DNSPromiseResolver.global.resolve6(hostname, opts)
}

exports.resolveAny = function resolveAny(hostname) {
  return DNSPromiseResolver.global.resolveAny(hostname)
}

exports.resolveCaa = function resolveCaa(hostname) {
  return DNSPromiseResolver.global.resolveCaa(hostname)
}

exports.resolveCname = function resolveCname(hostname) {
  return DNSPromiseResolver.global.resolveCname(hostname)
}

exports.resolveMx = function resolveMx(hostname) {
  return DNSPromiseResolver.global.resolveMx(hostname)
}

exports.resolveNaptr = function resolveNaptr(hostname) {
  return DNSPromiseResolver.global.resolveNaptr(hostname)
}

exports.resolveNs = function resolveNs(hostname) {
  return DNSPromiseResolver.global.resolveNs(hostname)
}

exports.resolvePtr = function resolvePtr(hostname) {
  return DNSPromiseResolver.global.resolvePtr(hostname)
}

exports.resolveSoa = function resolveSoa(hostname) {
  return DNSPromiseResolver.global.resolveSoa(hostname)
}

exports.resolveSrv = function resolveSrv(hostname) {
  return DNSPromiseResolver.global.resolveSrv(hostname)
}

exports.resolveTlsa = function resolveTlsa(hostname) {
  return DNSPromiseResolver.global.resolveTlsa(hostname)
}

exports.resolveTxt = function resolveTxt(hostname) {
  return DNSPromiseResolver.global.resolveTxt(hostname)
}

exports.reverse = function reverse(ip) {
  return DNSPromiseResolver.global.reverse(ip)
}

exports.constants = constants
exports.errors = errors

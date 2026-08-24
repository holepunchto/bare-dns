const binding = require('./binding')
const constants = require('./lib/constants')
const errors = require('./lib/errors')
const DNSResolver = require('./lib/resolver')

exports.Resolver = DNSResolver

function onlookup(err, addresses) {
  const req = this

  if (err) return req.cb(err, null, 0)

  const { address, family } = addresses[0]

  return req.cb(null, address, family)
}

function onlookupall(err, addresses) {
  const req = this

  if (err) return req.cb(err, null)

  return req.cb(null, addresses)
}

exports.lookup = function lookup(hostname, opts = {}, cb) {
  if (typeof opts === 'function') {
    cb = opts
    opts = {}
  }

  let { family = 0, all = false } = opts

  if (typeof family === 'string') {
    switch (family) {
      case 'IPv4':
        family = 4
        break
      case 'IPv6':
        family = 6
        break
      default:
        family = 0
    }
  }

  const req = {
    cb,
    handle: null
  }

  req.handle = binding.lookup(hostname, family || 0, all, req, all ? onlookupall : onlookup)
}

exports.getServers = function getServers() {
  return DNSResolver.global.getServers()
}

exports.setServers = function setServers(servers) {
  return DNSResolver.global.setServers(servers)
}

exports.setLocalAddress = function setLocalAddress(ipv4, ipv6) {
  return DNSResolver.global.setLocalAddress(ipv4, ipv6)
}

exports.cancel = function cancel() {
  return DNSResolver.global.cancel()
}

exports.resolve = function resolve(hostname, rrtype, cb) {
  return DNSResolver.global.resolve(hostname, rrtype, cb)
}

exports.resolve4 = function resolve4(hostname, opts, cb) {
  return DNSResolver.global.resolve4(hostname, opts, cb)
}

exports.resolve6 = function resolve6(hostname, opts, cb) {
  return DNSResolver.global.resolve6(hostname, opts, cb)
}

exports.resolveAny = function resolveAny(hostname, cb) {
  return DNSResolver.global.resolveAny(hostname, cb)
}

exports.resolveCaa = function resolveCaa(hostname, cb) {
  return DNSResolver.global.resolveCaa(hostname, cb)
}

exports.resolveCname = function resolveCname(hostname, cb) {
  return DNSResolver.global.resolveCname(hostname, cb)
}

exports.resolveMx = function resolveMx(hostname, cb) {
  return DNSResolver.global.resolveMx(hostname, cb)
}

exports.resolveNaptr = function resolveNaptr(hostname, cb) {
  return DNSResolver.global.resolveNaptr(hostname, cb)
}

exports.resolveNs = function resolveNs(hostname, cb) {
  return DNSResolver.global.resolveNs(hostname, cb)
}

exports.resolvePtr = function resolvePtr(hostname, cb) {
  return DNSResolver.global.resolvePtr(hostname, cb)
}

exports.resolveSoa = function resolveSoa(hostname, cb) {
  return DNSResolver.global.resolveSoa(hostname, cb)
}

exports.resolveSrv = function resolveSrv(hostname, cb) {
  return DNSResolver.global.resolveSrv(hostname, cb)
}

exports.resolveTlsa = function resolveTlsa(hostname, cb) {
  return DNSResolver.global.resolveTlsa(hostname, cb)
}

exports.resolveTxt = function resolveTxt(hostname, cb) {
  return DNSResolver.global.resolveTxt(hostname, cb)
}

exports.reverse = function reverse(ip, cb) {
  return DNSResolver.global.reverse(ip, cb)
}

exports.constants = constants
exports.errors = errors
exports.promises = require('./lib/promises')

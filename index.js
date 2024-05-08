const binding = require('./binding')

function onlookup (err, addresses) {
  const req = this

  if (err) return req.cb(err, null, 0)

  const { address, family } = addresses[0]

  return req.cb(null, address, family)
}

function onlookupall (err, addresses) {
  const req = this

  if (err) return req.cb(err, null)

  return req.cb(null, addresses)
}

exports.lookup = function lookup (hostname, opts = {}, cb) {
  if (typeof opts === 'function') {
    cb = opts
    opts = {}
  }

  const {
    family = 0,
    all = false
  } = opts

  const req = {
    cb,
    handle: null
  }

  req.handle = binding.lookup(hostname, family, all, req, all ? onlookupall : onlookup)
}

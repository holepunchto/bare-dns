const binding = require('./binding')

function onlookup (err, addresses) {
  const req = this

  if (err) return req.cb(err, null)

  if (req.all) return req.cb(null, addresses)

  const [{ address, family }] = addresses

  return req.cb(null, address, family)
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
    all,
    cb,
    handle: null
  }

  req.handle = binding.lookup(hostname, family, all, req, onlookup)
}

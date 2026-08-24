const constants = require('./constants')

// The status codes indexed by their value, for turning the status a query
// reports into the code its error carries.
const codes = []

for (const [name, value] of Object.entries(constants.status)) {
  codes[value] = name
}

module.exports = class DNSError extends Error {
  constructor(msg, fn = DNSError, code = fn.name) {
    super(`${code}: ${msg}`)

    this.code = code

    if (Error.captureStackTrace) Error.captureStackTrace(this, fn)
  }

  get name() {
    return 'DNSError'
  }

  static RESOLVER_DESTROYED(msg = 'Resolver is destroyed') {
    return new DNSError(msg, DNSError.RESOLVER_DESTROYED)
  }

  static UNKNOWN_RECORD_TYPE(msg = 'Unknown resource record type') {
    return new DNSError(msg, DNSError.UNKNOWN_RECORD_TYPE)
  }

  static INVALID_IP_ADDRESS(msg = 'Invalid IP address') {
    return new DNSError(msg, DNSError.INVALID_IP_ADDRESS)
  }

  static query(status, syscall, hostname = null) {
    const code = codes[status] || 'UNKNOWN'

    const err = new DNSError(
      `${syscall}` + (hostname === null ? '' : ` ${hostname}`),
      DNSError.query,
      code
    )

    err.syscall = syscall

    if (hostname !== null) err.hostname = hostname

    return err
  }
}

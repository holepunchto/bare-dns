// Shapes a parsed DNS record into the result each `resolve*()` method returns.
// The binding hands back every field a record type carries, named as the
// resolver names it.

function answers(record, type) {
  const result = []

  for (const rr of record.answers) {
    if (rr.type === type) result.push(rr)
  }

  return result
}

function string(value) {
  return value === null ? '' : Buffer.from(value).toString()
}

function buffer(value) {
  return value === null ? Buffer.alloc(0) : Buffer.from(value)
}

// Each shape returns `null` when the answer section holds no record of the
// requested type, which the caller reports as `ENODATA`.
function list(type, fn) {
  return (record) => {
    const rrs = answers(record, type)

    return rrs.length === 0 ? null : rrs.map(fn)
  }
}

const address = (rr) => rr.addr
const addressWithTTL = (rr) => ({ address: rr.addr, ttl: rr.ttl })

exports.a = (ttl) => list('A', ttl ? addressWithTTL : address)
exports.aaaa = (ttl) => list('AAAA', ttl ? addressWithTTL : address)

exports.cname = list('CNAME', (rr) => rr.cname)
exports.ns = list('NS', (rr) => rr.nsdname)
exports.ptr = list('PTR', (rr) => rr.dname)
exports.txt = list('TXT', (rr) => rr.data)

exports.mx = list('MX', (rr) => ({
  priority: rr.preference,
  exchange: rr.exchange
}))

exports.srv = list('SRV', (rr) => ({
  priority: rr.priority,
  weight: rr.weight,
  port: rr.port,
  name: rr.target
}))

exports.naptr = list('NAPTR', (rr) => ({
  flags: rr.flags,
  service: rr.services,
  regexp: rr.regexp,
  replacement: rr.replacement,
  order: rr.order,
  preference: rr.preference
}))

exports.caa = list('CAA', (rr) => ({
  critical: rr.critical,
  [rr.tag]: string(rr.value)
}))

exports.tlsa = list('TLSA', (rr) => ({
  certUsage: rr.cert_usage,
  selector: rr.selector,
  match: rr.match,
  data: buffer(rr.data)
}))

// Unlike every other type, a start of authority resolves to a single record
// rather than a list.
exports.soa = (record) => {
  const rrs = answers(record, 'SOA')

  return rrs.length === 0 ? null : soa(rrs[0])
}

function soa(rr) {
  return {
    nsname: rr.mname,
    hostmaster: rr.rname,
    serial: rr.serial,
    refresh: rr.refresh,
    retry: rr.retry,
    expire: rr.expire,
    minttl: rr.minimum
  }
}

// A wildcard query may come back with a mix of record types, each tagged with
// its type so that the caller can tell them apart.
exports.any = (record) => {
  const result = []

  for (const rr of record.answers) {
    switch (rr.type) {
      case 'A':
        result.push({ type: 'A', address: rr.addr, ttl: rr.ttl })
        break
      case 'AAAA':
        result.push({ type: 'AAAA', address: rr.addr, ttl: rr.ttl })
        break
      case 'CNAME':
        result.push({ type: 'CNAME', value: rr.cname })
        break
      case 'NS':
        result.push({ type: 'NS', value: rr.nsdname })
        break
      case 'PTR':
        result.push({ type: 'PTR', value: rr.dname })
        break
      case 'TXT':
        result.push({ type: 'TXT', entries: rr.data })
        break
      case 'MX':
        result.push({ type: 'MX', priority: rr.preference, exchange: rr.exchange })
        break
      case 'SRV':
        result.push({
          type: 'SRV',
          priority: rr.priority,
          weight: rr.weight,
          port: rr.port,
          name: rr.target
        })
        break
      case 'NAPTR':
        result.push({
          type: 'NAPTR',
          flags: rr.flags,
          service: rr.services,
          regexp: rr.regexp,
          replacement: rr.replacement,
          order: rr.order,
          preference: rr.preference
        })
        break
      case 'SOA':
        result.push({ type: 'SOA', ...soa(rr) })
        break
    }
  }

  return result
}

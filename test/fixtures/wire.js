// A minimal DNS message codec, covering just enough of RFC 1035 for a fixture
// server to read the queries the resolver sends and write the answers a test
// asks it to serve. It deliberately shares no code with the module under test,
// so that a test asserts against the wire format rather than against our own
// reading of it.
//
// The `data` of a record is shaped exactly like the result the matching
// `resolve*()` method returns, which lets a test declare a record and expect it
// back unchanged.

// Resource record types, limited to the ones the resolver can query for.
const types = (exports.types = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  NAPTR: 35,
  OPT: 41,
  TLSA: 52,
  ANY: 255,
  CAA: 257
})

// Response codes, as carried by the low four bits of the header flags.
const codes = (exports.codes = {
  NOERROR: 0,
  FORMERR: 1,
  SERVFAIL: 2,
  NXDOMAIN: 3,
  NOTIMP: 4,
  REFUSED: 5
})

const CLASS_IN = 1

const flags = {
  RESPONSE: 1 << 15,
  AUTHORITATIVE: 1 << 10,
  TRUNCATED: 1 << 9,
  RECURSION_DESIRED: 1 << 8,
  RECURSION_AVAILABLE: 1 << 7
}

// The type names indexed by their value, for naming the type a question asks
// for.
const names = []

for (const [name, value] of Object.entries(types)) names[value] = name

exports.decode = function decode(buffer) {
  const reader = new Reader(buffer)

  const id = reader.uint16()

  reader.uint16() // Flags, which a query carries nothing we act on in.

  const questions = reader.uint16()

  reader.uint16() // Answer count.
  reader.uint16() // Authority count.
  reader.uint16() // Additional count.

  const message = { id, questions: [] }

  for (let i = 0; i < questions; i++) {
    const name = reader.name()
    const type = reader.uint16()

    reader.uint16() // Class, which is always `IN` for the queries we serve.

    message.questions.push({ name, type, typeName: names[type] || null })
  }

  return message
}

exports.encode = function encode(message) {
  const {
    id,
    code = codes.NOERROR,
    truncated = false,
    questions = [],
    answers = [],
    authorities = []
  } = message

  const writer = new Writer()

  let header = flags.RESPONSE | flags.AUTHORITATIVE | flags.RECURSION_AVAILABLE | code

  if (truncated) header |= flags.TRUNCATED

  writer
    .uint16(id)
    .uint16(header)
    .uint16(questions.length)
    .uint16(answers.length)
    .uint16(authorities.length)
    .uint16(0)

  // The question section is echoed back as asked, which both keeps the
  // resolver's own matching of answers to queries happy and preserves the
  // casing of a name it may have randomized.
  for (const question of questions) {
    writer.name(question.name).uint16(question.type).uint16(CLASS_IN)
  }

  for (const record of answers) writer.record(record)
  for (const record of authorities) writer.record(record)

  return writer.toBuffer()
}

class Reader {
  constructor(buffer) {
    this._buffer = buffer
    this._offset = 0
  }

  uint16() {
    const value = this._buffer.readUInt16BE(this._offset)

    this._offset += 2

    return value
  }

  name() {
    const labels = []

    while (true) {
      const length = this._buffer.readUInt8(this._offset++)

      if (length === 0) break

      // A query never compresses the name it asks about, so there is no reason
      // for a fixture to follow a pointer.
      if ((length & 0xc0) !== 0) {
        throw new Error('Compressed names are not supported')
      }

      labels.push(this._buffer.toString('utf8', this._offset, this._offset + length))

      this._offset += length
    }

    return labels.join('.')
  }
}

class Writer {
  constructor(size = 4096) {
    this._buffer = Buffer.alloc(size)
    this._offset = 0
  }

  uint8(value) {
    this._offset = this._buffer.writeUInt8(value, this._offset)

    return this
  }

  uint16(value) {
    this._offset = this._buffer.writeUInt16BE(value, this._offset)

    return this
  }

  uint32(value) {
    this._offset = this._buffer.writeUInt32BE(value, this._offset)

    return this
  }

  bytes(buffer) {
    this._offset += buffer.copy(this._buffer, this._offset)

    return this
  }

  // A character string, which is a run of at most 255 bytes carrying its own
  // length.
  string(value) {
    const bytes = Buffer.from(value)

    return this.uint8(bytes.byteLength).bytes(bytes)
  }

  // A name, written out in full as compression is never required of a
  // responder.
  name(value) {
    for (const label of value.split('.')) {
      if (label !== '') this.string(label)
    }

    return this.uint8(0)
  }

  record(record) {
    const { name, type, ttl = 300, data } = record

    const write = rdata[type]

    if (write === undefined) throw new Error(`Cannot write a '${type}' record`)

    this.name(name).uint16(types[type]).uint16(CLASS_IN).uint32(ttl)

    // The length of the record data is only known once written, so leave room
    // for it and fill it in after the fact.
    const length = this._offset

    this._offset += 2

    write(this, data)

    this._buffer.writeUInt16BE(this._offset - length - 2, length)

    return this
  }

  toBuffer() {
    return this._buffer.subarray(0, this._offset)
  }
}

const rdata = {
  A(writer, address) {
    writer.bytes(ipv4(address))
  },

  AAAA(writer, address) {
    writer.bytes(ipv6(address))
  },

  NS(writer, name) {
    writer.name(name)
  },

  CNAME(writer, name) {
    writer.name(name)
  },

  PTR(writer, name) {
    writer.name(name)
  },

  SOA(writer, data) {
    writer
      .name(data.nsname)
      .name(data.hostmaster)
      .uint32(data.serial)
      .uint32(data.refresh)
      .uint32(data.retry)
      .uint32(data.expire)
      .uint32(data.minttl)
  },

  MX(writer, data) {
    writer.uint16(data.priority).name(data.exchange)
  },

  // Each entry of a text record is a character string of its own, which is how
  // a record longer than 255 bytes is carried.
  TXT(writer, entries) {
    for (const entry of entries) writer.string(entry)
  },

  SRV(writer, data) {
    writer.uint16(data.priority).uint16(data.weight).uint16(data.port).name(data.name)
  },

  NAPTR(writer, data) {
    writer
      .uint16(data.order)
      .uint16(data.preference)
      .string(data.flags)
      .string(data.service)
      .string(data.regexp)
      .name(data.replacement)
  },

  // The value of a certification authority record runs to the end of the
  // record, so unlike the tag it carries no length of its own.
  CAA(writer, data) {
    writer.uint8(data.critical).string(data.tag).bytes(Buffer.from(data.value))
  },

  TLSA(writer, data) {
    writer.uint8(data.certUsage).uint8(data.selector).uint8(data.match).bytes(data.data)
  }
}

function ipv4(address) {
  const parts = address.split('.')

  if (parts.length !== 4) throw new Error(`Invalid IPv4 address '${address}'`)

  return Buffer.from(parts.map((part) => parseInt(part, 10)))
}

function ipv6(address) {
  const [head, tail = null] = address.split('::')

  const groups = (part) => (part === '' ? [] : part.split(':'))

  const left = groups(head)
  const right = tail === null ? [] : groups(tail)

  if (tail === null && left.length !== 8) throw new Error(`Invalid IPv6 address '${address}'`)

  const middle = new Array(8 - left.length - right.length).fill('0')

  const buffer = Buffer.alloc(16)

  let offset = 0

  for (const group of [...left, ...middle, ...right]) {
    offset = buffer.writeUInt16BE(parseInt(group, 16), offset)
  }

  return buffer
}

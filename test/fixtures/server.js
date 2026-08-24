const dgram = require('bare-dgram')
const wire = require('./wire')

const { codes } = wire

// An authoritative DNS server that answers from a static set of records, so
// that a test can assert against a known zone rather than against whatever the
// network happens to hold.
//
// Behaves like a real server would for the cases a test cares about: a name
// with no records at all is answered with `NXDOMAIN`, a name that holds records
// of other types only is answered with an empty answer section, and a name that
// holds an alias is answered with the alias followed by the records of whatever
// it points at.
//
// Options include:
//
// ```js
// options = {
//   records: [],      // The zone to answer from.
//   code: 'NOERROR',  // A response code to answer every query with instead.
//   drop: false       // Whether to leave every query unanswered.
// }
// ```
module.exports = class DNSFixtureServer {
  constructor(opts = {}) {
    const { records = [], code = 'NOERROR', drop = false } = opts

    if (code in codes === false) throw new Error(`Unknown response code '${code}'`)

    this._records = records
    this._code = codes[code]
    this._drop = drop

    this._socket = null

    // Every question the server has been asked, in the order asked, for a test
    // to assert that a call queried what it should have.
    this.queries = []
  }

  address() {
    return this._socket === null ? null : this._socket.address()
  }

  // The servers to hand a resolver, in the form `setServers()` takes.
  get servers() {
    const { address, port } = this.address()

    return [`${address}:${port}`]
  }

  listen() {
    return new Promise((resolve, reject) => {
      this._socket = dgram.createSocket()

      // The listener stays on past binding, both to report a bind that failed
      // and to keep a socket error from being thrown at whatever the test was
      // doing at the time.
      this._socket.on('error', reject)
      this._socket.on('message', (message, from) => this._onmessage(message, from))

      this._socket.bind(0, '127.0.0.1', () => resolve(this))
    })
  }

  close() {
    if (this._socket === null) return Promise.resolve()

    const socket = this._socket

    this._socket = null

    return socket.close()
  }

  _onmessage(message, from) {
    const query = wire.decode(message)

    // The resolver only ever asks one question at a time.
    const question = query.questions[0]

    this.queries.push({ name: question.name, type: question.typeName })

    if (this._drop) return

    // A send that loses its race with `close()` is of no interest to a test, so
    // its error is swallowed rather than left to surface unhandled.
    this._socket.send(this._answer(query, question), from.port, from.address, noop)
  }

  _answer(query, question) {
    const message = { id: query.id, questions: query.questions, code: this._code }

    if (this._code !== codes.NOERROR) return wire.encode(message)

    const records = this._at(question.name)

    if (records.length === 0) {
      return wire.encode({ ...message, code: codes.NXDOMAIN })
    }

    return wire.encode({ ...message, answers: this._resolve(question) })
  }

  // Collects the records to answer a question with, following any alias until
  // it lands on the type asked for or runs out of zone.
  _resolve(question) {
    const answers = []
    const seen = new Set()

    let name = question.name

    while (seen.has(name.toLowerCase()) === false) {
      seen.add(name.toLowerCase())

      const records = this._at(name)

      const matching = records.filter(
        (record) => question.typeName === 'ANY' || record.type === question.typeName
      )

      if (matching.length > 0) {
        answers.push(...matching)
        break
      }

      const alias = records.find((record) => record.type === 'CNAME')

      if (alias === undefined) break

      answers.push(alias)

      name = alias.data
    }

    return answers
  }

  // A name is matched without regard for case, as a resolver is free to vary the
  // case of the name it asks about.
  _at(name) {
    name = name.toLowerCase()

    return this._records.filter((record) => record.name.toLowerCase() === name)
  }
}

function noop() {}

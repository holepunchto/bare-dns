const test = require('brittle')
const dns = require('.')

test('lookup', (t) => {
  t.plan(2)

  dns.lookup('nodejs.org', (err, address, family) => {
    t.absent(err)

    t.comment('address:', address)
    t.comment('family:', family)

    t.pass()
  })
})

test('lookup, ipv4 only', (t) => {
  t.plan(3)

  dns.lookup('nodejs.org', { family: 4 }, (err, address, family) => {
    t.absent(err)
    t.is(family, 4)

    t.comment('address:', address)
    t.comment('family:', family)

    t.pass()
  })
})

test('lookup, ipv6 only', (t) => {
  t.plan(3)

  dns.lookup('nodejs.org', { family: 6 }, (err, address, family) => {
    t.absent(err)
    t.is(family, 6)

    t.comment('address:', address)
    t.comment('family:', family)

    t.pass()
  })
})

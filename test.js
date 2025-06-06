const test = require('brittle')
const dns = require('.')

test('lookup', (t) => {
  t.plan(2)

  dns.lookup('bare.pears.com', (err, address, family) => {
    t.absent(err)

    t.comment('address:', address)
    t.comment('family:', family)

    t.pass()
  })
})

test('lookup, ipv4 only', (t) => {
  t.plan(3)

  dns.lookup('bare.pears.com', { family: 4 }, (err, address, family) => {
    t.absent(err)
    t.is(family, 4)

    t.comment('address:', address)
    t.comment('family:', family)

    t.pass()
  })
})

test('lookup, ipv6 only', (t) => {
  t.plan(3)

  dns.lookup('bare.pears.com', { family: 6 }, (err, address, family) => {
    if (err) {
      t.is(address, null)
      t.is(family, 0)

      t.comment(err.message)
    } else {
      t.is(typeof address, 'string')
      t.is(family, 6)

      t.comment('address:', address)
      t.comment('family:', family)
    }

    t.pass()
  })
})

test('lookup all', (t) => {
  t.plan(3)

  dns.lookup('bare.pears.com', { all: true }, (err, addresses) => {
    t.absent(err)
    t.ok(addresses.length > 0)

    for (const { address, family } of addresses) {
      t.comment('address:', address)
      t.comment('family:', family)
    }

    t.pass()
  })
})

test('resolveTxt', (t) => {
  t.test('unprobablenonexistentwebsite.com', (t) => {
    t.plan(2)

    dns.resolveTxt('unprobablenonexistentwebsite.com', (err, result) => {
      t.comment('Error:', err)
      t.comment('Result:', result)

      t.ok(err)
      t.absent(result)
    })
  })

  t.test('bare.pears.com', (t) => {
    t.plan(1)

    dns.resolveTxt('bare.pears.com', (err, result) => {
      t.comment('Error:', err)
      t.comment('Result:', result)

      t.pass()
    })
  })

  t.test('wikipedia.org', (t) => {
    t.plan(1)

    dns.resolveTxt('wikipedia.org', (err, result) => {
      t.comment('Error:', err)
      t.comment('Result:', result)

      t.pass()
    })
  })
})

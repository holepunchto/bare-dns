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

test('resolve4', async (t) => {
  t.plan(2)

  const addresses = await dns.promises.resolve4('bare.pears.com')

  t.ok(addresses.length > 0, 'has addresses')
  t.ok(
    addresses.every((address) => typeof address === 'string'),
    'addresses are strings'
  )
})

test('resolve4, with ttl', async (t) => {
  t.plan(2)

  const addresses = await dns.promises.resolve4('bare.pears.com', { ttl: true })

  t.ok(addresses.length > 0, 'has addresses')
  t.ok(
    addresses.every(({ address, ttl }) => typeof address === 'string' && typeof ttl === 'number'),
    'addresses have a ttl'
  )
})

test('resolve6', async (t) => {
  t.plan(1)

  try {
    const addresses = await dns.promises.resolve6('bare.pears.com')

    t.ok(
      addresses.every((address) => typeof address === 'string'),
      'addresses are strings'
    )
  } catch (err) {
    // Not every host has a AAAA record.
    t.is(err.code, 'ENODATA')
  }
})

test('resolveNs', async (t) => {
  t.plan(1)

  const servers = await dns.promises.resolveNs('pears.com')

  t.ok(
    servers.length > 0 && servers.every((server) => typeof server === 'string'),
    'name servers are strings'
  )
})

test('resolveSoa', async (t) => {
  t.plan(2)

  const soa = await dns.promises.resolveSoa('pears.com')

  t.is(typeof soa.nsname, 'string', 'nsname')
  t.is(typeof soa.serial, 'number', 'serial')
})

test('resolveMx', async (t) => {
  t.plan(1)

  const records = await dns.promises.resolveMx('gmail.com')

  t.ok(
    records.length > 0 &&
      records.every(
        ({ priority, exchange }) => typeof priority === 'number' && typeof exchange === 'string'
      ),
    'mail exchanges'
  )
})

test('resolveSrv', async (t) => {
  t.plan(1)

  const records = await dns.promises.resolveSrv('_sip._udp.sip2sip.info')

  t.ok(
    records.length > 0 &&
      records.every(
        ({ priority, weight, port, name }) =>
          typeof priority === 'number' &&
          typeof weight === 'number' &&
          typeof port === 'number' &&
          typeof name === 'string'
      ),
    'services'
  )
})

test('resolveCaa', async (t) => {
  t.plan(1)

  const records = await dns.promises.resolveCaa('google.com')

  t.ok(
    records.length > 0 && records.every((record) => typeof record.critical === 'number'),
    'certification authorities'
  )
})

test('resolveCname', async (t) => {
  t.plan(1)

  const records = await dns.promises.resolveCname('www.github.com')

  t.ok(
    records.length > 0 && records.every((record) => typeof record === 'string'),
    'canonical names are strings'
  )
})

test('resolveTxt, promises', async (t) => {
  t.plan(1)

  const records = await dns.promises.resolveTxt('google.com')

  t.ok(
    records.length > 0 &&
      records.every(
        (record) => Array.isArray(record) && record.every((chunk) => typeof chunk === 'string')
      ),
    'each record is an array of strings'
  )
})

test('resolve, by record type', async (t) => {
  t.plan(2)

  const addresses = await dns.promises.resolve('bare.pears.com', 'A')

  t.ok(addresses.length > 0, 'resolved A records')

  await t.exception(() => dns.promises.resolve('bare.pears.com', 'NOPE'), /UNKNOWN_RECORD_TYPE/)
})

test('reverse', async (t) => {
  t.plan(2)

  const hostnames = await dns.promises.reverse('8.8.8.8')

  t.ok(
    hostnames.length > 0 && hostnames.every((hostname) => typeof hostname === 'string'),
    'hostnames are strings'
  )

  await t.exception(() => dns.promises.reverse('not an ip'), /INVALID_IP_ADDRESS/)
})

test('query error carries a code, syscall and hostname', async (t) => {
  t.plan(3)

  try {
    await dns.promises.resolveMx('unprobablenonexistentwebsite.invalid')

    t.fail('should not resolve')
  } catch (err) {
    t.ok(err.code === 'ENOTFOUND' || err.code === 'ENODATA', `code is ${err.code}`)
    t.is(err.syscall, 'queryMx', 'syscall')
    t.is(err.hostname, 'unprobablenonexistentwebsite.invalid', 'hostname')
  }
})

test('getServers, setServers', (t) => {
  t.plan(2)

  const resolver = new dns.Resolver()

  t.ok(Array.isArray(resolver.getServers()), 'servers are an array')

  resolver.setServers(['1.1.1.1', '8.8.8.8'])

  t.alike(resolver.getServers(), ['1.1.1.1:53', '8.8.8.8:53'], 'servers round trip')

  resolver.destroy()
})

test('cancel aborts outstanding queries', async (t) => {
  t.plan(5)

  // A black hole, so nothing can complete on its own.
  const resolver = new dns.Resolver({ servers: ['192.0.2.1'] })

  const queries = []

  for (let i = 0; i < 4; i++) {
    queries.push(
      new Promise((resolve) => {
        resolver.resolve4(`unprobablenonexistentwebsite-${i}.invalid`, (err) => {
          t.is(err.code, 'ECANCELLED', 'query cancelled')
          resolve()
        })
      })
    )
  }

  resolver.cancel()

  await Promise.all(queries)

  resolver.destroy()

  await t.exception(() => resolver.resolve4('bare.pears.com', noop), /RESOLVER_DESTROYED/)
})

test('destroyed resolver rejects queries', (t) => {
  t.plan(1)

  const resolver = new dns.Resolver()

  resolver.destroy()

  t.exception(() => resolver.resolveTxt('bare.pears.com', noop), /RESOLVER_DESTROYED/)
})

test('callback is never synchronous, even when cached', async (t) => {
  t.plan(2)

  const resolver = new dns.Resolver()

  for (const pass of ['cold', 'warm']) {
    await new Promise((resolve) => {
      let returned = false
      let synchronous = false

      resolver.resolve4('bare.pears.com', () => {
        synchronous = returned === false

        t.absent(synchronous, `${pass} callback is asynchronous`)

        resolve()
      })

      returned = true
    })
  }

  resolver.destroy()
})

function noop() {}

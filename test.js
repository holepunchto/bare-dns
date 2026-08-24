const test = require('brittle')
const dns = require('.')
const DNSServer = require('./test/fixtures/server')

// The zone every fixture server serves unless a test asks for something else.
// Both the names and the addresses are reserved for documentation and testing,
// so nothing in here can be resolved for real.
const zone = [
  { name: 'example.test', type: 'A', ttl: 300, data: '192.0.2.1' },
  { name: 'example.test', type: 'A', ttl: 300, data: '192.0.2.2' },
  { name: 'example.test', type: 'AAAA', ttl: 120, data: '2001:db8::1' },
  { name: 'example.test', type: 'NS', ttl: 3600, data: 'ns1.example.test' },
  { name: 'example.test', type: 'NS', ttl: 3600, data: 'ns2.example.test' },
  { name: 'example.test', type: 'TXT', ttl: 300, data: ['v=spf1 -all'] },
  { name: 'example.test', type: 'TXT', ttl: 300, data: ['one chunk', 'and another'] },
  {
    name: 'example.test',
    type: 'MX',
    ttl: 300,
    data: { priority: 10, exchange: 'mail.example.test' }
  },
  {
    name: 'example.test',
    type: 'MX',
    ttl: 300,
    data: { priority: 20, exchange: 'backup.example.test' }
  },
  {
    name: 'example.test',
    type: 'SOA',
    ttl: 3600,
    data: {
      nsname: 'ns1.example.test',
      hostmaster: 'hostmaster.example.test',
      serial: 2024010101,
      refresh: 7200,
      retry: 3600,
      expire: 1209600,
      minttl: 300
    }
  },
  {
    name: 'example.test',
    type: 'NAPTR',
    ttl: 300,
    data: {
      order: 100,
      preference: 10,
      flags: 's',
      service: 'SIP+D2U',
      regexp: '',
      replacement: '_sip._udp.example.test'
    }
  },
  {
    name: 'example.test',
    type: 'CAA',
    ttl: 300,
    data: { critical: 0, tag: 'issue', value: 'letsencrypt.org' }
  },
  {
    name: '_sip._udp.example.test',
    type: 'SRV',
    ttl: 300,
    data: { priority: 10, weight: 5, port: 5060, name: 'sip.example.test' }
  },
  {
    name: '_443._tcp.example.test',
    type: 'TLSA',
    ttl: 300,
    data: {
      certUsage: 3,
      selector: 1,
      match: 1,
      data: Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex')
    }
  },

  // An alias, along with one pointing at a name the zone holds nothing for.
  { name: 'alias.test', type: 'CNAME', ttl: 300, data: 'example.test' },
  { name: 'dangling.test', type: 'CNAME', ttl: 300, data: 'nowhere.test' },

  // The reverse zone for the addresses above.
  { name: '1.2.0.192.in-addr.arpa', type: 'PTR', ttl: 300, data: 'example.test' },
  {
    name: '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa',
    type: 'PTR',
    ttl: 300,
    data: 'example.test'
  }
]

// Unlike the `resolve*()` methods, `lookup()` goes through the system resolver
// rather than the servers a resolver is configured with, so it cannot be
// pointed at a fixture. It is exercised against the loopback names instead,
// which every host names locally and so resolve without touching the network.
test('lookup', async (t) => {
  const { address, family } = await dns.promises.lookup('localhost')

  t.ok(address === '127.0.0.1' || address === '::1', `address is ${address}`)
  t.is(family, address === '127.0.0.1' ? 4 : 6, 'family matches the address')
})

test('lookup, ipv4 only', async (t) => {
  t.alike(await dns.promises.lookup('localhost', { family: 4 }), {
    address: '127.0.0.1',
    family: 4
  })
})

test('lookup, ipv6 only', async (t) => {
  try {
    t.alike(await dns.promises.lookup('localhost', { family: 6 }), {
      address: '::1',
      family: 6
    })
  } catch (err) {
    // Not every host names the IPv6 loopback address.
    t.comment(err.message)
    t.pass('no name for the IPv6 loopback address')
  }
})

test('lookup, family by name', async (t) => {
  t.alike(await dns.promises.lookup('localhost', { family: 'IPv4' }), {
    address: '127.0.0.1',
    family: 4
  })
})

test('lookup, unknown family', async (t) => {
  const { address, family } = await dns.promises.lookup('localhost', { family: 'IPv5' })

  t.ok(address === '127.0.0.1' || address === '::1', 'falls back to either family')
  t.ok(family === 4 || family === 6, 'family matches the address')
})

test('lookup all', async (t) => {
  const addresses = await dns.promises.lookup('localhost', { all: true })

  t.ok(addresses.length > 0, 'has addresses')
  t.ok(
    addresses.some(({ address, family }) => address === '127.0.0.1' && family === 4),
    'includes the IPv4 loopback address'
  )
})

test('resolve4', async (t) => {
  const { server, resolver } = await open(t)

  t.alike(await resolver.resolve4('example.test'), ['192.0.2.1', '192.0.2.2'])
  t.alike(server.queries, [{ name: 'example.test', type: 'A' }], 'queried for A records')
})

test('resolve4, with ttl', async (t) => {
  const { resolver } = await open(t)

  t.alike(await resolver.resolve4('example.test', { ttl: true }), [
    { address: '192.0.2.1', ttl: 300 },
    { address: '192.0.2.2', ttl: 300 }
  ])
})

test('resolve4, through an alias', async (t) => {
  const { resolver } = await open(t)

  t.alike(await resolver.resolve4('alias.test'), ['192.0.2.1', '192.0.2.2'])
})

test('resolve4, through an alias to a name with no records', async (t) => {
  const { resolver } = await open(t)

  // The answer holds the alias and nothing else, which is no data rather than
  // no such name.
  await failure(t, () => resolver.resolve4('dangling.test'), 'ENODATA')
})

test('resolve6', async (t) => {
  const { resolver } = await open(t)

  t.alike(await resolver.resolve6('example.test'), ['2001:db8::1'])
})

test('resolve6, with ttl', async (t) => {
  const { resolver } = await open(t)

  t.alike(await resolver.resolve6('example.test', { ttl: true }), [
    { address: '2001:db8::1', ttl: 120 }
  ])
})

test('resolveNs', async (t) => {
  const { resolver } = await open(t)

  t.alike(await resolver.resolveNs('example.test'), ['ns1.example.test', 'ns2.example.test'])
})

test('resolveSoa', async (t) => {
  const { resolver } = await open(t)

  t.alike(await resolver.resolveSoa('example.test'), {
    nsname: 'ns1.example.test',
    hostmaster: 'hostmaster.example.test',
    serial: 2024010101,
    refresh: 7200,
    retry: 3600,
    expire: 1209600,
    minttl: 300
  })
})

test('resolveMx', async (t) => {
  const { resolver } = await open(t)

  t.alike(await resolver.resolveMx('example.test'), [
    { priority: 10, exchange: 'mail.example.test' },
    { priority: 20, exchange: 'backup.example.test' }
  ])
})

test('resolveTxt', async (t) => {
  const { resolver } = await open(t)

  // Each record is an array of its own, as a record longer than 255 bytes is
  // carried as several chunks.
  t.alike(await resolver.resolveTxt('example.test'), [
    ['v=spf1 -all'],
    ['one chunk', 'and another']
  ])
})

test('resolveCname', async (t) => {
  const { resolver } = await open(t)

  t.alike(await resolver.resolveCname('alias.test'), ['example.test'])
})

test('resolveCaa', async (t) => {
  const { resolver } = await open(t)

  // The tag of the record names the property its value is reported under.
  t.alike(await resolver.resolveCaa('example.test'), [{ critical: 0, issue: 'letsencrypt.org' }])
})

test('resolveNaptr', async (t) => {
  const { resolver } = await open(t)

  t.alike(await resolver.resolveNaptr('example.test'), [
    {
      flags: 's',
      service: 'SIP+D2U',
      regexp: '',
      replacement: '_sip._udp.example.test',
      order: 100,
      preference: 10
    }
  ])
})

test('resolveSrv', async (t) => {
  const { resolver } = await open(t)

  t.alike(await resolver.resolveSrv('_sip._udp.example.test'), [
    { priority: 10, weight: 5, port: 5060, name: 'sip.example.test' }
  ])
})

test('resolveTlsa', async (t) => {
  const { resolver } = await open(t)

  t.alike(await resolver.resolveTlsa('_443._tcp.example.test'), [
    {
      certUsage: 3,
      selector: 1,
      match: 1,
      data: Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex')
    }
  ])
})

test('resolvePtr', async (t) => {
  const { resolver } = await open(t)

  t.alike(await resolver.resolvePtr('1.2.0.192.in-addr.arpa'), ['example.test'])
})

test('resolveAny', async (t) => {
  const { resolver } = await open(t)

  // Every record the name holds, in the order the server answered with, save
  // for the types a wildcard query does not report.
  t.alike(await resolver.resolveAny('example.test'), [
    { type: 'A', address: '192.0.2.1', ttl: 300 },
    { type: 'A', address: '192.0.2.2', ttl: 300 },
    { type: 'AAAA', address: '2001:db8::1', ttl: 120 },
    { type: 'NS', value: 'ns1.example.test' },
    { type: 'NS', value: 'ns2.example.test' },
    { type: 'TXT', entries: ['v=spf1 -all'] },
    { type: 'TXT', entries: ['one chunk', 'and another'] },
    { type: 'MX', priority: 10, exchange: 'mail.example.test' },
    { type: 'MX', priority: 20, exchange: 'backup.example.test' },
    {
      type: 'SOA',
      nsname: 'ns1.example.test',
      hostmaster: 'hostmaster.example.test',
      serial: 2024010101,
      refresh: 7200,
      retry: 3600,
      expire: 1209600,
      minttl: 300
    },
    {
      type: 'NAPTR',
      flags: 's',
      service: 'SIP+D2U',
      regexp: '',
      replacement: '_sip._udp.example.test',
      order: 100,
      preference: 10
    }
  ])
})

test('resolve, by record type', async (t) => {
  const { server, resolver } = await open(t)

  // A record type the method dispatches on, the name to ask about and the
  // records the answer should hold.
  const types = [
    ['A', 'example.test', ['192.0.2.1', '192.0.2.2']],
    ['AAAA', 'example.test', ['2001:db8::1']],
    ['CNAME', 'alias.test', ['example.test']],
    ['NS', 'example.test', ['ns1.example.test', 'ns2.example.test']],
    ['PTR', '1.2.0.192.in-addr.arpa', ['example.test']]
  ]

  for (const [rrtype, name, records] of types) {
    t.alike(await resolver.resolve(name, rrtype), records, rrtype)
  }

  t.alike(
    server.queries.map(({ type }) => type),
    types.map(([rrtype]) => rrtype),
    'queried for the type asked for'
  )
})

test('resolve, without a record type', async (t) => {
  const { server, resolver } = await open(t)

  t.alike(await resolver.resolve('example.test'), ['192.0.2.1', '192.0.2.2'])
  t.alike(server.queries, [{ name: 'example.test', type: 'A' }], 'defaults to A records')
})

test('resolve, unknown record type', async (t) => {
  const { resolver } = await open(t)

  await t.exception(() => resolver.resolve('example.test', 'NOPE'), /UNKNOWN_RECORD_TYPE/)
})

test('reverse', async (t) => {
  const { server, resolver } = await open(t)

  t.alike(await resolver.reverse('192.0.2.1'), ['example.test'])
  t.alike(
    server.queries,
    [{ name: '1.2.0.192.in-addr.arpa', type: 'PTR' }],
    'queried the reverse zone'
  )
})

test('reverse, ipv6', async (t) => {
  const { server, resolver } = await open(t)

  t.alike(await resolver.reverse('2001:db8::1'), ['example.test'])
  t.alike(
    server.queries,
    [
      {
        name: '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa',
        type: 'PTR'
      }
    ],
    'queried the reverse zone'
  )
})

test('reverse, invalid ip', async (t) => {
  const { resolver } = await open(t)

  await t.exception(() => resolver.reverse('not an ip'), /INVALID_IP_ADDRESS/)
})

test('reverse, address the reverse zone has no name for', async (t) => {
  const { resolver } = await open(t)

  await failure(t, () => resolver.reverse('192.0.2.9'), 'ENOTFOUND', 'getHostByAddr', '192.0.2.9')
})

test('unknown name', async (t) => {
  const { resolver } = await open(t)

  await failure(t, () => resolver.resolveMx('nowhere.test'), 'ENOTFOUND', 'queryMx', 'nowhere.test')
})

test('name with no records of the type asked for', async (t) => {
  const { resolver } = await open(t)

  await failure(t, () => resolver.resolveSrv('example.test'), 'ENODATA', 'querySrv', 'example.test')
})

test('server failure', async (t) => {
  const { resolver } = await open(t, { code: 'SERVFAIL' })

  await failure(t, () => resolver.resolve4('example.test'), 'ESERVFAIL')
})

test('query refused', async (t) => {
  const { resolver } = await open(t, { code: 'REFUSED' })

  await failure(t, () => resolver.resolve4('example.test'), 'EREFUSED')
})

test('query not implemented', async (t) => {
  const { resolver } = await open(t, { code: 'NOTIMP' })

  await failure(t, () => resolver.resolve4('example.test'), 'ENOTIMP')
})

test('getServers, setServers', (t) => {
  t.plan(2)

  const resolver = new dns.Resolver()

  t.ok(Array.isArray(resolver.getServers()), 'servers are an array')

  resolver.setServers(['1.1.1.1', '8.8.8.8'])

  t.alike(resolver.getServers(), ['1.1.1.1:53', '8.8.8.8:53'], 'servers round trip')

  resolver.destroy()
})

test('setServers, with a port', (t) => {
  t.plan(1)

  const resolver = new dns.Resolver()

  resolver.setServers(['1.1.1.1:5353'])

  t.alike(resolver.getServers(), ['1.1.1.1:5353'], 'the port is kept')

  resolver.destroy()
})

test('setServers redirects queries', async (t) => {
  const { resolver } = await open(t, {
    records: [{ name: 'example.test', type: 'A', data: '192.0.2.1' }]
  })

  const other = await open(t, {
    records: [{ name: 'example.test', type: 'A', data: '192.0.2.2' }]
  })

  t.alike(await resolver.resolve4('example.test'), ['192.0.2.1'], 'answered by the first server')

  // Changing the servers also drops whatever the previous ones answered, so the
  // second query is not served from the cache.
  resolver.setServers(other.server.servers)

  t.alike(await resolver.resolve4('example.test'), ['192.0.2.2'], 'answered by the second server')
})

test('setServers from a query callback', async (t) => {
  t.plan(2)

  const { resolver } = await open(t, {
    callbacks: true,
    records: [{ name: 'example.test', type: 'A', data: '192.0.2.1' }]
  })

  const other = await open(t, {
    records: [{ name: 'example.test', type: 'A', data: '192.0.2.2' }]
  })

  await new Promise((resolve) => {
    resolver.resolve4('example.test', (err, addresses) => {
      t.alike(addresses, ['192.0.2.1'], 'answered by the first server')

      resolver.setServers(other.server.servers)

      resolver.resolve4('example.test', (err, addresses) => {
        t.alike(addresses, ['192.0.2.2'], 'answered by the second server')

        resolve()
      })
    })
  })
})

test('cancel from a query callback', async (t) => {
  t.plan(1)

  const { resolver } = await open(t, { callbacks: true })

  await new Promise((resolve) => {
    resolver.resolve4('example.test', (err, addresses) => {
      t.alike(addresses, ['192.0.2.1', '192.0.2.2'])

      // Cancelling tears down the very query this answer arrived on.
      resolver.cancel()

      resolve()
    })
  })
})

test('destroy from a query callback', async (t) => {
  t.plan(1)

  const { resolver } = await open(t, { callbacks: true })

  await new Promise((resolve) => {
    resolver.resolve4('example.test', (err, addresses) => {
      t.alike(addresses, ['192.0.2.1', '192.0.2.2'])

      resolver.destroy()

      resolve()
    })
  })
})

test('cancel aborts outstanding queries', async (t) => {
  t.plan(5)

  // A server that answers nothing, so that no query can complete on its own.
  const { resolver } = await open(t, { callbacks: true, drop: true })

  const queries = []

  for (let i = 0; i < 4; i++) {
    queries.push(
      new Promise((resolve) => {
        resolver.resolve4(`example-${i}.test`, (err) => {
          t.is(err.code, 'ECANCELLED', 'query cancelled')
          resolve()
        })
      })
    )
  }

  resolver.cancel()

  await Promise.all(queries)

  resolver.destroy()

  await t.exception(() => resolver.resolve4('example.test', noop), /RESOLVER_DESTROYED/)
})

test('destroy cancels outstanding queries', async (t) => {
  t.plan(3)

  const { resolver } = await open(t, { callbacks: true, drop: true })

  const queries = []

  for (let i = 0; i < 3; i++) {
    queries.push(
      new Promise((resolve) => {
        resolver.resolve4(`example-${i}.test`, (err) => {
          t.is(err.code, 'ECANCELLED', 'query cancelled')
          resolve()
        })
      })
    )
  }

  resolver.destroy()

  await Promise.all(queries)
})

test('destroy cancels outstanding queries, promises', async (t) => {
  const { resolver } = await open(t, { drop: true })

  const queries = [resolver.resolve4('example-0.test'), resolver.resolveTxt('example-1.test')]

  resolver.destroy()

  for (const query of queries) {
    await failure(t, () => query, 'ECANCELLED')
  }
})

test('cancel followed by destroy still reports the cancellation', async (t) => {
  t.plan(3)

  const { resolver } = await open(t, { callbacks: true, drop: true })

  const queries = []

  for (let i = 0; i < 3; i++) {
    queries.push(
      new Promise((resolve) => {
        resolver.resolve4(`example-${i}.test`, (err) => {
          t.is(err.code, 'ECANCELLED', 'query cancelled')
          resolve()
        })
      })
    )
  }

  resolver.cancel()
  resolver.destroy()

  await Promise.all(queries)
})

test('destroyed resolver rejects queries', (t) => {
  t.plan(1)

  const resolver = new dns.Resolver()

  resolver.destroy()

  t.exception(() => resolver.resolveTxt('example.test', noop), /RESOLVER_DESTROYED/)
})

test('callback is never synchronous, even when cached', async (t) => {
  t.plan(3)

  const { server, resolver } = await open(t, { callbacks: true })

  for (const pass of ['cold', 'warm']) {
    await new Promise((resolve) => {
      let returned = false

      resolver.resolve4('example.test', () => {
        t.ok(returned, `${pass} callback is asynchronous`)

        resolve()
      })

      returned = true
    })
  }

  t.is(server.queries.length, 1, 'the second answer came from the cache')
})

// Opens a fixture server serving the zone above, along with a resolver pointed
// at it, both torn down when the test ends.
//
// Options are those of the server, along with `callbacks` for a resolver
// exposing the callback based API rather than the promise based one.
async function open(t, opts = {}) {
  const { callbacks = false, records = zone, ...rest } = opts

  const server = await new DNSServer({ records, ...rest }).listen()

  const Resolver = callbacks ? dns.Resolver : dns.promises.Resolver

  const resolver = new Resolver({ servers: server.servers })

  // The resolver goes first, so that nothing is left querying a server that has
  // gone away.
  t.teardown(() => resolver.destroy())
  t.teardown(() => server.close())

  return { server, resolver }
}

// Asserts that a query fails, along with what it reports about the failure.
async function failure(t, fn, code, syscall = null, hostname = null) {
  try {
    await fn()

    t.fail(`should have failed with ${code}`)
  } catch (err) {
    t.is(err.code, code, `code is ${code}`)

    if (syscall !== null) t.is(err.syscall, syscall, 'syscall')
    if (hostname !== null) t.is(err.hostname, hostname, 'hostname')
  }
}

function noop() {}

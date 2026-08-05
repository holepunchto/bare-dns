# bare-dns

Domain name resolution for JavaScript.

```
npm i bare-dns
```

## Usage

```js
const dns = require('bare-dns')

dns.lookup('github.com', (err, address, family) => {
  console.log(address, family)
})
```

## License

Apache-2.0

<!-- bare-refgen:api start -->

## API

### dns

#### `dns.IPFamily`

```ts
type IPFamily = 4 | 6
```

The IP address family: `4` for IPv4 or `6` for IPv6.

#### `dns.lookup`

```ts
dns.lookup(hostname: string, cb: (err: Error | null, address: string | null, family: IPFamily | 0) => void): void
```

Resolve `hostname` into an IP address using the operating system's `getaddrinfo` facility, not the DNS protocol directly. With `all: true`, the callback receives every resolved address instead of just the first.

**Parameters**

| Parameter  | Type                                                                           | Default | Description                                                                   |
| ---------- | ------------------------------------------------------------------------------ | ------- | ----------------------------------------------------------------------------- |
| `hostname` | `string`                                                                       | —       | The host name to resolve.                                                     |
| `cb`       | `(err: Error \| null, address: string \| null, family: IPFamily \| 0) => void` | —       | Called with `(err, address, family)`, or `(err, addresses)` when `all: true`. |

#### `dns.resolveTxt(hostname: string, cb: (err: Error | null, records: string[][]) => void): void`

Use the DNS protocol to resolve TXT records for `hostname`. The callback receives an array of records, each itself an array of the strings that make up that record.

**Parameters**

| Parameter  | Type                                                | Default | Description                                                                         |
| ---------- | --------------------------------------------------- | ------- | ----------------------------------------------------------------------------------- |
| `hostname` | `string`                                            | —       | The host name to query TXT records for.                                             |
| `cb`       | `(err: Error \| null, records: string[][]) => void` | —       | Called with `(err, records)`; each record is an array of the strings it is made of. |

### DNSResolver

#### `destroy(): void`

Cancel any pending queries on this resolver and release its underlying handle.

#### `resolveTxt(hostname: string, cb: (err: Error | null, records: string[][]) => void): void`

Use the DNS protocol to resolve TXT records for `hostname`. The callback receives an array of records, each itself an array of the strings that make up that record.

**Parameters**

| Parameter  | Type                                                | Default | Description                                                                         |
| ---------- | --------------------------------------------------- | ------- | ----------------------------------------------------------------------------------- |
| `hostname` | `string`                                            | —       | The host name to query TXT records for.                                             |
| `cb`       | `(err: Error \| null, records: string[][]) => void` | —       | Called with `(err, records)`; each record is an array of the strings it is made of. |

### Types

#### `LookupOptions`

```ts
interface LookupOptions {
  family?: `IPv${IPFamily}` | IPFamily | 0
  hints?: number
  all?: boolean
}
```

<!-- bare-refgen:api end -->

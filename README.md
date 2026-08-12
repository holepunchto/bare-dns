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

## API

See the [full API reference](https://docs.pears.com/reference/bare/modules/bare-dns).

declare namespace dns {
  interface LookupOptions {
    family?: string | number
  }

  interface LookupOptionsOne extends LookupOptions {
    all?: false
  }

  interface LookupOptionsAll extends LookupOptions {
    all: true
  }

  export function lookup(
    hostname: string,
    cb: (err: Error | null, address: string, family: number) => void
  ): void

  export function lookup(
    hostname: string,
    opts: LookupOptionsOne,
    cb: (err: Error | null, address: string, family: number) => void
  ): void

  export function lookup(
    hostname: string,
    opts: LookupOptionsAll,
    cb: (
      err: Error | null,
      addresses: { address: string; family: number }[]
    ) => void
  ): void
}

export = dns

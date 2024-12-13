declare namespace dns {
  interface LookupOptions {
    family?: string | number
  }

  export function lookup(
    hostname: string,
    cb: (err: Error | null, address: string, family: number) => void
  ): void

  export function lookup(
    hostname: string,
    opts: LookupOptions & { all?: false },
    cb: (err: Error | null, address: string, family: number) => void
  ): void

  export function lookup(
    hostname: string,
    opts: LookupOptions & { all: true },
    cb: (
      err: Error | null,
      addresses: { address: string; family: number }[]
    ) => void
  ): void
}

export = dns

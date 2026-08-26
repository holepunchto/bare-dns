declare class DNSError extends Error {
  readonly name: 'DNSError'
  readonly code: string

  /** Present on errors created by `DNSError.query()`. */
  readonly syscall?: string

  /** Present on errors created by `DNSError.query()` for a named host. */
  readonly hostname?: string

  static RESOLVER_DESTROYED(msg?: string): DNSError
  static UNKNOWN_RECORD_TYPE(msg?: string): DNSError
  static INVALID_IP_ADDRESS(msg?: string): DNSError

  static query(status: number, syscall: string, hostname?: string | null): DNSError
}

export = DNSError

import * as u8a from 'uint8arrays'


export function toJose({ r, s, recoveryParam }: any, recoverable?: boolean): string {
  const jose = new Uint8Array(recoverable ? 65 : 64)
  jose.set(u8a.fromString(r, 'base16'), 0)
  jose.set(u8a.fromString(s, 'base16'), 32)
  if (recoverable) {
    if (recoveryParam === undefined) {
      throw new Error('Signer did not return a recoveryParam')
    }
    jose[64] = recoveryParam
  }
  return bytesToBase64url(jose)
}

export function bytesToBase64url(b: Uint8Array): string {
  return u8a.toString(b, 'base64url')
}
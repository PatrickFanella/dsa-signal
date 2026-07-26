/** Dependency-neutral identity binding used before credentials become durable. */
export interface CanonicalProfile { homeserver: string; userId: string; deviceId: string; }
const hex = (bytes: Uint8Array): string => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
export async function canonicalProfileId(profile: CanonicalProfile): Promise<string> {
  const encoder = new TextEncoder(); const values = [profile.homeserver, profile.userId, profile.deviceId].map(value => encoder.encode(value));
  const bytes = new Uint8Array(values.reduce((size, value) => size + 4 + value.byteLength, 0)); const view = new DataView(bytes.buffer); let offset = 0;
  for (const value of values) { view.setUint32(offset, value.byteLength); offset += 4; bytes.set(value, offset); offset += value.byteLength; }
  if (!globalThis.crypto?.subtle) throw new Error('Web Crypto is unavailable');
  return hex(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes)));
}

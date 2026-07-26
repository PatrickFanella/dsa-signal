import { FoundationClient } from '@dsaslate/foundation-client';
import { describe, expect, it, vi } from 'vitest';
import { FOUNDATION_RESPONSE_MAX_BYTES, FoundationResponseUnavailableError, createBoundedFoundationFetch } from './composition.js';
import { FoundationService, FoundationUnavailableError } from './foundation/foundation-service.js';

const bytes = (size: number): Uint8Array => new TextEncoder().encode(`{}${' '.repeat(size - 2)}`);
const text = (size: number): string => `{}${' '.repeat(size - 2)}`;
const response = (body: BodyInit | null, headers?: HeadersInit): Response => new Response(body, { headers });
const bounded = (result: Response): typeof fetch => createBoundedFoundationFetch(vi.fn(async () => result) as unknown as typeof fetch);
const handoff = { code: 'A'.repeat(43), verifier: 'B'.repeat(43), audience: 'https://chat.example' };

describe('bounded Foundation transport', () => {
  it('accepts exactly 65,536 bytes and leaves JSON parsing to FoundationClient', async () => {
    const body = JSON.stringify({ did: 'did:plc:abcdefghijklmnopqrstuvwx', audience: handoff.audience, authenticatedAt: '2026-07-18T00:00:00Z', expiresIn: 60 });
    const padded = `${body}${' '.repeat(FOUNDATION_RESPONSE_MAX_BYTES - Buffer.byteLength(body))}`;
    const client = new FoundationClient('https://foundation.example', { fetch: bounded(response(padded, { 'content-length': String(FOUNDATION_RESPONSE_MAX_BYTES) })) });
    await expect(client.exchangeIdentityHandoff(handoff)).resolves.toMatchObject({ did: 'did:plc:abcdefghijklmnopqrstuvwx' });
  });

  it('rejects 65,537 bytes before FoundationClient can parse them', async () => {
    const client = new FoundationClient('https://foundation.example', { fetch: bounded(response(text(FOUNDATION_RESPONSE_MAX_BYTES + 1), { 'content-length': String(FOUNDATION_RESPONSE_MAX_BYTES + 1) })) });
    await expect(client.exchangeIdentityHandoff(handoff)).rejects.toBeInstanceOf(FoundationResponseUnavailableError);
  });

  it('does not trust absent or misleading Content-Length and enforces the streamed cap', async () => {
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(bytes(32_768)); controller.enqueue(bytes(32_769)); }, cancel() { cancelled = true; } });
    const fetch = createBoundedFoundationFetch(vi.fn(async () => response(stream, { 'content-length': '1' })) as unknown as typeof globalThis.fetch);
    await expect(fetch('https://foundation.example')).rejects.toBeInstanceOf(FoundationResponseUnavailableError);
    expect(cancelled).toBe(true);
    await expect(createBoundedFoundationFetch(vi.fn(async () => response(text(FOUNDATION_RESPONSE_MAX_BYTES + 1))) as unknown as typeof globalThis.fetch)('https://foundation.example')).rejects.toBeInstanceOf(FoundationResponseUnavailableError);
  });

  it('fails closed for malformed or duplicate Content-Length', async () => {
    for (const value of ['65536, 1', '-1', '01']) await expect(createBoundedFoundationFetch(vi.fn(async () => response('{}', { 'content-length': value })) as unknown as typeof globalThis.fetch)('https://foundation.example')).rejects.toBeInstanceOf(FoundationResponseUnavailableError);
  });

  it('fails closed for an absent or failed stream', async () => {
    await expect(createBoundedFoundationFetch(vi.fn(async () => response(null)) as unknown as typeof globalThis.fetch)('https://foundation.example')).rejects.toBeInstanceOf(FoundationResponseUnavailableError);
    const stream = new ReadableStream<Uint8Array>({ pull(controller) { controller.error(new Error('source failure')); } });
    await expect(createBoundedFoundationFetch(vi.fn(async () => response(stream)) as unknown as typeof globalThis.fetch)('https://foundation.example')).rejects.toBeInstanceOf(FoundationResponseUnavailableError);
  });

  it('maps an oversized identity exchange to FoundationUnavailableError', async () => {
    const client = new FoundationClient('https://foundation.example', { fetch: bounded(response(text(FOUNDATION_RESPONSE_MAX_BYTES + 1))) });
    await expect(new FoundationService(client).exchangeIdentityHandoff(handoff)).rejects.toBeInstanceOf(FoundationUnavailableError);
  });
});

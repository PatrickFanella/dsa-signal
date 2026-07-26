import { describe, expect, it, vi } from 'vitest';
import { FoundationService, FoundationUnavailableError } from './foundation-service.js';

describe('FoundationService identity handoff', () => {
  it('aborts a stalled identity exchange after five seconds', async () => {
    vi.useFakeTimers();
    try {
      const exchangeIdentityHandoff = vi.fn((_input: unknown, options: { signal: AbortSignal }) => new Promise((_, reject) => options.signal.addEventListener('abort', () => reject(new Error('aborted')))));
      const service = new FoundationService({ exchangeIdentityHandoff } as never);
      const pending = service.exchangeIdentityHandoff({ code: 'code', verifier: 'verifier', audience: 'https://chat.example' });
      const rejected = expect(pending).rejects.toBeInstanceOf(FoundationUnavailableError);
      await vi.advanceTimersByTimeAsync(5_000);
      await rejected;
      expect(exchangeIdentityHandoff.mock.calls[0]?.[1]).toEqual({ signal: expect.any(AbortSignal) });
    } finally { vi.useRealTimers(); }
  });
});

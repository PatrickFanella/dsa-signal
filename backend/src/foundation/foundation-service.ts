import type { IdentityFoundation, IdentityHandoffResult } from '../identity/identity-handoff.js';
import { FoundationClientError, type FoundationClient as PackageFoundationClient, type ResolveAuthorityParams, type ResolveAuthorityResult } from '@dsaslate/foundation-client';

export type FoundationAuthorityResponse = ResolveAuthorityResult;

/** The sole Foundation boundary. Browser values are limited to the exchange input. */
export class FoundationService implements IdentityFoundation {
  constructor(private readonly client: PackageFoundationClient) {}
  async exchangeIdentityHandoff(input: { code: string; verifier: string; audience: string }): Promise<IdentityHandoffResult> {
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 5_000);
    try { return await this.client.exchangeIdentityHandoff({ code: input.code, verifier: input.verifier, audience: input.audience }, { signal: controller.signal }); }
    catch (error) {
      if (error instanceof FoundationClientError && error.status >= 400 && error.status < 500 && ['invalid_request', 'invalid_handoff', 'replayed', 'replayed_handoff'].includes(error.code)) throw new FoundationHandoffRejectedError();
      throw new FoundationUnavailableError();
    } finally { clearTimeout(timer); }
  }
  /** Policy refresh is the only non-browser Foundation call. */
  resolveAuthority(input: { uri: string; depth: 16 }, options: { signal: AbortSignal }): Promise<FoundationAuthorityResponse> {
    // The generated package brands validated AT URIs, while this boundary receives
    // an already validated policy URI as a plain string.
    return this.client.resolveAuthority({ ...input, uri: input.uri as ResolveAuthorityParams['uri'] }, options);
  }
}

/** Safe adapter errors: Foundation diagnostics never cross this boundary. */
export class FoundationHandoffRejectedError extends Error { constructor() { super(); this.name = 'FoundationHandoffRejectedError'; } }
export class FoundationUnavailableError extends Error { constructor() { super(); this.name = 'FoundationUnavailableError'; } }

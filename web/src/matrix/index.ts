export type {
  CreateEncryptedRoomRequest,
  DirectConversation,
  DirectConversationIdentity,
  DirectConversationListener,
  DirectConversationRequest,
  DirectTrustListener,
  DirectTrustState,
  DeviceTrustState,
  JoinEncryptedRoomRequest,
  LocalIdentityObservation,
  MatrixDeviceId,
  MatrixEventId,
  MatrixGateway,
  MatrixRoomId,
  MatrixSecurityState,
  MatrixSecurityStateListener,
  MatrixUnsubscribe,
  MatrixUserId,
  MatrixTransactionId,
  SasDisplay,
  SasEmoji,
  SasVerificationPhase,
  SendDirectTextRequest,
  TextDeliveryState,
  TextDirection,
  TimelineListener,
  TimelineTextMessage,
  UserTrustState,
  VerificationListener,
  VerificationRequest,
  VerificationState,
} from './contract';
import { IndexedDbSessionStore } from '../auth/session-store';
import { completeMatrixOAuth, createTokenRefreshCoordinator, startMatrixOAuth, type TokenRefreshCoordinator } from '../auth/matrix-oauth';
import { takeCapturedOAuthCallback } from '../auth/oauth-callback';
import { CryptoOwnerCoordinator, browserCryptoOwnerDependencies } from '../crypto/crypto-owner';
import { MatrixStartupCoordinator, type ClientStartupResult } from './create-client';
import { createSdkBootstrapPort, createSdkOAuthPort, refreshSdkOAuth } from './internal/sdk';
import type { MatrixGateway } from './contract';

/** Public, SDK-free application runtime. The raw Matrix client stays in the seam. */
export interface MatrixRuntime { readonly startup: Promise<import('./contract').MatrixSecurityState>; readonly gateway: MatrixGateway | undefined; startSignIn(): Promise<void>; logout(): Promise<void>; close(): Promise<void>; }
export async function createMatrixRuntime(): Promise<MatrixRuntime> {
  const store = await IndexedDbSessionStore.open();
  const owner = new CryptoOwnerCoordinator(browserCryptoOwnerDependencies());
  const locks = { acquire: (profileId: string, stop: () => Promise<void>) => owner.acquire({ profileId, stop }) };
  const oauth = createSdkOAuthPort();
  const callback = takeCapturedOAuthCallback();
  let callbackFailed = false;
  if (callback.kind !== 'none') { try { await completeMatrixOAuth({ store, locks, port: oauth, callback }); } catch { callbackFailed = true; } }
  const coordinator = new MatrixStartupCoordinator();
  let result: ClientStartupResult | undefined;
  let activeRefresh: TokenRefreshCoordinator | undefined;
  const bootstrap = {
    begin(session: import('../auth/session-store').MatrixSession, signal: AbortSignal) {
      let terminal: (() => Promise<void> | void) | undefined;
      const refresh = createTokenRefreshCoordinator({ store, locator: { profileId: session.profileId, generation: session.generation }, discoverAuthMetadata: oauth.discoverAuthMetadata, refresh: oauth.refresh ?? refreshSdkOAuth, terminalShutdown: async () => { await terminal?.(); } });
      activeRefresh = refresh;
      // The active store is injected into the private SDK seam; it is never a
      // process-global crypto/bootstrap facade.
      const operation = createSdkBootstrapPort(refresh, { store }).begin(session, signal);
      return { ...operation, onTerminal: (listener: () => Promise<void> | void) => { terminal = listener; operation.onTerminal?.(listener); } };
    },
  };
  const startup: Promise<import('./contract').MatrixSecurityState> = callbackFailed ? Promise.resolve('blocked') : coordinator.start(store, locks, bootstrap).then<import('./contract').MatrixSecurityState>(value => { result = value; if (value.kind !== 'runtime') return value.kind === 'follower' ? 'follower' : 'blocked'; let security: import('./contract').MatrixSecurityState = 'blocked'; const gateway = value.gateway; if (!gateway) return security; const unsubscribe = gateway.subscribeSecurityState(next => { security = next; }); unsubscribe(); return security; }).catch(() => 'blocked');
  let logoutFlight: Promise<void> | undefined;
  const logout = (): Promise<void> => logoutFlight ??= (async () => {
    const runtime = result;
    if (runtime?.kind !== 'runtime' || !runtime.beforeRelease) throw new Error('logout unavailable');
    const refresh = activeRefresh;
    if (!refresh) throw new Error('logout unavailable');
    const locator = { profileId: runtime.session.profileId, generation: runtime.session.generation };
    runtime.beforeRelease(async () => {
      await refresh.quiesce();
      const active = await store.getActiveProfile();
      if (!active || active.profileId !== locator.profileId || active.generation !== locator.generation) throw new Error('logout locator drift');
      const session = await store.loadSession(active);
      if (!session) throw new Error('logout session unavailable');
      const revoke = async (token: string | undefined, hint: 'refresh_token' | 'access_token'): Promise<void> => { if (!token) return; try { await oauth.revoke(session.metadata.revocationEndpoint, token, session.clientId, hint); } catch { /* logout continues */ } };
      await revoke(session.refreshToken, 'refresh_token'); await revoke(session.accessToken, 'access_token');
      if (!await store.clearSessionAndAttemptsForLocator(locator)) throw new Error('logout session changed');
    });
    await coordinator.close();
  })().catch(error => { logoutFlight = undefined; throw error; });
  return { startup, get gateway() {
    const runtime = result;
    if (runtime?.kind !== 'runtime' || !runtime.gateway) return undefined;
    const gateway = runtime.gateway;
    // Public stop is the runtime-handle close, not the private SDK operation stop.
    return { ...gateway, stop: () => runtime.close() };
  }, startSignIn: async () => { const destination = await startMatrixOAuth({ store, port: oauth }); window.location.assign(destination); }, logout, close: async () => { await coordinator.close(); store.close(); } };
}

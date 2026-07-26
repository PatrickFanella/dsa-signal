import { captureInstalledOAuthCallback } from './auth/oauth-callback';

// Non-secret identity used by the optional local browser gate to reject an
// image built without its expected source marker.
document.documentElement.dataset.buildMarker = import.meta.env.VITE_BUILD_MARKER ?? 'development';
captureInstalledOAuthCallback({ location: window.location, history: window.history, hardNavigate: url => window.location.replace(url) });
void import('./app-entry').then(({ mountApplication }) => mountApplication());

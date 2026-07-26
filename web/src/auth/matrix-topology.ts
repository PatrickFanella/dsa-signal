/** Immutable Task 7 topology.  Kept SDK-free so persistence and startup share it. */
export const MATRIX_HOMESERVER = 'https://matrix.localhost:8443';
export const MATRIX_ISSUER = 'https://auth.localhost:8443/';
export const MATRIX_AUTHORIZATION_ENDPOINT = 'https://auth.localhost:8443/authorize';
export const MATRIX_TOKEN_ENDPOINT = 'https://auth.localhost:8443/oauth2/token';
export const MATRIX_REGISTRATION_ENDPOINT = 'https://auth.localhost:8443/oauth2/registration';
export const MATRIX_REVOCATION_ENDPOINT = 'https://auth.localhost:8443/oauth2/revoke';
export const MATRIX_REDIRECT_URI = 'https://chat.localhost:8443/';
/** Bump whenever any exact DCR metadata field changes; this value is non-secret. */
export const MATRIX_CLIENT_METADATA_VERSION = 'dcr-v1-7f5a56e2';

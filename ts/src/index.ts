// Public API. Everything else in src/ is internal.
export { createAuth, type Auth } from "./auth.js";
export type { AuthConfig } from "./config.js";
export { KeycloakError } from "./keycloak.js";
export { AUTH_ROUTES, loginUrl } from "./routes.js";
export { decodeAccessToken, isTokenExpired } from "./tokens.js";
export type {
  AuthErrorBody,
  AuthUser,
  KeycloakAccessTokenPayload,
  KeycloakIdTokenPayload,
  KeycloakTokenResponse,
} from "./types.js";

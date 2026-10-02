/** The raw claims inside a Keycloak access token, as Keycloak issues them.
 *  Most code wants {@link AuthUser} (via `auth.getCurrentUser()`) instead; reach
 *  for this only when you need a claim `AuthUser` doesn't carry. */
export interface KeycloakAccessTokenPayload {
  /** Issuer: `${keycloakUrl}/realms/${realm}`. */
  iss: string;
  /** Keycloak user ID (a UUID). Stable across sessions; use it as the user key. */
  sub: string;
  aud: string | string[];
  /** Expiry, in seconds since the epoch. */
  exp: number;
  /** Issued at, in seconds since the epoch. */
  iat: number;
  jti: string;
  nbf?: number;
  preferred_username: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  locale?: string;
  /** Realm-wide roles, shared by every client in the realm. */
  realm_access?: {
    roles: string[];
  };
  /** Client roles, keyed by client ID. This app's are under its `clientId`. */
  resource_access?: {
    [clientId: string]: {
      roles: string[];
    };
  };
  /** Keycloak SSO session ID. */
  sid: string;
  session_state?: string;
  azp?: string;
  scope?: string;
}

/** The raw claims inside a Keycloak ID token. The library only uses the ID
 *  token as `id_token_hint` on logout; app code rarely needs this type. */
export interface KeycloakIdTokenPayload {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  auth_time?: number;
  nonce?: string;
  preferred_username: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  locale?: string;
  sid: string;
}

/** What Keycloak's token endpoint returns on login and on refresh. */
export interface KeycloakTokenResponse {
  access_token: string;
  id_token: string;
  refresh_token: string;
  token_type: "Bearer";
  /** Access token lifetime, in seconds. */
  expires_in: number;
  /** Refresh token lifetime, in seconds. `0` means an offline token, with no time limit. */
  refresh_expires_in: number;
  session_state: string;
  scope: string;
}

/** The signed-in user, as returned by `auth.getCurrentUser()` and
 *  `auth.requireAnyRole()`. Built from the access token's claims; optional
 *  profile fields are `undefined` when the Keycloak client doesn't map them.
 *
 *  @example
 *  const user = await auth.getCurrentUser();
 *  if (user) console.log(`${user.name ?? user.username} <${user.email}>`);
 */
export interface AuthUser {
  /** Keycloak user ID (a UUID). Stable across sessions; use it as the user key. */
  sub: string;
  /** Login name (`preferred_username`). */
  username: string;
  email: string | undefined;
  /** `false` when Keycloak doesn't say otherwise. */
  emailVerified: boolean;
  /** Full display name. */
  name: string | undefined;
  givenName: string | undefined;
  familyName: string | undefined;
  /** The user's Keycloak locale, e.g. `"pt-BR"`. */
  locale: string | undefined;
  /** Realm-wide roles, shared by every client in the realm. */
  realmRoles: string[];
  /** Roles of this app's client (`clientId` in `createAuth`) only. */
  clientRoles: string[];
  /** `realmRoles` and `clientRoles` merged, without duplicates. This is what
   *  `auth.hasRole`, `requireAnyRole` and `guardAnyRole` check. */
  allRoles: string[];
  /** Keycloak SSO session ID (`sid`). */
  sessionId: string;
}

/** JSON body of the 401/403 responses from `auth.guardAnyRole`. */
export interface AuthErrorBody {
  /** `"Unauthorized"` or `"Forbidden"`. */
  error: string;
}

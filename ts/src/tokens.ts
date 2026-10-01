import { decodeJwt } from "jose";
import type { AuthUser, KeycloakAccessTokenPayload } from "./types.js";

/** Reads an access token's claims **without verifying its signature**.
 *  Fine for the token in this app's httpOnly cookie, which only the server
 *  sets; never use it to trust a token received from elsewhere. Throws if
 *  `token` isn't a JWT. */
export function decodeAccessToken(token: string): KeycloakAccessTokenPayload {
  return decodeJwt(token) as KeycloakAccessTokenPayload;
}

/** `true` if `token` expires within `bufferSeconds` (default 30), has no
 *  `exp` claim, or can't be decoded. The buffer avoids sending a token that
 *  expires on its way to the backend.
 *
 *  @example
 *  isTokenExpired(token);    // expired or expiring within 30s
 *  isTokenExpired(token, 0); // strictly expired
 */
export function isTokenExpired(token: string, bufferSeconds = 30): boolean {
  try {
    const payload = decodeJwt(token);
    if (!payload.exp) return true;
    return payload.exp < Math.floor(Date.now() / 1000) + bufferSeconds;
  } catch {
    return true;
  }
}

export function getRealmRoles(
  payload: KeycloakAccessTokenPayload,
): string[] {
  return payload.realm_access?.roles ?? [];
}

export function getClientRoles(
  payload: KeycloakAccessTokenPayload,
  clientId: string,
): string[] {
  return payload.resource_access?.[clientId]?.roles ?? [];
}

export function buildAuthUser(
  payload: KeycloakAccessTokenPayload,
  clientId: string,
): AuthUser {
  const realmRoles = getRealmRoles(payload);
  const clientRoles = getClientRoles(payload, clientId);
  return {
    sub: payload.sub,
    username: payload.preferred_username,
    email: payload.email,
    emailVerified: payload.email_verified ?? false,
    name: payload.name,
    givenName: payload.given_name,
    familyName: payload.family_name,
    locale: payload.locale,
    realmRoles,
    clientRoles,
    allRoles: [...new Set([...realmRoles, ...clientRoles])],
    sessionId: payload.sid,
  };
}

/** Whether `user` holds at least one of `roles`, realm or client. */
export function hasAnyRole(user: AuthUser, roles: readonly string[]): boolean {
  return roles.some((role) => user.allRoles.includes(role));
}

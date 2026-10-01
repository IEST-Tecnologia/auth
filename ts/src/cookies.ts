import { cookies } from "next/headers";
import type { KeycloakTokenResponse } from "./types.js";

/** Cookie names. Every consuming app depends on these: renaming one signs
 *  everybody out and is a major version. */
export const COOKIE = {
  accessToken: "kc_access_token",
  idToken: "kc_id_token",
  refreshToken: "kc_refresh_token",
  pkceState: "kc_pkce_state",
} as const;

const COOKIE_BASE = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax" as const,
  path: "/",
};

// Stored in the kc_pkce_state cookie while sign-in is in progress.
export interface PKCEState {
  codeVerifier: string;
  state: string;
  returnTo: string;
}

/** Anything cookies can be written to: `cookies()` in a Route Handler, or
 *  `response.cookies` in the proxy. */
interface CookieWriter {
  set(name: string, value: string, options: typeof COOKIE_BASE & { maxAge: number }): unknown;
}

// Refresh tokens with refresh_expires_in=0 are offline tokens (no time expiry).
// Fall back to 30 days for the cookie maxAge.
function refreshMaxAge(refreshExpiresIn: number): number {
  return refreshExpiresIn > 0 ? refreshExpiresIn : 60 * 60 * 24 * 30;
}

/** Stores a token response as the session cookies. */
export function writeTokenCookies(store: CookieWriter, tokens: KeycloakTokenResponse): void {
  store.set(COOKIE.accessToken, tokens.access_token, {
    ...COOKIE_BASE,
    maxAge: tokens.expires_in,
  });
  store.set(COOKIE.idToken, tokens.id_token, {
    ...COOKIE_BASE,
    maxAge: tokens.expires_in,
  });
  store.set(COOKIE.refreshToken, tokens.refresh_token, {
    ...COOKIE_BASE,
    maxAge: refreshMaxAge(tokens.refresh_expires_in),
  });
}

async function read(name: string): Promise<string | undefined> {
  return (await cookies()).get(name)?.value;
}

export const getAccessToken = () => read(COOKIE.accessToken);
export const getIdToken = () => read(COOKIE.idToken);
export const getRefreshToken = () => read(COOKIE.refreshToken);

export async function setAuthCookies(tokens: KeycloakTokenResponse): Promise<void> {
  writeTokenCookies(await cookies(), tokens);
}

export async function clearAuthCookies(): Promise<void> {
  const cookieStore = await cookies();
  cookieStore.delete(COOKIE.accessToken);
  cookieStore.delete(COOKIE.idToken);
  cookieStore.delete(COOKIE.refreshToken);
}

export async function setPKCEStateCookie(state: PKCEState): Promise<void> {
  (await cookies()).set(COOKIE.pkceState, JSON.stringify(state), {
    ...COOKIE_BASE,
    maxAge: 600, // 10 minutes — enough time to complete login
  });
}

export async function getPKCEStateCookie(): Promise<PKCEState | null> {
  const raw = await read(COOKIE.pkceState);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as PKCEState;
  } catch {
    return null;
  }
}

export async function clearPKCEStateCookie(): Promise<void> {
  (await cookies()).delete(COOKIE.pkceState);
}

import type { NextRequest, NextResponse } from "next/server";
import { lazyConfig, type AuthConfig } from "./config.js";
import { getAccessToken, getIdToken, getRefreshToken } from "./cookies.js";
import { createHandlers } from "./handlers.js";
import { createProxy } from "./proxy.js";
import type { AuthErrorBody, AuthUser } from "./types.js";
import { createUserHelpers } from "./user.js";

/** Everything an app needs, bound to one Keycloak client. Create it once
 *  with `createAuth()` and import it wherever it's needed. */
export interface Auth {
  // --- Wiring (one line each in the app) ---

  /** `GET /api/auth/login`: starts sign-in. Redirects to Keycloak and, once
   *  the user signs in, back to the `?returnTo=` path (default `"/"`). A
   *  `returnTo` that isn't a same-origin path is replaced with `"/"`. Build
   *  links with `loginUrl()`.
   *
   *  @example
   *  // app/api/auth/login/route.ts
   *  import { auth } from "@/lib/auth";
   *  export const GET = auth.loginHandler;
   */
  loginHandler(request: NextRequest): Promise<NextResponse>;

  /** `GET /api/auth/callback`: where Keycloak sends the user after sign-in.
   *  Register `${appUrl}/api/auth/callback` in the client's "Valid redirect
   *  URIs". On success it stores the tokens in cookies and redirects to
   *  `returnTo`. On failure it redirects to `/?error=<reason>`, where the
   *  reason is Keycloak's error description, `invalid_callback`,
   *  `state_mismatch` or `token_exchange_failed`.
   *
   *  @example
   *  // app/api/auth/callback/route.ts
   *  import { auth } from "@/lib/auth";
   *  export const GET = auth.callbackHandler;
   */
  callbackHandler(request: NextRequest): Promise<NextResponse>;

  /** `GET /api/auth/logout`: signs out. Revokes the refresh token, clears
   *  the auth cookies and ends the Keycloak SSO session, then returns to
   *  `${appUrl}/`. Register that URL in the client's "Valid post logout
   *  redirect URIs". Link to it with `AUTH_ROUTES.logout`.
   *
   *  @example
   *  // app/api/auth/logout/route.ts
   *  import { auth } from "@/lib/auth";
   *  export const GET = auth.logoutHandler;
   */
  logoutHandler(): Promise<NextResponse>;

  /** Guards every page the proxy matcher covers. A valid access token passes
   *  through, an expired one is refreshed silently, and anything else goes
   *  to the login route, then back to the requested page.
   *
   *  The matcher must skip `/api`, or the login route itself would require
   *  a login. Write `config` in the file itself: Next reads it statically.
   *
   *  @example
   *  // proxy.ts
   *  import { auth } from "@/lib/auth";
   *  export const proxy = auth.proxy;
   *  export const config = {
   *    matcher: ["/((?!api|_next/static|_next/image|.*\\..*).*)"],
   *  };
   */
  proxy(request: NextRequest): Promise<NextResponse>;

  // --- Reading the user ---

  /** The signed-in user, or `null` if there's no session or the access token
   *  has expired. Works in Server Components, Server Actions and Route
   *  Handlers. It reads the cookie and never calls Keycloak, so it's cheap to
   *  call more than once per request.
   *
   *  @example
   *  const user = await auth.getCurrentUser();
   *  if (!user) return <a href={loginUrl("/reports")}>Entrar</a>;
   *  return <p>Olá, {user.givenName ?? user.username}</p>;
   */
  getCurrentUser(): Promise<AuthUser | null>;

  /** `true` if there's a signed-in user with an unexpired access token. */
  isAuthenticated(): Promise<boolean>;

  /** The current user's roles, split by source. All three lists are empty
   *  when nobody is signed in. */
  getUserRoles(): Promise<{ realmRoles: string[]; clientRoles: string[]; allRoles: string[] }>;

  /** `true` if the signed-in user holds `role`, as a realm **or** client role
   *  (see `AuthUser.allRoles`). `false` when nobody is signed in. Use it to
   *  show or hide UI; to block a page or endpoint, use `requireAnyRole` or
   *  `guardAnyRole`.
   *
   *  @example
   *  {(await auth.hasRole("gestor")) && <ApproveButton />}
   */
  hasRole(role: string): Promise<boolean>;

  /** `true` if the refresh token cookie exists and hasn't expired, meaning
   *  the proxy can renew the session without sending the user to Keycloak. */
  hasValidRefreshToken(): Promise<boolean>;

  // --- Guards ---

  /** Guards a page (Server Component) by role. Returns the user if they hold
   *  at least one of `roles`; otherwise it redirects and never returns:
   *
   *  - Nobody signed in → login, then back to `returnTo` (default `"/"`).
   *  - Signed in without any of `roles` → `forbiddenRedirect` (default `"/"`).
   *
   *  On pages the proxy covers, anonymous visitors never get here: the proxy
   *  already sent them to login and back. `returnTo` matters on pages
   *  outside the matcher, where Next doesn't tell the library the path.
   *
   *  @param roles - Any one of these is enough. Realm and client roles both count.
   *  @param options.returnTo - Same-origin path to come back to after login.
   *  @param options.forbiddenRedirect - Where to send users who lack the roles.
   *
   *  @example
   *  // app/reports/page.tsx
   *  export default async function ReportsPage() {
   *    const user = await auth.requireAnyRole(["supervisor", "gestor"]);
   *    return <h1>Relatórios de {user.name}</h1>;
   *  }
   */
  requireAnyRole(
    roles: readonly string[],
    options?: { returnTo?: string; forbiddenRedirect?: string },
  ): Promise<AuthUser>;

  /** Guards a Route Handler by role. Returns `null` when the user may
   *  proceed, or a response to return as-is:
   *
   *  - Nobody signed in → `401 { error: "Unauthorized" }`
   *  - Signed in without any of `roles` → `403 { error: "Forbidden" }`
   *
   *  Use this rather than `requireAnyRole` in API routes: callers there expect
   *  a status code, not a redirect to a login page.
   *
   *  @param roles - Any one of these is enough. Realm and client roles both count.
   *
   *  @example
   *  // app/api/reports/route.ts
   *  export async function GET() {
   *    const denied = await auth.guardAnyRole(["gestor"]);
   *    if (denied) return denied;
   *    return Response.json(await listReports());
   *  }
   */
  guardAnyRole(roles: readonly string[]): Promise<NextResponse<AuthErrorBody> | null>;

  // --- Raw tokens ---

  /** The raw access token from the `kc_access_token` cookie, or `undefined`.
   *  Send it to your backend as `Authorization: Bearer`. It isn't checked for
   *  expiry; use `getCurrentUser()` to know whether the session is valid.
   *
   *  @example
   *  const token = await auth.getAccessToken();
   *  const res = await fetch(`${process.env.API_URL}/orders`, {
   *    headers: { Authorization: `Bearer ${token}` },
   *  });
   */
  getAccessToken(): Promise<string | undefined>;

  /** The raw ID token from the `kc_id_token` cookie, or `undefined`. */
  getIdToken(): Promise<string | undefined>;

  /** The raw refresh token from the `kc_refresh_token` cookie, or `undefined`.
   *  Keep it server-side: whoever holds it can mint new access tokens. */
  getRefreshToken(): Promise<string | undefined>;
}

/** Creates the app's auth instance. Call it once, in a server-only module,
 *  and import the result everywhere else.
 *
 *  The config is checked on the first request, not here, so `next build`
 *  works in environments without the runtime secrets. A missing value then
 *  throws `createAuth: missing <field>`.
 *
 *  @example
 *  // lib/auth.ts
 *  import "server-only";
 *  import { createAuth } from "@iest-tecnologia/auth-next";
 *
 *  export const auth = createAuth({
 *    keycloakUrl: "https://auth.example.com",
 *    realm: "iest",
 *    clientId: "my-app",
 *    clientSecret: process.env.KEYCLOAK_CLIENT_SECRET!,
 *    appUrl: process.env.APP_URL!,
 *  });
 */
export function createAuth(config: AuthConfig): Auth {
  const getConfig = lazyConfig(config);
  return {
    ...createHandlers(getConfig),
    proxy: createProxy(getConfig),
    ...createUserHelpers(getConfig),
    getAccessToken,
    getIdToken,
    getRefreshToken,
  };
}

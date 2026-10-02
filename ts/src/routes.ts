/** Where the app must mount the handlers from `handlers.ts`. Fixed rather
 *  than configurable: the callback URL is registered in each Keycloak
 *  client's "Valid redirect URIs", so every app agreeing on it keeps that
 *  setup identical. Lives under `/api` because the recommended proxy
 *  matcher skips `/api` — otherwise reaching the login route would itself
 *  require being logged in. */
export const AUTH_ROUTES = {
  login: "/api/auth/login",
  callback: "/api/auth/callback",
  logout: "/api/auth/logout",
} as const;

/** A link to the login route that comes back to `returnTo` afterwards.
 *  `returnTo` must be a same-origin path like `"/reports?tab=2"`; anything
 *  else sends the user to `"/"`.
 *
 *  @example
 *  <a href={loginUrl("/reports")}>Entrar</a>
 *  // → /api/auth/login?returnTo=%2Freports
 */
export function loginUrl(returnTo: string): string {
  return `${AUTH_ROUTES.login}?returnTo=${encodeURIComponent(returnTo)}`;
}

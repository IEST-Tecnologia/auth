import { NextResponse, type NextRequest } from "next/server";
import type { ResolvedConfig } from "./config.js";
import {
  clearAuthCookies,
  clearPKCEStateCookie,
  getIdToken,
  getPKCEStateCookie,
  getRefreshToken,
  setAuthCookies,
  setPKCEStateCookie,
} from "./cookies.js";
import {
  buildAuthorizationUrl,
  buildLogoutUrl,
  exchangeCodeForTokens,
  revokeToken,
} from "./keycloak.js";
import { generateCodeVerifier, generateState } from "./pkce.js";
import { AUTH_ROUTES } from "./routes.js";

export function createHandlers(getConfig: () => ResolvedConfig) {
  async function loginHandler(request: NextRequest): Promise<NextResponse> {
    const config = getConfig();
    const returnTo = request.nextUrl.searchParams.get("returnTo") ?? "/";

    // Prevent open redirect: only same-origin paths. "//evil.com" is
    // protocol-relative, so a leading slash alone isn't enough.
    const safeReturnTo = returnTo.startsWith("/") && !returnTo.startsWith("//") ? returnTo : "/";

    const codeVerifier = generateCodeVerifier();
    const state = generateState();
    await setPKCEStateCookie({ codeVerifier, state, returnTo: safeReturnTo });

    return NextResponse.redirect(await buildAuthorizationUrl(config, codeVerifier, state));
  }

  async function callbackHandler(request: NextRequest): Promise<NextResponse> {
    const config = getConfig();
    const { searchParams } = request.nextUrl;
    const code = searchParams.get("code");
    const state = searchParams.get("state");
    const error = searchParams.get("error");

    if (error) {
      const desc = searchParams.get("error_description") ?? "Authentication failed";
      return NextResponse.redirect(new URL(`/?error=${encodeURIComponent(desc)}`, config.appUrl));
    }

    if (!code || !state) {
      return NextResponse.redirect(new URL("/?error=invalid_callback", config.appUrl));
    }

    const pkceState = await getPKCEStateCookie();
    if (!pkceState || pkceState.state !== state) {
      return NextResponse.redirect(new URL("/?error=state_mismatch", config.appUrl));
    }

    await clearPKCEStateCookie();

    try {
      const tokens = await exchangeCodeForTokens(config, code, pkceState.codeVerifier);
      await setAuthCookies(tokens);
      return NextResponse.redirect(new URL(pkceState.returnTo, config.appUrl));
    } catch (err) {
      console.error("[auth/callback] token exchange failed:", err);
      return NextResponse.redirect(new URL("/?error=token_exchange_failed", config.appUrl));
    }
  }

  async function logoutHandler(): Promise<NextResponse> {
    const config = getConfig();
    const idToken = await getIdToken();
    const refreshToken = await getRefreshToken();

    // Best-effort revocation of the refresh token at Keycloak
    if (refreshToken) {
      await revokeToken(config, refreshToken, "refresh_token").catch((e) =>
        console.error("[auth/logout] revoke failed:", e),
      );
    }

    await clearAuthCookies();

    // Redirect to Keycloak end-session endpoint to kill the SSO session
    if (idToken) {
      return NextResponse.redirect(buildLogoutUrl(config, idToken, `${config.appUrl}/`));
    }
    return NextResponse.redirect(new URL("/", config.appUrl));
  }

  // One entry point for app/api/auth/[...auth]/route.ts, dispatching on the
  // fixed paths in AUTH_ROUTES. Trailing slashes are tolerated so apps with
  // `trailingSlash: true` still match.
  async function GET(request: NextRequest): Promise<NextResponse> {
    const path = request.nextUrl.pathname.replace(/\/+$/, "");
    switch (path) {
      case AUTH_ROUTES.login:
        return loginHandler(request);
      case AUTH_ROUTES.callback:
        return callbackHandler(request);
      case AUTH_ROUTES.logout:
        return logoutHandler();
      default:
        return NextResponse.json({ error: "Not Found" }, { status: 404 });
    }
  }

  return { handlers: { GET } };
}

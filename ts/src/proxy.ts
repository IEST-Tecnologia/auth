import { NextResponse, type NextRequest } from "next/server";
import type { ResolvedConfig } from "./config.js";
import { COOKIE, writeTokenCookies } from "./cookies.js";
import { refreshAccessToken } from "./keycloak.js";
import { AUTH_ROUTES } from "./routes.js";
import { isTokenExpired } from "./tokens.js";

function redirectToLogin(request: NextRequest): NextResponse {
  const loginUrl = new URL(AUTH_ROUTES.login, request.url);
  loginUrl.searchParams.set("returnTo", request.nextUrl.pathname + request.nextUrl.search);
  return NextResponse.redirect(loginUrl);
}

export function createProxy(getConfig: () => ResolvedConfig) {
  return async function authProxy(request: NextRequest): Promise<NextResponse> {
    const accessToken = request.cookies.get(COOKIE.accessToken)?.value;
    if (accessToken && !isTokenExpired(accessToken)) {
      return NextResponse.next();
    }

    const refreshToken = request.cookies.get(COOKIE.refreshToken)?.value;
    if (!refreshToken || isTokenExpired(refreshToken, 0)) {
      return redirectToLogin(request);
    }

    try {
      const tokens = await refreshAccessToken(getConfig(), refreshToken);
      // Next also hands these cookies to this same request's Server
      // Components, so the page sees the new token, not the expired one.
      const response = NextResponse.next();
      writeTokenCookies(response.cookies, tokens);
      return response;
    } catch (err) {
      console.error("[proxy] silent refresh failed:", err);
      return redirectToLogin(request);
    }
  };
}

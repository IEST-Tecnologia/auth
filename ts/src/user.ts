import { redirect } from "next/navigation";
import { NextResponse } from "next/server";
import type { ResolvedConfig } from "./config.js";
import { getAccessToken, getRefreshToken } from "./cookies.js";
import { loginUrl } from "./routes.js";
import { buildAuthUser, decodeAccessToken, hasAnyRole, isTokenExpired } from "./tokens.js";
import type { AuthErrorBody, AuthUser } from "./types.js";

export function createUserHelpers(getConfig: () => ResolvedConfig) {
  async function getCurrentUser(): Promise<AuthUser | null> {
    const accessToken = await getAccessToken();
    if (!accessToken) return null;
    if (isTokenExpired(accessToken)) return null;
    try {
      return buildAuthUser(decodeAccessToken(accessToken), getConfig().clientId);
    } catch {
      return null;
    }
  }

  async function getUserRoles(): Promise<{
    realmRoles: string[];
    clientRoles: string[];
    allRoles: string[];
  }> {
    const user = await getCurrentUser();
    return {
      realmRoles: user?.realmRoles ?? [],
      clientRoles: user?.clientRoles ?? [],
      allRoles: user?.allRoles ?? [],
    };
  }

  async function hasRole(role: string): Promise<boolean> {
    const { allRoles } = await getUserRoles();
    return allRoles.includes(role);
  }

  async function isAuthenticated(): Promise<boolean> {
    return (await getCurrentUser()) !== null;
  }

  async function hasValidRefreshToken(): Promise<boolean> {
    const refreshToken = await getRefreshToken();
    if (!refreshToken) return false;
    return !isTokenExpired(refreshToken, 0);
  }

  async function requireAnyRole(
    roles: readonly string[],
    { returnTo, forbiddenRedirect = "/" }: { returnTo?: string; forbiddenRedirect?: string } = {},
  ): Promise<AuthUser> {
    const user = await getCurrentUser();
    if (!user) {
      redirect(loginUrl(returnTo ?? "/"));
    }
    if (!hasAnyRole(user, roles)) redirect(forbiddenRedirect);
    return user;
  }

  async function guardAnyRole(
    roles: readonly string[],
  ): Promise<NextResponse<AuthErrorBody> | null> {
    const user = await getCurrentUser();
    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    if (!hasAnyRole(user, roles)) {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 });
    }
    return null;
  }

  return {
    getCurrentUser,
    getUserRoles,
    hasRole,
    isAuthenticated,
    hasValidRefreshToken,
    requireAnyRole,
    guardAnyRole,
  };
}

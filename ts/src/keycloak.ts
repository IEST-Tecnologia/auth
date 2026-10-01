import type { ResolvedConfig } from "./config.js";
import { generateCodeChallenge } from "./pkce.js";
import type { KeycloakTokenResponse } from "./types.js";

/** A failed request to Keycloak's token or revocation endpoint.
 *  `statusCode` is the HTTP status; `errorCode` is the OAuth `error` field
 *  (e.g. `"invalid_grant"`) when Keycloak sends one. The built-in handlers
 *  catch and log it, so app code only sees it if it calls Keycloak itself. */
export class KeycloakError extends Error {
  constructor(
    message: string,
    public readonly statusCode: number,
    public readonly errorCode?: string,
  ) {
    super(message);
    this.name = "KeycloakError";
  }
}

// --- Authorization URL ---

export async function buildAuthorizationUrl(
  config: ResolvedConfig,
  codeVerifier: string,
  state: string,
): Promise<string> {
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const params = new URLSearchParams({
    client_id: config.clientId,
    response_type: "code",
    redirect_uri: config.callbackUrl,
    scope: "openid profile email",
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });
  return `${config.oidcUrl}/auth?${params.toString()}`;
}

// --- Token Requests ---

// POSTs a form to a Keycloak OIDC endpoint, turning an error response into
// a KeycloakError.
async function post(
  config: ResolvedConfig,
  endpoint: "token" | "revoke",
  params: Record<string, string>,
  fallbackMessage: string,
): Promise<Response> {
  const response = await fetch(`${config.oidcUrl}/${endpoint}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      ...params,
    }).toString(),
    cache: "no-store",
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({})) as {
      error?: string;
      error_description?: string;
    };
    throw new KeycloakError(
      error.error_description ?? fallbackMessage,
      response.status,
      error.error,
    );
  }

  return response;
}

async function fetchToken(
  config: ResolvedConfig,
  params: Record<string, string>,
): Promise<KeycloakTokenResponse> {
  const response = await post(config, "token", params, "Keycloak token request failed");
  return response.json() as Promise<KeycloakTokenResponse>;
}

export async function exchangeCodeForTokens(
  config: ResolvedConfig,
  code: string,
  codeVerifier: string,
): Promise<KeycloakTokenResponse> {
  return fetchToken(config, {
    grant_type: "authorization_code",
    code,
    redirect_uri: config.callbackUrl,
    code_verifier: codeVerifier,
  });
}

export async function refreshAccessToken(
  config: ResolvedConfig,
  refreshToken: string,
): Promise<KeycloakTokenResponse> {
  return fetchToken(config, {
    grant_type: "refresh_token",
    refresh_token: refreshToken,
  });
}

// --- Logout ---

export function buildLogoutUrl(
  config: ResolvedConfig,
  idToken: string,
  postLogoutRedirectUri: string,
): string {
  const params = new URLSearchParams({
    id_token_hint: idToken,
    post_logout_redirect_uri: postLogoutRedirectUri,
    client_id: config.clientId,
  });
  return `${config.oidcUrl}/logout?${params.toString()}`;
}

export async function revokeToken(
  config: ResolvedConfig,
  token: string,
  tokenTypeHint: "refresh_token" | "access_token",
): Promise<void> {
  await post(
    config,
    "revoke",
    { token, token_type_hint: tokenTypeHint },
    "Token revocation failed",
  );
}

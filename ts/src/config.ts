import { AUTH_ROUTES } from "./routes.js";

/** Settings for `createAuth()`. All five are required. Keep the secret in an
 *  environment variable; the others can be written in code.
 *
 *  @example
 *  createAuth({
 *    keycloakUrl: "https://auth.example.com",
 *    realm: "iest",
 *    clientId: "my-app",
 *    clientSecret: process.env.KEYCLOAK_CLIENT_SECRET!,
 *    appUrl: process.env.APP_URL!,
 *  });
 */
export interface AuthConfig {
  /** Keycloak's base URL, e.g. `"https://auth.example.com"`. */
  keycloakUrl: string;
  /** Realm name, e.g. `"iest"`. */
  realm: string;
  /** This app's client ID in Keycloak. Client roles are read from this client. */
  clientId: string;
  /** From the client's **Credentials** tab. Never hard-code it. */
  clientSecret: string;
  /** This app's public origin, e.g. `"https://app.example.com"`. Each
   *  environment (localhost, preview, production) has its own. */
  appUrl: string;
}

export interface ResolvedConfig extends AuthConfig {
  /** `${keycloakUrl}/realms/${realm}/protocol/openid-connect` */
  oidcUrl: string;
  /** `${appUrl}/api/auth/callback`, as registered in Keycloak. */
  callbackUrl: string;
}

const REQUIRED = ["keycloakUrl", "realm", "clientId", "clientSecret", "appUrl"] as const;

/** Defers validation to the first request. `next build` imports route files,
 *  and a build environment may lack runtime secrets, so failing inside
 *  `createAuth()` would break builds that never use them. */
export function lazyConfig(config: AuthConfig): () => ResolvedConfig {
  let resolved: ResolvedConfig | undefined;
  return () => {
    if (resolved) return resolved;
    const missing = REQUIRED.filter((key) => !config[key]);
    if (missing.length > 0) {
      throw new Error(`createAuth: missing ${missing.join(", ")}`);
    }
    const keycloakUrl = config.keycloakUrl.replace(/\/+$/, "");
    const appUrl = config.appUrl.replace(/\/+$/, "");
    resolved = {
      ...config,
      keycloakUrl,
      appUrl,
      oidcUrl: `${keycloakUrl}/realms/${config.realm}/protocol/openid-connect`,
      callbackUrl: `${appUrl}${AUTH_ROUTES.callback}`,
    };
    return resolved;
  };
}

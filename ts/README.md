# @ti-iest/auth-next

Keycloak sign-in for Next.js 16+ apps: one config file, four one-line
files, and you're done.

- **Sign-in and sign-out:** Authorization Code + PKCE, plus a full Keycloak
  logout.
- **Sessions in httpOnly cookies:** the browser's JavaScript never sees a
  token.
- **Silent refresh:** the proxy renews expired sessions on navigation.
- **Role guards:** for pages (redirect) and for API routes (401/403).

Server-side only: use it in Server Components, Server Actions, Route
Handlers and `proxy.ts`, never in Client Components.

## Contents

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Recipes](#recipes)
- [API reference](#api-reference)
- [Troubleshooting](#troubleshooting)
- [Release](#release)

## Quick start

### 1. Install

```sh
npm install @ti-iest/auth-next server-only
```

`server-only` makes the build fail if the auth config (and its secret) is
ever imported from client code.

### 2. Create the auth instance

```ts
// lib/auth.ts
import "server-only";
import { createAuth } from "@ti-iest/auth-next";

export const auth = createAuth({
  keycloakUrl: "https://auth.example.com",
  realm: "iest",
  clientId: "my-app",
  clientSecret: process.env.KEYCLOAK_CLIENT_SECRET!,
  appUrl: process.env.APP_URL!,
});
```

| Option | Example | Notes |
|---|---|---|
| `keycloakUrl` | `"https://auth.example.com"` | Keycloak's base URL |
| `realm` | `"iest"` | |
| `clientId` | `"my-app"` | Client roles are read from this client |
| `clientSecret` | `process.env.KEYCLOAK_CLIENT_SECRET!` | From the client's **Credentials** tab. **Always from an env var, never in code.** |
| `appUrl` | `process.env.APP_URL!` | This app's public origin. Usually an env var, since it differs per environment (`http://localhost:3000` locally). |

All five are required. They're checked on the first request, not at
import, so `next build` works even where the secret isn't set. A missing
value fails that request with `createAuth: missing <field>`.

### 3. Configure the Keycloak client

In the realm's **Clients → your client**:

- **Client authentication:** On (a confidential client).
- **Valid redirect URIs:** `${appUrl}/api/auth/callback`
- **Valid post logout redirect URIs:** `${appUrl}/`

Add a pair of these for each environment (localhost, preview, production).

### 4. Add the auth routes

One catch-all route serves login, callback and logout:

```ts
// app/api/auth/[...auth]/route.ts
import { auth } from "@/lib/auth";
export const { GET } = auth.handlers;
```

The paths it answers are fixed (see [`AUTH_ROUTES`](#routes)), so the file
must live at `app/api/auth/`. Any other path under `/api/auth` gets a `404`.

### 5. Add the proxy

```ts
// proxy.ts (project root, or src/ if you use it)
import { auth } from "@/lib/auth";

export const proxy = auth.proxy;

export const config = {
  // Must skip /api, or the login route itself would require a login.
  matcher: ["/((?!api|_next/static|_next/image|.*\\..*).*)"],
};
```

Write `config` in this file as shown. Next reads it statically, so it
can't come from the package.

That's it: every page now requires a signed-in user. Read the user in any
Server Component:

```tsx
import { AUTH_ROUTES } from "@ti-iest/auth-next";
import { auth } from "@/lib/auth";

export default async function Home() {
  const user = await auth.getCurrentUser();
  return (
    <p>
      Olá, {user?.name} · <a href={AUTH_ROUTES.logout}>Sair</a>
    </p>
  );
}
```

## How it works

```
Browser ──page request──▶ proxy.ts (auth.proxy)
                            ├─ access token valid?      → page renders
                            ├─ expired, refresh valid?  → refresh silently → page renders
                            └─ otherwise                → /api/auth/login?returnTo=<page>

/api/auth/login     → Keycloak sign-in page
Keycloak            → /api/auth/callback  (tokens stored in cookies)
/api/auth/callback  → back to returnTo
```

The session lives in three httpOnly cookies: `kc_access_token`,
`kc_id_token` and `kc_refresh_token`. A fourth one, `kc_pkce_state`, exists
only during sign-in. Cookies are `secure` when `NODE_ENV=production`.

**Two consequences worth knowing:**

- **The proxy only covers pages.** Its matcher skips `/api`, so Route
  Handlers never refresh the session themselves. If a page stays open long
  enough for the access token to expire, its `fetch("/api/...")` calls get
  `401` until the next navigation refreshes the session. Handle `401` in
  client code by reloading or navigating.
- **Tokens are read, not verified.** `auth.getCurrentUser()` decodes the
  token in this app's own httpOnly cookie, which only the server sets. A
  backend that receives the token as `Authorization: Bearer` **must verify
  its signature** against Keycloak itself.

## Recipes

All of these import `auth` from your `lib/auth.ts`.

### Protect a page by role

```tsx
// app/reports/page.tsx
export default async function ReportsPage() {
  // Missing both roles → redirected to "/". Returns the user otherwise.
  const user = await auth.requireAnyRole(["supervisor", "gestor"]);
  return <h1>Relatórios de {user.name}</h1>;
}
```

Anonymous visitors never reach this page: the proxy already sent them to
login and back. On a page *outside* the proxy matcher, pass
`{ returnTo: "/reports" }` so they come back here after signing in.

### Protect an API route by role

```ts
// app/api/reports/route.ts
export async function GET() {
  const denied = await auth.guardAnyRole(["gestor"]);
  if (denied) return denied; // 401 or 403 JSON
  return Response.json(await listReports());
}
```

### Show or hide UI by role

```tsx
{(await auth.hasRole("gestor")) && <ApproveButton />}
```

This only hides the button. Guard the action itself with `guardAnyRole`
or a backend check too.

### Keep role lists in your app

Role names are each app's business, so define them once in the app:

```ts
// lib/roles.ts (in your app, not this library)
export const EDITOR_ROLES = ["supervisor", "gestor"] as const;

// anywhere
await auth.requireAnyRole(EDITOR_ROLES);
```

### Call your backend with the user's token

```ts
const token = await auth.getAccessToken();
const res = await fetch(`${process.env.API_URL}/orders`, {
  headers: { Authorization: `Bearer ${token}` },
  cache: "no-store",
});
```

### Login and logout links

```tsx
import { AUTH_ROUTES, loginUrl } from "@ti-iest/auth-next";

<a href={loginUrl("/reports")}>Entrar</a>
<a href={AUTH_ROUTES.logout}>Sair</a>
```

Use plain `<a>` tags, not `<Link>`. These routes redirect to Keycloak and
must be full page loads.

### Show sign-in errors

When sign-in fails, the callback redirects to `/?error=<reason>`:

```tsx
// app/page.tsx
export default async function Home({ searchParams }: { searchParams: Promise<{ error?: string }> }) {
  const { error } = await searchParams;
  return error ? <p role="alert">Falha no login: {error}</p> : <Dashboard />;
}
```

### Public pages

Exclude them in the proxy matcher. For example, to also skip `/about`
and everything under `/public`:

```ts
matcher: ["/((?!api|about|public|_next/static|_next/image|.*\\..*).*)"],
```

On those pages, `auth.getCurrentUser()` returns the user if one is signed
in and `null` otherwise.

## API reference

Hover any of these in your editor for the full docs and examples.

### `createAuth(config)`

Takes an [`AuthConfig`](#2-create-the-auth-instance) and returns the `auth`
object below. Call it once per app.

### Wiring

| Member | Mount as |
|---|---|
| `auth.handlers` | `export const { GET } = auth.handlers` in `app/api/auth/[...auth]/route.ts` |
| `auth.proxy` | `proxy` in `proxy.ts` |

### Reading the user

| Method | Returns | Notes |
|---|---|---|
| `auth.getCurrentUser()` | `Promise<AuthUser \| null>` | `null` when not signed in or the token expired. No network call. |
| `auth.isAuthenticated()` | `Promise<boolean>` | `getCurrentUser() !== null` |
| `auth.getUserRoles()` | `Promise<{ realmRoles, clientRoles, allRoles }>` | Empty lists when not signed in |
| `auth.hasRole(role)` | `Promise<boolean>` | Realm **or** client role |
| `auth.hasValidRefreshToken()` | `Promise<boolean>` | Whether the session can still be renewed silently |

### Guards

| Method | When allowed | When denied |
|---|---|---|
| `auth.requireAnyRole(roles, { returnTo?, forbiddenRedirect? })` | Returns the `AuthUser` | Not signed in → login, then `returnTo` (default `"/"`). Missing roles → `forbiddenRedirect` (default `"/"`). |
| `auth.guardAnyRole(roles)` | Returns `null` | Returns a `NextResponse`: `401 { error: "Unauthorized" }` or `403 { error: "Forbidden" }` |

`roles` means "any one of these". To require several roles at once, check
`user.allRoles` yourself.

### Tokens

| Member | Returns |
|---|---|
| `auth.getAccessToken()` | Raw access token, or `undefined`. Not checked for expiry. |
| `auth.getIdToken()` | Raw ID token, or `undefined` |
| `auth.getRefreshToken()` | Raw refresh token, or `undefined`. Never send it to the browser. |

### Standalone exports

These don't depend on the config, so they're imported from the package
directly:

| Export | What |
|---|---|
| `AUTH_ROUTES` | `{ login: "/api/auth/login", callback: "/api/auth/callback", logout: "/api/auth/logout" }` |
| `loginUrl(returnTo)` | `"/api/auth/login?returnTo=<encoded>"` |
| `decodeAccessToken(token)` | `KeycloakAccessTokenPayload`, **unverified**. Throws on a malformed token. |
| `isTokenExpired(token, bufferSeconds = 30)` | `true` if expired, expiring within the buffer, or unreadable |
| `KeycloakError` | A failed Keycloak request, with `statusCode` and an optional OAuth `errorCode` |

### Routes

The paths are fixed, because every Keycloak client registers the same
callback shape:

| Constant | Value |
|---|---|
| `AUTH_ROUTES.login` | `"/api/auth/login"` |
| `AUTH_ROUTES.callback` | `"/api/auth/callback"` |
| `AUTH_ROUTES.logout` | `"/api/auth/logout"` |

### Types

**`AuthUser`**: the signed-in user.

| Field | Type | From claim |
|---|---|---|
| `sub` | `string` | `sub`: Keycloak user ID, use it as the user key |
| `username` | `string` | `preferred_username` |
| `email` | `string \| undefined` | `email` |
| `emailVerified` | `boolean` | `email_verified` (default `false`) |
| `name` | `string \| undefined` | `name` |
| `givenName` | `string \| undefined` | `given_name` |
| `familyName` | `string \| undefined` | `family_name` |
| `locale` | `string \| undefined` | `locale` |
| `realmRoles` | `string[]` | `realm_access.roles` |
| `clientRoles` | `string[]` | `resource_access[clientId].roles` |
| `allRoles` | `string[]` | Both of the above, deduplicated. The guards check this. |
| `sessionId` | `string` | `sid` |

**Other types:**

- `AuthConfig`: the options of `createAuth`.
- `Auth`: the type of the object `createAuth` returns.
- `AuthErrorBody`: `{ error: string }`, the body of `guardAnyRole`'s responses.
- `KeycloakAccessTokenPayload`, `KeycloakIdTokenPayload`: raw token claims.
- `KeycloakTokenResponse`: Keycloak's token endpoint response.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `createAuth: missing <field>` | That option was empty at runtime, usually an env var not set where the code runs (check Vercel's env scopes). |
| Keycloak shows "Invalid parameter: redirect_uri" | `${appUrl}/api/auth/callback` isn't in the client's **Valid redirect URIs**, or `appUrl` has the wrong host. |
| Redirect loop on `/api/auth/login` | The proxy matcher doesn't exclude `/api`. |
| Lands on `/?error=state_mismatch` | Sign-in took over 10 minutes, cookies are blocked, or it started on a different host than `appUrl` (e.g. `127.0.0.1` vs `localhost`). |
| Lands on `/?error=token_exchange_failed` | Wrong `clientSecret`, or client authentication is off. Server logs have the detail. |
| Signed in from a public page, but sent back to `/` | That page is outside the proxy matcher. Pass `returnTo` to `requireAnyRole`. |
| Logout says "Invalid redirect uri" | `${appUrl}/` isn't in **Valid post logout redirect URIs**. |
| A user has a role but the guard denies it | It's a client role of a *different* client. Only realm roles and this client's roles count. |
| Build error: "You're importing a module that depends on `server-only`" | A Client Component imports `lib/auth.ts`. Read the user in a Server Component and pass down what the client needs. |

## Release

Bump `version` in `package.json`, commit, then tag with the `ts/` prefix and
push. `.github/workflows/publish-ts.yml` publishes it to GitHub Packages:

```sh
git tag ts/v0.1.0 && git push origin ts/v0.1.0
```

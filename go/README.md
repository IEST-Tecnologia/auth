# github.com/IEST-Tecnologia/auth/go

Keycloak access-token verification for Go backends. It's the server-side
partner of [`@ti-iest/auth-next`](../ts/README.md): the Next.js app sends
`Authorization: Bearer <token>`, and this library checks it.

- **Verification:** signature (keys from the realm's discovery document),
  issuer and expiry.
- **Client roles only:** roles come from `resource_access.<clientId>.roles`.
  Realm roles are ignored because every app in the realm shares them.
- **Group lookup:** reads `groupId`/`groupName` from the token, or calls a
  resolver you provide when they're missing.
- **Echo support** in `echoauth`. The core package has no framework
  dependency.
- **Keycloak Admin API client** in `keycloak`: users, groups, group members
  and client-role holders, with a cached service-account token.

## Install

```sh
go get github.com/IEST-Tecnologia/auth/go@latest
```

The module path ends in `/go`, so import it with a name:

```go
import auth "github.com/IEST-Tecnologia/auth/go"
```

## Usage with Echo

```go
import (
	auth "github.com/IEST-Tecnologia/auth/go"
	"github.com/IEST-Tecnologia/auth/go/echoauth"
)

verifier, err := auth.New(ctx, auth.Config{
	KeycloakURL: os.Getenv("KEYCLOAK_URL"),
	Realm:       os.Getenv("KEYCLOAK_REALM"),
	ClientID:    os.Getenv("KEYCLOAK_CLIENT_ID"),
})
if err != nil {
	log.Fatal(err)
}

api := e.Group("/api/v1", echoauth.Middleware(verifier))
api.POST("/things", createThing, echoauth.RequireRoles("gestor"))
```

Inside a handler:

```go
claims, err := echoauth.GetClaims(c)
// claims.UserID, claims.UserName, claims.Roles, claims.GroupID, claims.GroupName
// claims.Raw holds every claim in the token, as decoded JSON.
```

| Situation | Response |
|---|---|
| No `Authorization: Bearer` header | `401 missing bearer token` |
| Bad signature, wrong issuer, expired | `401 invalid token: <reason>` |
| Valid token without any of the required roles | `403 insufficient role` |

## Config

| Field | Required | Notes |
|---|---|---|
| `KeycloakURL` | yes | Keycloak's base URL, e.g. `https://auth.example.com` |
| `Realm` | yes | |
| `ClientID` | yes | Client roles are read from this client |
| `ResolveGroup` | no | Called when the token has no `groupId`/`groupName`. A failure is logged and the request goes through with an empty group. |
| `Logger` | no | Defaults to `slog.Default()` |

No client secret is needed: verification only uses the realm's public keys.

`auth.New` fetches the discovery document, so it fails at startup if
Keycloak is unreachable.

### Resolving the group through the Admin API

Keycloak doesn't put the user's group in the token unless a protocol mapper
adds it. Without a mapper, let the admin client look it up:

```go
kcAdmin := keycloak.NewAdminClient(keycloakURL, realm, clientID, os.Getenv("KEYCLOAK_CLIENT_SECRET"))

auth.Config{
	// ...
	ResolveGroup: kcAdmin.GroupResolver(),
}
```

`GroupResolver` returns nil when the client has no secret, so the lookup is
skipped. It takes the user's first group and caches it for five minutes.
Any other resolver should cache too: it runs on every request whose token
lacks the group.

## Keycloak Admin API client

```go
import "github.com/IEST-Tecnologia/auth/go/keycloak"

kcAdmin := keycloak.NewAdminClient(keycloakURL, realm, clientID, clientSecret)
if !kcAdmin.Enabled() {
	// no secret: every call would fail
}
```

| Method | Returns | Service-account role |
|---|---|---|
| `User(ctx, id)` | one user, or `ErrUserNotFound` | `view-users` |
| `Group(ctx, id)` | one group, or `ErrGroupNotFound` | `query-groups` |
| `UserPrimaryGroup(ctx, userID)` | the user's first group (zero value if none) | `view-users` |
| `GroupMembers(ctx, groupID)` | every enabled member, all pages | `view-users` |
| `UsersWithClientRole(ctx, role)` | every enabled holder of this client's role | `view-users`, `view-clients` |

Users, groups and user-to-group lookups are cached for five minutes. Member
lists are not cached.

Setup in Keycloak, on the client given as `clientID`:

1. **Settings:** turn on **Client authentication** (it needs a secret) and
   **Service accounts roles**.
2. **Service account roles → Assign role:** filter by `realm-management` and
   assign the roles from the table that you use.
3. Copy the secret from the **Credentials** tab into an env var.

## Other frameworks

Use the core package directly:

```go
claims, err := verifier.VerifyRequest(r)
switch {
case errors.Is(err, auth.ErrMissingToken), errors.Is(err, auth.ErrInvalidToken):
	http.Error(w, err.Error(), http.StatusUnauthorized)
	return
}
if !claims.HasRole("gestor") {
	http.Error(w, "insufficient role", http.StatusForbidden)
	return
}
```

`verifier.Verify(ctx, token)` takes a raw token instead of a request.

## Testing your app

`auth.NewWithKeySet` skips discovery and checks signatures against keys you
supply, so tests can sign their own tokens:

```go
v, _ := auth.NewWithKeySet(cfg, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}})
```

Tokens must carry `iss` = `<KeycloakURL>/realms/<Realm>` and a future `exp`.
See `auth_test.go` for a signing helper.

## Release

Push a tag prefixed with the folder:

```sh
git tag go/v0.1.0
git push origin go/v0.1.0
```

A bare `v0.1.0` tag is invisible to Go for a module in a subfolder. Nothing
else needs publishing: the Go proxy picks the tag up on the first
`go get`.

# auth

Shared Keycloak authentication for IEST-Tecnologia's apps. One library
per language, each versioned and released on its own:

| Folder | Package | For |
|---|---|---|
| [`ts/`](ts/) | [`@ti-iest/auth-next`](ts/README.md) | Next.js 16+ frontends: sign-in, sessions, role guards |
| [`go/`](go/) | [`github.com/IEST-Tecnologia/auth/go`](go/README.md) | Go backends: bearer token verification, role guards, Keycloak Admin API client |

The two meet at the access token. The Next.js app keeps it in an httpOnly
cookie and sends it to the backend as `Authorization: Bearer <token>`. The
backend verifies it against Keycloak.

Neither library holds secrets. Each app passes its own Keycloak realm, client
and credentials when it sets the library up.

**Getting started:** see [`ts/README.md`](ts/README.md) or [`go/README.md`](go/README.md).

## Releasing

Tags are prefixed by folder:

- `ts/vX.Y.Z` publishes the npm package (see [`ts/README.md`](ts/README.md#release)).
- `go/vX.Y.Z` releases the Go module. A bare `vX.Y.Z` tag is invisible to Go for a module in a subfolder.

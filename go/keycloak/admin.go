// Package keycloak provides a minimal client for the Keycloak Admin REST
// API, used to resolve data that isn't available as a token claim (e.g. a
// user's group ID/name, when no custom protocol mapper exposes it).
package keycloak

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	auth "github.com/IEST-Tecnologia/auth/go"
)

// AdminClient calls the Keycloak Admin REST API using a service-account
// access token obtained via the client_credentials grant.
//
// Prerequisites in Keycloak, on the client identified by ClientID:
//   - "Client authentication" must be ON (confidential client), since this
//     needs a client secret.
//   - "Service accounts roles" must be enabled.
//   - The service account must be granted the realm-management client
//     roles "view-users", "query-groups" and "view-clients" (Clients ->
//     <client> -> Service account roles -> Assign role). "view-clients" is
//     what lets UsersWithClientRole resolve this client's internal UUID.
type AdminClient struct {
	baseURL      string
	realm        string
	clientID     string
	clientSecret string
	httpClient   *http.Client

	tokenMu     sync.Mutex
	accessToken string
	tokenExpiry time.Time

	// groupCache is keyed by group ID, userGroupCache by user ID: one answers
	// "what is this group called", the other "which group is this person in".
	groupCacheMu   sync.RWMutex
	groupCache     map[string]cachedGroup
	userGroupCache map[string]cachedGroup
	groupCacheTTL  time.Duration

	userCacheMu sync.RWMutex
	userCache   map[string]cachedMember

	// The client's internal UUID, resolved from clientID on first use. It
	// never changes for a realm, so it is cached without expiry.
	clientUUIDMu     sync.Mutex
	cachedClientUUID string
}

// NewAdminClient builds an AdminClient. baseURL is the Keycloak base URL,
// and clientID/clientSecret identify the confidential client used to
// authenticate as a service account. Without a secret the client is
// disabled (see Enabled).
func NewAdminClient(baseURL, realm, clientID, clientSecret string) *AdminClient {
	return &AdminClient{
		baseURL:        strings.TrimSuffix(baseURL, "/"),
		realm:          realm,
		clientID:       clientID,
		clientSecret:   clientSecret,
		httpClient:     &http.Client{Timeout: 5 * time.Second},
		groupCache:     make(map[string]cachedGroup),
		userGroupCache: make(map[string]cachedGroup),
		groupCacheTTL:  5 * time.Minute,
		userCache:      make(map[string]cachedMember),
	}
}

// Enabled reports whether this client has the credentials needed to call
// the Admin API at all (a client secret is required for the
// client_credentials grant).
func (c *AdminClient) Enabled() bool {
	return c != nil && c.clientSecret != ""
}

// GroupResolver adapts UserPrimaryGroup for auth.Config.ResolveGroup. It
// returns nil when the client is disabled, so the verifier skips the lookup.
func (c *AdminClient) GroupResolver() auth.GroupResolver {
	if !c.Enabled() {
		return nil
	}
	return func(ctx context.Context, userID string) (auth.Group, error) {
		g, err := c.UserPrimaryGroup(ctx, userID)
		return auth.Group{ID: g.ID, Name: g.Name}, err
	}
}

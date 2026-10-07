// Package auth verifies Keycloak access tokens for Go backends.
//
// A Verifier checks a bearer token's signature, issuer and expiry against a
// Keycloak realm and returns the caller's Claims: user ID and name, the
// client roles of one Keycloak client, and optionally the user's group.
//
// The core package does not depend on any web framework. For Echo, see the
// echoauth subpackage.
package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// ErrMissingToken is returned when a request carries no bearer token.
var ErrMissingToken = errors.New("missing bearer token")

// ErrInvalidToken is returned when a token fails verification or its claims
// cannot be decoded. The returned error wraps it with the reason.
var ErrInvalidToken = errors.New("invalid token")

// Config identifies the Keycloak realm and client whose tokens are accepted.
type Config struct {
	// KeycloakURL is Keycloak's base URL, e.g. "https://auth.example.com".
	KeycloakURL string
	// Realm is the Keycloak realm that issues the tokens.
	Realm string
	// ClientID is the client whose roles are read, from
	// "resource_access.<ClientID>.roles". Realm roles are ignored on purpose:
	// they are shared by every app in the realm.
	ClientID string
	// ResolveGroup is called when the token carries no "groupId"/"groupName"
	// claims. Optional. If it fails, the error is logged and the request
	// proceeds with an empty group.
	ResolveGroup GroupResolver
	// Logger receives group resolution warnings. Defaults to slog.Default().
	Logger *slog.Logger
}

// IssuerURL returns the realm's OIDC issuer, e.g.
// "https://auth.example.com/realms/iest".
func (c Config) IssuerURL() string {
	return strings.TrimSuffix(c.KeycloakURL, "/") + "/realms/" + c.Realm
}

func (c Config) validate() error {
	var missing []string
	if c.KeycloakURL == "" {
		missing = append(missing, "KeycloakURL")
	}
	if c.Realm == "" {
		missing = append(missing, "Realm")
	}
	if c.ClientID == "" {
		missing = append(missing, "ClientID")
	}
	if len(missing) > 0 {
		return fmt.Errorf("auth: missing config: %s", strings.Join(missing, ", "))
	}
	return nil
}

// Group is a user's Keycloak group.
type Group struct {
	ID   string
	Name string
}

// GroupResolver looks up a user's group, typically through the Keycloak
// Admin API, when the token does not carry it.
type GroupResolver func(ctx context.Context, userID string) (Group, error)

// Claims is the identity extracted from a verified access token.
type Claims struct {
	UserID    string         `json:"sub"`
	UserName  string         `json:"name"`
	Roles     []string       `json:"-"`
	GroupID   string         `json:"-"`
	GroupName string         `json:"-"`
	Raw       map[string]any `json:"-"`
}

// HasRole reports whether the claims hold any of the given roles.
func (c Claims) HasRole(roles ...string) bool {
	for _, want := range roles {
		if slices.Contains(c.Roles, want) {
			return true
		}
	}
	return false
}

type tokenClaims struct {
	Sub            string                 `json:"sub"`
	Name           string                 `json:"name"`
	GroupID        string                 `json:"groupId"`
	GroupName      string                 `json:"groupName"`
	ResourceAccess map[string]clientRoles `json:"resource_access"`
}

type clientRoles struct {
	Roles []string `json:"roles"`
}

// Verifier verifies access tokens issued by one Keycloak realm.
type Verifier struct {
	cfg      Config
	verifier *oidc.IDTokenVerifier
}

// New builds a Verifier, fetching the realm's OIDC discovery document and
// signing keys. It fails if Keycloak cannot be reached.
func New(ctx context.Context, cfg Config) (*Verifier, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL())
	if err != nil {
		return nil, fmt.Errorf("auth: failed to discover OIDC provider at %q: %w", cfg.IssuerURL(), err)
	}
	return newVerifier(cfg, provider.Verifier(verifierConfig())), nil
}

// NewWithKeySet builds a Verifier that checks signatures against keys
// instead of discovering them. Useful for tests and offline setups.
func NewWithKeySet(cfg Config, keys oidc.KeySet) (*Verifier, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return newVerifier(cfg, oidc.NewVerifier(cfg.IssuerURL(), keys, verifierConfig())), nil
}

// SkipClientIDCheck: requests carry access tokens, whose audience is not
// necessarily this client.
func verifierConfig() *oidc.Config {
	return &oidc.Config{SkipClientIDCheck: true}
}

func newVerifier(cfg Config, v *oidc.IDTokenVerifier) *Verifier {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Verifier{cfg: cfg, verifier: v}
}

// Verify checks rawToken and returns its claims. Errors wrap ErrInvalidToken.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (Claims, error) {
	token, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	var tc tokenClaims
	if err := token.Claims(&tc); err != nil {
		return Claims{}, fmt.Errorf("%w: claims: %v", ErrInvalidToken, err)
	}
	var raw map[string]any
	if err := token.Claims(&raw); err != nil {
		return Claims{}, fmt.Errorf("%w: claims: %v", ErrInvalidToken, err)
	}

	groupID, groupName := tc.GroupID, tc.GroupName
	if groupID == "" && groupName == "" && v.cfg.ResolveGroup != nil {
		group, err := v.cfg.ResolveGroup(ctx, tc.Sub)
		if err != nil {
			v.cfg.Logger.Warn("auth: failed to resolve the user's group", "userId", tc.Sub, "error", err)
		} else {
			groupID, groupName = group.ID, group.Name
		}
	}

	return Claims{
		UserID:    tc.Sub,
		UserName:  tc.Name,
		Roles:     tc.ResourceAccess[v.cfg.ClientID].Roles,
		GroupID:   groupID,
		GroupName: groupName,
		Raw:       raw,
	}, nil
}

// VerifyRequest reads the bearer token from r's Authorization header and
// verifies it. It returns ErrMissingToken when there is none.
func (v *Verifier) VerifyRequest(r *http.Request) (Claims, error) {
	token, ok := BearerToken(r)
	if !ok {
		return Claims{}, ErrMissingToken
	}
	return v.Verify(r.Context(), token)
}

// BearerToken returns the token from r's "Authorization: Bearer" header.
func BearerToken(r *http.Request) (string, bool) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return "", false
	}
	return token, true
}

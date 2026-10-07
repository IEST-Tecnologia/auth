package auth_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"

	auth "github.com/IEST-Tecnologia/auth/go"
)

var cfg = auth.Config{KeycloakURL: "https://kc.test/", Realm: "iest", ClientID: "app"}

type signer struct {
	key *rsa.PrivateKey
}

func newSigner(t *testing.T) signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return signer{key: key}
}

func (s signer) keySet() oidc.KeySet {
	return &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&s.key.PublicKey}}
}

func (s signer) token(t *testing.T, claims map[string]any) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: s.key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := sig.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func validClaims() map[string]any {
	return map[string]any{
		"iss":  "https://kc.test/realms/iest",
		"sub":  "user-1",
		"name": "Ana Souza",
		"exp":  time.Now().Add(time.Hour).Unix(),
		"resource_access": map[string]any{
			"app":   map[string]any{"roles": []string{"gestor"}},
			"other": map[string]any{"roles": []string{"admin"}},
		},
	}
}

func newVerifier(t *testing.T, c auth.Config, s signer) *auth.Verifier {
	t.Helper()
	v, err := auth.NewWithKeySet(c, s.keySet())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifyReadsOnlyTheConfiguredClientRoles(t *testing.T) {
	s := newSigner(t)
	claims, err := newVerifier(t, cfg, s).Verify(context.Background(), s.token(t, validClaims()))
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != "user-1" || claims.UserName != "Ana Souza" {
		t.Errorf("identity = %q %q", claims.UserID, claims.UserName)
	}
	if !claims.HasRole("gestor") || claims.HasRole("admin") {
		t.Errorf("roles = %v, want only the app client's", claims.Roles)
	}
	if claims.Raw["sub"] != "user-1" {
		t.Errorf("raw claims missing sub: %v", claims.Raw)
	}
}

func TestVerifyRejects(t *testing.T) {
	s := newSigner(t)
	expired := validClaims()
	expired["exp"] = time.Now().Add(-time.Minute).Unix()
	otherRealm := validClaims()
	otherRealm["iss"] = "https://kc.test/realms/other"

	cases := map[string]string{
		"expired":      s.token(t, expired),
		"other issuer": s.token(t, otherRealm),
		"other key":    newSigner(t).token(t, validClaims()),
		"not a jwt":    "garbage",
	}
	v := newVerifier(t, cfg, s)
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Verify(context.Background(), token); !errors.Is(err, auth.ErrInvalidToken) {
				t.Errorf("err = %v, want ErrInvalidToken", err)
			}
		})
	}
}

func TestGroupFromTokenWinsOverResolver(t *testing.T) {
	s := newSigner(t)
	c := cfg
	c.ResolveGroup = func(context.Context, string) (auth.Group, error) {
		t.Error("resolver called although the token carries the group")
		return auth.Group{}, nil
	}
	tc := validClaims()
	tc["groupId"], tc["groupName"] = "g-1", "Eco 1"

	claims, err := newVerifier(t, c, s).Verify(context.Background(), s.token(t, tc))
	if err != nil {
		t.Fatal(err)
	}
	if claims.GroupID != "g-1" || claims.GroupName != "Eco 1" {
		t.Errorf("group = %q %q", claims.GroupID, claims.GroupName)
	}
}

func TestGroupResolverFillsMissingGroup(t *testing.T) {
	s := newSigner(t)
	c := cfg
	c.ResolveGroup = func(_ context.Context, userID string) (auth.Group, error) {
		if userID != "user-1" {
			t.Errorf("resolver got %q", userID)
		}
		return auth.Group{ID: "g-2", Name: "News"}, nil
	}
	claims, err := newVerifier(t, c, s).Verify(context.Background(), s.token(t, validClaims()))
	if err != nil {
		t.Fatal(err)
	}
	if claims.GroupID != "g-2" || claims.GroupName != "News" {
		t.Errorf("group = %q %q", claims.GroupID, claims.GroupName)
	}
}

func TestGroupResolverFailureStillAuthenticates(t *testing.T) {
	s := newSigner(t)
	c := cfg
	c.ResolveGroup = func(context.Context, string) (auth.Group, error) {
		return auth.Group{}, errors.New("keycloak down")
	}
	claims, err := newVerifier(t, c, s).Verify(context.Background(), s.token(t, validClaims()))
	if err != nil {
		t.Fatal(err)
	}
	if claims.GroupID != "" || claims.UserID != "user-1" {
		t.Errorf("claims = %+v", claims)
	}
}

func TestVerifyRequestNeedsABearerToken(t *testing.T) {
	v := newVerifier(t, cfg, newSigner(t))
	for _, header := range []string{"", "Basic abc", "Bearer "} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", header)
		if _, err := v.VerifyRequest(r); !errors.Is(err, auth.ErrMissingToken) {
			t.Errorf("%q: err = %v, want ErrMissingToken", header, err)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	if _, err := auth.NewWithKeySet(auth.Config{KeycloakURL: "https://kc.test"}, nil); err == nil {
		t.Error("want an error for missing Realm and ClientID")
	}
	if got := cfg.IssuerURL(); got != "https://kc.test/realms/iest" {
		t.Errorf("IssuerURL = %q", got)
	}
}

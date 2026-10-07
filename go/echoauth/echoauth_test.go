package echoauth_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/labstack/echo/v4"

	auth "github.com/IEST-Tecnologia/auth/go"
	"github.com/IEST-Tecnologia/auth/go/echoauth"
)

func setup(t *testing.T) (*echo.Echo, func(roles ...string) string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	v, err := auth.NewWithKeySet(
		auth.Config{KeycloakURL: "https://kc.test", Realm: "iest", ClientID: "app"},
		&oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}},
	)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	token := func(roles ...string) string {
		payload, _ := json.Marshal(map[string]any{
			"iss":             "https://kc.test/realms/iest",
			"sub":             "user-1",
			"exp":             time.Now().Add(time.Hour).Unix(),
			"resource_access": map[string]any{"app": map[string]any{"roles": roles}},
		})
		jws, err := sig.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := jws.CompactSerialize()
		return out
	}

	e := echo.New()
	g := e.Group("", echoauth.Middleware(v))
	g.GET("/me", func(c echo.Context) error {
		claims, err := echoauth.GetClaims(c)
		if err != nil {
			return err
		}
		return c.String(http.StatusOK, claims.UserID)
	})
	g.GET("/admin", func(c echo.Context) error { return c.NoContent(http.StatusOK) }, echoauth.RequireRoles("gestor"))
	return e, token
}

func call(e *echo.Echo, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func TestMiddleware(t *testing.T) {
	e, token := setup(t)

	if rec := call(e, "/me", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d, want 401", rec.Code)
	}
	if rec := call(e, "/me", "garbage"); rec.Code != http.StatusUnauthorized {
		t.Errorf("bad token: %d, want 401", rec.Code)
	}
	if rec := call(e, "/me", token()); rec.Code != http.StatusOK || rec.Body.String() != "user-1" {
		t.Errorf("valid token: %d %q", rec.Code, rec.Body.String())
	}
}

func TestRequireRoles(t *testing.T) {
	e, token := setup(t)

	if rec := call(e, "/admin", token("colaborador")); rec.Code != http.StatusForbidden {
		t.Errorf("without role: %d, want 403", rec.Code)
	}
	if rec := call(e, "/admin", token("supervisor", "gestor")); rec.Code != http.StatusOK {
		t.Errorf("with role: %d, want 200", rec.Code)
	}
}

func TestGetClaimsOutsideMiddleware(t *testing.T) {
	c := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/", nil), httptest.NewRecorder())
	if _, err := echoauth.GetClaims(c); err != echoauth.ErrNoClaims {
		t.Errorf("err = %v, want ErrNoClaims", err)
	}
}

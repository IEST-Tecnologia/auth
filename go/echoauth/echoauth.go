// Package echoauth adapts auth.Verifier to the Echo web framework.
package echoauth

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"

	auth "github.com/IEST-Tecnologia/auth/go"
)

const claimsKey = "auth.claims"

// ErrNoClaims is returned by GetClaims on a route that is not behind
// Middleware.
var ErrNoClaims = errors.New("no claims found in context: is this route behind echoauth.Middleware?")

// Middleware verifies the request's bearer token and stores the claims in
// the echo.Context (see GetClaims). It responds 401 when the token is
// missing or invalid.
func Middleware(v *auth.Verifier) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims, err := v.VerifyRequest(c.Request())
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
			}
			c.Set(claimsKey, claims)
			return next(c)
		}
	}
}

// RequireRoles lets through only callers holding at least one of roles,
// responding 403 otherwise. It must run after Middleware.
func RequireRoles(roles ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims, err := GetClaims(c)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
			}
			if !claims.HasRole(roles...) {
				return echo.NewHTTPError(http.StatusForbidden, "insufficient role")
			}
			return next(c)
		}
	}
}

// GetClaims returns the claims stored by Middleware.
func GetClaims(c echo.Context) (auth.Claims, error) {
	claims, ok := c.Get(claimsKey).(auth.Claims)
	if !ok {
		return auth.Claims{}, ErrNoClaims
	}
	return claims, nil
}

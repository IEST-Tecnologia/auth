package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ErrUserNotFound is returned by User when the realm holds no user with the
// given ID.
var ErrUserNotFound = errors.New("no user with this ID exists in Keycloak")

// Member is the subset of a Keycloak user representation this client cares
// about.
type Member struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Enabled   bool   `json:"enabled"`
}

// DisplayName returns the member's full name, falling back to the username
// when the realm holds no first/last name for them.
func (m Member) DisplayName() string {
	if name := strings.TrimSpace(m.FirstName + " " + m.LastName); name != "" {
		return name
	}
	return m.Username
}

// User returns the realm's user with the given ID, or ErrUserNotFound when
// no such user exists. Successful lookups are cached for the same window as
// groups.
func (c *AdminClient) User(ctx context.Context, userID string) (Member, error) {
	if userID == "" {
		return Member{}, ErrUserNotFound
	}
	if m, ok := c.cachedUser(userID); ok {
		return m, nil
	}

	token, err := c.ensureToken(ctx)
	if err != nil {
		return Member{}, fmt.Errorf("failed to obtain admin token: %w", err)
	}

	reqURL := fmt.Sprintf("%s/admin/realms/%s/users/%s", c.baseURL, url.PathEscape(c.realm), url.PathEscape(userID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return Member{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Member{}, fmt.Errorf("failed to call Keycloak admin users endpoint: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusBadRequest:
		return Member{}, ErrUserNotFound
	default:
		return Member{}, fmt.Errorf("keycloak admin users endpoint returned status %d", resp.StatusCode)
	}

	var member Member
	if err := json.NewDecoder(resp.Body).Decode(&member); err != nil {
		return Member{}, fmt.Errorf("failed to decode user response: %w", err)
	}
	if member.ID == "" {
		return Member{}, ErrUserNotFound
	}

	c.cacheUser(userID, member)
	return member, nil
}

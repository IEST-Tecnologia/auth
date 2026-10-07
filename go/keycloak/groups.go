package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// ErrGroupNotFound is returned by Group when the realm holds no group with
// the given ID.
var ErrGroupNotFound = errors.New("no group with this ID exists in Keycloak")

// Group is the subset of a Keycloak group representation this client cares
// about.
type Group struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Group returns the realm's group with the given ID, or ErrGroupNotFound when
// no such group exists.
//
// Requires the service account to hold the realm-management role
// "query-groups" (see the AdminClient doc comment).
func (c *AdminClient) Group(ctx context.Context, groupID string) (Group, error) {
	if groupID == "" {
		return Group{}, ErrGroupNotFound
	}
	if g, ok := c.cachedGroup(groupID); ok {
		return g, nil
	}

	token, err := c.ensureToken(ctx)
	if err != nil {
		return Group{}, fmt.Errorf("failed to obtain admin token: %w", err)
	}

	reqURL := fmt.Sprintf("%s/admin/realms/%s/groups/%s", c.baseURL, url.PathEscape(c.realm), url.PathEscape(groupID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return Group{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Group{}, fmt.Errorf("failed to call Keycloak admin groups endpoint: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusBadRequest:
		return Group{}, ErrGroupNotFound
	default:
		return Group{}, fmt.Errorf("keycloak admin groups endpoint returned status %d", resp.StatusCode)
	}

	var group Group
	if err := json.NewDecoder(resp.Body).Decode(&group); err != nil {
		return Group{}, fmt.Errorf("failed to decode group response: %w", err)
	}
	if group.ID == "" {
		return Group{}, ErrGroupNotFound
	}

	c.cacheGroup(groupID, group)
	return group, nil
}

// UserPrimaryGroup returns the first Keycloak group the given user belongs
// to. If the user belongs to no group, it returns a zero Group and no
// error.
//
// A user can belong to several groups; this returns the first one Keycloak
// lists. Lookups are cached per user for five minutes.
func (c *AdminClient) UserPrimaryGroup(ctx context.Context, userID string) (Group, error) {
	if g, ok := c.cachedUserGroup(userID); ok {
		return g, nil
	}

	token, err := c.ensureToken(ctx)
	if err != nil {
		return Group{}, fmt.Errorf("failed to obtain admin token: %w", err)
	}

	reqURL := fmt.Sprintf("%s/admin/realms/%s/users/%s/groups", c.baseURL, url.PathEscape(c.realm), url.PathEscape(userID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return Group{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Group{}, fmt.Errorf("failed to call Keycloak admin groups endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Group{}, fmt.Errorf("keycloak admin groups endpoint returned status %d", resp.StatusCode)
	}

	var groups []Group
	if err := json.NewDecoder(resp.Body).Decode(&groups); err != nil {
		return Group{}, fmt.Errorf("failed to decode groups response: %w", err)
	}

	var group Group
	if len(groups) > 0 {
		group = groups[0]
	}

	c.cacheUserGroup(userID, group)
	return group, nil
}

package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// memberPageSize is how many members are requested per Admin API call.
// Keycloak caps a page server-side anyway; paging keeps a large team from
// being silently truncated.
const memberPageSize = 100

// GroupMembers returns every enabled user in the given Keycloak group,
// following pagination until the realm stops returning rows. Disabled users
// are skipped.
//
// Requires the service account to hold the realm-management role
// "view-users" (see the AdminClient doc comment).
func (c *AdminClient) GroupMembers(ctx context.Context, groupID string) ([]Member, error) {
	token, err := c.ensureToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain admin token: %w", err)
	}

	var out []Member
	for first := 0; ; first += memberPageSize {
		page, err := c.groupMembersPage(ctx, token, groupID, first)
		if err != nil {
			return nil, err
		}
		for _, m := range page {
			if m.Enabled {
				out = append(out, m)
			}
		}
		if len(page) < memberPageSize {
			return out, nil
		}
	}
}

func (c *AdminClient) groupMembersPage(ctx context.Context, token, groupID string, first int) ([]Member, error) {
	reqURL := fmt.Sprintf("%s/admin/realms/%s/groups/%s/members?briefRepresentation=true&first=%d&max=%d",
		c.baseURL, url.PathEscape(c.realm), url.PathEscape(groupID), first, memberPageSize)

	return c.getMembers(ctx, token, reqURL, "members of group "+groupID)
}

// UsersWithClientRole returns every enabled user holding the given role of
// this client — the same client roles the token carries under
// "resource_access.<clientID>.roles" and auth.Verifier reads, not realm
// roles.
//
// Requires the service account to hold the realm-management roles
// "view-users" and "view-clients" (the latter to resolve the client's
// internal UUID from its clientId).
func (c *AdminClient) UsersWithClientRole(ctx context.Context, role string) ([]Member, error) {
	token, err := c.ensureToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain admin token: %w", err)
	}

	clientUUID, err := c.clientUUID(ctx, token)
	if err != nil {
		return nil, err
	}

	var out []Member
	for first := 0; ; first += memberPageSize {
		reqURL := fmt.Sprintf("%s/admin/realms/%s/clients/%s/roles/%s/users?briefRepresentation=true&first=%d&max=%d",
			c.baseURL, url.PathEscape(c.realm), url.PathEscape(clientUUID), url.PathEscape(role), first, memberPageSize)

		page, err := c.getMembers(ctx, token, reqURL, fmt.Sprintf("users of client role %q", role))
		if err != nil {
			return nil, err
		}
		for _, m := range page {
			if m.Enabled {
				out = append(out, m)
			}
		}
		if len(page) < memberPageSize {
			return out, nil
		}
	}
}

// clientUUID resolves this client's internal Keycloak UUID from its
// clientId, which the role endpoints need. Cached for the client's lifetime:
// it never changes for a given realm.
func (c *AdminClient) clientUUID(ctx context.Context, token string) (string, error) {
	c.clientUUIDMu.Lock()
	defer c.clientUUIDMu.Unlock()

	if c.cachedClientUUID != "" {
		return c.cachedClientUUID, nil
	}

	reqURL := fmt.Sprintf("%s/admin/realms/%s/clients?clientId=%s",
		c.baseURL, url.PathEscape(c.realm), url.QueryEscape(c.clientID))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call Keycloak admin clients endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("keycloak admin clients endpoint returned status %d (the service account needs the realm-management role \"view-clients\")", resp.StatusCode)
	}

	var clients []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		return "", fmt.Errorf("failed to decode clients response: %w", err)
	}
	if len(clients) == 0 {
		return "", fmt.Errorf("keycloak realm %q has no client with clientId %q", c.realm, c.clientID)
	}

	c.cachedClientUUID = clients[0].ID
	return c.cachedClientUUID, nil
}

// getMembers fetches one page of user representations. what describes the
// collection being read, so a failure says which lookup went wrong.
func (c *AdminClient) getMembers(ctx context.Context, token, reqURL, what string) ([]Member, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list %s: %w", what, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keycloak returned status %d listing %s", resp.StatusCode, what)
	}

	var members []Member
	if err := json.NewDecoder(resp.Body).Decode(&members); err != nil {
		return nil, fmt.Errorf("failed to decode %s: %w", what, err)
	}
	return members, nil
}

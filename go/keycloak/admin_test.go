package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUserPrimaryGroup(t *testing.T) {
	var tokenCalls, groupCalls int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/iest/protocol/openid-connect/token":
			tokenCalls++
			if err := r.ParseForm(); err != nil {
				t.Fatalf("failed to parse token request form: %v", err)
			}
			if got := r.Form.Get("grant_type"); got != "client_credentials" {
				t.Fatalf("expected grant_type=client_credentials, got %q", got)
			}
			if got := r.Form.Get("client_secret"); got != "s3cr3t" {
				t.Fatalf("expected client_secret=s3cr3t, got %q", got)
			}
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "fake-admin-token",
				"expires_in":   60,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/iest/users/user-123/groups":
			groupCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer fake-admin-token" {
				t.Fatalf("expected Authorization: Bearer fake-admin-token, got %q", got)
			}
			json.NewEncoder(w).Encode([]Group{
				{ID: "group-abc", Name: "Equipe A"},
			})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	client := NewAdminClient(srv.URL, "iest", "my-app", "s3cr3t")

	if !client.Enabled() {
		t.Fatal("expected client to be enabled with a non-empty secret")
	}

	group, err := client.UserPrimaryGroup(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("UserPrimaryGroup returned error: %v", err)
	}
	if group.ID != "group-abc" || group.Name != "Equipe A" {
		t.Fatalf("unexpected group: %+v", group)
	}

	// Second call should hit the group cache, not the HTTP server again.
	if _, err := client.UserPrimaryGroup(context.Background(), "user-123"); err != nil {
		t.Fatalf("UserPrimaryGroup (cached) returned error: %v", err)
	}

	if tokenCalls != 1 {
		t.Errorf("expected exactly 1 token exchange, got %d", tokenCalls)
	}
	if groupCalls != 1 {
		t.Errorf("expected exactly 1 groups lookup (second call should be cached), got %d", groupCalls)
	}
}

func TestUser(t *testing.T) {
	var userCalls int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/iest/protocol/openid-connect/token":
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "fake-admin-token",
				"expires_in":   60,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/iest/users/user-123":
			userCalls++
			json.NewEncoder(w).Encode(Member{
				ID:        "user-123",
				Username:  "ana.silva",
				FirstName: "Ana",
				LastName:  "Silva",
				Enabled:   true,
			})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	client := NewAdminClient(srv.URL, "iest", "my-app", "s3cr3t")

	member, err := client.User(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("User returned error: %v", err)
	}
	if got := member.DisplayName(); got != "Ana Silva" {
		t.Fatalf("DisplayName = %q, want %q", got, "Ana Silva")
	}

	if _, err := client.User(context.Background(), "user-123"); err != nil {
		t.Fatalf("User (cached) returned error: %v", err)
	}
	if userCalls != 1 {
		t.Errorf("expected exactly 1 user lookup (second call should be cached), got %d", userCalls)
	}
}

func TestUserNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/iest/protocol/openid-connect/token":
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "fake-admin-token",
				"expires_in":   60,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := NewAdminClient(srv.URL, "iest", "my-app", "s3cr3t")

	if _, err := client.User(context.Background(), "nao-existe"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("User error = %v, want ErrUserNotFound", err)
	}
}

func TestGroup(t *testing.T) {
	var groupCalls int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/iest/protocol/openid-connect/token":
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "fake-admin-token",
				"expires_in":   60,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/iest/groups/group-abc":
			groupCalls++
			json.NewEncoder(w).Encode(Group{ID: "group-abc", Name: "Eco 1"})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/iest/groups/nao-existe":
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	client := NewAdminClient(srv.URL, "iest", "my-app", "s3cr3t")

	group, err := client.Group(context.Background(), "group-abc")
	if err != nil {
		t.Fatalf("Group returned error: %v", err)
	}
	if group.Name != "Eco 1" {
		t.Fatalf("group.Name = %q, want %q", group.Name, "Eco 1")
	}

	if _, err := client.Group(context.Background(), "group-abc"); err != nil {
		t.Fatalf("Group (cached) returned error: %v", err)
	}
	if groupCalls != 1 {
		t.Errorf("expected exactly 1 group lookup (second call should be cached), got %d", groupCalls)
	}

	if _, err := client.Group(context.Background(), "nao-existe"); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("Group error = %v, want ErrGroupNotFound", err)
	}
}

// The group-by-ID lookup and the user's-primary-group lookup share a mutex
// and a TTL but not a key space: a user ID must never read a group ID's entry.
func TestGroupCachesAreSeparate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/iest/protocol/openid-connect/token":
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "fake-admin-token",
				"expires_in":   60,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/iest/groups/shared-id":
			json.NewEncoder(w).Encode(Group{ID: "shared-id", Name: "Eco 1"})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/iest/users/shared-id/groups":
			json.NewEncoder(w).Encode([]Group{{ID: "group-abc", Name: "Eco 2"}})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	client := NewAdminClient(srv.URL, "iest", "my-app", "s3cr3t")

	if _, err := client.Group(context.Background(), "shared-id"); err != nil {
		t.Fatalf("Group returned error: %v", err)
	}

	group, err := client.UserPrimaryGroup(context.Background(), "shared-id")
	if err != nil {
		t.Fatalf("UserPrimaryGroup returned error: %v", err)
	}
	if group.Name != "Eco 2" {
		t.Fatalf("UserPrimaryGroup read the group-by-ID cache: got %q, want %q", group.Name, "Eco 2")
	}
}

func TestAdminClientDisabledWithoutSecret(t *testing.T) {
	client := NewAdminClient("https://auth.example.com", "iest", "my-app", "")
	if client.Enabled() {
		t.Fatal("expected client to be disabled with an empty secret")
	}
}

func TestGroupResolver(t *testing.T) {
	if NewAdminClient("https://auth.example.com", "iest", "my-app", "").GroupResolver() != nil {
		t.Error("a disabled client must return a nil resolver")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/iest/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "t", "expires_in": 60})
		case "/admin/realms/iest/users/user-1/groups":
			_ = json.NewEncoder(w).Encode([]Group{{ID: "g-1", Name: "Eco 1"}})
		default:
			t.Fatalf("unexpected request: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	group, err := NewAdminClient(srv.URL, "iest", "my-app", "s3cr3t").GroupResolver()(context.Background(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if group.ID != "g-1" || group.Name != "Eco 1" {
		t.Errorf("group = %+v", group)
	}
}

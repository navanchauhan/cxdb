// Copyright 2025 StrongDM Inc
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteMethodsRemainAnonymousWhenNoWriteTokenConfigured(t *testing.T) {
	store := newTestSessionStore(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	handler := RequireAuthForReadsWithOptions(AuthMiddlewareOptions{Store: store}, next)

	req := httptest.NewRequest(http.MethodPost, "/v1/contexts/create", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected anonymous write to pass when no token is configured, got %d", rec.Code)
	}
}

func TestWriteMethodsRequireBearerWhenWriteTokenConfigured(t *testing.T) {
	store := newTestSessionStore(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	handler := RequireAuthForReadsWithOptions(AuthMiddlewareOptions{
		Store:       store,
		WriteTokens: []string{"secret-token"},
	}, next)

	req := httptest.NewRequest(http.MethodPost, "/v1/contexts/create", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected missing bearer token to be unauthorized, got %d", rec.Code)
	}
}

func TestWriteMethodsAcceptConfiguredBearer(t *testing.T) {
	store := newTestSessionStore(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if UserFromContext(r.Context()) == nil {
			t.Fatal("expected bearer auth to inject a session")
		}
		w.WriteHeader(http.StatusCreated)
	})
	handler := RequireAuthForReadsWithOptions(AuthMiddlewareOptions{
		Store:       store,
		WriteTokens: []string{"secret-token"},
	}, next)

	req := httptest.NewRequest(http.MethodPost, "/v1/contexts/create", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected bearer-authenticated write to pass, got %d", rec.Code)
	}
}

func TestPublicContextListDoesNotMakePostAliasPublic(t *testing.T) {
	store := newTestSessionStore(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	handler := RequireAuthForReadsWithOptions(AuthMiddlewareOptions{
		Store:       store,
		WriteTokens: []string{"secret-token"},
	}, next)

	req := httptest.NewRequest(http.MethodPost, "/v1/contexts", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected POST /v1/contexts to require bearer token, got %d", rec.Code)
	}
}

func TestWriteBearerDoesNotAuthorizeProtectedReads(t *testing.T) {
	store := newTestSessionStore(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := RequireAuthForReadsWithOptions(AuthMiddlewareOptions{
		Store:       store,
		WriteTokens: []string{"secret-token"},
	}, next)

	req := httptest.NewRequest(http.MethodGet, "/v1/contexts/1/turns", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected write bearer token not to authorize protected reads, got %d", rec.Code)
	}
}

func newTestSessionStore(t *testing.T) *SessionStore {
	t.Helper()
	store, err := NewSessionStore(
		filepath.Join(t.TempDir(), "sessions.db"),
		"cxdb_session",
		time.Hour,
		"",
		false,
		"test-secret",
	)
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store
}

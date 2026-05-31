// Copyright 2025 StrongDM Inc
// SPDX-License-Identifier: Apache-2.0

package auth

import "testing"

func TestOIDCAllowed(t *testing.T) {
	t.Run("allows any provider user without an allowlist", func(t *testing.T) {
		auth := &OIDCAuth{}
		if !auth.allowed("user@example.com") {
			t.Fatal("expected email to be allowed")
		}
	})

	t.Run("allows explicit emails", func(t *testing.T) {
		auth := &OIDCAuth{allowedEmails: map[string]bool{"user@example.com": true}}
		if !auth.allowed("user@example.com") {
			t.Fatal("expected email to be allowed")
		}
		if auth.allowed("other@example.com") {
			t.Fatal("expected email to be denied")
		}
	})

	t.Run("allows matching domains", func(t *testing.T) {
		auth := &OIDCAuth{allowedDomain: "example.com"}
		if !auth.allowed("user@example.com") {
			t.Fatal("expected domain email to be allowed")
		}
		if auth.allowed("user@other.com") {
			t.Fatal("expected non-domain email to be denied")
		}
	})
}

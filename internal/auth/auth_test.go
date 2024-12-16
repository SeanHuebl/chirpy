package auth

import (
	"testing"
)

func TestHashPassword(t *testing.T) {
	password := "securepassword"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned an error: %v", err)
	}

	if hash == "" {
		t.Fatalf("HashPassword returned an empty hash")
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "securepassword"
	wrongPassword := "wrongpassword"

	// Generate a hash for the correct password
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned an error: %v", err)
	}

	// Verify the correct password against the hash
	err = CheckPasswordHash(password, hash)
	if err != nil {
		t.Errorf("CheckPasswordHash failed for the correct password: %v", err)
	}

	// Verify an incorrect password against the hash
	err = CheckPasswordHash(wrongPassword, hash)
	if err == nil {
		t.Errorf("CheckPasswordHash did not fail for an incorrect password")
	}
}

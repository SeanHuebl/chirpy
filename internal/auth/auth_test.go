package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
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

func TestMakeJWT(t *testing.T) {
	tokenSecret := "testsecret"
	expiresIn := time.Hour
	userID := uuid.New()

	t.Run("Valid JWT", func(t *testing.T) {
		token, err := MakeJWT(userID, tokenSecret, expiresIn)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if token == "" {
			t.Fatalf("expected non-empty token, got: %v", token)
		}
	})

	t.Run("Invalid Secret", func(t *testing.T) {
		invalidSecret := ""
		_, err := MakeJWT(userID, invalidSecret, expiresIn)
		if err == nil {
			t.Fatalf("expected error for invalid secret, got nil")
		}
	})
}

func TestValidateJWT(t *testing.T) {
	tokenSecret := "testsecret"
	expiresIn := time.Hour
	userID := uuid.New()

	t.Run("Valid JWT", func(t *testing.T) {
		token, err := MakeJWT(userID, tokenSecret, expiresIn)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		parsedUserID, err := ValidateJWT(token, tokenSecret)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if parsedUserID != userID {
			t.Fatalf("expected userID %v, got %v", userID, parsedUserID)
		}
	})

	t.Run("Invalid Token", func(t *testing.T) {
		invalidToken := "invalid.token"
		_, err := ValidateJWT(invalidToken, tokenSecret)
		if err == nil {
			t.Fatalf("expected error for invalid token, got nil")
		}
	})

	t.Run("Invalid Secret", func(t *testing.T) {
		token, err := MakeJWT(userID, tokenSecret, expiresIn)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		invalidSecret := "wrongsecret"
		_, err = ValidateJWT(token, invalidSecret)
		if err == nil {
			t.Fatalf("expected error for invalid secret, got nil")
		}
	})

	t.Run("Expired Token", func(t *testing.T) {
		expiredDuration := -time.Hour
		token, err := MakeJWT(userID, tokenSecret, expiredDuration)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		_, err = ValidateJWT(token, tokenSecret)
		if err == nil {
			t.Fatalf("expected error for expired token, got nil")
		}
	})

	t.Run("Invalid Issuer", func(t *testing.T) {
		token := jwt.NewWithClaims(
			jwt.SigningMethodHS256,
			jwt.RegisteredClaims{
				Issuer:    "wrongissuer",
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
				Subject:   userID.String(),
			},
		)
		signedToken, err := token.SignedString([]byte(tokenSecret))
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		_, err = ValidateJWT(signedToken, tokenSecret)
		if err == nil {
			t.Fatalf("expected error for invalid issuer, got nil")
		}
	})
}

func TestGetBearerToken(t *testing.T) {
	t.Run("Valid Authorization Header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer validtoken123")

		token, err := GetBearerToken(headers)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if token != "validtoken123" {
			t.Fatalf("expected token 'validtoken123', got: %v", token)
		}
	})

	t.Run("Missing Authorization Header", func(t *testing.T) {
		headers := http.Header{}

		_, err := GetBearerToken(headers)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if err.Error() != "authorization header must start with 'Bearer '" {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("Invalid Authorization Prefix", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Basic sometoken123")

		_, err := GetBearerToken(headers)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if err.Error() != "authorization header must start with 'Bearer '" {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("Empty Token", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer ")

		_, err := GetBearerToken(headers)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if err.Error() != "token does not exist" {
			t.Fatalf("unexpected error message: %v", err)
		}
	})
}

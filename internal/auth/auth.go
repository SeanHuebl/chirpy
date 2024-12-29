// Package auth provides utilities for password hashing, JWT creation and validation,
// token generation, and retrieval of authorization headers.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes the provided password using bcrypt.
// It returns the hashed password as a string or an error if hashing fails.
func HashPassword(password string) (string, error) {
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(password), 0)
	if err != nil {
		log.Fatalf("error signing token: %v", err)
	}

	return string(hashBytes), nil
}

// CheckPasswordHash compares a hashed password with a plain-text password.
// It returns an error if the passwords do not match or the hash is invalid.
func CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// MakeJWT creates a JWT for the given user ID with a specified secret and expiration duration.
// It returns the signed JWT as a string or an error if signing fails.
func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	if tokenSecret == "" {
		return "", fmt.Errorf("invalid secret")
	}
	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.RegisteredClaims{
			Issuer:    "chirpy",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
			Subject:   userID.String(),
		},
	)
	signedToken, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

// ValidateJWT validates the given JWT using the specified secret.
// It returns the user ID encoded in the token or an error if validation fails.
func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(tokenSecret), nil
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("token parsing failed: %v", err)
	}
	if !token.Valid {
		return uuid.Nil, fmt.Errorf("token is invalid")
	}
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		fmt.Println("invalid claims format")
	}
	if claims.Issuer != "chirpy" {
		return uuid.Nil, fmt.Errorf("invalid issuer: %v", claims.Issuer)
	}
	if claims.Subject == "" {
		return uuid.Nil, fmt.Errorf("missing subject in token")
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, fmt.Errorf("error parsing userID: %v", err)
	}
	return userID, nil
}

// GetBearerToken extracts the Bearer token from the Authorization header of an HTTP request.
// It returns the token or an error if the header is missing or invalid.
func GetBearerToken(headers http.Header) (string, error) {
	auth := headers.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", fmt.Errorf("authorization header must start with 'Bearer '")
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	if token == "" {
		return "", fmt.Errorf("token does not exist")
	}
	return token, nil
}

// MakeRefreshToken generates a random refresh token as a hex-encoded string.
// It returns the token or an error if random byte generation fails.
func MakeRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("unable to generate random bytes")
	}
	return hex.EncodeToString(bytes), nil
}

// GetAPIKey extracts the API key from the Authorization header of an HTTP request.
// It returns the API key or an error if the header is missing or invalid.
func GetAPIKey(headers http.Header) (string, error) {
	auth := headers.Get("Authorization")
	if !strings.HasPrefix(auth, "ApiKey ") {
		return "", fmt.Errorf("authorization header must start with 'ApiKey '")
	}
	key := strings.TrimPrefix(auth, "ApiKey ")
	if key == "" {
		return "", fmt.Errorf("API key does not exist")
	}
	return key, nil
}

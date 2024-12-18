package auth

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {

	hashBytes, err := bcrypt.GenerateFromPassword([]byte(password), 0)
	if err != nil {
		log.Fatalf("error signing token: %v", err)
	}

	return string(hashBytes), nil
}

func CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

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

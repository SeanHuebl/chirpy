package auth

import (
	"log"
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
	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256, 
		jwt.RegisteredClaims{
			Issuer: "chirpy", 
			IssuedAt: jwt.NewNumericDate(time.Now()), 
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)), 
			Subject: userID.String(),
		},
	)
	signedToken, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

/* func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	return nil, nil
} */

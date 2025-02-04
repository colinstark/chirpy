package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte("yalla"+password), 12)
	return string(hashed), err
}

func CheckPasswordHash(password, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("yalla"+password))
	if err != nil {
		return err
	}
	return nil
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		Subject:   userID.String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(tokenSecret), nil
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return uuid.Nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return uuid.Nil, fmt.Errorf("invalid claims format")
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user ID in token: %w", err)
	}

	return userID, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	// Fetch the Authorization header
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("Authorization header is missing")
	}

	// Check that it starts with "Bearer "
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", errors.New("Authorization header is malformed")
	}

	// Extract the token part by trimming "Bearer " and any extra spaces
	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))

	// Validate the token is not empty after trimming
	if token == "" {
		return "", errors.New("Token is empty")
	}

	return token, nil
}

func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("Authorization header is missing")
	}

	if !strings.HasPrefix(authHeader, "ApiKey ") {
		return "", errors.New("Authorization header is malformed")
	}

	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "ApiKey "))

	if token == "" {
		return "", errors.New("ApiKey is empty")
	}

	return token, nil
}

func MakeRefreshToken() (string, error) {
	token := make([]byte, 32) // 32 bytes = 256 bits
	if _, err := rand.Read(token); err != nil {
		return "", errors.New("failed to generate token: " + err.Error())
	}
	return hex.EncodeToString(token), nil
}

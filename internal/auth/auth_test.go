package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	password := "password123"
	hashed, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if hashed == "" {
		t.Error("HashPassword() returned an empty string")
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "password123"
	hashed, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	err = CheckPasswordHash(password, hashed)
	if err != nil {
		t.Errorf("CheckPasswordHash() error = %v", err)
	}

	wrongPassword := "wrongpassword"
	err = CheckPasswordHash(wrongPassword, hashed)
	if err == nil {
		t.Error("CheckPasswordHash() should return an error for incorrect password")
	}
}

func TestMakeJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "supersecretkey"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT() error = %v", err)
	}
	if token == "" {
		t.Error("MakeJWT() returned an empty token")
	}
}

func TestValidateJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "supersecretkey"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT() error = %v", err)
	}

	validatedUserID, err := ValidateJWT(token, tokenSecret)
	if err != nil {
		t.Fatalf("ValidateJWT() error = %v", err)
	}
	if validatedUserID != userID {
		t.Errorf("ValidateJWT() = %v, want %v", validatedUserID, userID)
	}

	// Test with invalid token
	invalidToken := "invalid.token.here"
	_, err = ValidateJWT(invalidToken, tokenSecret)
	if err == nil {
		t.Error("ValidateJWT() should return an error for invalid token")
	}

	// Test with expired token
	expiredToken, err := MakeJWT(userID, tokenSecret, -time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT() error = %v", err)
	}
	_, err = ValidateJWT(expiredToken, tokenSecret)
	if err == nil {
		t.Error("ValidateJWT() should return an error for expired token")
	}
}

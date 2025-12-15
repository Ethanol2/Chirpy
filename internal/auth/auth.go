package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

var (
	ErrMissingHeader     = errors.New("authorization header is missing")
	ErrInvalidFormat     = errors.New("authorization header format is invalid")
	ErrMissingBearerText = errors.New("authorization header must start with Bearer")
)

func HashPassword(password string) (string, error) {
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return "", err
	}
	return hash, nil
}
func CheckPasswordHash(password, hash string) (bool, error) {
	isMatch, err := argon2id.ComparePasswordAndHash(password, hash)
	if err != nil {
		return false, err
	}
	return isMatch, nil
}
func MakeJWT(userId uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn).UTC()),
		Subject:   userId.String(),
	})

	return token.SignedString([]byte(tokenSecret))
}
func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(tokenSecret), nil
	})
	if err != nil || !token.Valid {
		return uuid.Nil, err
	}

	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, err
	}

	return id, nil
}
func GetBearerToken(headers http.Header) (string, error) {
	var split []string

	if val := headers.Get("authorization"); len(val) > 0 {

		split = strings.Split(val, " ")

	} else {
		return "", ErrMissingHeader
	}

	if len(split) != 2 {
		return "", ErrInvalidFormat
	}

	if split[0] != "Bearer" {
		return "", ErrMissingBearerText
	}

	if len(split[1]) == 0 {
		return "", ErrInvalidFormat
	}

	return split[1], nil
}
func MakeRefreshToken() string {
	key := make([]byte, 32)
	rand.Read(key)

	return hex.EncodeToString(key)
}

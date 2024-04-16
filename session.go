package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Session struct {
	UserID       int64  `json:"userID,omitempty"`
	FirstName    string `json:"firstName,omitempty"`
	LastName     string `json:"lastName,omitempty"`
	AccessToken  string `json:"accessToken,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty"`
}

type UserClaims struct {
	ID             int64  `json:"id,omitempty"`
	Nonce          string `json:"nonce,omitempty"` // prevent constraint fails on user_token
	ExpirationTime int64  `json:"exp,omitempty"`
	IssuedAt       int64  `json:"iat,omitempty"`
}

func (m UserClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(m.ExpirationTime, 0)), nil
}

// GetNotBefore implements the Claims interface.
func (UserClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return nil, nil
}

// GetIssuedAt implements the Claims interface.
func (m UserClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(m.IssuedAt, 0)), nil
}

// GetAudience implements the Claims interface.
func (UserClaims) GetAudience() (jwt.ClaimStrings, error) {
	return nil, nil
}

// GetIssuer implements the Claims interface.
func (UserClaims) GetIssuer() (string, error) {
	return "", nil
}

// GetSubject implements the Claims interface.
func (UserClaims) GetSubject() (string, error) {
	return "", nil
}

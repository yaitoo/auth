package auth

import "crypto/sha256"

type Session struct {
	UserID       int64  `json:"userID,omitempty"`
	AccessToken  string `json:"accessToken,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty"`
}

func (s *Session) refreshTokenHash() string {
	return generateHash(sha256.New(), s.RefreshToken, "")
}

package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/yaitoo/sqle/shardid"
)

type Session struct {
	UserID       shardid.ID   `json:"userID,omitempty"`
	AccessToken  jwt.Token    `json:"accessToken,omitempty"`
	RefreshToken RefreshToken `json:"refreshToken,omitempty"`
}

type RefreshToken struct {
	Token     string `json:"token,omitempty"`
	ExpiresOn int64  `json:"expiresOn,omitempty"`
}

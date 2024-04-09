package auth

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	"github.com/yaitoo/sqle/shardid"
)

// SignOut sign out the user, and delete his refresh token
func (a *Auth) SignOut(ctx context.Context, uid shardid.ID) error {
	return a.deleteUserToken(ctx, uid, "")
}

// RefreshSession refresh access token and refresh token
func (a *Auth) RefreshSession(ctx context.Context, refreshToken string) (Session, error) {
	token, err := jwt.ParseWithClaims(refreshToken, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return a.jwtSignKey, nil
	})

	if err != nil {
		return noSession, err
	}

	if !token.Valid {
		return noSession, ErrInvalidRefreshToken
	}

	uc := token.Claims.(*UserClaims)

	uid := shardid.Parse(uc.ID)

	err = a.checkRefreshToken(ctx, uid, refreshToken)
	if err != nil {
		return noSession, err
	}

	go a.deleteUserToken(ctx, uid, refreshToken) // nolint: errcheck

	return a.createSession(ctx, uid)
}

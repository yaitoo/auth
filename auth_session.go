package auth

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	"github.com/yaitoo/sqle/shardid"
)

var noUserID shardid.ID

// SignOut sign out the user, and delete his refresh token
func (a *Auth) SignOut(ctx context.Context, uid shardid.ID) error {
	return a.deleteUserToken(ctx, uid, "")
}

// IsAuthenticated check access token if it is valid
func (a *Auth) IsAuthenticated(ctx context.Context, accessToken string) (shardid.ID, error) {
	token, err := jwt.ParseWithClaims(accessToken, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return a.jwtSignKey, nil
	})

	if err != nil {
		return noUserID, ErrInvalidToken
	}

	if !token.Valid {
		return noUserID, ErrInvalidToken
	}

	uc := token.Claims.(*UserClaims)

	return shardid.Parse(uc.ID), nil

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
		return noSession, ErrInvalidToken
	}

	uc := token.Claims.(*UserClaims)

	uid := shardid.Parse(uc.ID)

	err = a.checkRefreshToken(ctx, uid, refreshToken)
	if err != nil {
		return noSession, err
	}

	go a.deleteUserToken(ctx, uid, refreshToken) // nolint: errcheck

	u, err := a.getUserByID(ctx, uid)
	if err != nil {
		return noSession, err
	}

	return a.createSession(ctx, uid, u.FirstName, u.FirstName)
}

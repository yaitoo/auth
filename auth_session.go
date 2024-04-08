package auth

import (
	"context"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/yaitoo/sqle/shardid"
)

func (a *Auth) createSession(ctx context.Context, userID shardid.ID) (Session, error) {
	s := Session{
		UserID: userID.Int64,
	}

	accToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  userID,
		"exp": time.Now().Add(a.accessTokenTTL).Unix(),
		"ttl": a.accessTokenTTL,
	})

	exp := time.Now().Add(a.refreshTokenTTL)
	now := time.Now()
	refToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  userID,
		"exp": exp.Unix(),
		"ttl": a.refreshTokenTTL,
	})

	var err error
	s.AccessToken, err = accToken.SignedString(a.jwtSignKey)
	if err != nil {
		a.logger.Error("auth: createSession",
			slog.String("tag", "token"),
			slog.String("step", "access_token"),
			slog.Any("err", err))
		return s, ErrUnknown
	}

	s.RefreshToken, err = refToken.SignedString(a.jwtSignKey)
	if err != nil {
		a.logger.Error("auth: createSession",
			slog.String("tag", "token"),
			slog.String("step", "refresh_token"),
			slog.Any("err", err))
		return s, ErrUnknown
	}

	_, err = a.db.On(userID).
		ExecBuilder(ctx, a.createBuilder().
			Insert("<prefix>user_token").
			Set("user_id", userID.Int64).
			Set("hash", s.refreshTokenHash()).
			Set("expires_on", exp).
			Set("created_at", now).
			End())

	if err != nil {
		a.logger.Error("auth: createSession",
			slog.String("tag", "db"),
			slog.Int64("user_id", userID.Int64),
			slog.Any("err", err))
		return s, ErrBadDatabase
	}

	return s, nil
}

func (a *Auth) RefreshSession(ctx context.Context) (Session, error) {
	var s Session

	return s, nil
}

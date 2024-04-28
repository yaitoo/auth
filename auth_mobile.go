package auth

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/yaitoo/sqle"
	"github.com/yaitoo/sqle/shardid"
)

// getUserIDByMobile retrieves the user ID associated with a mobile number.
// It takes a context and a mobile number as input and returns the user ID and an error.
func (a *Auth) getUserIDByMobile(ctx context.Context, mobile string) (shardid.ID, error) {
	var userID shardid.ID

	h := generateHash(a.hash(), mobile, "")

	db, err := a.db.OnDHT(h, a.dhtMobile)
	if err != nil {
		return userID, err
	}

	err = db.
		QueryRowBuilder(ctx, a.createBuilder().
			Select("<prefix>user_mobile", "user_id").
			Where("hash = {hash}").
			Param("hash", generateHash(a.hash(), mobile, ""))).
		Scan(&userID)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return userID, ErrMobileNotFound
		}
		a.logger.Error("auth: getUserIDByMobile",
			slog.String("tag", "db"),
			slog.String("mobile", mobile),
			slog.Any("err", err))
		return userID, ErrBadDatabase
	}

	return userID, nil
}

// createMobile creates a new mobile entry for a user.
// It takes a context, a transaction, user ID, mobile number, hash, and creation time as input and returns an error.
func (a *Auth) createMobile(ctx context.Context, conn sqle.Connector, userID shardid.ID, mobile, hash string, now time.Time) error {

	_, err := conn.ExecBuilder(ctx, a.createBuilder().
		Insert("<prefix>user_mobile").
		Set("user_id", userID).
		Set("hash", hash).
		Set("created_at", now).
		End())

	if err != nil {
		a.logger.Error("auth: createMobile",
			slog.String("tag", "db"),
			slog.Int64("user_id", userID.Int64),
			slog.String("mobile", mobile),
			slog.Any("err", err))
		return ErrBadDatabase
	}

	return nil
}

// deleteMobile deletes a mobile entry for a user.
// It takes a context, a transaction, user ID, and hash as input and returns an error.
func (a *Auth) deleteMobile(ctx context.Context, conn sqle.Connector, userID shardid.ID, hash string) error {

	_, err := conn.ExecBuilder(ctx, a.createBuilder().
		Delete("<prefix>user_mobile").
		Where("hash = {hash} AND user_id = {user_id}").
		Param("hash", hash).
		Param("user_id", userID.Int64))

	if err != nil {
		a.logger.Error("auth: deleteMobile",
			slog.String("tag", "db"),
			slog.Int64("user_id", userID.Int64),
			slog.String("hash", hash),
			slog.Any("err", err))
		return ErrBadDatabase
	}

	return nil
}

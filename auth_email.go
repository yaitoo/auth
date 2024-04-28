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

func (a *Auth) getUserIDByEmail(ctx context.Context, email string) (shardid.ID, error) {
	var userID shardid.ID

	h := generateHash(a.hash(), email, "")

	db, err := a.db.OnDHT(h, a.dhtEmail)
	if err != nil {
		return userID, err
	}

	err = db.
		QueryRowBuilder(ctx, a.createBuilder().
			Select("<prefix>user_email", "user_id").
			Where("hash = {hash}").
			Param("hash", generateHash(a.hash(), email, ""))).
		Scan(&userID)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return userID, ErrEmailNotFound
		}
		a.logger.Error("auth: getUserIDByEmail",
			slog.String("tag", "db"),
			slog.String("email", email),
			slog.Any("err", err))
		return userID, ErrBadDatabase
	}

	return userID, nil
}

// createEmail creates a new email record for a user in the database.
// It inserts the user ID, email hash, masked email, verification status, and creation timestamp.
func (a *Auth) createEmail(ctx context.Context, conn sqle.Connector, userID shardid.ID, email, hash string, now time.Time) error {

	_, err := conn.ExecBuilder(ctx, a.createBuilder().
		Insert("<prefix>user_email").
		Set("user_id", userID).
		Set("hash", hash).
		Set("created_at", now).
		End())

	if err != nil {
		a.logger.Error("auth: createEmail",
			slog.String("tag", "db"),
			slog.Int64("user_id", userID.Int64),
			slog.String("email", email),
			slog.Any("err", err))
		return ErrBadDatabase
	}

	return nil
}

// deleteEmail deletes an email record for a user from the database.
// It deletes the record based on the email hash and user ID.
func (a *Auth) deleteEmail(ctx context.Context, conn sqle.Connector, userID shardid.ID, hash string) error {

	_, err := conn.ExecBuilder(ctx, a.createBuilder().
		Delete("<prefix>user_email").
		Where("hash = {hash} AND user_id = {user_id}").
		Param("hash", hash).
		Param("user_id", userID.Int64))

	if err != nil {
		a.logger.Error("auth: deleteEmail",
			slog.String("tag", "db"),
			slog.Int64("user_id", userID.Int64),
			slog.String("hash", hash),
			slog.Any("err", err))
		return ErrBadDatabase
	}

	return nil
}

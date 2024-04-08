package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/yaitoo/auth/masker"
	"github.com/yaitoo/sqle"
	"github.com/yaitoo/sqle/migrate"
	"github.com/yaitoo/sqle/shardid"
)

// Migrate automatically migrate database schema for auth module
func (a *Auth) Migrate(ctx context.Context, options ...migrate.Option) error {
	m := migrate.New(a.db)

	err := m.Init(ctx)
	if err != nil {
		return err
	}

	options = append(options, migrate.WithModule("auth"))
	err = m.Discover(migration, options...)
	if err != nil {
		return err
	}

	var vers []migrate.Semver

	for _, v := range m.Versions {

		var migrations []migrate.Migration
		for _, m := range v.Migrations {
			m.Scripts = strings.ReplaceAll(m.Scripts, "<prefix>", a.prefix)
			migrations = append(migrations, m)
		}

		v.Migrations = migrations
		vers = append(vers, v)
	}

	m.Versions = vers

	return m.Migrate(ctx)
}

func (a *Auth) createBuilder() *sqle.Builder {
	return sqle.New().Input("prefix", a.prefix)
}

func (a *Auth) getUserByEmail(ctx context.Context, email string) (User, error) {
	var u User

	h := generateHash(a.hash(), email, "")

	db, err := a.db.OnDHT(h)
	if err != nil {
		return u, err
	}

	var userID shardid.ID
	err = db.
		QueryRowBuilder(ctx, a.createBuilder().
			Select("<prefix>user_email", "user_id").
			Where("hash = {hash}").
			Param("hash", generateHash(a.hash(), email, ""))).
		Scan(&userID)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return u, ErrEmailNotFound
		}
		a.logger.Error("auth: getUserByEmail",
			slog.String("pos", "user_email"),
			slog.String("tag", "db"),
			slog.String("email", email),
			slog.Any("err", err))
		return u, ErrBadDatabase
	}

	err = a.db.On(userID).
		QueryRowBuilder(ctx, a.createBuilder().
			Select("<prefix>user").
			Where("id = {id}").Param("id", userID)).
		Bind(&u)

	if err != nil {
		// email exists, but user_id can't be found. so data should be corrupted.
		if errors.Is(err, sql.ErrNoRows) {
			a.logger.Error("auth: getUserByEmail",
				slog.String("pos", "user"),
				slog.String("tag", "db"),
				slog.String("email", email),
				slog.Int64("user_id", userID.Int64),
				slog.Any("err", "email/user is corrupted"))

			return u, ErrBadDatabase
		}
		a.logger.Error("auth: getUserByEmail",
			slog.String("pos", "user"),
			slog.String("tag", "db"),
			slog.String("email", email),
			slog.Any("err", err))
		return u, ErrBadDatabase
	}

	return u, nil
}

func (a *Auth) deleteUserToken(ctx context.Context, userID shardid.ID) error {
	_, err := a.db.On(userID).
		ExecBuilder(ctx, a.createBuilder().
			Delete("<prefix>user_token").
			Where("user_id = {user_id}").
			Param("user_id", userID))

	if err != nil {
		a.logger.Error("auth: deleteUserToken",
			slog.String("tag", "db"),
			slog.Int64("user_id", userID.Int64),
			slog.Any("err", err))
		return ErrBadDatabase
	}
	return nil
}

func (a *Auth) createLoginWithEmail(ctx context.Context, email string, passwd string, firstName, lastName string) (User, error) {
	var (
		txUser, txEmail *sqle.Tx
		txErr           error

		txUserPending, txEmailPending bool
		u                             User
	)
	id := a.genUser.Next()

	defer func() {
		// transaction fails, try to rollback
		if txErr != nil {
			var err error
			// txEmail is not fault-tolerant, so rollback it first
			if txEmailPending {
				err = txEmail.Rollback()
				if err != nil {
					a.logger.Error("auth: createLoginWithEmail",
						slog.Any("err", err),
						slog.String("tag", "db"),
						slog.String("step", "createEmail:Rollback"),
						slog.String("email", email))
				}
			}

			// txtUser is fault-tolerant
			if txUserPending {
				err = txUser.Rollback()
				if err != nil {
					a.logger.Error("auth: createLoginWithEmail",
						slog.Any("err", err),
						slog.String("tag", "db"),
						slog.String("step", "createUser:Rollback"),
						slog.Int64("user_id", id.Int64))
				}
			}
		}
	}()

	txUser, txErr = a.db.On(id).BeginTx(ctx, &sql.TxOptions{})
	if txErr != nil {
		a.logger.Error("auth: createLoginWithEmail",
			slog.Any("err", txErr),
			slog.String("tag", "db"),
			slog.String("step", "txUser:BeginTx"),
			slog.Int64("user_id", id.Int64))
		return u, ErrBadDatabase
	}
	txUserPending = true

	now := time.Now()
	u, txErr = a.createUser(ctx, txUser, id, passwd, firstName, lastName, now)
	if txErr != nil {
		return u, txErr
	}

	_, txErr = a.createUserProfile(ctx, txUser, id, email, "", now)
	if txErr != nil {
		return u, txErr
	}

	// commit it first before txEmail starts. Because concurrency transaction doesn't work on SQLite
	txErr = txUser.Commit()
	if txErr != nil {
		a.logger.Error("auth: createLoginWithEmail",
			slog.Any("err", txErr),
			slog.String("tag", "db"),
			slog.String("step", "txtUser:Commit"),
			slog.String("email", email))
		return u, ErrBadDatabase
	}
	// txUser is committed, it is impossible to rollback anymore.
	// User and UserProfile have to be deleted manually when email fails to commit
	txUserPending = false

	h := generateHash(a.hash(), email, "")

	var db *sqle.Context
	db, txErr = a.db.OnDHT(h)

	if txErr != nil {
		return u, txErr
	}

	txEmail, txErr = db.BeginTx(ctx, nil)
	if txErr != nil {
		a.logger.Error("auth: createLoginWithEmail",
			slog.Any("err", txErr),
			slog.String("tag", "db"),
			slog.String("step", "txEmail:BeginTx"),
			slog.String("email", email))
		return u, ErrBadDatabase
	}
	txEmailPending = true

	txErr = a.createUserEmail(ctx, txEmail, id, email, h, now)
	if txErr != nil {
		return u, txErr
	}

	txErr = txEmail.Commit()
	if txErr != nil {
		a.logger.Error("auth: createLoginWithEmail",
			slog.Any("err", txErr),
			slog.String("tag", "db"),
			slog.String("step", "txEmail:Commit"),
			slog.String("email", email))

		// User/UserProfile are fault-tolerant, so ignore errcheck
		a.deleteUser(ctx, id)        // nolint: errcheck
		a.deleteUserProfile(ctx, id) // nolint: errcheck

		return u, ErrBadDatabase
	}

	return u, nil
}

func (a *Auth) createUser(ctx context.Context, tx *sqle.Tx, id shardid.ID, passwd string, firstName, lastName string, now time.Time) (User, error) {
	u := User{
		ID:        id,
		Status:    UserStatusWaiting,
		FirstName: firstName,
		LastName:  lastName,
		Salt:      randLetters(10),
	}

	u.Passwd = generateHash(a.hash(), passwd, u.Salt)

	u.CreatedAt = now
	u.UpdatedAt = now

	_, err := tx.ExecBuilder(ctx, a.createBuilder().
		Insert("<prefix>user").
		Set("id", id).
		Set("status", UserStatusWaiting).
		Set("first_name", firstName).
		Set("last_name", lastName).
		Set("passwd", u.Passwd).
		Set("salt", u.Salt).
		Set("created_at", now).
		Set("updated_at", now).
		End())

	if err != nil {
		a.logger.Error("auth: createUser",
			slog.String("tag", "db"),
			slog.Int64("id", id.Int64),
			slog.Any("err", err))
		return u, ErrBadDatabase
	}
	return u, nil
}

func (a *Auth) deleteUser(ctx context.Context, id shardid.ID) error {
	_, err := a.db.On(id).
		ExecBuilder(ctx, a.createBuilder().
			Delete("<prefix>user").
			Where("id = {id}").
			Param("id", id))

	if err != nil {
		a.logger.Error("auth: deleteUser",
			slog.String("tag", "db"),
			slog.Int64("id", id.Int64),
			slog.Any("err", err))
		return ErrBadDatabase
	}
	return nil
}

func (a *Auth) deleteUserProfile(ctx context.Context, userID shardid.ID) error {

	_, err := a.db.On(userID).
		ExecBuilder(ctx, a.createBuilder().
			Delete("<prefix>user_profile").
			Where("user_id = {user_id}").
			Param("user_id", userID))

	if err != nil {
		a.logger.Error("auth: deleteUserProfile",
			slog.String("tag", "db"),
			slog.Int64("user_id", userID.Int64),
			slog.Any("err", err))
		return ErrBadDatabase
	}
	return nil
}

func (a *Auth) createUserProfile(ctx context.Context, tx *sqle.Tx, userID shardid.ID, email, mobile string, now time.Time) (Profile, error) {

	p := Profile{
		UserID:    userID,
		CreatedAt: now,
		UpdatedAt: now,
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      a.totpIssuer,
		AccountName: a.totpAccountName,
	})

	if err != nil {
		a.logger.Error("auth: totp:Generate",
			slog.String("tag", "crypto"),
			slog.Any("err", err))
		return p, ErrUnknown
	}

	buf, _ := json.Marshal(ProfileData{
		Email:  email,
		Mobile: mobile,
		TKey:   key.String(),
	})

	if a.aesKey == nil {
		p.Data = string(buf)
	} else {
		ct, err := encryptText(buf, a.aesKey)
		if err != nil {
			a.logger.Error("auth: encryptText",
				slog.String("tag", "crypto"),
				slog.String("text", string(buf)),
				slog.Any("err", err))
			return p, ErrUnknown
		}

		p.Data = ct
	}

	_, err = tx.ExecBuilder(ctx, a.createBuilder().
		Insert("<prefix>user_profile").
		Set("user_id", userID).
		Set("data", p.Data).
		Set("created_at", now).
		Set("updated_at", now).
		End())

	if err != nil {
		a.logger.Error("auth: createUserProfile",
			slog.String("tag", "db"),
			slog.Int64("user_id", userID.Int64),
			slog.Any("err", err))
		return p, ErrBadDatabase
	}
	return p, nil
}

func (a *Auth) createUserEmail(ctx context.Context, tx *sqle.Tx, userID shardid.ID, email string, hash string, now time.Time) error {

	_, err := tx.ExecBuilder(ctx, a.createBuilder().
		Insert("<prefix>user_email").
		Set("user_id", userID).
		Set("hash", hash).
		Set("mask", masker.Email(email)).
		Set("is_verified", false).
		Set("created_at", now).
		End())

	if err != nil {
		a.logger.Error("auth: createUserEmail",
			slog.String("tag", "db"),
			slog.Int64("user_id", userID.Int64),
			slog.String("email", email),
			slog.Any("err", err))
		return ErrBadDatabase
	}

	return nil
}

func (a *Auth) createLoginWithMobile(ctx context.Context, mobile string, passwd string, firstName, lastName string) (User, error) {
	var (
		txUser, txMobile *sqle.Tx
		txErr            error

		txUserPending, txMobilePending bool
		u                              User
	)
	id := a.genUser.Next()

	defer func() {
		// transaction fails, try to rollback
		if txErr != nil {
			var err error
			// txEmail is not fault-tolerant, so rollback it first
			if txMobilePending {
				err = txMobile.Rollback()
				if err != nil {
					a.logger.Error("auth: createLoginWithMobile",
						slog.Any("err", err),
						slog.String("tag", "db"),
						slog.String("step", "createMobile:Rollback"),
						slog.String("mobile", mobile))
				}
			}

			// txtUser is fault-tolerant
			if txUserPending {
				err = txUser.Rollback()
				if err != nil {
					a.logger.Error("auth: createLoginWithMobile",
						slog.Any("err", err),
						slog.String("tag", "db"),
						slog.String("step", "createUser:Rollback"),
						slog.Int64("user_id", id.Int64))
				}
			}
		}
	}()

	txUser, txErr = a.db.On(id).BeginTx(ctx, &sql.TxOptions{})
	if txErr != nil {
		a.logger.Error("auth: createLoginWithMobile",
			slog.Any("err", txErr),
			slog.String("tag", "db"),
			slog.String("step", "BeginTx"),
			slog.Int64("user_id", id.Int64))
		return u, ErrBadDatabase
	}
	txUserPending = true

	now := time.Now()
	u, txErr = a.createUser(ctx, txUser, id, passwd, firstName, lastName, now)
	if txErr != nil {
		return u, txErr
	}

	_, txErr = a.createUserProfile(ctx, txUser, id, "", mobile, now)
	if txErr != nil {
		return u, txErr
	}

	// commit it first before txEmail starts. Because concurrency transaction doesn't work on SQLite
	txErr = txUser.Commit()
	if txErr != nil {
		a.logger.Error("auth: createLoginWithMobile",
			slog.Any("err", txErr),
			slog.String("tag", "db"),
			slog.String("step", "txtUser:Commit"),
			slog.String("mobile", mobile))
		return u, ErrBadDatabase
	}
	// txUser is committed, it is impossible to rollback anymore.
	// User and UserProfile have to be deleted manually when email fails to commit
	txUserPending = false

	h := generateHash(a.hash(), mobile, "")

	var db *sqle.Context
	db, txErr = a.db.OnDHT(h)

	if txErr != nil {
		return u, txErr
	}

	txMobile, txErr = db.BeginTx(ctx, nil)
	if txErr != nil {
		a.logger.Error("auth: createLoginWithMobile",
			slog.Any("err", txErr),
			slog.String("tag", "db"),
			slog.String("step", "txMobile:BeginTx"),
			slog.String("mobile", mobile))
		return u, ErrBadDatabase
	}
	txMobilePending = true

	txErr = a.createUserMobile(ctx, txMobile, id, mobile, h, now)
	if txErr != nil {
		return u, txErr
	}

	txErr = txMobile.Commit()
	if txErr != nil {
		a.logger.Error("auth: createLoginWithMobile",
			slog.Any("err", txErr),
			slog.String("tag", "db"),
			slog.String("step", "txMobile:Commit"),
			slog.String("mobile", mobile))

		// User/UserProfile are fault-tolerant, so ignore errcheck
		a.deleteUser(ctx, id)        // nolint: errcheck
		a.deleteUserProfile(ctx, id) // nolint: errcheck

		return u, ErrBadDatabase
	}

	return u, nil
}

func (a *Auth) getUserByMobile(ctx context.Context, mobile string) (User, error) {
	var u User

	h := generateHash(a.hash(), mobile, "")

	db, err := a.db.OnDHT(h)
	if err != nil {
		return u, err
	}

	var userID shardid.ID
	err = db.
		QueryRowBuilder(ctx, a.createBuilder().
			Select("<prefix>user_mobile", "user_id").
			Where("hash = {hash}").
			Param("hash", generateHash(a.hash(), mobile, ""))).
		Scan(&userID)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return u, ErrMobileNotFound
		}
		a.logger.Error("auth: getUserByMobile",
			slog.String("pos", "user_mobile"),
			slog.String("tag", "db"),
			slog.String("mobile", mobile),
			slog.Any("err", err))
		return u, ErrBadDatabase
	}

	err = a.db.On(userID).
		QueryRowBuilder(ctx, a.createBuilder().
			Select("<prefix>user").
			Where("id = {id}").Param("id", userID)).
		Bind(&u)

	if err != nil {
		// mobile exists, but user_id can't be found. so data should be corrupted.
		if errors.Is(err, sql.ErrNoRows) {
			a.logger.Error("auth: getUserBymobile",
				slog.String("pos", "user"),
				slog.String("tag", "db"),
				slog.String("mobile", mobile),
				slog.Int64("user_id", userID.Int64),
				slog.Any("err", "mobile/user is corrupted"))

			return u, ErrBadDatabase
		}
		a.logger.Error("auth: getUserByMobile",
			slog.String("pos", "user"),
			slog.String("tag", "db"),
			slog.String("mobile", mobile),
			slog.Any("err", err))
		return u, ErrBadDatabase
	}

	return u, nil
}

func (a *Auth) createUserMobile(ctx context.Context, tx *sqle.Tx, userID shardid.ID, mobile string, hash string, now time.Time) error {

	_, err := tx.ExecBuilder(ctx, a.createBuilder().
		Insert("<prefix>user_mobile").
		Set("user_id", userID).
		Set("hash", hash).
		Set("mask", masker.Mobile(mobile)).
		Set("is_verified", false).
		Set("created_at", now).
		End())

	if err != nil {
		a.logger.Error("auth: createUserMobile",
			slog.String("tag", "db"),
			slog.Int64("user_id", userID.Int64),
			slog.String("mobile", mobile),
			slog.Any("err", err))
		return ErrBadDatabase
	}

	return nil
}

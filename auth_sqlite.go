//go:build sqlite
// +build sqlite

package auth

// WARNING: all methods should be implemented without multi-transactions on SQLite. Because concurrency transaction doesn't work on SQLite.
import (
	"context"
	"log/slog"
	"time"

	"github.com/yaitoo/sqle"
	"github.com/yaitoo/sqle/shardid"
)

func (a *Auth) CreateUser(ctx context.Context, status UserStatus, email, mobile, passwd, firstName, lastName string) (User, error) {
	var (
		txUser, txEmail, txMobile *sqle.Tx

		doneEmail, doneMobile bool
		hashEmail, hashMobile string
		err                   error
		u                     User
	)

	id := a.genUser.Next()

	defer func() {
		if err != nil {
			if txEmail != nil {
				if doneEmail {
					err = a.deleteUserEmail(ctx, txEmail, id, hashEmail)
					if err != nil {
						a.logger.Error("auth: CreateUser:Email:Fix",
							slog.String("tag", "db"),
							slog.String("email", email),
							slog.Any("err", err))
					}
				} else {
					err = txEmail.Rollback()
					if err != nil {
						a.logger.Error("auth: CreateUser:Email:Rollback",
							slog.String("tag", "db"),
							slog.String("email", email),
							slog.Any("err", err))
					}
				}
			}
		}

		if txMobile != nil {
			if doneMobile {
				err = a.deleteUserMobile(ctx, txMobile, id, hashMobile)
				if err != nil {
					a.logger.Error("auth: CreateUser:Mobile:Fix",
						slog.String("tag", "db"),
						slog.String("mobile", mobile),
						slog.Any("err", err))
				}
			} else {
				err = txMobile.Rollback()
				if err != nil {
					a.logger.Error("auth: CreateUser:Mobile:Rollback",
						slog.String("tag", "db"),
						slog.String("mobile", mobile),
						slog.Any("err", err))
				}
			}
		}

	}()

	now := time.Now()
	if email != "" {
		hashEmail = generateHash(a.hash(), email, "")
		dbEmail, err := a.db.OnDHT(hashEmail, a.dhtEmail)
		if err != nil {
			return u, err
		}

		txEmail, err = dbEmail.BeginTx(ctx, nil)
		if err != nil {
			a.logger.Error("auth: CreateUser:Email:BeginTx",
				slog.String("tag", "db"),
				slog.String("email", email),
				slog.Any("err", err))
			return u, err
		}

		err = a.createUserEmail(ctx, txEmail, id, email, hashEmail, now)
		if err != nil {
			a.logger.Error("auth: CreateUser:Email",
				slog.String("tag", "db"),
				slog.String("email", email),
				slog.Any("err", err))
			return u, ErrBadDatabase
		}

		err = txEmail.Commit()
		if err != nil {
			a.logger.Error("auth: CreateUser:Email:Commit",
				slog.String("tag", "db"),
				slog.String("email", email),
				slog.Any("err", err))
			return u, ErrBadDatabase
		}

		doneEmail = true
	}

	if mobile != "" {
		hashMobile = generateHash(a.hash(), mobile, "")
		dbMobile, err := a.db.OnDHT(hashMobile, a.dhtMobile)
		if err != nil {
			return u, err
		}

		txMobile, err = dbMobile.BeginTx(ctx, nil)
		if err != nil {
			a.logger.Error("auth: CreateUser:Mobile:BeginTx",
				slog.String("tag", "db"),
				slog.String("mobile", mobile),
				slog.Any("err", err))
			return u, err
		}

		err = a.createUserMobile(ctx, txMobile, id, mobile, hashMobile, now)
		if err != nil {
			a.logger.Error("auth: CreateUser:Mobile",
				slog.String("tag", "db"),
				slog.String("mobile", mobile),
				slog.Any("err", err))
			return u, ErrBadDatabase
		}

		err = txMobile.Commit()
		if err != nil {
			a.logger.Error("auth: CreateUser:Mobile:Commit",
				slog.String("tag", "db"),
				slog.String("mobile", mobile),
				slog.Any("err", err))
			return u, ErrBadDatabase
		}

		doneMobile = true

	}

	txUser, err = a.db.On(id).BeginTx(ctx, nil)
	if err != nil {
		a.logger.Error("auth: CreateUser:User:BeginTx",
			slog.String("tag", "db"),
			slog.Int64("user_id", id.Int64),
			slog.Any("err", err))
		return u, ErrBadDatabase
	}

	u, err = a.createUser(ctx, txUser, id, status, passwd, firstName, lastName, email, mobile, now)
	if err != nil {
		return u, err
	}

	_, err = a.createUserProfile(ctx, txUser, id, email, mobile, now)
	if err != nil {
		return u, err
	}

	err = txUser.Commit()
	if err != nil {
		a.logger.Error("auth: CreateUser:User:Commit",
			slog.String("tag", "db"),
			slog.Int64("user_id", id.Int64),
			slog.Any("err", err))
		return u, ErrBadDatabase
	}

	return u, nil
}

func (a *Auth) DeleteUser(ctx context.Context, id int64) error {
	var (
		dbEmail, dbMobile         *sqle.Context
		txUser, txEmail, txMobile *sqle.Tx

		doneEmail  bool
		doneMobile bool

		hashEmail  string
		hashMobile string
	)

	uid := shardid.Parse(id)
	dbUser := a.db.On(uid)
	pd, err := a.getUserProfileData(ctx, uid)
	if err != nil {
		return err
	}

	if pd.Email != "" {
		hashEmail = generateHash(a.hash(), pd.Email, "")
		dbEmail, err = a.db.OnDHT(hashEmail, a.dhtEmail)
		if err != nil {
			return err
		}
	}

	if pd.Mobile != "" {
		hashMobile = generateHash(a.hash(), pd.Mobile, "")
		dbMobile, err = a.db.OnDHT(hashMobile, a.dhtMobile)
		if err != nil {
			return err
		}
	}

	defer func() {
		if err != nil {
			if txUser != nil {
				err = txUser.Rollback()
				if err != nil {
					a.logger.Error("auth: DeleteUser:User:Rollback",
						slog.String("tag", "db"),
						slog.Int64("user_id", id),
						slog.Any("err", err))
				}
			}

			now := time.Now()

			if txEmail != nil {
				if doneEmail {
					err = a.createUserEmail(ctx, txEmail, uid, pd.Email, hashEmail, now)
					if err != nil {
						a.logger.Error("auth: DeleteUser:Email:Fix",
							slog.String("tag", "db"),
							slog.Int64("user_id", id),
							slog.String("email", pd.Email),
							slog.Any("err", err))
					}
				} else {
					err = txEmail.Rollback()
					if err != nil {
						a.logger.Error("auth: DeleteUser:Email:Rollback",
							slog.String("tag", "db"),
							slog.Int64("user_id", id),
							slog.String("email", pd.Email),
							slog.Any("err", err))
					}
				}
			}

			if txMobile != nil {
				if doneMobile {
					err = a.createUserMobile(ctx, txMobile, uid, pd.Mobile, hashMobile, now)
					if err != nil {
						a.logger.Error("auth: DeleteUser:Mobile:Fix",
							slog.String("tag", "db"),
							slog.Int64("user_id", id),
							slog.String("mobile", pd.Mobile),
							slog.Any("err", err))
					}
				} else {
					err = txMobile.Rollback()
					if err != nil {
						a.logger.Error("auth: DeleteUser:Mobile:Rollback",
							slog.String("tag", "db"),
							slog.Int64("user_id", id),
							slog.String("mobile", pd.Mobile),
							slog.Any("err", err))
					}
				}
			}
		}
	}()

	if pd.Email != "" {
		txEmail, err = dbEmail.BeginTx(ctx, nil)
		if err != nil {
			a.logger.Error("auth: DeleteUser:Email:BeginTx",
				slog.String("tag", "db"),
				slog.Int64("user_id", id),
				slog.String("email", pd.Email),
				slog.Any("err", err))
			return ErrBadDatabase
		}

		_, err = txEmail.ExecBuilder(ctx, a.createBuilder().
			Delete("<prefix>user_email").
			Where("user_id = {id}").
			Param("id", id))

		if err != nil {
			a.logger.Error("auth: DeleteUser:Email",
				slog.String("tag", "db"),
				slog.Int64("user_id", id),
				slog.String("email", pd.Email),
				slog.Any("err", err))
			return ErrBadDatabase
		}

	}

	if pd.Mobile != "" {
		txMobile, err = dbMobile.BeginTx(ctx, nil)
		if err != nil {
			a.logger.Error("auth: DeleteUser:Mobile:BeginTx",
				slog.String("tag", "db"),
				slog.Int64("user_id", id),
				slog.String("mobile", pd.Mobile),
				slog.Any("err", err))
			return ErrBadDatabase
		}

		_, err = txMobile.ExecBuilder(ctx, a.createBuilder().
			Delete("<prefix>user_mobile").
			Where("user_id = {id}").
			Param("id", id))

		if err != nil {
			a.logger.Error("auth: DeleteUser:Mobile",
				slog.String("tag", "db"),
				slog.Int64("user_id", id),
				slog.String("mobile", pd.Mobile),
				slog.Any("err", err))
			return ErrBadDatabase
		}
	}

	txUser, err = dbUser.BeginTx(ctx, nil)
	if err != nil {
		a.logger.Error("auth: DeleteUser:User:BeginTx",
			slog.String("tag", "db"),
			slog.Int64("user_id", id),
			slog.String("mobile", pd.Mobile),
			slog.Any("err", err))
		return ErrBadDatabase
	}

	_, err = txUser.ExecBuilder(ctx, a.createBuilder().
		Delete("<prefix>user").
		Where("id = {id}").
		Param("id", id))
	if err != nil {
		a.logger.Error("auth: DeleteUser",
			slog.String("tag", "db"),
			slog.Int64("id", id),
			slog.Any("err", err))
		return ErrBadDatabase
	}

	_, err = txUser.ExecBuilder(ctx, a.createBuilder().
		Delete("<prefix>user_profile").
		Where("user_id = {id}").
		Param("id", id))

	if err != nil {
		a.logger.Error("auth: DeleteUser",
			slog.String("tag", "db"),
			slog.Int64("id", id),
			slog.Any("err", err))
		return ErrBadDatabase
	}
	if txEmail != nil {
		err = txEmail.Commit()
		if err != nil {
			a.logger.Error("auth: DeleteUser:Email:Commit",
				slog.String("tag", "db"),
				slog.Int64("user_id", id),
				slog.String("email", pd.Email),
				slog.Any("err", err))
			return ErrBadDatabase
		}
		doneEmail = true
	}
	if txMobile != nil {
		err = txMobile.Commit()
		if err != nil {
			a.logger.Error("auth: DeleteUser:Mobile:Commit",
				slog.String("tag", "db"),
				slog.Int64("user_id", id),
				slog.String("mobile", pd.Mobile),
				slog.Any("err", err))
			return ErrBadDatabase
		}
		doneMobile = true
	}

	err = txUser.Commit()
	if err != nil {
		a.logger.Error("auth: DeleteUser:User:Commit",
			slog.String("tag", "db"),
			slog.Int64("user_id", id),
			slog.Any("err", err))
		return ErrBadDatabase
	}

	return nil
}
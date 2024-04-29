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

// QueryUsers queries the users from the database based on the provided conditions and returns a limited result.
// It takes a context, a where clause builder, and a limit as input parameters.
// The function returns a LimitResult of User objects and an error if any.
func (a *Auth) QueryUsers(ctx context.Context, where *sqle.WhereBuilder, limit int) ([]User, error) {
	query := sqle.NewQuery[User](a.db)

	b := a.createBuilder().Select("<prefix>user")

	b.WithWhere(where)
	items, err := query.QueryLimit(ctx, b, nil, limit)
	if err != nil {
		a.logger.Error("auth: QueryUsers",
			slog.String("tag", "db"),
			slog.Any("err", err))
		return nil, ErrBadDatabase
	}

	return items, nil
}

func (a *Auth) QueryUsersCount(ctx context.Context, where *sqle.WhereBuilder) (int64, error) {
	query := sqle.NewQuery[User](a.db)

	b := a.createBuilder().
		Select("<prefix>user", "count(id) as c")

	b.WithWhere(where)

	total, err := query.Count(ctx, b)
	if err != nil {
		a.logger.Error("auth: QueryUserCount",
			slog.String("tag", "db"),
			slog.Any("err", err))
		return 0, ErrBadDatabase
	}

	return total, nil
}

func (a *Auth) GetUserByEmail(ctx context.Context, email string) (User, error) {
	var u User

	h := generateHash(a.hash(), email, "")

	db, err := a.db.OnDHT(h, a.dhtEmail)
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
		a.logger.Error("auth: GetUserByEmail",
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
			a.logger.Error("auth: GetUserByEmail:User",
				slog.String("tag", "db"),
				slog.String("email", email),
				slog.Int64("user_id", userID.Int64),
				slog.Any("err", "email/user is corrupted"))

			return u, ErrBadDatabase
		}
		a.logger.Error("auth: GetUserByEmail",
			slog.String("pos", "user"),
			slog.String("tag", "db"),
			slog.String("email", email),
			slog.Any("err", err))
		return u, ErrBadDatabase
	}

	return u, nil
}

func (a *Auth) GetUserByMobile(ctx context.Context, mobile string) (User, error) {
	var u User

	h := generateHash(a.hash(), mobile, "")

	db, err := a.db.OnDHT(h, a.dhtMobile)
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
		a.logger.Error("auth: GetUserByMobile",
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
			a.logger.Error("auth: GetUserByMobile",
				slog.String("pos", "user"),
				slog.String("tag", "db"),
				slog.String("mobile", mobile),
				slog.Int64("user_id", userID.Int64),
				slog.Any("err", "mobile/user is corrupted"))

			return u, ErrBadDatabase
		}
		a.logger.Error("auth: GetUserByMobile",
			slog.String("pos", "user"),
			slog.String("tag", "db"),
			slog.String("mobile", mobile),
			slog.Any("err", err))
		return u, ErrBadDatabase
	}

	return u, nil
}

// GetUsersByRole get users by role id
func (a *Auth) GetUsersByRole(ctx context.Context, rid int) ([]int64, error) {
	var items [][]int64
	rows, err := a.db.
		QueryBuilder(ctx, a.createBuilder().
			Select("<prefix>role_user", "user_id").
			Where("role_id = {role_id}").
			Param("role_id", rid))

	if err != nil {
		a.logger.Error("auth: GetUsersByRole",
			slog.String("tag", "db"),
			slog.Int("role_id", rid),
			slog.Any("err", err))
		return nil, ErrBadDatabase
	}

	err = rows.Bind(&items)
	if err != nil {
		a.logger.Error("auth: GetUsersByRole:Bind",
			slog.String("tag", "db"),
			slog.Int("role_id", rid),
			slog.Any("err", err))
		return nil, ErrBadDatabase
	}

	var ids []int64
	for _, it := range items {
		ids = append(ids, it[0])
	}

	return ids, nil
}

// GetUserRoles get roles by user id
func (a *Auth) GetUserRoles(ctx context.Context, uid int64) ([]Role, error) {
	var items []Role
	rows, err := a.db.
		QueryBuilder(ctx, a.createBuilder().
			SQL(`SELECT <prefix>role.* FROM <prefix>role_user
JOIN <prefix>role on <prefix>role_user.role_id = <prefix>role.id 
WHERE <prefix>role_user.user_id = {user_id}`).
			Param("user_id", uid))

	if err != nil {
		a.logger.Error("auth: GetRolesByUser",
			slog.String("tag", "db"),
			slog.Int64("user_id", uid),
			slog.Any("err", err))
		return nil, ErrBadDatabase
	}

	err = rows.Bind(&items)
	if err != nil {
		a.logger.Error("auth: GetRolesByUser:Bind",
			slog.String("tag", "db"),
			slog.Int64("user_id", uid),
			slog.Any("err", err))
		return nil, ErrBadDatabase
	}

	return items, nil
}

// CreateUser creates a new user with the provided information.
// It generates a unique user ID, hashes the email and mobile numbers,
// and stores the user details in the database.
// The function returns the created user and any error encountered during the process.
func (a *Auth) CreateUser(ctx context.Context, status UserStatus, email, mobile, passwd, firstName, lastName string) (User, error) {
	var (
		hashEmail, hashMobile string
		u                     User
	)

	dtc := sqle.NewDTC(ctx, nil)

	id := a.genUser.Next()
	now := time.Now()

	if email != "" {
		hashEmail = generateHash(a.hash(), email, "")
		dbEmail, err := a.db.OnDHT(hashEmail, a.dhtEmail)
		if err != nil {
			return u, err
		}

		dtc.Prepare(dbEmail, func(ctx context.Context, conn sqle.Connector) error {
			err := a.createEmail(ctx, conn, id, email, hashEmail, now)
			if err != nil {
				a.logger.Error("auth: CreateUser:Email",
					slog.String("tag", "db"),
					slog.String("email", email),
					slog.Any("err", err))
				return ErrBadDatabase
			}

			return nil
		}, func(ctx context.Context, conn sqle.Connector) error {
			err = a.deleteEmail(ctx, conn, id, hashEmail)
			if err != nil {
				a.logger.Error("auth: CreateUser:Email:Revert",
					slog.String("tag", "db"),
					slog.String("email", email),
					slog.Any("err", err))

				return ErrBadDatabase
			}

			return nil
		})

	}

	if mobile != "" {
		hashMobile = generateHash(a.hash(), mobile, "")
		dbMobile, err := a.db.OnDHT(hashMobile, a.dhtMobile)
		if err != nil {
			return u, err
		}

		dtc.Prepare(dbMobile, func(ctx context.Context, conn sqle.Connector) error {
			err = a.createMobile(ctx, conn, id, mobile, hashMobile, now)
			if err != nil {
				a.logger.Error("auth: CreateUser:Mobile",
					slog.String("tag", "db"),
					slog.String("mobile", mobile),
					slog.Any("err", err))
				return ErrBadDatabase
			}
			return nil
		}, func(ctx context.Context, conn sqle.Connector) error {
			err = a.deleteMobile(ctx, conn, id, hashMobile)
			if err != nil {
				a.logger.Error("auth: CreateUser:Mobile:Revert",
					slog.String("tag", "db"),
					slog.String("mobile", mobile),
					slog.Any("err", err))
				return ErrBadDatabase
			}

			return nil
		})
	}

	dtc.Prepare(a.db.On(id), func(ctx context.Context, conn sqle.Connector) error {
		var err error
		u, err = a.createUser(ctx, conn, id, status, passwd, firstName, lastName, email, mobile, now)
		if err != nil {
			return err
		}

		_, err = a.createProfile(ctx, conn, id, email, mobile, now)
		if err != nil {
			return err
		}

		return nil
	}, nil)

	err := dtc.Commit()

	if err != nil {
		a.logger.Error("auth: CreateUser:Commit",
			slog.String("tag", "db"),
			slog.Int64("user_id", id.Int64),
			slog.String("email", email),
			slog.String("mobile", mobile),
			slog.Any("err", err))

		errs := dtc.Rollback()
		if len(errs) > 0 {
			a.logger.Error("auth: CreateUser:Rollback",
				slog.String("tag", "db"),
				slog.Int64("user_id", id.Int64),
				slog.String("email", email),
				slog.String("mobile", mobile),
				slog.Any("err", errs))
		}

		return u, ErrBadDatabase
	}

	return u, nil
}

// UpdateUser updates the user with the specified ID in the database.
// It sets the first name, last name, and status of the user.
// If an error occurs during the update, it logs the error and returns ErrBadDatabase.
func (a *Auth) UpdateUser(ctx context.Context, id int64, status UserStatus, firstName, lastName string) error {
	uid := shardid.Parse(id)
	_, err := a.db.On(uid).ExecBuilder(ctx, a.createBuilder().
		Update("<prefix>user").
		Set("first_name", firstName).
		Set("last_name", lastName).
		Set("status", status).
		Where("id = {id}").
		Param("id", id))
	if err != nil {
		a.logger.Error("auth: UpdateUser",
			slog.String("tag", "db"),
			slog.Int64("id", id),
			slog.Any("err", err))
		return ErrBadDatabase
	}

	return nil
}

// DeleteUser deletes a user from the authentication system.
// It takes a context and the ID of the user to be deleted as parameters.
// It returns an error if any error occurs during the deletion process.
func (a *Auth) DeleteUser(ctx context.Context, id int64) error {
	var (
		hashEmail  string
		hashMobile string
	)

	uid := shardid.Parse(id)
	dbUser := a.db.On(uid)
	pd, err := a.GetProfileData(ctx, dbUser, id)
	if err != nil {
		return err
	}

	dtc := sqle.NewDTC(ctx, nil)
	now := time.Now()

	if pd.Email != "" {
		hashEmail = generateHash(a.hash(), pd.Email, "")
		dbEmail, err := a.db.OnDHT(hashEmail, a.dhtEmail)
		if err != nil {
			return err
		}

		dtc.Prepare(dbEmail, func(ctx context.Context, conn sqle.Connector) error {
			return a.deleteEmail(ctx, conn, uid, hashEmail)
		}, func(ctx context.Context, conn sqle.Connector) error {
			err = a.createEmail(ctx, conn, uid, pd.Email, hashEmail, now)
			if err != nil {
				a.logger.Error("auth: DeleteUser:Email:Revert",
					slog.String("tag", "db"),
					slog.Int64("user_id", id),
					slog.String("email", pd.Email),
					slog.Any("err", err))

				return ErrBadDatabase
			}

			return nil

		})

	}

	if pd.Mobile != "" {
		hashMobile = generateHash(a.hash(), pd.Mobile, "")
		dbMobile, err := a.db.OnDHT(hashMobile, a.dhtMobile)
		if err != nil {
			return err
		}

		dtc.Prepare(dbMobile, func(ctx context.Context, conn sqle.Connector) error {
			return a.deleteMobile(ctx, conn, uid, hashMobile)
		}, func(ctx context.Context, conn sqle.Connector) error {
			err := a.createMobile(ctx, conn, uid, pd.Mobile, hashMobile, now)
			if err != nil {
				a.logger.Error("auth: DeleteUser:Mobile:Revert",
					slog.String("tag", "db"),
					slog.Int64("user_id", id),
					slog.String("mobile", pd.Mobile),
					slog.Any("err", err))

				return ErrBadDatabase
			}

			return nil
		})
	}

	dtc.Prepare(dbUser, func(ctx context.Context, conn sqle.Connector) error {
		err := a.deleteUser(ctx, conn, uid)
		if err != nil {
			return err
		}

		return a.deleteProfile(ctx, conn, uid)

	}, nil)

	err = dtc.Commit()
	if err != nil {
		a.logger.Error("auth: DeleteUser:Commit",
			slog.String("tag", "db"),
			slog.Int64("user_id", id),
			slog.Any("err", err))

		errs := dtc.Rollback()
		if errs != nil {
			a.logger.Error("auth: DeleteUser:Rollback",
				slog.String("tag", "db"),
				slog.Int64("user_id", id),
				slog.Any("err", errs))
		}

		return ErrBadDatabase
	}

	return nil
}

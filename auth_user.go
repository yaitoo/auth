package auth

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"

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
			a.logger.Error("auth: GetUserByEmail",
				slog.String("pos", "user"),
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

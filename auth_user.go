package auth

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/yaitoo/sqle"
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

// AddUserRoles add the user into roles
func (a *Auth) AddUserRoles(ctx context.Context, uid int64, rIDs ...int) error {
	return a.db.Transaction(ctx, &sql.TxOptions{}, func(ctx context.Context, tx *sqle.Tx) error {
		now := time.Now()
		var err error
		for _, rid := range rIDs {
			_, err = tx.ExecBuilder(ctx, a.createBuilder().
				Insert("<prefix>role_user").
				Set("role_id", rid).
				Set("user_id", uid).
				Set("created_at", now).
				End())
			if err != nil {
				a.logger.Error("auth: AddUserToRoles",
					slog.String("tag", "db"),
					slog.Any("err", err))
				return ErrBadDatabase
			}
		}
		return nil
	})
}

// RemoveUserRoles remove roles from the user
func (a *Auth) RemoveUserRoles(ctx context.Context, uid int64, rIDs ...int) error {
	return a.db.Transaction(ctx, &sql.TxOptions{}, func(ctx context.Context, tx *sqle.Tx) error {
		var err error
		for _, rid := range rIDs {
			_, err = tx.ExecBuilder(ctx, a.createBuilder().
				Delete("<prefix>role_user").
				Where("user_id = {user_id} AND role_id = {role_id}").
				Param("role_id", rid).
				Param("user_id", uid))
			if err != nil {
				a.logger.Error("auth: RemoveRolesFromUser",
					slog.String("tag", "db"),
					slog.Any("err", err))
				return ErrBadDatabase
			}
		}
		return nil
	})
}

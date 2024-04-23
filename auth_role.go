package auth

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/yaitoo/sqle"
)

// QueryRoles retrieves a list of roles from the database based on the provided WHERE condition.
// It returns a slice of Role objects and an error if any.
func (a *Auth) QueryRoles(ctx context.Context, where *sqle.WhereBuilder) ([]Role, error) {
	b := a.createBuilder().Select("<prefix>role")

	b.WithWhere(where)

	rows, err := a.db.
		QueryBuilder(ctx, b)

	if err != nil {
		a.logger.Error("auth: QueryRoles",
			slog.String("tag", "db"),
			slog.Any("err", err))
		return nil, ErrBadDatabase
	}
	var items []Role
	err = rows.Bind(&items)

	if err != nil {
		a.logger.Error("auth: QueryRoles:Bind",
			slog.String("tag", "db"),
			slog.Any("err", err))
		return nil, ErrBadDatabase
	}

	return items, nil
}

// CreateRole create new role with name
func (a *Auth) CreateRole(ctx context.Context, name string) (int, error) {
	now := time.Now()
	r, err := a.db.
		ExecBuilder(ctx, a.createBuilder().
			Insert("<prefix>role").
			Set("name", name).
			Set("created_at", now).
			Set("updated_at", now).
			End())

	if err != nil {
		a.logger.Error("auth: CreateRole",
			slog.String("tag", "db"),
			slog.String("name", name),
			slog.Any("err", err))
		return 0, ErrBadDatabase
	}

	id, err := r.LastInsertId()
	if err != nil {
		a.logger.Error("auth: CreateRole",
			slog.String("tag", "db"),
			slog.String("step", "LastInsertId"),
			slog.String("name", name),
			slog.Any("err", err))
		return 0, ErrBadDatabase
	}

	return int(id), nil
}

// UpdateRole update role name
func (a *Auth) UpdateRole(ctx context.Context, id int, name string) error {
	_, err := a.db.
		ExecBuilder(ctx, a.createBuilder().
			Update("<prefix>role").
			Set("name", name).
			Set("updated_at", time.Now()).
			Where("id = {id}").
			Param("id", id))

	if err != nil {
		a.logger.Error("auth: UpdateRole",
			slog.String("tag", "db"),
			slog.String("name", name),
			slog.Any("err", err))
		return ErrBadDatabase
	}

	return nil
}

// DeleteRole delete role, role_user, role_perm
func (a *Auth) DeleteRole(ctx context.Context, id int) error {
	err := a.db.Transaction(ctx, nil, func(ctx context.Context, tx *sqle.Tx) error {
		_, err := tx.ExecBuilder(ctx, a.createBuilder().Delete("<prefix>role").Where("id = {id}").Param("id", id))
		if err != nil {
			return err
		}

		_, err = tx.ExecBuilder(ctx, a.createBuilder().Delete("<prefix>role_user").Where("role_id = {role_id}").Param("role_id", id))
		if err != nil {
			return err
		}

		_, err = tx.ExecBuilder(ctx, a.createBuilder().Delete("<prefix>role_perm").Where("role_id = {role_id}").Param("role_id", id))
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		a.logger.Error("auth: DeleteRole",
			slog.String("tag", "db"),
			slog.Int("role_id", id),
			slog.Any("err", err))
		return ErrBadDatabase
	}

	return nil
}

// GetRoleUsers get users by role id
func (a *Auth) GetRoleUsers(ctx context.Context, rid int) ([]User, error) {
	var items []User
	rows, err := a.db.
		QueryBuilder(ctx, a.createBuilder().
			SQL(`SELECT user_id as id
FROM <prefix>role_user
WHERE role_id = {role_id}`).
			Param("role_id", rid))

	if err != nil {
		a.logger.Error("auth: GetRoleUsers",
			slog.String("tag", "db"),
			slog.Int("role_id", rid),
			slog.Any("err", err))
		return nil, ErrBadDatabase
	}

	err = rows.Bind(&items)
	if err != nil {
		a.logger.Error("auth: GetRoleUsers:Bind",
			slog.String("tag", "db"),
			slog.Int("role_id", rid),
			slog.Any("err", err))
		return nil, ErrBadDatabase
	}

	for i, it := range items {
		err := a.db.On(it.ID).
			QueryRowBuilder(ctx, a.createBuilder().
				Select("<prefix>user").
				Where("id = {id}").Param("id", it.ID.Int64)).
			Bind(&items[i])

		if err != nil {
			a.logger.Error("auth: GetRoleUsers:GetUser",
				slog.String("tag", "db"),
				slog.Int64("user_id", it.ID.Int64),
				slog.Any("err", err))
			return nil, ErrBadDatabase
		}
	}

	return items, nil
}

// AddRoleUsers add users into the role
func (a *Auth) AddRoleUsers(ctx context.Context, rid int, uIDs ...int64) error {
	return a.db.Transaction(ctx, &sql.TxOptions{}, func(ctx context.Context, tx *sqle.Tx) error {
		now := time.Now()
		var (
			err error
			n   int
			c   int
		)
		for _, uid := range uIDs {

			err = tx.QueryRowBuilder(ctx,
				a.createBuilder().
					Select("<prefix>", "count(user_id) as c").
					Where("role_id = {role_id} AND user_id = {user_id}").
					Param("role_id", rid).
					Param("user_id", uid)).
				Scan(&c)

			if err != nil {
				a.logger.Error("auth: AddRoleUsers:Exists",
					slog.String("tag", "db"),
					slog.Any("err", err))
				return ErrBadDatabase
			}

			if c > 0 {
				continue
			}

			n++

			_, err = tx.ExecBuilder(ctx, a.createBuilder().
				Insert("<prefix>role_user").
				Set("role_id", rid).
				Set("user_id", uid).
				Set("created_at", now).
				End())
			if err != nil {
				a.logger.Error("auth: AddRoleUsers",
					slog.String("tag", "db"),
					slog.Any("err", err))
				return ErrBadDatabase
			}
		}

		_, err = tx.ExecBuilder(ctx, a.createBuilder().
			Update("<prefix>role").
			Set("user_count", n).
			Where("id = {id}").
			Param("id", rid))

		if err != nil {
			a.logger.Error("auth: AddRoleUsers:UserCount",
				slog.String("tag", "db"),
				slog.Any("err", err))
			return ErrBadDatabase
		}

		return nil
	})

}

// RemoveRoleUsers remove users from the role
func (a *Auth) RemoveRoleUsers(ctx context.Context, rid int, uIDs ...int64) error {
	return a.db.Transaction(ctx, &sql.TxOptions{}, func(ctx context.Context, tx *sqle.Tx) error {
		var err error
		for _, uid := range uIDs {
			_, err = tx.ExecBuilder(ctx, a.createBuilder().
				Delete("<prefix>role_user").
				Where("user_id = {user_id} AND role_id = {role_id}").
				Param("role_id", rid).
				Param("user_id", uid))
			if err != nil {
				a.logger.Error("auth: RemoveRoleUsers",
					slog.String("tag", "db"),
					slog.Any("err", err))
				return ErrBadDatabase
			}
		}

		var n int
		err = tx.QueryRowBuilder(ctx,
			a.createBuilder().
				Select("<prefix>role_user", "count(user_id) as n").
				Where("role_id = {role_id}").Param("role_id", rid)).
			Scan(&n)

		if err != nil {
			a.logger.Error("auth: RemoveRoleUsers:Count",
				slog.String("tag", "db"),
				slog.Any("err", err))
			return ErrBadDatabase
		}

		_, err = tx.ExecBuilder(ctx, a.createBuilder().
			Update("<prefix>role").
			Set("user_count", n).
			Where("id = {id}").
			Param("id", rid))

		if err != nil {
			a.logger.Error("auth: RemoveRoleUsers:UserCount",
				slog.String("tag", "db"),
				slog.Any("err", err))
			return ErrBadDatabase
		}

		return nil
	})
}

package auth

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/yaitoo/sqle"
)

// QueryPerms queries the permissions based on the provided context and where clause.
// It returns a slice of Perm objects and an error if any.
func (a *Auth) QueryPerms(ctx context.Context, where *sqle.WhereBuilder) ([]Perm, error) {
	b := a.createBuilder().Select("<prefix>perm")
	b.WithWhere(where)

	rows, err := a.db.QueryBuilder(ctx, b)

	if err != nil {
		a.logger.Error("auth: QueryPerms",
			slog.String("tag", "db"),
			slog.Any("err", err))
		return nil, ErrBadDatabase
	}
	var items []Perm
	err = rows.Bind(&items)

	if err != nil {
		a.logger.Error("auth: QueryPerms:Bind",
			slog.String("tag", "db"),
			slog.Any("err", err))
		return nil, ErrBadDatabase
	}

	return items, nil
}

// RegisterPerm create new permission if it doesn't exists
func (a *Auth) RegisterPerm(ctx context.Context, code, tag string) error {

	t, err := a.getPermTag(ctx, code)

	// perm exits
	if err == nil {
		// tag is not changed
		if t == tag {
			return nil
		}

		// update tag
		return a.updatePerm(ctx, code, tag)
	}

	return a.createPerm(ctx, code, tag)
}

// GrantPerms grant permissions to the role
func (a *Auth) GrantPerms(ctx context.Context, rid int, codes ...string) error {
	return a.db.Transaction(ctx, &sql.TxOptions{}, func(ctx context.Context, tx *sqle.Tx) error {
		var (
			err error
			n   int
			c   int
		)

		now := time.Now()
		for _, code := range codes {
			err = tx.QueryRowBuilder(ctx,
				a.createBuilder().
					Select("<prefix>role_perm", "count(perm_code) as c").
					Where("role_id = {role_id} AND perm_code = {perm_code}").
					Param("role_id", rid).
					Param("perm_code", code)).
				Scan(&c)

			if err != nil {
				a.logger.Error("auth: GrantPerms:Exists",
					slog.String("tag", "db"),
					slog.Any("err", err))

				return ErrBadDatabase
			}

			if c > 0 {
				continue
			}

			n++

			_, err = tx.ExecBuilder(ctx, a.createBuilder().
				Insert("<prefix>role_perm").
				Set("role_id", rid).
				Set("perm_code", code).
				Set("created_at", now).End())
			if err != nil {
				a.logger.Error("auth: GrantPerms",
					slog.String("tag", "db"),
					slog.Any("err", err))
				return ErrBadDatabase
			}
		}

		_, err = tx.ExecBuilder(ctx, a.createBuilder().
			Update("<prefix>role").
			SetExpr("perm_count = perm_count + {n}").
			Where("id = {id}").
			Param("n", n).
			Param("id", rid))

		if err != nil {
			a.logger.Error("auth: GrantPerms:PermCount",
				slog.String("tag", "db"),
				slog.Any("err", err))
			return ErrBadDatabase
		}

		return nil
	})
}

// RevokePerms revoke permissions from the role
func (a *Auth) RevokePerms(ctx context.Context, rid int, codes ...string) error {
	return a.db.Transaction(ctx, &sql.TxOptions{}, func(ctx context.Context, tx *sqle.Tx) error {
		var err error

		for _, code := range codes {
			_, err = tx.ExecBuilder(ctx, a.createBuilder().
				Delete("<prefix>role_perm").
				Where("role_id = {role_id} AND perm_code = {perm_code}").
				Param("role_id", rid).
				Param("perm_code", code))
			if err != nil {
				a.logger.Error("auth: RevokePerms",
					slog.String("tag", "db"),
					slog.Any("err", err))
				return ErrBadDatabase
			}
		}
		var n int
		err = tx.QueryRowBuilder(ctx, a.createBuilder().
			Select("<prefix>role_perm", "count(perm_code) as n").
			Where("role_id = {role_id}").
			Param("role_id", rid)).Scan(&n)

		if err != nil {
			a.logger.Error("auth: RevokePerms:Count",
				slog.String("tag", "db"),
				slog.Any("err", err))
			return ErrBadDatabase
		}

		_, err = tx.ExecBuilder(ctx, a.createBuilder().
			Update("<prefix>role").
			Set("perm_count", n).
			Where("id = {id}").
			Param("id", rid))

		if err != nil {
			a.logger.Error("auth: RevokePerms:PermCount",
				slog.String("tag", "db"),
				slog.Any("err", err))
			return ErrBadDatabase
		}

		return nil
	})
}

// GetRolePerms get role's permissions
func (a *Auth) GetRolePerms(ctx context.Context, rid int) ([]Perm, error) {
	rows, err := a.db.QueryBuilder(ctx, a.createBuilder().
		SQL(`SELECT <prefix>perm.*
FROM <prefix>role_perm
  JOIN <prefix>perm ON <prefix>perm.code = <prefix>role_perm.perm_code
WHERE <prefix>role_perm.role_id = {role_id}`).
		Param("role_id", rid))

	if err != nil {
		a.logger.Error("auth: GetRolePerms",
			slog.String("tag", "db"),
			slog.Int("role_id", rid),
			slog.Any("err", err))

		return nil, ErrBadDatabase
	}

	var items []Perm
	err = rows.Bind(&items)
	if err != nil {
		a.logger.Error("auth: GetRolePerms:Bind",
			slog.String("tag", "db"),
			slog.Int("role_id", rid),
			slog.Any("err", err))

		return nil, ErrBadDatabase
	}

	return items, nil
}

// GetUserPerms get user's permissions granted by its roles
func (a *Auth) GetUserPerms(ctx context.Context, uid int64) ([]string, error) {
	rows, err := a.db.QueryBuilder(ctx, a.createBuilder().
		SQL(`SELECT <prefix>role_perm.perm_code as code
FROM <prefix>role_perm
  JOIN <prefix>role_user ON <prefix>role_perm.role_id = <prefix>role_user.role_id
WHERE <prefix>role_user.user_id = {user_id}`).
		Param("user_id", uid))

	if err != nil {
		a.logger.Error("auth: GetUserPerms",
			slog.String("tag", "db"),
			slog.Int64("user_id", uid),
			slog.Any("err", err))

		return nil, ErrBadDatabase
	}

	var items [][]string
	err = rows.Bind(&items)
	if err != nil {
		a.logger.Error("auth: GetUserPerms:Bind",
			slog.String("tag", "db"),
			slog.Int64("user_id", uid),
			slog.Any("err", err))

		return nil, ErrBadDatabase
	}

	var codes []string
	for _, r := range items {
		codes = append(codes, r[0])
	}

	return codes, nil
}

package auth

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/yaitoo/sqle"
)

// GetPerms get all permissions
func (a *Auth) GetPerms(ctx context.Context) ([]Perm, error) {
	rows, err := a.db.
		QueryBuilder(ctx, a.createBuilder().
			Select("<prefix>perm"))

	if err != nil {
		a.logger.Error("auth: GetPerms",
			slog.String("tag", "db"),
			slog.Any("err", err))
		return nil, ErrBadDatabase
	}
	var items []Perm
	err = rows.Bind(&items)

	if err != nil {
		a.logger.Error("auth: GetPerms:Bind",
			slog.String("tag", "db"),
			slog.Any("err", err))
		return nil, ErrBadDatabase
	}

	return items, nil
}

// GetRoles get all roles
func (a *Auth) GetRoles(ctx context.Context) ([]Role, error) {
	rows, err := a.db.
		QueryBuilder(ctx, a.createBuilder().
			Select("<prefix>role"))

	if err != nil {
		a.logger.Error("auth: GetRoles",
			slog.String("tag", "db"),
			slog.Any("err", err))
		return nil, ErrBadDatabase
	}
	var items []Role
	err = rows.Bind(&items)

	if err != nil {
		a.logger.Error("auth: GetRoles:Bind",
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
		return a.updatePermTag(ctx, code, tag)
	}

	return a.createPerm(ctx, code, tag)
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

// GetRolesByUser get roles by user id
func (a *Auth) GetRolesByUser(ctx context.Context, uid int64) ([]Role, error) {
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
			slog.Int("user_id", int(uid)),
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

// AddRoleToUsers add users into the role
func (a *Auth) AddRoleToUsers(ctx context.Context, rid int, uIDs ...int64) error {
	return a.db.Transaction(ctx, &sql.TxOptions{}, func(ctx context.Context, tx *sqle.Tx) error {
		now := time.Now()
		var err error
		for _, uid := range uIDs {
			_, err = tx.ExecBuilder(ctx, a.createBuilder().
				Insert("<prefix>role_user").
				Set("role_id", rid).
				Set("user_id", uid).
				Set("created_at", now).
				End())
			if err != nil {
				a.logger.Error("auth: AddRoleToUsers",
					slog.String("tag", "db"),
					slog.Any("err", err))
				return ErrBadDatabase
			}
		}
		return nil
	})

}

// AddUserToRoles add the user into roles
func (a *Auth) AddUserToRoles(ctx context.Context, uid int64, rIDs ...int) error {
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

// RemoveRolesFromUser remove roles from the user
func (a *Auth) RemoveRolesFromUser(ctx context.Context, uid int64, rIDs ...int) error {
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

// RemoveUsersFromRole remove users from the role
func (a *Auth) RemoveUsersFromRole(ctx context.Context, rid int, uIDs ...int64) error {
	return a.db.Transaction(ctx, &sql.TxOptions{}, func(ctx context.Context, tx *sqle.Tx) error {
		var err error
		for _, uid := range uIDs {
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

// GrantPerms grant permissions to the role
func (a *Auth) GrantPerms(ctx context.Context, rid int, codes ...string) error {
	return a.db.Transaction(ctx, &sql.TxOptions{}, func(ctx context.Context, tx *sqle.Tx) error {
		var err error
		now := time.Now()
		for _, code := range codes {
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

		return nil
	})
}

// GrantPerms revoke permissions from the role
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
				a.logger.Error("auth: GrantPerms",
					slog.String("tag", "db"),
					slog.Any("err", err))
				return ErrBadDatabase
			}
		}

		return nil
	})
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

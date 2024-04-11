package auth

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/yaitoo/sqle"
)

func TestRBAC(t *testing.T) {
	au := createAuthTest("./tests_rbac.db")

	// setup database
	err := au.RegisterPerm(context.Background(), "reg_perm_code", "test")
	require.NoError(t, err)

	_, err = au.CreateRole(context.Background(), "create_role")
	require.NoError(t, err)

	ruRole1, err := au.CreateRole(context.Background(), "role_user_1")
	require.NoError(t, err)
	ruRole2, err := au.CreateRole(context.Background(), "role_user_2")
	require.NoError(t, err)
	ruRole3, err := au.CreateRole(context.Background(), "role_user_3")
	require.NoError(t, err)

	ruRole4, err := au.CreateRole(context.Background(), "role_user_4")
	require.NoError(t, err)

	ruUser1 := au.genUser.Next()
	ruUser2 := au.genUser.Next()
	ruUser3 := au.genUser.Next()
	ruUser4 := au.genUser.Next()

	err = au.db.Transaction(context.Background(), nil, func(ctx context.Context, tx *sqle.Tx) error {
		_, err = au.createUser(context.Background(), tx, ruUser1, "", "", "", time.Now())
		require.NoError(t, err)

		_, err = au.createUser(context.Background(), tx, ruUser2, "", "", "", time.Now())
		require.NoError(t, err)

		_, err = au.createUser(context.Background(), tx, ruUser3, "", "", "", time.Now())
		require.NoError(t, err)

		_, err = au.createUser(context.Background(), tx, ruUser4, "", "", "", time.Now())
		require.NoError(t, err)

		return nil
	})
	require.NoError(t, err)

	err = au.AddRoleToUsers(context.Background(), ruRole1, ruUser1.Int64, ruUser2.Int64, ruUser3.Int64)
	require.NoError(t, err)

	err = au.AddUserToRoles(context.Background(), ruUser4.Int64, ruRole2, ruRole3, ruRole4)
	require.NoError(t, err)

	tests := []struct {
		name   string
		setup  func(r *require.Assertions)
		assert func(r *require.Assertions)
	}{
		{
			name: "register_perm_should_work",
			assert: func(r *require.Assertions) {
				perms, err := au.GetPerms(context.Background())
				r.NoError(err)

				slices.ContainsFunc(perms, func(it Perm) bool {
					return it.Code == "reg_perm_code" && it.Tag == "test"
				})

			},
		},
		{
			name: "create_role_should_work",
			assert: func(r *require.Assertions) {
				items, err := au.GetRoles(context.Background())
				r.NoError(err)

				slices.ContainsFunc(items, func(it Role) bool {
					return it.Name == "create_role"
				})

			},
		},
		{
			name: "role_user_should_work",
			assert: func(r *require.Assertions) {
				users, err := au.GetUsersByRole(context.Background(), ruRole1)
				r.NoError(err)
				r.Len(users, 3)
				slices.Sort(users)
				r.Equal(ruUser1.Int64, users[0])
				r.Equal(ruUser2.Int64, users[1])
				r.Equal(ruUser3.Int64, users[2])

				err = au.RemoveUsersFromRole(context.Background(), ruRole1, ruUser3.Int64)
				r.NoError(err)

				users, err = au.GetUsersByRole(context.Background(), ruRole1)
				r.NoError(err)
				r.Len(users, 2)
				slices.Sort(users)
				r.Equal(ruUser1.Int64, users[0])
				r.Equal(ruUser2.Int64, users[1])

				roles, err := au.GetRolesByUser(context.Background(), ruUser4.Int64)
				r.NoError(err)
				r.Len(roles, 3)

				var rIDs []int
				for _, r := range roles {
					rIDs = append(rIDs, r.ID)
				}

				r.Equal(ruRole2, rIDs[0])
				r.Equal(ruRole3, rIDs[1])
				r.Equal(ruRole4, rIDs[2])

				err = au.RemoveRolesFromUser(context.Background(), ruUser4.Int64, ruRole4)
				r.NoError(err)

				roles, err = au.GetRolesByUser(context.Background(), ruUser4.Int64)
				r.NoError(err)
				r.Len(roles, 2)

				rIDs = make([]int, 0)
				for _, r := range roles {
					rIDs = append(rIDs, r.ID)
				}
				r.Equal(ruRole2, rIDs[0])
				r.Equal(ruRole3, rIDs[1])

			},
		},
		{
			name: "grant_should_work",
			assert: func(r *require.Assertions) {
				ctx := context.Background()

				err := au.RegisterPerm(ctx, "grant:view", "test")
				r.NoError(err)

				err = au.RegisterPerm(ctx, "grant:update", "test")
				r.NoError(err)

				err = au.RegisterPerm(ctx, "grant:delete", "test")
				r.NoError(err)

				rid, err := au.CreateRole(ctx, "grant_role")
				r.NoError(err)

				uid := au.genUser.Next()
				err = au.db.Transaction(ctx, nil, func(ctx context.Context, tx *sqle.Tx) error {
					_, err := au.createUser(ctx, tx, uid, "", "", "", time.Now())
					return err
				})
				r.NoError(err)

				err = au.AddUserToRoles(ctx, uid.Int64, rid)
				r.NoError(err)

				err = au.GrantPerms(ctx, rid, "grant:view", "grant:update")
				r.NoError(err)

				items, err := au.GetUserPerms(ctx, uid.Int64)
				r.NoError(err)
				r.Len(items, 2)
				slices.Sort(items)

				r.Equal("grant:update", items[0])
				r.Equal("grant:view", items[1])
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.assert(require.New(t))
		})
	}
}

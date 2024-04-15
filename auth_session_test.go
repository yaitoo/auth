package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yaitoo/sqle/shardid"
)

func TestSession(t *testing.T) {
	au := createAuthTest("./tests_session.db")

	s, err := au.SignIn(context.TODO(), "u@session.com", "abc123", LoginOption{CreateIfNotExists: true})
	require.NoError(t, err)

	uid := shardid.Parse(s.UserID)
	err = au.checkRefreshToken(context.Background(), uid, s.RefreshToken)
	require.NoError(t, err)

	// refresh token should be refreshed
	rs, err := au.RefreshSession(context.Background(), s.RefreshToken)
	require.NoError(t, err)
	err = au.checkRefreshToken(context.Background(), uid, rs.RefreshToken)
	require.NoError(t, err)
	// old token should be deleted
	err = au.checkRefreshToken(context.Background(), uid, s.RefreshToken)
	require.ErrorIs(t, err, ErrInvalidToken)

	// sign out should delete all tokens
	err = au.SignOut(context.Background(), uid)
	require.NoError(t, err)

	err = au.checkRefreshToken(context.Background(), uid, rs.RefreshToken)
	require.ErrorIs(t, err, ErrInvalidToken)

}

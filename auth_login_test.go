package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yaitoo/sqle/shardid"
)

func TestSignIn(t *testing.T) {

	authTest := createAuthTest("./tests_sign_in.db")

	tests := []struct {
		name      string
		setup     func(r *require.Assertions) func()
		email     string
		passwd    string
		option    LoginOption
		wantedErr error
		assert    func(r *require.Assertions, s Session)
	}{
		{
			name:      "email_not_found_should_not_work",
			email:     "not_found@mail.com",
			passwd:    "abc123",
			wantedErr: ErrEmailNotFound,
		},
		{
			name:      "create_if_not_exists_should_work",
			email:     "test@mail.com",
			passwd:    "abc123",
			option:    LoginOption{CreateIfNotExists: true, FirstName: "first", LastName: "last"},
			wantedErr: nil,
			assert: func(r *require.Assertions, s Session) {
				userID := shardid.Parse(s.UserID)
				var id int64
				err := authTest.db.On(userID).
					QueryRowBuilder(context.Background(), authTest.createBuilder().
						Select("<prefix>user_token", "user_id").
						Where("hash = {hash}").
						Param("hash", s.refreshTokenHash())).
					Scan(&id)

				r.NoError(err)

			},
		},
		{
			name:      "passwd_not_matched_should_not_work",
			email:     "passwd_not_matched@mail.com",
			passwd:    "not_abc123",
			wantedErr: ErrPasswdNotMatched,
			setup: func(r *require.Assertions) func() {
				_, err := authTest.createLoginWithEmail(context.Background(), "passwd_not_matched@mail.com", "abc123", "", "")

				r.NoError(err)

				return nil
			},
		},
		{
			name:   "passwd_should_work",
			email:  "passwd@mail.com",
			passwd: "abc123",
			setup: func(r *require.Assertions) func() {
				_, err := authTest.createLoginWithEmail(context.Background(), "passwd@mail.com", "abc123", "", "")

				r.NoError(err)

				return nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)
			if test.setup != nil {
				down := test.setup(r)
				if down != nil {
					defer down()
				}
			}

			s, err := authTest.SignIn(context.TODO(), test.email, test.passwd, test.option)
			if test.wantedErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, test.wantedErr)
			}

			if test.assert != nil {
				test.assert(r, s)
			}

		})
	}
}

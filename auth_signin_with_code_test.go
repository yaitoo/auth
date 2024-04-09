package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yaitoo/sqle/shardid"
)

func TestSignInWithCode(t *testing.T) {

	authTest := createAuthTest("./tests_sign_in_with_code.db")

	tests := []struct {
		name         string
		setup        func(r *require.Assertions) string
		email        string
		wantedErr    error
		checkSession bool
	}{
		{
			name:  "email_not_found_should_not_work",
			email: "not_found@sign_in_with_code.com",
			setup: func(r *require.Assertions) string {
				return ""
			},
			wantedErr: ErrEmailNotFound,
		},
		{
			name:      "code_not_matched_should_not_work",
			email:     "code_not_matched@sign_in_with_code.com",
			wantedErr: ErrCodeNotMatched,
			setup: func(r *require.Assertions) string {
				_, err := authTest.CreateSignInCode(context.Background(), "code_not_matched@sign_in_with_code.com", LoginOption{CreateIfNotExists: true})
				r.NoError(err)

				return ""
			},
		},
		{
			name:  "code_should_work",
			email: "code@sign_in_with_code.com",
			setup: func(r *require.Assertions) string {
				code, err := authTest.CreateSignInCode(context.Background(), "code@sign_in_with_code.com", LoginOption{CreateIfNotExists: true})
				r.NoError(err)

				return code

			},
			checkSession: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)

			code := test.setup(r)

			s, err := authTest.SignInWithCode(context.TODO(), test.email, code)
			if test.wantedErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, test.wantedErr)
			}

			if test.checkSession {
				userID := shardid.Parse(s.UserID)
				var id int64
				err := authTest.db.On(userID).
					QueryRowBuilder(context.Background(), authTest.createBuilder().
						Select("<prefix>user_token", "user_id").
						Where("hash = {hash}").
						Param("hash", hashToken(s.RefreshToken))).
					Scan(&id)

				r.NoError(err)
			}

		})
	}
}

func TestSignInMobileWithCode(t *testing.T) {

	authTest := createAuthTest("./tests_sign_in_mobile_with_code.db")

	tests := []struct {
		name         string
		setup        func(r *require.Assertions) string
		mobile       string
		wantedErr    error
		checkSession bool
	}{
		{
			name:   "mobile_not_found_should_not_work",
			mobile: "1+222333444",
			setup: func(r *require.Assertions) string {
				return ""
			},
			wantedErr: ErrMobileNotFound,
		},
		{
			name:      "code_not_matched_should_not_work",
			mobile:    "1+333444555",
			wantedErr: ErrCodeNotMatched,
			setup: func(r *require.Assertions) string {
				_, err := authTest.CreateSignInMobileCode(context.Background(), "1+333444555", LoginOption{CreateIfNotExists: true})
				r.NoError(err)

				return ""
			},
		},
		{
			name:   "code_should_work",
			mobile: "1+444555666",
			setup: func(r *require.Assertions) string {
				code, err := authTest.CreateSignInMobileCode(context.Background(), "1+444555666", LoginOption{CreateIfNotExists: true})
				r.NoError(err)

				return code
			},
			checkSession: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)

			code := test.setup(r)

			s, err := authTest.SignInMobileWithCode(context.TODO(), test.mobile, code)
			if test.wantedErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, test.wantedErr)
			}

			if test.checkSession {
				userID := shardid.Parse(s.UserID)
				var id int64
				err := authTest.db.On(userID).
					QueryRowBuilder(context.Background(), authTest.createBuilder().
						Select("<prefix>user_token", "user_id").
						Where("hash = {hash}").
						Param("hash", hashToken(s.RefreshToken))).
					Scan(&id)

				r.NoError(err)
			}

		})
	}
}

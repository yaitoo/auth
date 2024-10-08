package auth

import (
	"context"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"github.com/yaitoo/sqle/shardid"
)

func TestLoginWithOTP(t *testing.T) {

	authTest := createAuthTest("./tests_login_with_otp.db")

	tests := []struct {
		name         string
		setup        func(r *require.Assertions) string
		email        string
		wantedErr    error
		checkSession bool
	}{
		{
			name:  "email_not_found_should_not_work",
			email: "not_found@sign_in_with_otp.com",
			setup: func(r *require.Assertions) string {
				return ""
			},
			wantedErr: ErrEmailNotFound,
		},
		{
			name:      "otp_not_matched_should_not_work",
			email:     "otp_not_matched@sign_in_with_otp.com",
			wantedErr: ErrOtpNotMatched,
			setup: func(r *require.Assertions) string {
				_, err := authTest.CreateUser(context.Background(), UserStatusWaiting, "otp_not_matched@sign_in_with_otp.com", "", "abc123", "", "")
				r.NoError(err)

				return ""
			},
		},
		{
			name:  "otp_should_work",
			email: "otp@sign_in_with_otp.com",
			setup: func(r *require.Assertions) string {
				u, err := authTest.CreateUser(context.Background(), UserStatusWaiting, "otp@sign_in_with_otp.com", "", "abc123", "", "")
				r.NoError(err)

				pd, err := authTest.getProfileData(context.Background(), authTest.db.On(u.ID), u.ID.Int64)
				r.NoError(err)

				code, err := totp.GenerateCode(pd.TKey, time.Now())
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

			s, err := authTest.LoginWithOTP(context.TODO(), test.email, code)
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

func TestLoginMobileWithOTP(t *testing.T) {

	authTest := createAuthTest("./tests_login_mobile_with_otp.db")

	tests := []struct {
		name         string
		setup        func(r *require.Assertions) string
		mobile       string
		wantedErr    error
		checkSession bool
	}{
		{
			name:   "mobile_not_found_should_not_work",
			mobile: "1+111222333",
			setup: func(r *require.Assertions) string {
				return ""
			},
			wantedErr: ErrMobileNotFound,
		},
		{
			name:      "otp_not_matched_should_not_work",
			mobile:    "1+222333444",
			wantedErr: ErrOtpNotMatched,
			setup: func(r *require.Assertions) string {
				_, err := authTest.CreateUser(context.Background(), UserStatusActivated, "", "1+222333444", "abc123", "", "")
				r.NoError(err)

				return ""
			},
		},
		{
			name:   "otp_should_work",
			mobile: "1+333444555",
			setup: func(r *require.Assertions) string {
				u, err := authTest.CreateUser(context.Background(), UserStatusActivated, "", "1+333444555", "abc123", "", "")
				r.NoError(err)

				pd, err := authTest.getProfileData(context.Background(), authTest.db.On(u.ID), u.ID.Int64)
				r.NoError(err)

				code, err := totp.GenerateCode(pd.TKey, time.Now())
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

			s, err := authTest.LoginMobileWithOTP(context.TODO(), test.mobile, code)
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

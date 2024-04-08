package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/yaitoo/sqle/shardid"
)

// SignIn sign in with email and password.
func (a *Auth) SignIn(ctx context.Context, email, passwd string, option LoginOption) (Session, error) {
	var (
		s   Session
		u   User
		err error
	)

	u, err = a.getUserByEmail(ctx, email)

	if err != nil {
		if !option.CreateIfNotExists {
			return s, err
		}

		if errors.Is(err, ErrEmailNotFound) {
			u, err = a.createLoginWithEmail(ctx, email, passwd, option.FirstName, option.LastName)
			if err != nil {
				return s, err
			}
		}

		return s, err
	}

	fmt.Println(u.CreatedAt)

	return s, nil
}

// SignInWithOTP sign in with email and otp.
func (a *Auth) SignInWithOTP(ctx context.Context, email, otp string, option LoginOption) (*Session, error) {
	return nil, nil
}

// SignInWithCode sign in with email and code.
func (a *Auth) SignInWithCode(ctx context.Context, email, code string, option LoginOption) (*Session, error) {
	return nil, nil
}

// SignInMobile sign in with mobile and password.
func (a *Auth) SignInMobile(ctx context.Context, mobile, passwd string, option LoginOption) (*Session, error) {
	return nil, nil
}

// SignInMobileWithCode sign in with mobile and code.
func (a *Auth) SignInMobileWithCode(ctx context.Context, mobile, code string, option LoginOption) (*Session, error) {
	return nil, nil
}

// SignOut sign out the user, and delete his refresh token
func (a *Auth) SignOut(ctx context.Context, userID shardid.ID) error {
	return a.deleteUserToken(ctx, userID)
}

// RefreshTokens refresh access token and refresh token
func (a *Auth) RefreshTokens(ctx context.Context, userID shardid.ID, refreshToken string) (*Session, error) {
	return nil, nil
}

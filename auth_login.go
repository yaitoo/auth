package auth

import (
	"context"
	"errors"

	"github.com/pquerna/otp/totp"
	"github.com/yaitoo/sqle/shardid"
)

// SignIn sign in with email and password.
func (a *Auth) SignIn(ctx context.Context, email, passwd string, option LoginOption) (Session, error) {
	var (
		u   User
		err error
	)

	u, err = a.getUserByEmail(ctx, email)

	if err == nil {
		if verifyHash(a.hash(), u.Passwd, passwd, u.Salt) {
			return a.createSession(ctx, u.ID)
		}

		return noSession, ErrPasswdNotMatched
	}

	if option.CreateIfNotExists && errors.Is(err, ErrEmailNotFound) {
		u, err = a.createLoginWithEmail(ctx, email, passwd, option.FirstName, option.LastName)
		if err != nil {
			return noSession, err
		}

		return a.createSession(ctx, u.ID)
	}

	return noSession, err

}

// SignInWithOTP sign in with email and otp.
func (a *Auth) SignInWithOTP(ctx context.Context, email, otp string) (Session, error) {

	u, err := a.getUserByEmail(ctx, email)

	if err != nil {
		return noSession, ErrEmailNotFound
	}

	pd, err := a.getUserProfileData(ctx, u.ID)
	if err != nil {
		return noSession, err
	}

	if !totp.Validate(otp, pd.TKey) {
		return noSession, ErrOTPNotMatched
	}

	return a.createSession(ctx, u.ID)

}

// SignInWithCode sign in with email and code.
func (a *Auth) SignInWithCode(ctx context.Context, email, code string, option LoginOption) (*Session, error) {
	return nil, nil
}

// SignInMobile sign in with mobile and password.
func (a *Auth) SignInMobile(ctx context.Context, mobile, passwd string, option LoginOption) (Session, error) {
	var (
		u   User
		err error
	)

	u, err = a.getUserByMobile(ctx, mobile)

	if err == nil {
		if verifyHash(a.hash(), u.Passwd, passwd, u.Salt) {
			return a.createSession(ctx, u.ID)
		}

		return noSession, ErrPasswdNotMatched
	}

	if option.CreateIfNotExists && errors.Is(err, ErrMobileNotFound) {
		u, err = a.createLoginWithMobile(ctx, mobile, passwd, option.FirstName, option.LastName)
		if err != nil {
			return noSession, err
		}

		return a.createSession(ctx, u.ID)
	}

	return noSession, err
}

// SignInMobileWithOTP sign in with mobile and otp.
func (a *Auth) SignInMobileWithOTP(ctx context.Context, mobile, otp string) (Session, error) {
	u, err := a.getUserByMobile(ctx, mobile)

	if err != nil {
		return noSession, ErrMobileNotFound
	}

	pd, err := a.getUserProfileData(ctx, u.ID)
	if err != nil {
		return noSession, err
	}

	if !totp.Validate(otp, pd.TKey) {
		return noSession, ErrOTPNotMatched
	}

	return a.createSession(ctx, u.ID)
}

// SignInMobileWithCode sign in with mobile and code.
func (a *Auth) SignInMobileWithCode(ctx context.Context, mobile, code string, option LoginOption) (*Session, error) {
	return nil, nil
}

// SignOut sign out the user, and delete his refresh token
func (a *Auth) SignOut(ctx context.Context, userID shardid.ID) error {
	return a.deleteUserToken(ctx, userID)
}

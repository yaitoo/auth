package auth

import (
	"context"
	"errors"
)

// CreateLoginCode create a code for loging in by email
func (a *Auth) CreateLoginCode(ctx context.Context, email string, option LoginOption) (string, error) {
	id, err := a.getUserIDByEmail(ctx, email)

	if option.CreateIfNotExists && errors.Is(err, ErrEmailNotFound) {
		u, err := a.createLoginWithEmail(ctx, email, randStr(12, dicAlphaNumber), option.FirstName, option.LastName)
		if err != nil {
			return "", err
		}

		id = u.ID
	}

	return a.createLoginCode(ctx, id, option.UserIP)
}

// LoginWithCode sign in with email and code.
func (a *Auth) LoginWithCode(ctx context.Context, email, code string) (Session, error) {
	u, err := a.getUserByEmail(ctx, email)
	if err != nil {
		return noSession, err
	}

	userIP, err := a.getLoginCodeUserIP(ctx, u.ID, code)
	if err != nil {
		return noSession, err
	}

	return a.createSession(ctx, u.ID, u.FirstName, u.LastName, userIP, "CODE")
}

// CreateLoginMobileCode create a code for loging in by mobile
func (a *Auth) CreateLoginMobileCode(ctx context.Context, mobile string, option LoginOption) (string, error) {
	id, err := a.getUserIDByMobile(ctx, mobile)

	if option.CreateIfNotExists && errors.Is(err, ErrMobileNotFound) {
		u, err := a.createLoginWithMobile(ctx, mobile, randStr(12, dicAlphaNumber), option.FirstName, option.LastName)
		if err != nil {
			return "", err
		}

		id = u.ID
	}

	return a.createLoginCode(ctx, id, option.UserIP)
}

// LoginMobileWithCode sign in with mobile and code.
func (a *Auth) LoginMobileWithCode(ctx context.Context, mobile, code string) (Session, error) {
	u, err := a.getUserByMobile(ctx, mobile)
	if err != nil {
		return noSession, err
	}

	userIP, err := a.getLoginCodeUserIP(ctx, u.ID, code)
	if err != nil {
		return noSession, err
	}

	return a.createSession(ctx, u.ID, u.FirstName, u.LastName, userIP, "CODE")
}

package auth

import (
	"context"
	"errors"
)

// CreateSignInCode create a code for signing in by email
func (a *Auth) CreateSignInCode(ctx context.Context, email string, option LoginOption) (string, error) {
	id, err := a.getUserIDByEmail(ctx, email)

	if option.CreateIfNotExists && errors.Is(err, ErrEmailNotFound) {
		u, err := a.createLoginWithEmail(ctx, email, randStr(12, dicAlphaNumber), option.FirstName, option.LastName)
		if err != nil {
			return "", err
		}

		id = u.ID
	}

	return a.createSignInCode(ctx, id, option.UserIP)
}

// SignInWithCode sign in with email and code.
func (a *Auth) SignInWithCode(ctx context.Context, email, code string) (Session, error) {
	id, err := a.getUserIDByEmail(ctx, email)
	if err != nil {
		return noSession, err
	}

	err = a.checkSignInCode(ctx, id, code)
	if err != nil {
		return noSession, err
	}

	return a.createSession(ctx, id)
}

// CreateSignInMobileCode create a code for signing in by mobile
func (a *Auth) CreateSignInMobileCode(ctx context.Context, mobile string, option LoginOption) (string, error) {
	id, err := a.getUserIDByMobile(ctx, mobile)

	if option.CreateIfNotExists && errors.Is(err, ErrMobileNotFound) {
		u, err := a.createLoginWithMobile(ctx, mobile, randStr(12, dicAlphaNumber), option.FirstName, option.LastName)
		if err != nil {
			return "", err
		}

		id = u.ID
	}

	return a.createSignInCode(ctx, id, option.UserIP)
}

// SignInMobileWithCode sign in with mobile and code.
func (a *Auth) SignInMobileWithCode(ctx context.Context, mobile, code string) (Session, error) {
	id, err := a.getUserIDByMobile(ctx, mobile)
	if err != nil {
		return noSession, err
	}

	err = a.checkSignInCode(ctx, id, code)
	if err != nil {
		return noSession, err
	}

	return a.createSession(ctx, id)
}

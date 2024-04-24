package auth

import (
	"context"
	"errors"
)

// Login sign in with email and password.
func (a *Auth) Login(ctx context.Context, email, passwd string, option LoginOption) (Session, error) {
	u, err := a.GetUserByEmail(ctx, email)

	if err == nil {
		if verifyHash(a.hash(), u.Passwd, passwd, u.Salt) {
			return a.createSession(ctx, u.ID, u.FirstName, u.LastName, option.UserIP, option.UserAgent)
		}

		return noSession, ErrPasswdNotMatched
	}

	if option.CreateIfNotExists && errors.Is(err, ErrEmailNotFound) {
		u, err = a.CreateUser(ctx, UserStatusWaiting, email, "", passwd, option.FirstName, option.LastName)
		if err != nil {
			return noSession, err
		}

		return a.createSession(ctx, u.ID, u.FirstName, u.LastName, option.UserIP, option.UserAgent)
	}

	return noSession, err

}

// LoginMobile sign in with mobile and password.
func (a *Auth) LoginMobile(ctx context.Context, mobile, passwd string, option LoginOption) (Session, error) {
	u, err := a.GetUserByMobile(ctx, mobile)

	if err == nil {
		if verifyHash(a.hash(), u.Passwd, passwd, u.Salt) {
			return a.createSession(ctx, u.ID, u.FirstName, u.LastName, option.UserIP, option.UserAgent)
		}

		return noSession, ErrPasswdNotMatched
	}

	if option.CreateIfNotExists && errors.Is(err, ErrMobileNotFound) {
		u, err = a.CreateUser(ctx, UserStatusWaiting, "", mobile, passwd, option.FirstName, option.LastName)
		if err != nil {
			return noSession, err
		}

		return a.createSession(ctx, u.ID, u.FirstName, u.LastName, option.UserIP, option.UserAgent)
	}

	return noSession, err
}

package auth

import (
	"context"

	"github.com/pquerna/otp/totp"
)

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

	return a.createSession(ctx, u.ID, u.FirstName, u.LastName)

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

	return a.createSession(ctx, u.ID, u.FirstName, u.LastName)
}

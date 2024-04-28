package auth

import (
	"context"

	"github.com/pquerna/otp/totp"
)

// LoginWithOTP sign in with email and otp.
func (a *Auth) LoginWithOTP(ctx context.Context, email, otp string) (Session, error) {

	u, err := a.GetUserByEmail(ctx, email)

	if err != nil {
		return noSession, ErrEmailNotFound
	}

	pd, err := a.getProfileData(ctx, a.db.On(u.ID), u.ID.Int64)
	if err != nil {
		return noSession, err
	}

	if !totp.Validate(otp, pd.TKey) {
		return noSession, ErrOTPNotMatched
	}

	return a.createSession(ctx, u.ID, u.FirstName, u.LastName, "", "OTP")

}

// LoginMobileWithOTP sign in with mobile and otp.
func (a *Auth) LoginMobileWithOTP(ctx context.Context, mobile, otp string) (Session, error) {
	u, err := a.GetUserByMobile(ctx, mobile)

	if err != nil {
		return noSession, ErrMobileNotFound
	}

	pd, err := a.getProfileData(ctx, a.db.On(u.ID), u.ID.Int64)
	if err != nil {
		return noSession, err
	}

	if !totp.Validate(otp, pd.TKey) {
		return noSession, ErrOTPNotMatched
	}

	return a.createSession(ctx, u.ID, u.FirstName, u.LastName, "", "OTP")
}

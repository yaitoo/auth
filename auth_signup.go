package auth

import "context"

// SignUp sign up with email
func (a *Auth) SignUp(ctx context.Context, email, passwd, firstName, lastName string) (User, error) {
	return a.createLoginWithEmail(ctx, email, passwd, firstName, lastName)
}

// SignUpMobile sign up with mobile
func (a *Auth) SignUpMobile(ctx context.Context, mobile, passwd, firstName, lastName string) (User, error) {
	return a.createLoginWithMobile(ctx, mobile, passwd, firstName, lastName)
}
